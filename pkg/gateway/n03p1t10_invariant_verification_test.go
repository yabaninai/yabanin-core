package cli

// N03-P01-T10 «Контракт SSE и границы сообщений: Независимая проверка
// инвариантов» — the packet's independent risk pass over the streaming
// surface: permissions, resource limits, data integrity and the negative
// scenario, each probed through the FULL gateway, most with the policy
// writer chain active (PolicyModeEnforce + stream_prefix hold) so the
// invariants hold under the new configuration, not only the legacy relay.
//
// Invariant map (IV-*):
//   IV-P1 permissions: the auth boundary sits before the stream — missing,
//         invalid and empty credentials are 401 JSON refusals with zero
//         upstream dials and zero SSE bytes.
//   IV-P2 permissions: stream policies are org-scoped permission objects —
//         an org-1 hold policy gates org-1's stream (control) and never
//         gates org-2's identical stream (isolation), same runtime.
//   IV-R1 resource limits: a multi-megabyte held stream releases byte-exact
//         and the ledger's upstream capture stays bounded (16 KiB tee)
//         regardless of the stream size.
//   IV-R2 resource limits: the idle watchdog measures upstream silence, not
//         stream duration — a slow steady drip far exceeding the timeout in
//         total completes byte-exact with no failure event.
//   IV-R3 resource limits: concurrent held streams are isolated — every
//         client receives exactly its own wire, no cross-stream bleed
//         through the shared runtime and resolver.
//   IV-R4 resource limits: an upstream line past the 1 MiB scanner bound
//         fails the drain honestly — the verified held prefix is released,
//         the canonical interrupted terminal follows exactly once, the
//         oversized bytes never reach the client or the ledger.
//   IV-D1 data integrity: byte-wise upstream delivery with the pseudonymize
//         chain active — the client wire carries every multi-byte rune
//         intact (no replacement characters) with the secret rewritten
//         everywhere through the joined-buffer prefix evaluation plus the
//         carry map; at the full gateway the processor receives assembled
//         frames, so the torn-rune teeth for split spans live in the
//         drain-level corpus (pkg/pipeline/streaming).
//   IV-D2 data integrity: the documented CRLF→LF relay normalization
//         survives the policy chain — the held release is the LF golden.
//   IV-N1 negative: frames after the upstream's own [DONE] (followed by a
//         transport death) relay faithfully and add NO second terminal —
//         exactly one [DONE] rides the wire; the drain failure stays a
//         ledger matter with upstream_error.
//   IV-N2 negative: a mid-stream transport break with the hold active
//         (non-idle, live context) releases the verified held prefix, then
//         the canonical interrupted error frame plus exactly one [DONE] —
//         never a silent truncation, never a double terminal.
//
// Distinctness: T05 owns the no-policy split property and late-error wire
// shapes; T07 owns the old-config static goldens; T08 owns the
// interruption/retry/resume families; T09 owns consumer shapes × configs
// and the any-split property under policies. This corpus composes the risk
// facets (permissions, limits, data, negative) none of those pins as such.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	apierrs "github.com/reireirei/yabanin/pkg/apierrors"
	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// --- harness -----------------------------------------------------------------------

// t10HoldGateway wires the shared T10 rig: a strict runtime with the hold
// policy attached to org-1 only, so the org-isolation probes observe both
// the gated and the ungated side of the same runtime. The dial target comes
// from the resolver entries (mi.UpstreamURL wins over cfg.Provider), so a
// placeholder provider URL is safe.
func t10HoldGateway(t *testing.T, url string) *gateway {
	t.Helper()
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "t10-hold", OrgID: testOrg, Name: "t10-hold", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: t09HoldYAML()}, []adminstore.PolicyAttachment{chatAttachment(10)})
	gw := withUpstream(streamTestGateway(url), url)
	gw.policyRuntime = newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	return gw
}

// t10PostAsyncAsOrg drives serveStream on its own goroutine as the given
// org and model (the parameterized twin of streamPolicyPostAsync).
func t10PostAsyncAsOrg(t *testing.T, gw *gateway, orgID, model, body string) (*syncRecorder, chan struct{}) {
	t.Helper()
	info := rt06TestResolve(gw, model)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	ctx := withReservationGate(r.Context(), &reservationGate{
		plan: &budget.Plan{Mode: budget.ModeOff},
		rsv: &budget.Reservation{OrgID: orgID, Scopes: []budget.ScopeReserve{
			{Scope: budget.ScopeWallet, Key: orgID, Bound: 1_000_000},
		}},
	})
	rec := newSyncRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		gw.serveStream(rec, ctx, info, []byte(body), false,
			"sess", orgID, "", "task", "req", testLogger(), routingDecision{From: model}, "", 0, "", "", "", false)
	}()
	return rec, done
}

// t10RawUpstream serves hand-written raw bytes over a hijacked chunked
// connection and then closes WITHOUT the terminal zero chunk — the
// transport-death primitive for the negative and oversized-line probes.
func t10RawUpstream(t *testing.T, write func(rw io.Writer)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = fmt.Fprint(rw, "HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/event-stream\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: close\r\n"+
			"\r\n")
		write(rw)
		_ = rw.Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(250 * time.Millisecond):
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// t10RawChunk writes one raw body chunk through the hijacked writer.
func t10RawChunk(rw io.Writer, piece string) {
	_, _ = fmt.Fprintf(rw, "%x\r\n%s\r\n", len(piece), piece)
}

// t10Model points a stub resolver model at the given upstream URL.
func t10Model(url, name string) resolver.ModelInfo {
	return resolver.ModelInfo{ModelName: name, Provider: "openai", UpstreamURL: url, Enabled: true}
}

// t10EventsOf returns the captured events of the given type.
func t10EventsOf(t *testing.T, events func() []*eventpub.Event, eventType string) []*eventpub.Event {
	t.Helper()
	var matched []*eventpub.Event
	for _, ev := range events() {
		if ev.EventType == eventType {
			matched = append(matched, ev)
		}
	}
	return matched
}

// t10InterruptedTail is the exact client-side tail finishDrainFailure emits
// for a non-idle drain failure (writeSSEError + [DONE] terminator).
func t10InterruptedTail() string {
	return string(apierrs.SSEErrorFrame(&apierrs.E{Type: apierrors.ErrorCodeAPI, Message: "stream interrupted"})) +
		"data: [DONE]\n\n"
}

// --- IV-P: permissions --------------------------------------------------------------

// TestN03P1T10_IVP1_AuthBoundary_BeforeStream: missing, invalid and empty
// credentials are explicit 401 JSON refusals on the production route table —
// no upstream dial, no SSE bytes, before any stream machinery runs.
func TestN03P1T10_IVP1_AuthBoundary_BeforeStream(t *testing.T) {
	dial := &atomic.Int64{}
	up := t09CountingUpstream(t, dial)
	cfg := config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: up.URL}
	gw := &gateway{
		cfg:  cfg,
		log:  testLogger(),
		auth: NewAuthMiddleware(cfg, nil),
		res:  stubModelResolver{"m": t10Model(up.URL, "m")},
		pool: upstream.NewPool(upstream.Options{}),
	}

	cases := []struct {
		name      string
		sendAuth  bool
		authValue string
	}{
		{"missing-header", false, ""},
		{"wrong-token", true, "Bearer not-the-key"},
		{"empty-bearer", true, "Bearer "},
		{"wrong-scheme", true, "Basic dXNlcjpwYXNz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
				"/v1/chat/completions", strings.NewReader(streamRequestBody))
			if tc.sendAuth {
				req.Header.Set("Authorization", tc.authValue)
			}
			rec := httptest.NewRecorder()
			r := chi.NewRouter()
			gw.routes(r)
			r.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Contains(t, rec.Header().Get("Content-Type"), "application/json",
				"the refusal must be JSON, not an SSE stream")
			assert.NotContains(t, rec.Body.String(), "data:",
				"no SSE bytes may ride a refusal wire")
		})
	}
	assert.Equal(t, int64(0), dial.Load(), "unauthenticated requests must never reach the upstream")
}

// TestN03P1T10_IVP2_StreamPolicies_OrgIsolated: one runtime, one hold
// policy on org-1. The control proves the hold gates org-1; the isolation
// half proves the identical org-2 stream flows mid-stream untouched and
// completes byte-exact — one org's policies are not another org's
// permission boundary.
func TestN03P1T10_IVP2_StreamPolicies_OrgIsolated(t *testing.T) {
	const otherOrg = "org-2"
	frames := []string{
		t09Chunk("p2", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("p2", "org-two flows freely"),
		streamChunkFrame("p2", " second frame"),
		t09UsageChunk("p2"),
	}
	fixture := t09Wire(frames...)
	body := `{"model":"m1","stream":true,"messages":[{"role":"user","content":"org isolation probe"}]}`

	t.Run("control-org-1-held", func(t *testing.T) {
		up := newStreamPolicyUpstream(t, 150*time.Millisecond, frames...)
		gw := t10HoldGateway(t, up.srv.URL)
		gw.res = stubModelResolver{"m1": t10Model(up.srv.URL, "m1")}
		events := captureEvents(t)

		rec, done := t10PostAsyncAsOrg(t, gw, testOrg, "m1", body)
		time.Sleep(75 * time.Millisecond)
		assert.NotContains(t, rec.body(), "org-two flows freely",
			"the org-1 hold must gate the stream (control for the isolation half)")
		<-done
		assert.Equal(t, fixture, rec.body(), "the held release must still be byte-exact")
		t09ValidateWire(t, rec.body())

		completed := t09AwaitEvents(t, events, "request.completed")
		require.Len(t, completed, 1)
		assert.Equal(t, testOrg, completed[0].OrgID)
	})

	t.Run("org-2-untouched", func(t *testing.T) {
		up := newStreamPolicyUpstream(t, 150*time.Millisecond, frames...)
		gw := t10HoldGateway(t, up.srv.URL)
		gw.res = stubModelResolver{"m1": t10Model(up.srv.URL, "m1")}
		events := captureEvents(t)

		rec, done := t10PostAsyncAsOrg(t, gw, otherOrg, "m1", body)
		require.Eventually(t, func() bool { return strings.Contains(rec.body(), "org-two flows freely") },
			300*time.Millisecond, 5*time.Millisecond,
			"org-2 must stream mid-flight — org-1's hold policy is not org-2's boundary")
		<-done
		assert.Equal(t, fixture, rec.body(), "the ungated stream must be byte-exact")
		t09ValidateWire(t, rec.body())

		completed := t09AwaitEvents(t, events, "request.completed")
		require.Len(t, completed, 1)
		assert.Equal(t, otherOrg, completed[0].OrgID)
		assert.Equal(t, "completed", completed[0].Termination)
	})
}

// --- IV-R: resource limits -----------------------------------------------------------

// TestN03P1T10_IVR1_MegabyteHeldStream_ByteExactBoundedLedger: a ~1 MiB
// stream held to end-of-stream releases byte-exact, and the ledger's
// upstream capture stays at the 16 KiB tee bound regardless of the stream
// size — the hold never scales the event payload.
func TestN03P1T10_IVR1_MegabyteHeldStream_ByteExactBoundedLedger(t *testing.T) {
	frames := []string{
		t09Chunk("r1", `{"index":0,"delta":{"role":"assistant","content":""}}`),
	}
	for i := 0; i < 32; i++ {
		frames = append(frames, streamChunkFrame("r1", fmt.Sprintf("frame-%04d ", i)+strings.Repeat("x", 32<<10)))
	}
	frames = append(frames, t09UsageChunk("r1"))
	fixture := t09Wire(frames...)
	up := newStreamPolicyUpstream(t, 0, frames...)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, t09HoldYAML()), up.srv.URL)
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)

	assert.Equal(t, fixture, rec.body(), "the megabyte held stream must release byte-exact")
	t09ValidateWire(t, rec.body())

	completed := t09AwaitEvents(t, events, "request.completed")
	require.Len(t, completed, 1)
	assert.LessOrEqual(t, len(completed[0].UpstreamResponse), 16*1024,
		"the ledger capture must stay bounded no matter how large the stream was")
	assert.Equal(t, "provider", completed[0].UsageSource)
	assert.Equal(t, int64(7), completed[0].TokensIn)
	assert.Equal(t, int64(3), completed[0].TokensOut)
}

// TestN03P1T10_IVR2_SlowDrip_CompletesUnderWatchdog: frames arrive every
// 15ms for ~200ms total under a 120ms idle watchdog — silence never
// accumulates, so the watchdog must not fire and the held release must be
// byte-exact with a clean completion.
func TestN03P1T10_IVR2_SlowDrip_CompletesUnderWatchdog(t *testing.T) {
	frames := []string{
		t09Chunk("r2", `{"index":0,"delta":{"role":"assistant","content":""}}`),
	}
	for i := 0; i < 10; i++ {
		frames = append(frames, streamChunkFrame("r2", fmt.Sprintf("drip %02d", i)))
	}
	frames = append(frames, t09UsageChunk("r2"))
	fixture := t09Wire(frames...)
	up := newStreamPolicyUpstream(t, 15*time.Millisecond, frames...)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, t09HoldYAML()), up.srv.URL)
	gw.streamIdleTimeout = 120 * time.Millisecond
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)

	assert.Equal(t, fixture, rec.body(),
		"a slow steady stream must complete byte-exact under the idle watchdog")
	t09ValidateWire(t, rec.body())
	assert.Empty(t, t10EventsOf(t, events, "request.failed"),
		"the watchdog must measure silence, not stream duration")
}

// TestN03P1T10_IVR3_ConcurrentHeldStreams_Isolated: six clients stream
// distinct fixtures through one gateway and runtime, all held; every wire
// must come back byte-exact and complete — no cross-stream bleed through
// the shared machinery.
func TestN03P1T10_IVR3_ConcurrentHeldStreams_Isolated(t *testing.T) {
	const n = 6
	gw := t10HoldGateway(t, "placeholder")
	res := stubModelResolver{}
	fixtures := make([]string, n)
	bodies := make([]string, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("r3-%d", i)
		model := fmt.Sprintf("m%d", i)
		frames := []string{
			t09Chunk(id, `{"index":0,"delta":{"role":"assistant","content":""}}`),
			streamChunkFrame(id, fmt.Sprintf("unique stream %d marker", i)),
			t09UsageChunk(id),
		}
		up := newStreamPolicyUpstream(t, 10*time.Millisecond, frames...)
		fixtures[i] = t09Wire(frames...)
		res[model] = t10Model(up.srv.URL, model)
		bodies[i] = fmt.Sprintf(`{"model":"%s","stream":true,"messages":[{"role":"user","content":"c%d"}]}`, model, i)
	}
	gw.res = res
	events := captureEvents(t)

	recs := make([]*syncRecorder, n)
	dones := make([]chan struct{}, n)
	for i := 0; i < n; i++ {
		recs[i], dones[i] = t10PostAsyncAsOrg(t, gw, testOrg, fmt.Sprintf("m%d", i), bodies[i])
	}
	for i := 0; i < n; i++ {
		<-dones[i]
		assert.Equal(t, fixtures[i], recs[i].body(),
			"stream %d must come back byte-exact — no cross-stream bleed", i)
		t09ValidateWire(t, recs[i].body())
	}
	completed := t09AwaitEvents(t, events, "request.completed")
	assert.Len(t, completed, n, "every concurrent held stream completes")
}

// TestN03P1T10_IVR4_OversizedLine_HonestFailSingleTerminal: an upstream
// line past the 1 MiB scanner bound fails the drain while the hold is
// still buffering. The verified held prefix is released, the canonical
// interrupted terminal follows exactly once, and the oversized bytes reach
// neither the client wire nor the (bounded) ledger capture.
func TestN03P1T10_IVR4_OversizedLine_HonestFailSingleTerminal(t *testing.T) {
	frames := []string{
		t09Chunk("r4", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("r4", "verified prefix before the oversized line"),
	}
	held := ""
	for _, f := range frames {
		held += "data: " + f + "\n\n"
	}
	oversized := "data: {\"choices\":[{\"delta\":{\"content\":\"" + strings.Repeat("O", (1<<20)+64) + "\"}}]}\n\n"
	up := t10RawUpstream(t, func(rw io.Writer) {
		t10RawChunk(rw, held)
		t10RawChunk(rw, oversized)
	})
	gw := t10HoldGateway(t, up.URL)
	gw.res = stubModelResolver{"m1": t10Model(up.URL, "m1")}
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)

	want := held +
		t10InterruptedTail()
	assert.Equal(t, want, rec.body(),
		"the wire must be the released prefix plus the interrupted terminal, exactly once")
	assert.NotContains(t, rec.body(), "OOO",
		"the oversized line must never reach the client")
	t09ValidateWire(t, rec.body())

	failed := t09AwaitEvents(t, events, "request.failed")
	require.Len(t, failed, 1)
	assert.Equal(t, "upstream_error", failed[0].Termination)
	assert.True(t, strings.HasPrefix(failed[0].Error, "stream drain failed: "), "got %q", failed[0].Error)
	assert.LessOrEqual(t, len(failed[0].UpstreamResponse), 16*1024,
		"the oversized bytes must not scale the ledger capture")
}

// --- IV-D: data integrity -------------------------------------------------------------

// TestN03P1T10_IVD1_TornRune_SurvivesMutationChain: byte-by-byte upstream
// delivery with the pseudonymize policy active. At the full gateway the
// processor receives assembled frames — the torn-rune teeth for split
// spans are pinned by the drain-level corpus in pkg/pipeline/streaming —
// so this test pins the end-to-end property: the joined-prefix rewrite
// plus carry map delivers no secret anywhere, at least two aliases, no
// replacement characters, and the intact emoji.
func TestN03P1T10_IVD1_TornRune_SurvivesMutationChain(t *testing.T) {
	const secret = "fixture-pseudonym-t10"
	frames := []string{
		t09Chunk("d1", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("d1", "the "+secret+" in the prefix ✓"),
		streamChunkFrame("d1", " again "+secret+" and 🌍 in a later frame"),
		t09UsageChunk("d1"),
	}
	fixture := t09Wire(frames...)
	up := t09SplitUpstream(t, fixture, t09EveryByteCuts(fixture), time.Millisecond)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamPseudonymizeYAML(secret)), up.URL)
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)

	assert.NotContains(t, rec.body(), secret, "the raw secret must never reach the client")
	assert.GreaterOrEqual(t, strings.Count(rec.body(), "{{YPP_1}}"), 2,
		"the carry map must rewrite the secret in the later frames too")
	assert.NotContains(t, rec.body(), "\uFFFD",
		"no torn rune may degrade to a replacement character")
	assert.Contains(t, rec.body(), "🌍", "the multi-byte content must survive intact")
	t09ValidateWire(t, rec.body())

	completed := t09AwaitEvents(t, events, "request.completed")
	require.Len(t, completed, 1)
	assert.Equal(t, "completed", completed[0].Termination)
}

// TestN03P1T10_IVD2_CRLFUpstream_HoldReleasesLFGolden: a CRLF-framed
// upstream under the hold-to-end policy releases the documented LF
// normalization (T07 pins it old-config; here the policy chain must
// preserve it) — contract-valid, byte-exact against the LF golden.
func TestN03P1T10_IVD2_CRLFUpstream_HoldReleasesLFGolden(t *testing.T) {
	frames := []string{
		t09Chunk("d2", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("d2", "crlf content"),
		t09UsageChunk("d2"),
	}
	crlfFixture := strings.ReplaceAll(t09Wire(frames...), "\n", "\r\n")
	up := t09SplitUpstream(t, crlfFixture, nil, 0)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, t09HoldYAML()), up.URL)
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)

	assert.Equal(t, t09Wire(frames...), rec.body(),
		"the held release must be the LF-normalized golden")
	t09ValidateWire(t, rec.body())

	completed := t09AwaitEvents(t, events, "request.completed")
	require.Len(t, completed, 1)
	assert.Equal(t, "provider", completed[0].UsageSource)
}

// --- IV-N: negative scenario -----------------------------------------------------------

// TestN03P1T10_IVN1_GarbageAfterDone_NoSecondTerminal: the upstream sends
// its own [DONE], then contract-violating frames, then dies without the
// terminal chunk. The relay stays byte-faithful (the violation is the
// upstream's), the gateway appends NO second terminal — the late death is
// a ledger matter with upstream_error and exactly one [DONE] on the wire.
func TestN03P1T10_IVN1_GarbageAfterDone_NoSecondTerminal(t *testing.T) {
	frames := []string{
		t09Chunk("n1", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("n1", "content before the terminator"),
	}
	wire := ""
	for _, f := range frames {
		wire += "data: " + f + "\n\n"
	}
	wire += "data: [DONE]\n\n"
	wire += "data: " + streamChunkFrame("n1", "LATE-GARBAGE-AFTER-DONE") + "\n\n"
	up := t10RawUpstream(t, func(rw io.Writer) {
		t10RawChunk(rw, wire)
	})
	gw := t10HoldGateway(t, up.URL)
	gw.res = stubModelResolver{"m1": t10Model(up.URL, "m1")}
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)

	assert.Equal(t, wire, rec.body(),
		"the relay must stay byte-faithful — the violation relays, nothing is added")
	assert.Equal(t, 1, strings.Count(rec.body(), "data: [DONE]"),
		"exactly one terminal: the upstream's own — the late death must not append another")
	assert.NotContains(t, rec.body(), "request blocked",
		"no refusal frame may appear for an upstream contract violation")
	require.ErrorContains(t, apiformat.ValidateChatStream(strings.Split(rec.body(), "\n")),
		"data after [DONE]")

	failed := t09AwaitEvents(t, events, "request.failed")
	require.Len(t, failed, 1)
	assert.Equal(t, "upstream_error", failed[0].Termination)
	assert.True(t, strings.HasPrefix(failed[0].Error, "stream drain failed: "), "got %q", failed[0].Error)
}

// TestN03P1T10_IVN2_MidStreamBreak_HoldInterruptSingleTerminal: a
// mid-stream transport break (connection death, no [DONE]) with the hold
// active and a live context is not idle-abort: the verified held prefix is
// released, then the canonical interrupted error frame plus exactly one
// [DONE] — never a silent truncation, never a double terminal.
func TestN03P1T10_IVN2_MidStreamBreak_HoldInterruptSingleTerminal(t *testing.T) {
	frames := []string{
		t09Chunk("n2", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("n2", "held content one"),
		streamChunkFrame("n2", " held content two"),
	}
	held := ""
	for _, f := range frames {
		held += "data: " + f + "\n\n"
	}
	up := t10RawUpstream(t, func(rw io.Writer) {
		t10RawChunk(rw, held)
		// No [DONE], no terminal chunk: the connection dies mid-stream.
	})
	gw := t10HoldGateway(t, up.URL)
	gw.res = stubModelResolver{"m1": t10Model(up.URL, "m1")}
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)

	want := held +
		t10InterruptedTail()
	assert.Equal(t, want, rec.body(),
		"the wire must be the verified prefix plus one interrupted terminal")
	assert.NotContains(t, rec.body(), "idle timeout",
		"a mid-stream break is not an idle abort")
	t09ValidateWire(t, rec.body())

	failed := t09AwaitEvents(t, events, "request.failed")
	require.Len(t, failed, 1)
	assert.Equal(t, "upstream_error", failed[0].Termination)
	assert.True(t, strings.HasPrefix(failed[0].Error, "stream drain failed: "), "got %q", failed[0].Error)
}
