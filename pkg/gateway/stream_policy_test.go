package cli

// OP-4/OP-8 streaming-policy seam regressions (OUTPLAY-PLAN-2026-10-06
// §2.2 п.5): the PrefixGate hold-back releases or aborts BEFORE any buffered
// byte reaches the client, the chunk carry-map mutates the rest of the
// stream before the RT-05 cache record, a post-issuance stream_final deny
// degrades to a flag event, the kill-switch keeps the relay bit-for-bit, and
// the pseudonym carry label never leaves the pipeline payload.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// --- harness -----------------------------------------------------------------

// syncRecorder serializes recorder access: the prefix deadline timer
// goroutine writes concurrently with the drain goroutine.
type syncRecorder struct {
	mu  sync.Mutex
	rec *httptest.ResponseRecorder
}

func newSyncRecorder() *syncRecorder { return &syncRecorder{rec: httptest.NewRecorder()} }

func (s *syncRecorder) Header() http.Header { return s.rec.Header() }

func (s *syncRecorder) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec.Write(p)
}

func (s *syncRecorder) WriteHeader(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rec.WriteHeader(code)
}

func (s *syncRecorder) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rec.Flush()
}

func (s *syncRecorder) body() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec.Body.String()
}

// streamPolicyUpstream is a paced SSE upstream that captures the request
// body it received (the carry-leak probe).
type streamPolicyUpstream struct {
	srv  *httptest.Server
	got  atomic.Value // string — the upstream request body
	gap  time.Duration
	sent atomic.Int64 // frames written before the handler stopped
}

func newStreamPolicyUpstream(t *testing.T, gap time.Duration, frames ...string) *streamPolicyUpstream {
	t.Helper()
	up := &streamPolicyUpstream{gap: gap}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err == nil {
			up.got.Store(string(raw))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for i, f := range frames {
			if up.gap > 0 && i > 0 {
				time.Sleep(up.gap)
			}
			if r.Context().Err() != nil {
				return // the gateway canceled the stream (policy abort)
			}
			up.sent.Add(1)
			printSSEFixture(t, w, "data: "+f+"\n\n")
			if flusher != nil {
				flusher.Flush() // reach the gateway's scanner immediately
			}
		}
		printSSEFixture(t, w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	up.srv = srv
	return up
}

// streamPolicyPost drives the full serveStream path with a policy runtime.
// The request context carries a reservation gate (chatCompletions installs
// one in production) so the finisher stamps the termination class on the
// event; the off-mode plan keeps the escrow out of the test.
func streamPolicyPost(t *testing.T, gw *gateway, body string) *syncRecorder {
	t.Helper()
	rec, done := streamPolicyPostAsync(t, gw, body)
	<-done
	return rec
}

// streamPolicyPostAsync runs serveStream on its own goroutine and returns the
// synchronized recorder, so tests can observe mid-stream client state.
func streamPolicyPostAsync(t *testing.T, gw *gateway, body string) (*syncRecorder, chan struct{}) {
	t.Helper()
	gw.res = stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: gw.cfg.Provider, Enabled: true},
	}
	info := rt06TestResolve(gw, "m1")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	ctx := withReservationGate(r.Context(), &reservationGate{
		plan: &budget.Plan{Mode: budget.ModeOff},
		rsv: &budget.Reservation{OrgID: testOrg, Scopes: []budget.ScopeReserve{
			{Scope: budget.ScopeWallet, Key: testOrg, Bound: 1_000_000},
		}},
	})
	rec := newSyncRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		gw.serveStream(rec, ctx, info, []byte(body), false,
			"sess", testOrg, "", "task", "req", testLogger(), routingDecision{From: "m1"}, "", 0, "", "", "", false)
	}()
	return rec, done
}

// streamPolicyGateway wires a streaming gateway with the org's policies.
func streamPolicyGateway(t *testing.T, mode PolicyMode, yamls ...string) *gateway {
	t.Helper()
	store := newFakePolicyStore()
	for i, y := range yamls {
		store.add(testOrg, adminstore.PolicyPipeline{
			ID: fmt.Sprintf("sp-%d", i), OrgID: testOrg, Name: fmt.Sprintf("stream-policy-%d", i), Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: y}, []adminstore.PolicyAttachment{chatAttachment(10 + i)})
	}
	gw := streamTestGateway("placeholder")
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, mode)
	gw.policyRuntime = rt
	return gw
}

func withUpstream(gw *gateway, url string) *gateway {
	gw.cfg.Provider = url
	return gw
}

// streamChunkFrame renders one content-delta chunk fixture.
func streamChunkFrame(id, content string) string {
	return `{"id":"` + id + `","object":"chat.completion.chunk","created":1700000000,"model":"m1","choices":[{"index":0,"delta":{"content":` + quoteJSON(content) + `}}]}`
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// streamDenyPrefixYAML denies a trigger word in the prefix buffer.
func streamDenyPrefixYAML(word string) string {
	return `
apiVersion: ypp/v1
kind: Policy
name: stream-prefix-deny
mode: enforce
hooks: [stream_prefix]
steps:
  - id: deny-word
    detector: builtin/contains
    params:
      words: ["` + word + `"]
      action: deny
      prefix_tokens: 1
`
}

// streamPseudonymizeYAML pseudonymizes a secret in the prefix buffer using
// the mutator's default kinds, then carries the alias map for the rest of the
// stream. Omitting kinds here exercises the default at the stream consumer.
func streamPseudonymizeYAML(secret string) string {
	return `
apiVersion: ypp/v1
kind: Policy
name: stream-pseudonymize
mode: enforce
hooks: [stream_prefix]
steps:
  - id: pseudo
    mutator: builtin/pseudonymize
    params:
      patterns:
        - category: secret
          pattern: "` + secret + `"
      carry: session
      prefix_tokens: 1
`
}

// streamDenyFinalYAML denies a trigger word in the full aggregate
// (post-issuance: degrades to flag).
func streamDenyFinalYAML(word string) string {
	return `
apiVersion: ypp/v1
kind: Policy
name: stream-final-deny
mode: enforce
hooks: [stream_final]
steps:
  - id: deny-final
    detector: builtin/contains
    params:
      words: ["` + word + `"]
      action: deny
`
}

const streamRequestBody = `{"model":"m1","stream":true,"messages":[{"role":"user","content":"stream-policy-probe"}]}`

// --- prefix deny ---------------------------------------------------------------

// TestStreamPolicy_PrefixDeny_AbortsBeforeFirstByte: a stream_prefix deny
// terminates the stream with the canonical AbortFrame before any buffered
// byte reaches the client, cancels the upstream, and emits request.failed
// with termination=policy_denied plus the decision record.
func TestStreamPolicy_PrefixDeny_AbortsBeforeFirstByte(t *testing.T) {
	const trigger = "forbidden-phrase"
	frames := []string{
		`{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
		streamChunkFrame("c1", "here comes the "+trigger+" and more text to fill the buffer"),
		streamChunkFrame("c1", "tail the client must never see"),
	}
	up := newStreamPolicyUpstream(t, 30*time.Millisecond, frames...)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamDenyPrefixYAML(trigger)), up.srv.URL)
	events := captureEvents(t)

	before := testutil.ToFloat64(metrics.GatewayPolicyDeniesTotal.WithLabelValues("stream-prefix-deny", "chat"))
	rec := streamPolicyPost(t, gw, streamRequestBody)
	after := testutil.ToFloat64(metrics.GatewayPolicyDeniesTotal.WithLabelValues("stream-prefix-deny", "chat"))

	body := rec.body()
	// Note: the SSE error frame renders message+type only (apierrors
	// SSEErrorFrame contract) — the abort is identified by its message.
	assert.Contains(t, body, "request blocked by organization policy")
	assert.Contains(t, body, `"type":"api_error"`)
	assert.Contains(t, body, "data: [DONE]\n\n", "the stream terminates with [DONE]")
	assert.NotContains(t, body, trigger, "denied content must never reach the client")
	assert.NotContains(t, body, `"content"`, "no content frame may pass the prefix gate")
	assert.Greater(t, after, before, "the deny must count in the gateway_policy metrics")

	// The upstream generation was canceled at the abort.
	assert.Less(t, up.sent.Load(), int64(len(frames))+1, "the upstream read must be canceled")

	// The analytics record: request.failed, termination=policy_denied, the
	// decision payload, and no denied content.
	require.Eventually(t, func() bool {
		for _, ev := range events() {
			if ev.EventType == "request.failed" {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "no request.failed event")
	for _, ev := range events() {
		if ev.EventType != "request.failed" {
			continue
		}
		assert.Equal(t, "policy_denied", ev.Termination)
		decisions := parseDecisions(t, ev.Policy)
		require.Len(t, decisions, 1)
		assert.Equal(t, "deny", decisions[0].Verdict)
		assert.NotContains(t, ev.UpstreamResponse, trigger, "denied content stays off the log stream")
		assert.NotContains(t, ev.Policy, "ypp.pseudonyms.v1")
		for k, v := range ev.Labels {
			assert.NotContains(t, k, "ypp.pseudonyms")
			assert.NotContains(t, v, "ypp.pseudonyms")
		}
	}
}

// --- prefix mutator + cache consistency -----------------------------------------

// TestStreamPolicy_PrefixMutator_ClientAndCacheMutated: the kinds-less default
// mutates the prefix released to the client and RT-05 cache, the carry-map
// rewrites later chunks, and the pseudonym carrier label stays internal.
func TestStreamPolicy_PrefixMutator_ClientAndCacheMutated(t *testing.T) {
	const secret = "super-secret-value"
	frames := []string{
		`{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
		streamChunkFrame("c1", "the "+secret+" in the prefix"),
		streamChunkFrame("c1", " and again "+secret+" in a later chunk"),
	}
	up := newStreamPolicyUpstream(t, 10*time.Millisecond, frames...)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamPseudonymizeYAML(secret)), up.srv.URL)
	gw.cfg.CacheStreamEnabled = true
	c := newRT05Cache()
	gw.cache = c
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)
	body := rec.body()

	assert.NotContains(t, body, secret, "the raw secret must never reach the client")
	assert.Contains(t, body, "{{YPP_1}}", "the pseudonym token replaces the secret")
	assert.NotContains(t, body, "ypp.pseudonyms.v1", "the carry label must not reach the client")
	assert.Contains(t, body, "data: [DONE]\n\n", "the stream completes normally")

	// RT-05: the cache entry holds the MUTATED text, not the upstream raw.
	require.Eventually(t, func() bool { return c.writeCount() == 1 }, 2*time.Second, 10*time.Millisecond)
	hit, err := c.LookupWithResult(context.Background(),
		rt05WarmRI(gw, testOrg, "m1"), []byte(streamRequestBody)) // H1: pinned lookup identity
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.NotContains(t, string(hit.Data), secret, "the cache must never store the raw secret")
	assert.Contains(t, string(hit.Data), "{{YPP_1}}")

	// Carry hygiene: not upstream, not in any event surface.
	upBody, _ := up.got.Load().(string)
	require.NotEmpty(t, upBody)
	assert.NotContains(t, upBody, "ypp.pseudonyms.v1", "the carrier must not ride the upstream request")
	assert.NotContains(t, upBody, "{{YPP_1}}", "the upstream request body is the client's own payload")
	require.Eventually(t, func() bool {
		for _, ev := range events() {
			if ev.EventType == "request.completed" {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond)
	for _, ev := range events() {
		assert.NotContains(t, ev.Policy, "ypp.pseudonyms.v1")
		assert.NotContains(t, ev.Payload, "ypp.pseudonyms.v1")
		for k, v := range ev.Labels {
			assert.NotContains(t, k, "ypp.pseudonyms")
			assert.NotContains(t, v, "ypp.pseudonyms")
		}
	}
}

// --- final flag ------------------------------------------------------------------

// TestStreamPolicy_FinalDeny_DegradesToFlagEvent: a stream_final deny after
// issuance cannot recall delivered bytes — the client keeps the full content
// and the completion event records the effective flag with the deny finding.
func TestStreamPolicy_FinalDeny_DegradesToFlagEvent(t *testing.T) {
	const trigger = "final-forbidden"
	frames := []string{
		streamChunkFrame("c1", "the client gets everything: "+trigger),
	}
	up := newStreamPolicyUpstream(t, 10*time.Millisecond, frames...)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamDenyFinalYAML(trigger)), up.srv.URL)
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)
	body := rec.body()

	assert.Contains(t, body, trigger, "post-issuance: the delivered bytes are not recalled")
	assert.Contains(t, body, "data: [DONE]\n\n", "the stream completed normally")
	assert.NotContains(t, body, "blocked by", "no abort frame may appear")

	require.Eventually(t, func() bool {
		for _, ev := range events() {
			if ev.EventType == "request.completed" {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "the request completes (flag, not failure)")
	var completed bool
	for _, ev := range events() {
		if ev.EventType != "request.completed" {
			continue
		}
		completed = true
		decisions := parseDecisions(t, ev.Policy)
		require.Len(t, decisions, 1)
		assert.Equal(t, "flag", decisions[0].Verdict, "the payload records the effective post-issuance verdict")
		require.NotEmpty(t, decisions[0].Findings)
		assert.Equal(t, "deny", decisions[0].Findings[0].Action, "the true deny stays visible in the finding")
		// CORE-TRACE-05: the degrade is explicit, not to be inferred from
		// finding actions — applied says what happened (flag: recorded and
		// delivered), effective keeps what the policy wanted (deny).
		assert.Equal(t, "deny", decisions[0].EffectiveAction, "effective_action keeps the policy's demand")
		assert.Equal(t, "flag", decisions[0].AppliedAction, "applied_action records the post-issuance degrade")
		assert.Equal(t, "stream_final", decisions[0].Hook, "the record names its hook")
	}
	assert.True(t, completed)
}

// --- kill-switch + TTFB ----------------------------------------------------------

// TestStreamPolicy_KillSwitchOff_BitForBit: with the runtime off the relay is
// byte-identical to the upstream stream — no writer, no hold, no frames.
func TestStreamPolicy_KillSwitchOff_BitForBit(t *testing.T) {
	frames := []string{
		`{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
		streamChunkFrame("c1", "plain passthrough"),
	}
	up := newStreamPolicyUpstream(t, 5*time.Millisecond, frames...)
	gw := withUpstream(streamTestGateway(up.srv.URL), up.srv.URL)
	gw.policyRuntime = nil

	rec := streamPolicyPost(t, gw, streamRequestBody)

	want := "data: " + frames[0] + "\n\ndata: " + frames[1] + "\n\ndata: [DONE]\n\n"
	assert.Equal(t, want, rec.body(), "off-mode relay must be byte-identical to the upstream")
}

// TestStreamPolicy_NoPrefixPolicy_NoTTFBDelay: without a stream_prefix
// attachment there is no hold-back — the first chunk reaches the client while
// the upstream is still streaming.
func TestStreamPolicy_NoPrefixPolicy_NoTTFBDelay(t *testing.T) {
	frames := []string{
		streamChunkFrame("c1", "alpha"),
		streamChunkFrame("c1", " beta"),
	}
	up := newStreamPolicyUpstream(t, 300*time.Millisecond, frames...)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamDenyFinalYAML("never-matches")), up.srv.URL)

	rec, done := streamPolicyPostAsync(t, gw, streamRequestBody)

	require.Eventually(t, func() bool { return strings.Contains(rec.body(), "alpha") },
		200*time.Millisecond, 5*time.Millisecond,
		"the first chunk must pass while the upstream is still streaming (no prefix hold)")
	<-done
	assert.Contains(t, rec.body(), "beta")
	assert.Contains(t, rec.body(), "data: [DONE]\n\n")
}

// TestStreamPolicy_PrefixPolicy_HoldsBuffer: with a stream_prefix attachment
// whose thresholds never fire on a short stream, the buffered bytes reach the
// client only when the stream ends — the hold-back is observable.
func TestStreamPolicy_PrefixPolicy_HoldsBuffer(t *testing.T) {
	frames := []string{
		streamChunkFrame("c1", "alpha"),
		streamChunkFrame("c1", " beta"),
	}
	up := newStreamPolicyUpstream(t, 150*time.Millisecond, frames...)
	holdYAML := strings.Replace(streamDenyFinalYAML("never-matches"), "[stream_final]", "[stream_prefix]", 1)
	holdYAML = strings.Replace(holdYAML,
		"      words:",
		"      prefix_tokens: 100000\n      prefix_delay_ms: 30000\n      words:", 1)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, holdYAML), up.srv.URL)

	rec, done := streamPolicyPostAsync(t, gw, streamRequestBody)

	time.Sleep(75 * time.Millisecond)
	assert.NotContains(t, rec.body(), "alpha",
		"the prefix gate must hold the buffer while no threshold has fired")
	<-done
	assert.Contains(t, rec.body(), "alpha", "the end-of-stream flush must release the held buffer")
	assert.Contains(t, rec.body(), "beta")
	assert.Contains(t, rec.body(), "data: [DONE]\n\n")
}
