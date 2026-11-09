package cli

// N03-P01-T09 «Контракт SSE и границы сообщений: Совместимость потребителей».
//
// The card walks the REAL supported consumers of the SSE streaming surface
// (docs/compatibility.md tested rows) through the OLD configuration
// (streaming-policy runtime in kill-switch OFF mode — the pre-OP4 posture,
// bit-for-bit relay) and the NEW configuration (PolicyModeEnforce with
// stream_prefix/stream_final attachments), and pins the explicit refusals
// for unsupported shapes (wrong-typed stream flag, unsupported HTTP method,
// policy denial, malformed policy params). Every consumer-facing wire is
// judged by the pkg/apiformat chat-stream oracle: every data line JSON,
// exactly one [DONE], [DONE] last.
//
// Corpus boundaries:
//   CC-01 OpenCode-shaped /v1/chat/completions, old config — byte-exact contract.
//   CC-02 OpenCode-shaped, new config — the prefix pseudonymize mutator keeps
//         the chunk contract valid for the client.
//   CC-03 Cline-shaped (tools + stream_options.include_usage + fragment
//         merge-by-index), old config — fragment order and usage chunk survive.
//   CC-04 Cline-shaped, new config — the prefix hold-back releases the
//         fragmented tool stream byte-exact at end-of-stream.
//   CC-05 Continue-shaped legacy /v1/completions FIM streaming — the legacy
//         consumer contract is identical under both configurations (the
//         streaming hooks are chat-surface only).
//   UR-01 wrong-typed "stream" field → explicit JSON 400 BEFORE any upstream
//         dial; no phantom SSE bytes.
//   UR-02 unsupported HTTP method on the streaming route → explicit 405,
//         no upstream dial.
//   UR-03 policy prefix deny composed with the richest consumer → the refusal
//         wire is the canonical abort frame + [DONE] only, zero tool bytes.
//   UR-04 malformed prefix policy params → loud degrade (warn logged), the
//         consumer stream stays contract-valid (defaults, byte-exact).
//
// Distinctness: stream_policy_test.go pins the policy mechanics (deny, mutate,
// final flag, kill-switch, TTFB, hold) for a plain content consumer;
// stream_usage_test.go pins the RM-03 injection/suppression shapes;
// n03p1t08_* pins interruption/retry/resume. This corpus composes the SAME
// accepted surface with consumer shapes and configuration flips and judges
// the client wire with the contract oracle — it adds no new policy semantics.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// --- t09 helpers ----------------------------------------------------------------

// t09Wire is the exact SSE wire newStreamPolicyUpstream emits for frames.
func t09Wire(frames ...string) string {
	var b strings.Builder
	for _, f := range frames {
		b.WriteString("data: ")
		b.WriteString(f)
		b.WriteString("\n\n")
	}
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

// code reads the recorder status under the sync lock.
func (s *syncRecorder) code() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec.Code
}

// t09Chunk renders one chat-completion chunk fixture with the given choice JSON.
func t09Chunk(id, choiceJSON string) string {
	return `{"id":"` + id + `","object":"chat.completion.chunk","created":1700000000,"model":"m1","choices":[` + choiceJSON + `]}`
}

// t09UsageChunk renders the RM-03 usage-only terminal chunk (empty choices).
func t09UsageChunk(id string) string {
	return `{"id":"` + id + `","object":"chat.completion.chunk","created":1700000000,"model":"m1","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`
}

// t09ValidateWire judges the CLIENT wire with the contract oracle: every data
// line JSON, exactly one [DONE], [DONE] the final frame.
func t09ValidateWire(t *testing.T, wire string) {
	t.Helper()
	require.NoError(t, apiformat.ValidateChatStream(strings.Split(wire, "\n")),
		"the client wire must satisfy the SSE chat contract")
	assert.Equal(t, 1, strings.Count(wire, "data: [DONE]"), "exactly one terminal frame")
	assert.True(t, strings.HasSuffix(strings.TrimRight(wire, "\n"), "data: [DONE]"),
		"[DONE] must be the final data frame")
}

// t09AwaitEvents waits for at least one event of the given type and returns
// the matching events.
func t09AwaitEvents(t *testing.T, events func() []*eventpub.Event, eventType string) []*eventpub.Event {
	t.Helper()
	var matched []*eventpub.Event
	require.Eventually(t, func() bool {
		matched = matched[:0]
		for _, ev := range events() {
			if ev.EventType == eventType {
				matched = append(matched, ev)
			}
		}
		return len(matched) > 0
	}, 2*time.Second, 10*time.Millisecond, "no %s event", eventType)
	return matched
}

// t09HoldYAML is a stream_prefix policy whose thresholds never fire on a
// short stream (hold to end-of-stream) and whose deny word never matches.
func t09HoldYAML() string {
	hold := strings.Replace(streamDenyFinalYAML("t09-never-matches"), "[stream_final]", "[stream_prefix]", 1)
	return strings.Replace(hold,
		"      words:",
		"      prefix_tokens: 100000\n      prefix_delay_ms: 30000\n      words:", 1)
}

// t09RoutesPost drives a request through the production route table
// (gw.routes) the same way postCompletions does, with method/target freedom.
func t09RoutesPost(t *testing.T, gw *gateway, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// t09CountingUpstream is a passthrough SSE upstream for the full-route rigs;
// dial counts upstream hits (must stay zero for refusal tests).
func t09CountingUpstream(t *testing.T, dial *atomic.Int64, frames ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dial.Add(1)
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"model":"m"`) {
			t.Errorf("upstream body missing model: %s", raw)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, f := range frames {
			_, _ = w.Write([]byte("data: " + f + "\n\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// t09LogCapture captures slog records (and passes them through) so the
// malformed-policy-params degrade can be pinned as LOUD.
type t09LogCapture struct {
	mu      sync.Mutex
	records []string
	next    slog.Handler
}

func (c *t09LogCapture) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (c *t09LogCapture) Handle(ctx context.Context, r slog.Record) error {
	c.mu.Lock()
	c.records = append(c.records, r.Message)
	c.mu.Unlock()
	if c.next != nil {
		return c.next.Handle(ctx, r)
	}
	return nil
}

func (c *t09LogCapture) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &t09LogCapture{next: c.next.WithAttrs(attrs)}
}

func (c *t09LogCapture) WithGroup(name string) slog.Handler {
	return &t09LogCapture{next: c.next.WithGroup(name)}
}

func (c *t09LogCapture) contains(sub string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.records {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// --- supported consumers × configuration matrix ----------------------------------

// TestN03P1T09_CC01_OpenCodeShape_OldConfig_ByteExactContract: an
// OpenCode-shaped chat streaming consumer under the OLD configuration
// (kill-switch off) receives a bit-for-bit relay: multi-line content and the
// opted-in usage chunk ride the wire unmodified, the contract oracle passes,
// and the completion event reports provider usage.
func TestN03P1T09_CC01_OpenCodeShape_OldConfig_ByteExactContract(t *testing.T) {
	frames := []string{
		t09Chunk("oc1", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("oc1", "first line\nsecond line"),
		streamChunkFrame("oc1", " tail"),
		t09UsageChunk("oc1"),
	}
	up := newStreamPolicyUpstream(t, 25*time.Millisecond, frames...)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeOff), up.srv.URL)
	events := captureEvents(t)

	body := `{"model":"m1","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"compat probe"}]}`
	rec := streamPolicyPost(t, gw, body)

	assert.Equal(t, http.StatusOK, rec.code())
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
	assert.Equal(t, t09Wire(frames...), rec.body(),
		"old config: the consumer wire must be bit-for-bit the upstream stream")
	t09ValidateWire(t, rec.body())

	// The consumer's stream_options opt-in is relayed verbatim upstream.
	upBody, _ := up.got.Load().(string)
	require.NotEmpty(t, upBody)
	assert.Contains(t, upBody, `"stream_options":{"include_usage":true}`)

	completed := t09AwaitEvents(t, events, "request.completed")
	require.Len(t, completed, 1)
	ev := completed[0]
	assert.Equal(t, "completed", ev.Termination)
	assert.Equal(t, "chat.completions", ev.Endpoint)
	assert.Equal(t, "provider", ev.UsageSource)
	assert.Equal(t, int64(7), ev.TokensIn)
	assert.Equal(t, int64(3), ev.TokensOut)
}

// TestN03P1T09_CC02_OpenCodeShape_NewConfig_MutatedStreamValid: under the NEW
// configuration the prefix pseudonymize mutator rewrites the secret in the
// held prefix and carries the alias map over later frames — and the resulting
// consumer wire still satisfies the chunk contract (valid JSON data lines,
// one [DONE], completed event).
func TestN03P1T09_CC02_OpenCodeShape_NewConfig_MutatedStreamValid(t *testing.T) {
	const secret = "fixture-pseudonym-9f8e7d6c"
	frames := []string{
		t09Chunk("oc2", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("oc2", "the "+secret+" in the prefix"),
		streamChunkFrame("oc2", " and again "+secret+" in a later frame"),
	}
	up := newStreamPolicyUpstream(t, 25*time.Millisecond, frames...)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamPseudonymizeYAML(secret)), up.srv.URL)
	events := captureEvents(t)

	body := `{"model":"m1","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"compat probe"}]}`
	rec := streamPolicyPost(t, gw, body)

	assert.Equal(t, http.StatusOK, rec.code())
	assert.NotContains(t, rec.body(), secret, "the raw secret must never reach the client")
	assert.GreaterOrEqual(t, strings.Count(rec.body(), "{{YPP_1}}"), 2,
		"the carry map must rewrite the secret in later frames too")
	t09ValidateWire(t, rec.body())

	// Mutation is response-side only: the upstream request stays the
	// client's own payload.
	upBody, _ := up.got.Load().(string)
	require.NotEmpty(t, upBody)
	assert.NotContains(t, upBody, "{{YPP_1}}")
	assert.Contains(t, upBody, `"stream_options":{"include_usage":true}`)

	completed := t09AwaitEvents(t, events, "request.completed")
	require.Len(t, completed, 1)
	assert.Equal(t, "completed", completed[0].Termination)
}

// TestN03P1T09_CC03_ClineShape_OldConfig_FragmentsAndUsage: a Cline-shaped
// consumer (tools + stream_options.include_usage + merge-by-index client) under
// the OLD configuration receives the tool-call fragments in upstream order,
// then the finish chunk and the usage-only chunk — the exact wire a
// merge-by-index client assembles, contract-valid, with provider usage on the
// completion event.
func TestN03P1T09_CC03_ClineShape_OldConfig_FragmentsAndUsage(t *testing.T) {
	frames := t09ClineFixtureFrames("cl1")
	up := newStreamPolicyUpstream(t, 25*time.Millisecond, frames...)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeOff), up.srv.URL)
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, t09ClineRequestBody())

	assert.Equal(t, http.StatusOK, rec.code())
	assert.Equal(t, t09Wire(frames...), rec.body(),
		"old config: fragment order and chunk boundaries must survive untouched")
	t09ValidateWire(t, rec.body())

	upBody, _ := up.got.Load().(string)
	require.NotEmpty(t, upBody)
	assert.Contains(t, upBody, `"tools":[`)
	assert.Contains(t, upBody, `"stream_options":{"include_usage":true}`)

	completed := t09AwaitEvents(t, events, "request.completed")
	require.Len(t, completed, 1)
	ev := completed[0]
	assert.Equal(t, "completed", ev.Termination)
	assert.Equal(t, "provider", ev.UsageSource)
	assert.Equal(t, int64(7), ev.TokensIn)
	assert.Equal(t, int64(3), ev.TokensOut)
}

// TestN03P1T09_CC04_ClineShape_NewConfig_HoldReleaseByteExact: the same
// Cline-shaped consumer under the NEW configuration with a prefix hold-back:
// the buffer holds every fragment (nothing mid-stream), then end-of-stream
// releases the whole fragmented tool+usage stream BYTE-EXACT — the hold is
// invisible to the consumer contract.
func TestN03P1T09_CC04_ClineShape_NewConfig_HoldReleaseByteExact(t *testing.T) {
	frames := t09ClineFixtureFrames("cl2")
	up := newStreamPolicyUpstream(t, 150*time.Millisecond, frames...)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, t09HoldYAML()), up.srv.URL)
	events := captureEvents(t)

	rec, done := streamPolicyPostAsync(t, gw, t09ClineRequestBody())

	time.Sleep(75 * time.Millisecond)
	assert.NotContains(t, rec.body(), "call_9",
		"the prefix gate must hold the buffer while no threshold has fired")
	<-done
	assert.Equal(t, t09Wire(frames...), rec.body(),
		"the held release must be byte-exact for the merge-by-index consumer")
	t09ValidateWire(t, rec.body())

	completed := t09AwaitEvents(t, events, "request.completed")
	require.Len(t, completed, 1)
	assert.Equal(t, "completed", completed[0].Termination)
}

// TestN03P1T09_CC05_ContinueShape_LegacySurface_OldAndNewConfig: the
// Continue-shaped legacy /v1/completions FIM streaming consumer gets an
// identical contract under BOTH configurations — the policy runtime (even
// with a chat-attached stream_prefix policy) leaves the legacy surface a
// byte-exact passthrough with one [DONE] terminal and a completion event.
func TestN03P1T09_CC05_ContinueShape_LegacySurface_OldAndNewConfig(t *testing.T) {
	frames := []string{
		`{"id":"cmpl-1","object":"text_completion.chunk","created":1700000000,"model":"fim","choices":[{"index":0,"text":"return a + b"}]}`,
		`{"id":"cmpl-1","object":"text_completion.chunk","created":1700000000,"model":"fim","choices":[{"index":0,"text":"\n"}]}`,
	}
	const fimBody = `{"model":"m","prompt":"def add(","suffix":"\n    return a + b","max_tokens":16,"stream":true}`

	for name, runtime := range map[string]*PolicyRuntime{
		"old_no_policy_runtime": nil,
		"new_policy_runtime_enforce": func() *PolicyRuntime {
			store := newFakePolicyStore()
			store.add(testOrg, adminstore.PolicyPipeline{
				ID: "t09-legacy", OrgID: testOrg, Name: "t09-chat-prefix", Enabled: true, CurrentVersion: 1,
			}, map[int]string{1: t09HoldYAML()}, []adminstore.PolicyAttachment{chatAttachment(1)})
			return newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			up := newStreamPolicyUpstream(t, 0, frames...)
			gw := &gateway{
				cfg:               config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: up.srv.URL},
				log:               slog.Default(),
				auth:              NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
				res:               stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: up.srv.URL, Enabled: true}},
				pool:              upstream.NewPool(upstream.Options{}),
				streamIdleTimeout: 0,
				policyRuntime:     runtime,
			}
			var mu sync.Mutex
			var seen []*eventpub.Event
			gw.eventNote = func(e *eventpub.Event) { mu.Lock(); defer mu.Unlock(); seen = append(seen, e) }
			events := func() []*eventpub.Event { mu.Lock(); defer mu.Unlock(); return seen }

			rec := t09RoutesPost(t, gw, http.MethodPost, "/v1/completions", fimBody)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
			assert.True(t, rec.Flushed, "the legacy stream must flush")
			assert.Equal(t, t09Wire(frames...), rec.Body.String(),
				"the legacy consumer contract must not depend on the policy configuration")
			t09ValidateWire(t, rec.Body.String())

			// The FIM request forwards prompt+suffix; with no RM-03 provider
			// wiring the consumer body is relayed verbatim (no injection).
			upBody, _ := up.got.Load().(string)
			require.NotEmpty(t, upBody)
			assert.Contains(t, upBody, `"prompt":"def add("`)
			assert.Contains(t, upBody, `"suffix":"\n    return a + b"`)
			assert.NotContains(t, upBody, "include_usage")

			completed := t09AwaitEvents(t, events, "request.completed")
			require.Len(t, completed, 1)
			assert.Equal(t, "completions", completed[0].Endpoint)
		})
	}
}

// --- explicit refusals for unsupported shapes ------------------------------------

// TestN03P1T09_UR01_UnsupportedStreamType_ExplicitJSON400: a wrong-typed
// "stream" field (string instead of bool) on the streaming route is refused
// with an explicit JSON 400 BEFORE anything else — no upstream dial, no SSE
// bytes, no phantom non-stream completion.
func TestN03P1T09_UR01_UnsupportedStreamType_ExplicitJSON400(t *testing.T) {
	dial := &atomic.Int64{}
	up := t09CountingUpstream(t, dial)
	gw := &gateway{
		cfg:               config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: up.URL},
		log:               slog.Default(),
		auth:              NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:               stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: up.URL, Enabled: true}},
		pool:              upstream.NewPool(upstream.Options{}),
		streamIdleTimeout: 0,
	}

	rec := t09RoutesPost(t, gw, http.MethodPost, "/v1/chat/completions",
		`{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":"true"}`)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json",
		"the refusal must be JSON, not an SSE stream")
	assert.Contains(t, rec.Body.String(), "malformed JSON")
	assert.NotContains(t, rec.Body.String(), "data:",
		"no SSE bytes may ride a refusal wire")
	assert.Equal(t, int64(0), dial.Load(), "an unsupported request shape must never reach the upstream")
}

// TestN03P1T09_UR02_UnsupportedMethod_Explicit405: an unsupported HTTP method
// on the streaming route is refused explicitly by the production router —
// no upstream dial, no SSE bytes.
func TestN03P1T09_UR02_UnsupportedMethod_Explicit405(t *testing.T) {
	dial := &atomic.Int64{}
	up := t09CountingUpstream(t, dial)
	gw := &gateway{
		cfg:               config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: up.URL},
		log:               slog.Default(),
		auth:              NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:               stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: up.URL, Enabled: true}},
		pool:              upstream.NewPool(upstream.Options{}),
		streamIdleTimeout: 0,
	}

	rec := t09RoutesPost(t, gw, http.MethodGet, "/v1/chat/completions", `{}`)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.NotContains(t, rec.Body.String(), "data:")
	assert.Equal(t, int64(0), dial.Load())
}

// TestN03P1T09_UR03_PolicyDeny_ToolsConsumer_RefusalWireOnly: a policy prefix
// deny composed with the richest consumer shape produces ONLY the canonical
// refusal wire — the abort error frame plus one [DONE]; zero tool bytes
// (ids, names, argument fragments) reach the client, the wire stays
// contract-valid, and the termination class is policy_denied.
func TestN03P1T09_UR03_PolicyDeny_ToolsConsumer_RefusalWireOnly(t *testing.T) {
	frames := append([]string{
		t09Chunk("ur3", `{"index":0,"delta":{"role":"assistant","content":"about to use the forbidden-phrase helper"}}`),
	}, t09ClineFixtureFrames("ur3")[1:]...)
	up := newStreamPolicyUpstream(t, 30*time.Millisecond, frames...)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamDenyPrefixYAML("forbidden-phrase")), up.srv.URL)
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, t09ClineRequestBody())
	body := rec.body()

	assert.Equal(t, http.StatusOK, rec.code())
	assert.Contains(t, body, "request blocked by organization policy", "the canonical refusal frame")
	assert.NotContains(t, body, "call_9", "no tool-call id may leak")
	assert.NotContains(t, body, "get_weather", "no tool name may leak")
	assert.NotContains(t, body, "tool_calls", "no tool fragment may leak")
	t09ValidateWire(t, body)

	assert.Less(t, up.sent.Load(), int64(len(frames))+1, "the upstream read must be canceled at the abort")

	failed := t09AwaitEvents(t, events, "request.failed")
	require.Len(t, failed, 1)
	assert.Equal(t, "policy_denied", failed[0].Termination)
}

// TestN03P1T09_UR04_MalformedPrefixParams_LoudDegradeValidStream: a malformed
// prefix_tokens policy param cannot silently change the buffer shape — the
// gateway logs the malformed params loudly and serves the consumer stream
// under the documented defaults: byte-exact wire, contract-valid, completed.
func TestN03P1T09_UR04_MalformedPrefixParams_LoudDegradeValidStream(t *testing.T) {
	prev := slog.Default()
	capture := &t09LogCapture{next: prev.Handler()}
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(prev) })

	frames := []string{
		t09Chunk("ur4", `{"index":0,"delta":{"role":"assistant","content":""}}`),
		streamChunkFrame("ur4", "benign content one"),
		streamChunkFrame("ur4", " benign content two"),
	}
	up := newStreamPolicyUpstream(t, 25*time.Millisecond, frames...)
	typoYAML := strings.Replace(t09HoldYAML(),
		"prefix_tokens: 100000", `prefix_tokens: "not-a-number"`, 1)
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, typoYAML), up.srv.URL)
	events := captureEvents(t)

	rec := streamPolicyPost(t, gw, streamRequestBody)

	assert.Equal(t, http.StatusOK, rec.code())
	assert.Equal(t, t09Wire(frames...), rec.body(),
		"the degrade must keep the consumer wire byte-exact (defaults)")
	t09ValidateWire(t, rec.body())
	assert.True(t, capture.contains("malformed"),
		"the malformed policy params must be logged loudly (warn)")

	completed := t09AwaitEvents(t, events, "request.completed")
	require.Len(t, completed, 1)
	assert.Equal(t, "completed", completed[0].Termination)
}

// --- fixtures --------------------------------------------------------------------

// t09ClineFixtureFrames is the Cline-shaped stream fixture: an assistant
// preamble, tool-call fragments split for a merge-by-index client (one index,
// argument JSON torn across two frames), the finish chunk, and the usage-only
// chunk.
func t09ClineFixtureFrames(id string) []string {
	return []string{
		t09Chunk(id, `{"index":0,"delta":{"role":"assistant","content":"Checking the weather."}}`),
		t09Chunk(id, `{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_9","type":"function","function":{"name":"get_weather","arguments":""}}]}}`),
		t09Chunk(id, `{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":`+quoteJSON(`{"city":`)+`}}]}}`),
		t09Chunk(id, `{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":`+quoteJSON(`"Paris"}`)+`}}]}}`),
		t09Chunk(id, `{"index":0,"delta":{},"finish_reason":"tool_calls"}`),
		t09UsageChunk(id),
	}
}

// t09ClineRequestBody is the consumer request matching the fixture: tools
// declared, tool_choice auto, usage opted in.
func t09ClineRequestBody() string {
	return `{"model":"m1","stream":true,"stream_options":{"include_usage":true},` +
		`"tools":[{"type":"function","function":{"name":"get_weather","description":"look up weather",` +
		`"parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}],` +
		`"tool_choice":"auto","messages":[{"role":"user","content":"weather in Paris?"}]}`
}
