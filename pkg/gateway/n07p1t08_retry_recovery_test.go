package cli

// N07-P01-T08 — retry/recovery corpus on the packet's chat surface
// (interruption / retry / resume, composed with the N07 facets).
//
// Card action: «Проверить interruption/retry/resume и восстановление
// результатов без дубликатов и потерь». The family behaviors are covered by
// the predecessor corpora and are CITED, not duplicated: stream-path
// disconnect taxonomy/capture/reconnect replay (N03P1T08 INT-01/02, RSM-01,
// ISO-01), JSON/stream retry billing and fallback chain accounting
// (N03P6T08 clauses 1–6), cache self-heal under retry (N03P2T08). What this
// corpus adds is the N07-specific composition — the typed translated-route
// refusals (T05/T07) and the facet fields (T03/T04) inside the recovery
// machinery:
//
//   - REC-01 a refused primary hop (deterministic translate refusal, typed
//     not-sent proof) advances the fallback chain: the openai fallback
//     serves exactly once, the refusal never dials its upstream, the facet
//     fields (extensions, effort, tools) ride the winning dial verbatim,
//     and the ledger bills the winning hop once (attempt accounting:
//     AttemptCount=2, RetryCount=0);
//   - REC-02 every hop refuses: the typed 400 with the exact reason is the
//     terminal render, zero upstream dials, zero ledger events — recovery
//     exhaustion never invents a success or a duplicate failure;
//   - REC-03 intra-model retry: every retried dial carries the identical
//     facet-bearing body (no field loss on retry), the client sees one
//     completion, the ledger records one completed event with the winning
//     usage and RetryCount=1;
//   - REC-04 stream refusal advances the fallback chain the same way: the
//     client sees one clean stream from the winning hop, the refused hop
//     never dials.
//
// The REAL leg (production stand, retry-then-success and refusal→fallback
// on real routing/ledger) lives in
// services/gateway/integration/n07p1t08_recovery_int_test.go; the consumer
// view of recovery in sdks/go/compat_joint_recovery_test.go.
//
// Stable IDs: N07P1T08-REC-01..04.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
)

// n07t08RetryGateway builds the chat gateway with a deterministic retry
// policy (same shape as the predecessor's n03p6t08RetryGateway), installs
// the stub resolver and ONLY THEN the fallback executor — the executor
// captures the resolver interface value at construction, so the stub must
// be in place first (wiring the executor before reassigning gw.res would
// resolve failover hops through the default stub, i.e. passthrough hops).
func n07t08RetryGateway(t *testing.T, upstreamURL string, res stubModelResolver, maxAttempts int) *gateway {
	t.Helper()
	gw := n03p6t06ChatGateway(t, upstreamURL)
	gw.retryPolicy = retry.Policy{
		MaxAttempts:  maxAttempts,
		BaseDelay:    time.Millisecond,
		MaxDelay:     2 * time.Millisecond,
		JitterFactor: 0,
		RetryOn:      retry.DefaultClassifier,
	}
	gw.res = res
	gw.fallback = router.NewFallbackExecutor(gw.res, 3, nil)
	return gw
}

// n07t08AnthropicUpstream answers with a native Anthropic completion and
// counts dials (the refused hops must never dial).
func n07t08AnthropicUpstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_t08","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"text","text":"не должен отвечать"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestN07P1T08_RefusedPrimary_FallbackServesOnce (REC-01): the primary hop
// is an anthropic-provider model whose translate layer refuses
// reasoning_effort (T05) — a deterministic refusal with the typed not-sent
// proof, so the hop is not retried (MayRepeat forbids repeating Unknown)
// and the chain advances to the openai fallback. The client sees exactly
// one completion from the winning hop, the facet fields ride that dial
// verbatim, and the ledger bills the winner once.
func TestN07P1T08_RefusedPrimary_FallbackServesOnce(t *testing.T) {
	anthSrv, anthHits := n07t08AnthropicUpstream(t)
	var openHits atomic.Int64
	var mu sync.Mutex
	var lastOpen string
	openSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openHits.Add(1)
		b := make([]byte, r.ContentLength)
		_, _ = io.ReadFull(r.Body, b)
		mu.Lock()
		lastOpen = string(b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-t08","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"fallback-t08"},"finish_reason":"stop"}],"usage":{"prompt_tokens":6,"completion_tokens":2,"total_tokens":8}}`))
	}))
	defer openSrv.Close()

	gw := n07t08RetryGateway(t, openSrv.URL, stubModelResolver{
		"smart-claude": {
			ModelName: "smart-claude", Provider: "anthropic", UpstreamURL: anthSrv.URL, Enabled: true,
			FailoverModels: []string{"gpt-4o-mini"},
		},
		"gpt-4o-mini": {
			ModelName: "gpt-4o-mini", Provider: "openai", UpstreamURL: openSrv.URL, Enabled: true,
		},
	}, 2)
	cap := captureAll(t)

	body := `{"model":"smart-claude","messages":[{"role":"user","content":"Погода?","x_client_part":{"locale":"ru"}}],` +
		`"reasoning_effort":"high","tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}],` +
		`"tool_choice":"auto","response_format":{"type":"text"},"x_client_ext":{"trace":"t08"}}`
	rec := n03p6t06PostChat(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	out := rec.Body.String()
	assert.Contains(t, out, `"fallback-t08"`, "the client sees the WINNING hop's answer")
	assert.NotContains(t, out, "reasoning_effort", "no refusal leak: the chain recovered")

	// The refusal is pre-dial: the anthropic upstream was never contacted.
	assert.Zero(t, anthHits.Load(), "a translate refusal must not dial its upstream")
	assert.EqualValues(t, 1, openHits.Load(), "the fallback serves exactly once")

	// The facet fields ride the winning dial verbatim (no loss across hops).
	mu.Lock()
	sent := lastOpen
	mu.Unlock()
	for _, want := range []string{
		`"reasoning_effort":"high"`,
		`"x_client_ext":{"trace":"t08"}`,
		`"x_client_part":{"locale":"ru"}`,
		`"tool_choice":"auto"`,
		`"response_format":{"type":"text"}`,
		`"get_weather"`,
	} {
		assert.Contains(t, sent, want, "the winning dial must carry the facet field %s", want)
	}

	// Ledger: exactly one completed event from the winning hop — the refused
	// hop publishes nothing; the chain transition is an attempt, not a retry.
	events := cap.all()
	require.Len(t, events, 1, "the refused primary hop publishes no event: %v", events)
	ev := events[0]
	require.Equal(t, "request.completed", ev.EventType)
	assert.Equal(t, "smart-claude", ev.ModelRequested, "the client's model")
	assert.Equal(t, "gpt-4o-mini", ev.ModelUsed, "the winning hop's model")
	assert.Equal(t, int64(6), ev.TokensIn)
	assert.Equal(t, int64(2), ev.TokensOut)
	assert.Equal(t, "provider", ev.UsageSource)
	assert.Equal(t, 2, ev.AttemptCount, "the chain transition counts as the second hop")
	assert.Equal(t, 0, ev.RetryCount, "a refusal transition is NOT an intra-model retry")
}

// TestN07P1T08_AllHopsRefuse_TypedTerminal_LedgerSilent (REC-02): every hop
// in the chain refuses (deterministic translate refusals, zero dials). The
// client gets the typed 400 with the exact refusal reason — recovery
// exhaustion must not invent a success — and the ledger stays completely
// silent (no completed, no failed: escrow settles locally).
func TestN07P1T08_AllHopsRefuse_TypedTerminal_LedgerSilent(t *testing.T) {
	anthSrv, anthHits := n07t08AnthropicUpstream(t)
	anth2Srv, anth2Hits := n07t08AnthropicUpstream(t)

	gw := n07t08RetryGateway(t, anth2Srv.URL, stubModelResolver{
		"smart-claude": {
			ModelName: "smart-claude", Provider: "anthropic", UpstreamURL: anthSrv.URL, Enabled: true,
			FailoverModels: []string{"smart-claude-2"},
		},
		"smart-claude-2": {
			ModelName: "smart-claude-2", Provider: "anthropic", UpstreamURL: anth2Srv.URL, Enabled: true,
		},
	}, 2)
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw,
		`{"model":"smart-claude","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"high"}`)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	errMsg := n07t07ErrorMessage(t, rec.Body.Bytes())
	assert.Contains(t, errMsg, "invalid_request_error")
	assert.Contains(t, errMsg, `reasoning_effort "high" is not mapped`, "the exact refusal reason survives chain exhaustion")
	assert.Zero(t, anthHits.Load(), "refusals never dial")
	assert.Zero(t, anth2Hits.Load(), "refusals never dial, on any hop")

	events := cap.all()
	assert.Empty(t, events, "recovery exhaustion of refusals is ledger-silent: %v", events)
}

// TestN07P1T08_Retry_ExtensionsRideEveryDial (REC-03): a transient 503 on
// the JSON path is retried (connection-phase classification), and EVERY
// dial carries the byte-identical facet-bearing body — no field loss on
// retry. The client sees exactly one completion; the ledger bills the
// winning attempt once with RetryCount=1.
func TestN07P1T08_Retry_ExtensionsRideEveryDial(t *testing.T) {
	var mu sync.Mutex
	var dials []string
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		b := make([]byte, r.ContentLength)
		_, _ = io.ReadFull(r.Body, b)
		mu.Lock()
		dials = append(dials, string(b))
		mu.Unlock()
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"message":"overloaded"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-t08r","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ок-t08"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`))
	}))
	defer up.Close()

	gw := n07t08RetryGateway(t, up.URL, stubModelResolver{
		"m": {ModelName: "m", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
	}, 3)
	cap := captureAll(t)

	body := `{"model":"m","messages":[{"role":"user","content":"Привет","x_client_part":{"locale":"ru"}}],` +
		`"reasoning_effort":"high","x_client_ext":{"trace":"t08"},"tool_choice":"auto"}`
	rec := n03p6t06PostChat(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"ок-t08"`, "exactly one completion, no duplicate bodies")

	require.EqualValues(t, 2, hits.Load(), "one retry: two dials, one answer")
	mu.Lock()
	dialsCopy := append([]string(nil), dials...)
	mu.Unlock()
	require.Len(t, dialsCopy, 2)
	assert.Equal(t, dialsCopy[0], dialsCopy[1], "every retried dial carries the byte-identical body")
	for _, want := range []string{`"reasoning_effort":"high"`, `"x_client_ext":{"trace":"t08"}`, `"x_client_part":{"locale":"ru"}`, `"tool_choice":"auto"`} {
		assert.Contains(t, dialsCopy[0], want)
	}

	events := cap.all()
	require.Len(t, events, 1, "the retried-away attempt publishes no event: %v", events)
	ev := events[0]
	require.Equal(t, "request.completed", ev.EventType)
	assert.Equal(t, 1, ev.RetryCount, "the intra-model retry is visible in the event")
	assert.Equal(t, 1, ev.AttemptCount, "no fallback hop was needed")
	assert.Equal(t, int64(5), ev.TokensIn)
	assert.Equal(t, int64(3), ev.TokensOut)
}

// TestN07P1T08_StreamRefusalAdvancesFallback (REC-04): the same refusal→
// fallback recovery on the STREAM path — the refused anthropic hop never
// dials, the openai fallback's stream is served exactly once and clean.
func TestN07P1T08_StreamRefusalAdvancesFallback(t *testing.T) {
	anthSrv, anthHits := n07t08AnthropicUpstream(t)
	var openHits atomic.Int64
	openSSE := "data: {\"id\":\"s-t08\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"поток-t08\"}}]}\n\n" +
		"data: {\"id\":\"s-t08\",\"model\":\"gpt-4o-mini\",\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n" +
		"data: [DONE]\n\n"
	openSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		openHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, openSSE)
	}))
	defer openSrv.Close()

	gw := n07t08RetryGateway(t, openSrv.URL, stubModelResolver{
		"smart-claude": {
			ModelName: "smart-claude", Provider: "anthropic", UpstreamURL: anthSrv.URL, Enabled: true,
			FailoverModels: []string{"gpt-4o-mini"},
		},
		"gpt-4o-mini": {
			ModelName: "gpt-4o-mini", Provider: "openai", UpstreamURL: openSrv.URL, Enabled: true,
		},
	}, 2)
	cap := captureAll(t)

	rec := n03p6t06PostChat(t, gw,
		`{"model":"smart-claude","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"high","stream":true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	sse := rec.Body.String()
	assert.Contains(t, sse, `"поток-t08"`, "the client sees the winning hop's stream")
	assert.True(t, strings.HasSuffix(strings.TrimSpace(sse), "data: [DONE]"), "one clean terminal [DONE]: %q", sse)
	assert.NotContains(t, sse, "reasoning_effort", "no refusal leak into the stream")

	assert.Zero(t, anthHits.Load(), "the refused hop never dials")
	assert.EqualValues(t, 1, openHits.Load(), "the fallback stream serves exactly once")

	events := cap.all()
	require.Len(t, events, 1, "the refused hop publishes no event: %v", events)
	ev := events[0]
	require.Equal(t, "request.completed", ev.EventType)
	assert.Equal(t, "gpt-4o-mini", ev.ModelUsed)
	assert.Equal(t, int64(4), ev.TokensIn, "the winning stream's usage bills once")
	assert.Equal(t, int64(2), ev.TokensOut)
}
