package cli

// N07-P01-T06 — the packet's joint user scenario on the MOCK surface.
//
// Card acceptance: «Совместный пользовательский сценарий пакета выполнен на
// согласованной среде; реальные и mock проверки явно различены» —
// compatibility proven on pinned SDK versions, with REAL and MOCK checks
// explicitly distinguished. This file is the explicitly-MOCK leg: the full
// gateway pipeline (guard → route → effort inject → upstream client →
// adapter translate → render → analytics) on one gateway instance with a
// stubbed resolver and a hermetic upstream. The REAL leg (production server
// factory, real DB/Redis auth, real escrow, real event stream) lives in
// services/gateway/integration/n07p1t06_joint_scenario_int_test.go (build
// tag `integration`); the pinned-SDK consumer leg lives in
// sdks/go/compat_joint_scenario_test.go (recorded gateway bytes, also MOCK).
//
// The story integrates the packet's facets on their surfaces, in one
// session narrative:
//   - facet 3 (T04): unknown client extensions (top-level + per-message)
//     reach the upstream verbatim and response extensions ride back;
//   - facet 2 (T03): structured-output and tool fields forward verbatim; a
//     refusal and tool_calls decode untouched on the client;
//   - effort (T05): reasoning_effort is honored verbatim on the
//     OpenAI-compatible route and refused with the exact reason (400, no
//     dial, no analytics event) on the translated route;
//   - facet 1 (T02): SSE streams stay byte-faithful with the usage chunk
//     and one [DONE]; the RM-03 usage asymmetry is pinned both ways
//     (usage-only chunk suppressed when the client did not ask for usage,
//     passed verbatim with stream_options.include_usage);
//   - the analytics ledger is exact: one request.completed per successful
//     leg, nothing for refusals (escrow settles without an event).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// n07t06CountingEvents returns a restore func counting every analytics event
// by type while a leg runs (the joint scenario asserts the exact ledger),
// plus the usage totals observed across request.completed events.
func n07t06CountingEvents(t *testing.T) (restore func(), counts func() map[string]int, usage func() (int64, int64)) {
	t.Helper()
	var mu sync.Mutex
	byType := map[string]int{}
	var tokensIn, tokensOut int64
	restore = observeEvent(func(e *eventpub.Event) {
		mu.Lock()
		defer mu.Unlock()
		byType[e.EventType]++
		if e.EventType == "request.completed" {
			tokensIn += e.TokensIn
			tokensOut += e.TokensOut
		}
	})
	return restore, func() map[string]int {
			mu.Lock()
			defer mu.Unlock()
			out := make(map[string]int, len(byType))
			for k, v := range byType {
				out[k] = v
			}
			return out
		}, func() (int64, int64) {
			mu.Lock()
			defer mu.Unlock()
			return tokensIn, tokensOut
		}
}

// n07t06OpenAIUpstream answers non-stream turns with a completion that
// carries a refusal, a tool call and provider-extension fields, and stream
// turns with a byte-faithful OpenAI SSE fixture (usage chunk + one [DONE]).
// Every dial is recorded verbatim for the pass-through assertions.
func n07t06OpenAIUpstream(t *testing.T) (*httptest.Server, *atomic.Int64, func() string) {
	t.Helper()
	var hits atomic.Int64
	var mu sync.Mutex
	lastBody := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		mu.Lock()
		lastBody = string(b)
		mu.Unlock()

		var probe struct {
			Stream bool `json:"stream"`
		}
		_ = json.Unmarshal(b, &probe)
		if probe.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-t06\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Привет\"}}]}\n\n")
			_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-t06\",\"model\":\"m\",\"choices\":[],\"usage\":{\"prompt_tokens\":6,\"completion_tokens\":2,\"total_tokens\":8},\"x_provider_ext\":{\"latency_ms\":42}}\n\n")
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-t06","object":"chat.completion","model":"m","provider_ext":{"trace":"t06"},"choices":[{"index":0,"message":{"role":"assistant","content":"","refusal":"Я не могу помочь с этим.","tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Москва\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10},"x_provider_usage":{"cached":true}}`))
	}))
	t.Cleanup(srv.Close)
	last := func() string {
		mu.Lock()
		defer mu.Unlock()
		return lastBody
	}
	return srv, &hits, last
}

// TestN07P1T06_JointOpenAISurfaceSession walks one client session through
// the OpenAI-compatible surface: extensions + effort + structured fields in,
// provider extensions + refusal + tool calls back, then the streaming turn —
// with an exact analytics ledger.
func TestN07P1T06_JointOpenAISurfaceSession(t *testing.T) {
	srv, hits, lastBody := n07t06OpenAIUpstream(t)
	gw := compatGateway(t, srv.URL, "openai")

	restore, counts, usage := n07t06CountingEvents(t)
	defer restore()

	// Turn 1 — non-stream: extensions + effort + structured fields forward
	// verbatim (facets 2+3 + effort asymmetry), provider extensions +
	// refusal + tool calls come back untouched.
	body := `{"model":"m","messages":[{"role":"user","content":"Погода?","x_client_part":{"locale":"ru"}}],"reasoning_effort":"high","tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}],"tool_choice":"auto","response_format":{"type":"text"},"x_client_ext":{"trace":"t06"},"stream_options":{"include_usage":true}}`
	rec := serveGateway(t, gw, http.MethodPost, "/v1/chat/completions", []byte(body), true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	sent := lastBody()
	var sentJSON struct {
		Messages []map[string]json.RawMessage `json:"messages"`
	}
	require.NoError(t, json.Unmarshal([]byte(sent), &sentJSON))
	var sentTop map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(sent), &sentTop))
	for _, key := range []string{"reasoning_effort", "tools", "tool_choice", "response_format", "stream_options", "x_client_ext"} {
		assert.Contains(t, sent, key, "facets 2+3/effort: %s must reach the upstream", key)
	}
	assert.JSONEq(t, `"high"`, string(sentTop["reasoning_effort"]))
	assert.JSONEq(t, `{"trace":"t06"}`, string(sentTop["x_client_ext"]))
	require.Len(t, sentJSON.Messages, 1)
	assert.JSONEq(t, `{"locale":"ru"}`, string(sentJSON.Messages[0]["x_client_part"]), "per-message extension must survive verbatim")

	out := rec.Body.String()
	for _, want := range []string{`"refusal":"Я не могу помочь с этим."`, `"tool_calls"`, `"get_weather"`, `"provider_ext":{"trace":"t06"}`, `"x_provider_usage":{"cached":true}`} {
		assert.Contains(t, out, want, "facet 2/3: provider-side fields must reach the client untouched")
	}

	// Turn 2 — stream without stream_options: the usage-only chunk is
	// suppressed from the client bytes (RM-03: the gateway did not ask the
	// client for usage), the stream still terminates with one [DONE], and
	// the ledger still records the usage it parsed from that chunk.
	streamBody := `{"model":"m","messages":[{"role":"user","content":"Привет"}],"stream":true}`
	rec = serveGateway(t, gw, http.MethodPost, "/v1/chat/completions", []byte(streamBody), true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	sse := rec.Body.String()
	assert.True(t, strings.HasSuffix(strings.TrimSpace(sse), "data: [DONE]"), "exactly one terminal [DONE]: %q", sse)
	assert.NotContains(t, sse, `"prompt_tokens":6`, "RM-03: usage-only chunk is withheld when the client did not ask for usage")

	// Turn 3 — stream with stream_options.include_usage: the usage chunk
	// passes byte-faithfully (facet 1) with the response extension riding it.
	wantsUsage := `{"model":"m","messages":[{"role":"user","content":"Привет"}],"stream":true,"stream_options":{"include_usage":true}}`
	rec = serveGateway(t, gw, http.MethodPost, "/v1/chat/completions", []byte(wantsUsage), true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	sse = rec.Body.String()
	assert.True(t, strings.HasSuffix(strings.TrimSpace(sse), "data: [DONE]"), "exactly one terminal [DONE]: %q", sse)
	assert.Contains(t, sse, `"usage":{"prompt_tokens":6,"completion_tokens":2,"total_tokens":8}`)
	assert.Contains(t, sse, `"x_provider_ext":{"latency_ms":42}`, "response extension must ride the SSE chunk untouched")

	// Ledger: exactly one request.completed per successful turn — usage from
	// every turn (including the suppressed-chunk one), nothing else.
	c := counts()
	assert.Equal(t, 3, c["request.completed"], "exactly one ledger event per successful turn: %v", c)
	assert.Zero(t, c["request.failed"], "no failures in the session: %v", c)
	inTok, outTok := usage()
	assert.EqualValues(t, 19, inTok, "usage from all three turns (7+6+6 prompt), incl. the suppressed chunk")
	assert.EqualValues(t, 7, outTok, "usage from all three turns (3+2+2 completion)")
	assert.EqualValues(t, 3, hits.Load(), "exactly one upstream dial per turn")
}

// TestN07P1T06_JointTranslatedRefusalSession walks the same client through
// the translated (Anthropic) surface: the effort/structured refusals are
// loud 400s with the exact reason, zero upstream dials and NO analytics
// events (escrow settles locally), and a clean turn on the same surface
// still completes with a translated answer and a ledger event.
func TestN07P1T06_JointTranslatedRefusalSession(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_t06","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"text","text":"Привет! Чем помочь?"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":9,"output_tokens":4}}`))
	}))
	defer srv.Close()
	gw := compatGateway(t, srv.URL, "anthropic")

	restore, counts, _ := n07t06CountingEvents(t)
	defer restore()

	// Refusal 1 — reasoning_effort on the translated route (T05 negative,
	// composed): 400 + exact reason, no dial, no event.
	rec := serveGateway(t, gw, http.MethodPost, "/v1/chat/completions",
		[]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"high"}`), true)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_request_error")
	assert.Contains(t, rec.Body.String(), "reasoning_effort")
	assert.Zero(t, hits.Load(), "the refusal must not dial the upstream")

	// Refusal 2 — response_format json_schema (T03 family render class):
	// 400 + the field and variant named, no dial, no event.
	rec = serveGateway(t, gw, http.MethodPost, "/v1/chat/completions",
		[]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"o","schema":{"type":"object"}}}}`), true)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "response_format")
	assert.Contains(t, rec.Body.String(), "json_schema")
	assert.Zero(t, hits.Load())

	// Clean turn on the same surface: the translated answer completes and
	// the ledger records it.
	rec = serveGateway(t, gw, http.MethodPost, "/v1/chat/completions",
		[]byte(`{"model":"m","messages":[{"role":"user","content":"Привет"}]}`), true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	out := rec.Body.String()
	assert.Contains(t, out, `Привет! Чем помочь?`, "the translated answer must reach the client")
	assert.Contains(t, out, `"usage"`, "usage must ride the translated completion")
	assert.EqualValues(t, 1, hits.Load(), "exactly one upstream dial for the clean turn")

	// Ledger: the two refusals produced NOTHING; the clean turn produced
	// exactly one request.completed.
	c := counts()
	assert.Equal(t, 1, c["request.completed"], "only the clean turn settles an event: %v", c)
	assert.Zero(t, c["request.failed"], "refusals settle the escrow without an event (T05): %v", c)
}
