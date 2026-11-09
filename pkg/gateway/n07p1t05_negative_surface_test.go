package cli

// N07-P01-T05 — negative-surface wire corpus for translated (cross-API)
// routes. The card's negative criterion: a modeled request field the target
// API cannot express must not be silently dropped. Before this card the
// Anthropic/Bedrock/Vertex adapters ignored `reasoning_effort`, so the
// client received a default-effort answer while the wire said 200 OK.
// After the card the translate layer refuses with the exact reason (I51:
// reject modeled-unsupported fields instead of silently losing them), the
// refusal is the typed request-not-sent proof, and the client-facing render
// is 400 invalid_request_error carrying that reason.
//
// Companion asymmetry pin: on the OpenAI-compatible route the same field is
// not translated at all — the raw body (with `reasoning_effort`) reaches
// the upstream verbatim, which is why only translated routes may reject.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n07t05NativeSSE is a minimal native Anthropic Messages stream. It only
// matters for the RED state and the stream companion: once the translate
// layer refuses, the upstream is never dialed for the negative cases.
const n07t05NativeSSE = "event: ping\n" +
	`data: {"type":"ping"}` + "\n\n" +
	"event: message_delta\n" +
	`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":2,"output_tokens":1,"cache_read_input_tokens":4,"cache_creation_input_tokens":0}}` + "\n\n" +
	"event: message_stop\n" +
	`data: {"type":"message_stop"}` + "\n\n"

type n07t05Upstream struct {
	URL  string
	hits *atomic.Int64
}

// n07t05Serve counts every dial and answers with a native Anthropic SSE
// stream (any non-stream dial also gets SSE bytes; the negative cases must
// never dial at all, so the answer shape is irrelevant to them).
func n07t05Serve(t *testing.T) *n07t05Upstream {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(n07t05NativeSSE))
	}))
	t.Cleanup(srv.Close)
	return &n07t05Upstream{URL: srv.URL, hits: &hits}
}

func TestN07P1T05_AnthropicRouteReasoningEffortRejectedWithExactReason(t *testing.T) {
	up := n07t05Serve(t)
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"high"}`

	rec := serveGateway(t, compatGateway(t, up.URL, "anthropic"), http.MethodPost, "/v1/chat/completions", []byte(body), true)

	out := rec.Body.String()
	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"silent-drop RED: today the request is translated without the field and answered 200; want 400")
	assert.Contains(t, out, "invalid_request_error", "wire type must be the canonical client-error surface")
	assert.Contains(t, out, "reasoning_effort", "the render must carry the exact reason, not a generic failure")
	assert.Contains(t, out, "rejecting", "the refusal must say what happened instead of a silent default")
	assert.Zero(t, up.hits.Load(), "a translate-layer refusal must never dial the upstream")
}

func TestN07P1T05_AnthropicRouteResponseFormatRejectionSurfacesExactReason(t *testing.T) {
	// Established render-class precedent (response_format json_schema, T03
	// family): an unsupported structured-output request is rejected with the
	// field named, not a generic upstream failure. Pinning the same
	// observable contract for the reasoning_effort refusal keeps one
	// client-facing class instead of two.
	up := n07t05Serve(t)
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"o","schema":{"type":"object"}}}}`

	rec := serveGateway(t, compatGateway(t, up.URL, "anthropic"), http.MethodPost, "/v1/chat/completions", []byte(body), true)

	out := rec.Body.String()
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, out, "invalid_request_error")
	assert.Contains(t, out, "response_format", "the field at fault must be named")
	assert.Contains(t, out, "json_schema", "the unsupported variant must be named")
	assert.NotContains(t, out, "outcome unknown", "no silent-drop disguise as a transport failure")
	assert.Zero(t, up.hits.Load())
}

func TestN07P1T05_AnthropicRouteStreamReasoningEffortRejectionIsTerminalSSE(t *testing.T) {
	up := n07t05Serve(t)
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true,"reasoning_effort":"high"}`

	rec := serveGateway(t, compatGateway(t, up.URL, "anthropic"), http.MethodPost, "/v1/chat/completions", []byte(body), true)

	out := rec.Body.String()
	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"streaming RED: today the stream starts 200 and silently answers at default effort; want a terminal 400")
	assert.True(t, strings.Contains(out, `"error"`) || strings.Contains(out, "event: error"),
		"SSE surface must render the refusal as an error frame, got %q", out)
	assert.Contains(t, out, "reasoning_effort")
	assert.Zero(t, up.hits.Load())
}

func TestN07P1T05_OpenAICompatReasoningEffortReachesUpstream(t *testing.T) {
	// Companion asymmetry: OpenAI-compatible routes forward the raw body,
	// so `reasoning_effort` is honored by an OpenAI-speaking upstream and
	// must reach it verbatim. The translated-route refusal must not leak
	// into this surface.
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		captured = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer srv.Close()

	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"high"}`
	rec := serveGateway(t, compatGateway(t, srv.URL, "openai"), http.MethodPost, "/v1/chat/completions", []byte(body), true)

	require.Equal(t, http.StatusOK, rec.Code, "compat route must keep honoring the field: %s", rec.Body.String())
	assert.Contains(t, captured, `"reasoning_effort":"high"`, "the raw field must be forwarded verbatim")
}
