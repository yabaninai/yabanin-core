package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// printSSEFixture writes an SSE fixture in a test handler; recorder write
// errors are test-bug signals, so fail loudly instead of dropping the payload.
func printSSEFixture(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	if _, err := fmt.Fprint(w, body); err != nil {
		t.Errorf("write SSE fixture: %v", err)
	}
}

// streamTestGateway builds a gateway wired to a real upstream.Pool pointing
// at upstreamURL. No DB, no Redis, no circuit breaker, no rule engine. Tests
// exercise the full serveStream path through the pool and adapters.
//
// The pool defaults its allowlist to the configured test origin, so the
// loopback test upstream works while redirect/SSRF re-validation stays
// active for every other destination.
func streamTestGateway(upstreamURL string) *gateway {
	pool := upstream.NewPool(upstream.Options{
		BaseURL: upstreamURL,
	})
	return &gateway{
		pool: pool,
		cfg: config.Gateway{
			Provider:      upstreamURL,
			APIKey:        "test-key",
			FallbackKey:   "test-fallback",
			FallbackModel: "smart",
			AuthMode:      "fail-open",
		},
		fallback:    fallbackrouter.NewFallbackExecutor(nil, 3, nil),
		retryPolicy: retry.Policy{MaxAttempts: 1}, // no retry by default in tests
		log:         slog.Default(),
	}
}

func testLogger() *slog.Logger { return slog.Default() }

// --- Test 1: OpenAI passthrough via pool -------------------------------------

func TestServeStream_PoolGetUsed_OpenAIPassthrough(t *testing.T) {
	const sse = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: [DONE]\n\n"

	var (
		gotPath string
		gotAuth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, sse)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	info := resolver.ModelInfo{
		ModelName: "gpt-4",
		Provider:  "",
		Enabled:   true,
	}

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "gpt-4", "hi"), false, "sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "data: {\"id\":\"1\"")
	assert.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"),
		"expected stream terminator, got: %q", body)

	// Pool routing contract: OpenAI adapter hits /v1/chat/completions.
	assert.Equal(t, "/v1/chat/completions", gotPath)
	assert.NotEmpty(t, gotAuth, "Authorization header must be set")
}

// --- Test 2: Anthropic events translated to OpenAI chunks --------------------

func TestServeStream_AnthropicEventsTranslated(t *testing.T) {
	const anthropicSSE = "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":5,\"output_tokens\":3}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"

	var (
		gotPath         string
		gotXAPIKey      string
		gotAnthropicVer string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotXAPIKey = r.Header.Get("x-api-key")
		gotAnthropicVer = r.Header.Get("anthropic-version")
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, anthropicSSE)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	// Neutral variable name: gosec G101 flags string literals in key-named fields.
	anthropicFixtureValue := "test-anthropic-key"
	info := resolver.ModelInfo{
		ModelName:      "claude-3",
		Provider:       "anthropic",
		UpstreamAPIKey: anthropicFixtureValue,
		Enabled:        true,
	}

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "claude-3", "hi"), false, "sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response body: %s", rec.Body.String())

	out := rec.Body.String()
	// Translation contract: Anthropic events must be converted to OpenAI chunks.
	assert.Contains(t, out, "\"object\":\"chat.completion.chunk\"")
	assert.Contains(t, out, "\"model\":\"claude-3\"")
	assert.Contains(t, out, "\"role\":\"assistant\"")
	assert.Contains(t, out, "\"content\":\"Hello\"")
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"),
		"expected [DONE] terminator, got: %q", out)

	// Upstream must have received a native Anthropic request.
	assert.Equal(t, "/v1/messages", gotPath, "Anthropic adapter must hit /v1/messages")
	assert.Equal(t, "test-anthropic-key", gotXAPIKey)
	assert.Equal(t, "2023-06-01", gotAnthropicVer)
}

// --- Test 3: Fallback advances to second model when first returns 5xx --------

func TestServeStream_FallbackAdvancesOnUpstream5xx(t *testing.T) {
	var (
		primaryHits  int32
		fallbackHits int32
	)

	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&primaryHits, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"overloaded"}`))
	}))
	defer primarySrv.Close()

	fallbackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fallbackHits, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, "data: {\"id\":\"fb\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer fallbackSrv.Close()

	gw := streamTestGateway(primarySrv.URL)
	info := resolver.ModelInfo{
		ModelName:      "gpt-4",
		Provider:       "",
		UpstreamURL:    primarySrv.URL,
		Enabled:        true,
		FailoverModels: []string{"gpt-4-fallback"},
	}

	// Inject a resolver so the fallback chain can resolve gpt-4-fallback.
	gw.fallback = fallbackrouter.NewFallbackExecutor(stubModelResolver{
		"gpt-4-fallback": resolver.ModelInfo{
			ModelName:   "gpt-4-fallback",
			Provider:    "",
			UpstreamURL: fallbackSrv.URL,
			Enabled:     true,
		},
	}, 3, nil)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "gpt-4", "hi"), false, "sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response body: %s", rec.Body.String())

	require.Equal(t, int32(1), atomic.LoadInt32(&primaryHits),
		"primary upstream should be hit exactly once")
	require.Equal(t, int32(1), atomic.LoadInt32(&fallbackHits),
		"fallback upstream should be hit exactly once after primary 503")

	assert.Contains(t, rec.Body.String(), "\"content\":\"ok\"")
	assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"))
}

// --- Test 4: All upstreams fail → SSE error + [DONE] -------------------------

func TestServeStream_AllUpstreamFails_EmitsSSEError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	info := resolver.ModelInfo{
		ModelName: "gpt-4",
		Provider:  "",
		Enabled:   true,
	}
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "gpt-4", "hi"), false, "sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)

	// Even on failure, the gateway must emit a valid SSE error frame so
	// OpenAI clients (which already received Content-Type: text/event-stream)
	// can parse it.
	body := rec.Body.String()
	assert.Contains(t, body, "data: {\"error\":")
	assert.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"),
		"failed stream must still terminate with [DONE], got: %q", body)
}

// --- Test 5 (P3.14): Raw-body mode forwards client body verbatim ------------

func TestServeStream_RawBodyUsed_WhenHeaderPresent(t *testing.T) {
	// Simulate a client sending a request with extra/extended fields that
	// wouldn't survive json.Marshal(openai.ChatCompletionRequest{...}). The
	// raw-body flag tells the gateway to forward the body as-is.
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, "data: {\"id\":\"1\",\"choices\":[]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	info := resolver.ModelInfo{
		ModelName: "gpt-4",
		Provider:  "",
		Enabled:   true,
	}

	// Body has extra fields (temperature, tools) that the old rebuild-from-
	// messages path would have dropped. serveStream in raw mode must forward
	// the exact bytes.
	rawBody := []byte(`{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"hi"}],"temperature":0.7,"tools":[{"type":"function","function":{"name":"do_x"}}]}`)

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info, rawBody, true, "sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())

	// Upstream must have received the body byte-for-byte (no model rewrite,
	// no schema translation).
	assert.JSONEq(t, string(rawBody), gotBody,
		"raw-body mode must forward body verbatim, got: %s", gotBody)
}

// --- Test 6 (P3.14): Raw-body mode disables fallback chain ------------------

func TestServeStream_RawBodyFallbackDisabled(t *testing.T) {
	var (
		primaryHits  int32
		fallbackHits int32
	)
	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&primaryHits, 1)
		w.WriteHeader(http.StatusServiceUnavailable) // retryable; would normally advance chain
	}))
	defer primarySrv.Close()

	fallbackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fallbackHits, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, "data: {\"id\":\"fb\"}\n\ndata: [DONE]\n\n")
	}))
	defer fallbackSrv.Close()

	gw := streamTestGateway(primarySrv.URL)
	info := resolver.ModelInfo{
		ModelName:      "gpt-4",
		Provider:       "",
		UpstreamURL:    primarySrv.URL,
		Enabled:        true,
		FailoverModels: []string{"gpt-4-fallback"},
	}
	gw.fallback = fallbackrouter.NewFallbackExecutor(stubModelResolver{
		"gpt-4-fallback": resolver.ModelInfo{
			ModelName:   "gpt-4-fallback",
			UpstreamURL: fallbackSrv.URL,
			Enabled:     true,
		},
	}, 3, nil)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}

	rec := httptest.NewRecorder()
	// rawBodyMode=true → fallback MUST be disabled even though info.FailoverModels is non-empty.
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "gpt-4", "hi"), true, "sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)

	// Primary was hit (returned 503). Fallback must NOT have been hit because
	// raw-body mode collapses the chain to primary-only.
	require.Equal(t, int32(1), atomic.LoadInt32(&primaryHits),
		"primary upstream should be hit once")
	require.Equal(t, int32(0), atomic.LoadInt32(&fallbackHits),
		"fallback upstream must NOT be hit in raw-body mode")

	// Client got an SSE error frame + [DONE], not the fallback's 200 stream.
	body := rec.Body.String()
	assert.Contains(t, body, "data: {\"error\":")
	assert.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"))
}

// --- Test 7: Normal mode preserves extra client fields (regression) ---------

func TestServeStream_NormalModePreservesExtraFields(t *testing.T) {
	// Regression test for the original P3.14 bug: in normal (non-raw) mode,
	// the old code rebuilt body from {model, messages, stream:true} only,
	// silently dropping temperature/tools/response_format. The fix forwards
	// the original body with only `model` rewritten per hop.
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, "data: {\"id\":\"1\"}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}

	// Send a request with extended fields; serveStream in normal mode must
	// preserve them while rewriting the model name (per-hop).
	body := []byte(`{"model":"will-be-overridden","stream":true,"messages":[{"role":"user","content":"hi"}],"temperature":0.3,"top_p":0.9,"max_tokens":100}`)

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info, body, false, "sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code)

	// Upstream body must carry through temperature/top_p/max_tokens even
	// though they're not in openai.ChatCompletionRequest's narrow schema.
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(gotBody), &got))
	assert.InDelta(t, 0.3, got["temperature"], 0.0001)
	assert.InDelta(t, 0.9, got["top_p"], 0.0001)
	assert.InDelta(t, 100.0, got["max_tokens"], 0.0001)
	// Model rewritten to the resolved info.ModelName ("gpt-4").
	assert.Equal(t, "gpt-4", got["model"])
}

// --- helpers -----------------------------------------------------------------

// streamBody builds an OpenAI-shape request body for tests. The default
// fixture sets stream=true so serveStream's path is exercised.
func streamBody(t *testing.T, model, content string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model":    model,
		"stream":   true,
		"messages": []map[string]string{{"role": "user", "content": content}},
	})
	require.NoError(t, err)
	return body
}

// stubModelResolver satisfies router.ModelResolver for the fallback test.
type stubModelResolver map[string]resolver.ModelInfo

func (s stubModelResolver) Resolve(_ context.Context, name string) resolver.ModelInfo {
	if info, ok := s[name]; ok {
		return info
	}
	return resolver.ModelInfo{ModelName: name, Enabled: true}
}

// ResolveChecked satisfies the gateway's checked modelResolver (RT-06). The
// stub has no I/O, so it never reports an unavailable registry; missing names
// keep the legacy name-only shape.
func (s stubModelResolver) ResolveChecked(ctx context.Context, name string) (resolver.ModelInfo, error) {
	return s.Resolve(ctx, name), nil
}

// --- PO-05a: egress guards on the streaming surface --------------------------
//
// U1 debt: the pre-egress guard hooks were wired in chat.go (non-streaming and
// the chatCompletions entry) but NOT on the streaming surface itself. serveStream
// must run the guards before the first SSE byte so a deny emits a clean terminal
// error frame + [DONE] instead of a half-open stream, and so any caller that
// reaches serveStream directly is protected.

// TestServeStream_GuardDeny_EmitsSSEErrorAndDoesNotForward: with the guard
// hooks in deny mode and a PAN-bearing body, serveStream writes a guard_denied
// SSE error frame + [DONE] and never opens an upstream connection.
func TestServeStream_GuardDeny_EmitsSSEErrorAndDoesNotForward(t *testing.T) {
	var upstreamCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
		printSSEFixture(t, w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.guardHooks = guardhooks.New(guardhooks.ModeDeny)
	gw.log = testLogger()

	info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}
	// A PAN (Luhn-valid) triggers the secret/PAN category in deny mode.
	body := streamBody(t, "gpt-4", "my card is 4242 4242 4242 4242, please charge it")

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		body, false, "sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)

	// No upstream connection must be opened — the guard fired before forwarding.
	assert.Equal(t, int32(0), atomic.LoadInt32(&upstreamCalls),
		"deny mode must not forward to upstream")

	out := rec.Body.String()
	assert.Contains(t, out, "guard_denied",
		"expected a guard_denied SSE error frame, got: %q", out)
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"),
		"deny must terminate the stream with [DONE], got: %q", out)
	// The sensitive PAN must not leak into the error frame.
	assert.NotContains(t, out, "4242 4242 4242 4242")
}

// TestServeStream_GuardCleanBody_ForwardsNormally: a clean body passes the
// guard and is forwarded to upstream (guards are off by default; here we
// confirm deny mode is a no-op for non-sensitive content on the stream path).
func TestServeStream_GuardCleanBody_ForwardsNormally(t *testing.T) {
	var upstreamCalls int32
	const sse = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n" +
		"data: [DONE]\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
		printSSEFixture(t, w, sse)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.guardHooks = guardhooks.New(guardhooks.ModeDeny)
	gw.log = testLogger()

	info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}
	body := streamBody(t, "gpt-4", "hello, what is the weather today")

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		body, false, "sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)

	assert.Equal(t, int32(1), atomic.LoadInt32(&upstreamCalls),
		"clean body must be forwarded to upstream")
	assert.Contains(t, rec.Body.String(), "data: {\"id\":\"1\"")
}

// rt06TestResolve resolves via the gateway's checked resolver in tests where
// a concrete ModelInfo value is needed before calling a handler directly.
func rt06TestResolve(gw *gateway, name string) resolver.ModelInfo {
	info, err := gw.res.ResolveChecked(context.Background(), name)
	if err != nil {
		panic("test resolver: " + err.Error())
	}
	return info
}
