package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessages_ClaudeCodeTurn_Stream(t *testing.T) {
	fixture, err := os.ReadFile("testdata/compat/claude_code_turn.json")
	if err != nil {
		t.Fatal(err)
	}
	var sawTool bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), `"role":"tool"`) {
			sawTool = true
		} else {
			t.Errorf("upstream chat missing tool role: %s", raw)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"model\":\"claude-3-5-sonnet\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"On it\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	gw := responsesTestGateway(t, server.URL)
	info := resolver.ModelInfo{ModelName: "claude-3-5-sonnet", Provider: "openai", UpstreamURL: server.URL, Enabled: true}
	res := stubModelResolver{
		"claude-3-5-sonnet": info,
		"m":                 {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, Enabled: true},
	}
	gw.res = res
	gw.fallback = router.NewFallbackExecutor(res, 3, gw.log)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.completed" {
			ev = e
		}
	})
	t.Cleanup(restore)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages?beta=true", strings.NewReader(string(fixture)))
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "claude-code-20250219")
	req.Header.Set("x-claude-code-session-id", "cc-session-1")
	req.Header.Set("x-claude-code-agent-id", "agent-1")
	req.Header.Set("x-claude-code-parent-agent-id", "parent-1")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !sawTool {
		t.Fatal("upstream did not see a tool message")
	}
	events := apiformat.ParseSSE(rec.Body.Bytes())
	if err := apiformat.ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, rec.Body.String())
	}
	var stop string
	for _, evn := range events {
		if evn.Event != "message_delta" {
			continue
		}
		var doc struct {
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(evn.Data), &doc); err != nil {
			t.Fatal(err)
		}
		stop = doc.Delta.StopReason
	}
	if stop != "tool_use" {
		t.Fatalf("stop %q\n%s", stop, rec.Body.String())
	}
	if ev == nil || ev.Endpoint != "messages" || ev.SessionID != "cc-session-1" {
		t.Fatalf("event %+v", ev)
	}
}

func TestMessages_NonStream_Text(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"c","created":1,"model":"m","choices":[{"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`)
	}))
	defer server.Close()
	gw := responsesTestGateway(t, server.URL)
	rec := postMessages(t, gw, `{"model":"m","max_tokens":16,"messages":[{"role":"user","content":"Hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.StopReason != "end_turn" || len(doc.Content) != 1 || doc.Content[0].Text != "Hello" {
		t.Fatalf("%+v", doc)
	}
}

func TestMessages_Unauthorized_AnthropicEnvelope(t *testing.T) {
	gw := responsesTestGateway(t, "http://127.0.0.1:1")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"Hi"}]}`))
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"type":"error"`) || !strings.Contains(rec.Body.String(), `"type":"authentication_error"`) {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestMessages_Budget429_AnthropicEnvelope(t *testing.T) {
	gw := responsesTestGateway(t, "http://127.0.0.1:1")
	gw.auth = NewAuthMiddleware(gw.cfg, newTestResolver("team-budget", nil))
	gw.budgetEnforcer = fakeTeamBudget{err: budget.ErrBudgetExceeded}
	rec := postMessages(t, gw, `{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"Hi"}]}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"type":"rate_limit_error"`) {
		t.Fatalf("body %s", rec.Body.String())
	}
	if rec.Header().Get("x-should-retry") != "false" {
		t.Fatalf("retry %q body %s", rec.Header().Get("x-should-retry"), rec.Body.String())
	}
}

func TestMessages_HelloNoAuth(t *testing.T) {
	gw := responsesTestGateway(t, "http://127.0.0.1:1")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodHead, "/api/hello", nil)
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
}

func postMessages(t *testing.T, gw *gateway, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// N07-P01-T02 (INCLUDE, owner decision 2026-10-30): the ADAPTED /v1/messages
// SSE branch must deliver the provider prompt-cache outcome as an HTTP
// trailer, exactly like the native relay twin
// (TestPromptCache_MessagesNativeSSE_Trailer). The chat pipeline writes the
// trailer into the AnthropicStreamWriter's private header map after the
// stream committed; before the writer forwarded late entries at Finish, the
// trailer never reached the client (N07-P02-T01 scope §4.2.1).
//
// These tests ride an openai-routed (non-anthropic) upstream so the adapted
// branch serves the request; the trailing chat usage chunk carries
// prompt_tokens_details.cached_tokens, the same provider field the native
// JSON twins assert on.

func messagesAdaptedPromptCacheUpstream(t *testing.T, usageChunk string) *httptest.Server {
	t.Helper()
	sse := "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"}}]}\n\n"
	if usageChunk != "" {
		sse += usageChunk
	}
	sse += "data: [DONE]\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"include_usage":true`) {
			t.Errorf("adapted chat request must ask for trailing usage: %s", raw)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, sse)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestMessages_AdaptedStream_PromptCacheTrailer(t *testing.T) {
	cases := []struct {
		name       string
		usageChunk string
		want       string
	}{
		{
			name:       "hit",
			usageChunk: "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2,\"total_tokens\":11,\"prompt_tokens_details\":{\"cached_tokens\":5}}}\n\n",
			want:       "hit",
		},
		{
			name:       "miss",
			usageChunk: "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2,\"total_tokens\":11}}\n\n",
			want:       "miss",
		},
		{
			name:       "absent without provider usage",
			usageChunk: "",
			want:       "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := messagesAdaptedPromptCacheUpstream(t, tc.usageChunk)
			gw := responsesTestGateway(t, server.URL)

			rec := postMessages(t, gw, `{"model":"m","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hi"}]}`)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

			assert.Equal(t, tc.want, rec.Header().Get(promptCacheTrailerKey),
				"adapted messages SSE must report the provider prompt-cache outcome as an HTTP trailer")

			// The translation itself is unchanged: a valid Anthropic stream
			// ending in message_stop — the trailer adds no SSE byte.
			events := apiformat.ParseSSE(rec.Body.Bytes())
			if err := apiformat.ValidateAnthropicStream(events); err != nil {
				t.Fatalf("%v\n%s", err, rec.Body.String())
			}
			if !strings.HasSuffix(rec.Body.String(), "data: {\"type\":\"message_stop\"}\n\n") {
				t.Fatalf("stream must end with message_stop:\n%s", rec.Body.String())
			}
			assert.NotContains(t, rec.Body.String(), "X-Yabanin-Prompt-Cache",
				"the outcome rides trailers, not the event body")
		})
	}
}

// TestMessages_AdaptedStream_PromptCacheTrailer_RealRoundtrip pins the
// client-visible end of the same contract over a real HTTP/1.1 roundtrip:
// net/http materializes the post-commit TrailerPrefix entry as an actual
// trailer after the chunked SSE body (mirrors the native drain-failure
// roundtrip precedent in prompt_cache_transparency_test.go).
func TestMessages_AdaptedStream_PromptCacheTrailer_RealRoundtrip(t *testing.T) {
	server := messagesAdaptedPromptCacheUpstream(t,
		"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2,\"total_tokens\":11,\"prompt_tokens_details\":{\"cached_tokens\":5}}}\n\n")
	gw := responsesTestGateway(t, server.URL)

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	t.Cleanup(gwServer.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gwServer.URL+"/v1/messages",
		strings.NewReader(`{"model":"m","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, "hit", resp.Trailer.Get(PromptCacheHeader),
		"an adapted /v1/messages SSE client must see the prompt-cache outcome as a real HTTP trailer")
	assert.Contains(t, string(raw), "data: {\"type\":\"message_stop\"}", "stream shape unchanged: %s", raw)
}

// TestMessages_AdaptedStream_PromptCacheTrailer_DrainFailure completes the
// adapted /v1/messages trailer parity matrix (N07-P02-T02): an upstream
// mid-stream transport break (no [DONE], no in-band error chunk) reaches the
// drain-failure branch, and the partial provider usage parsed before the
// break still rides the real HTTP trailer — the adapted twin of the native
// precedents TestPromptCache_ResponsesNativeSSE_DrainFailure_Trailer and the
// native relay's unconditional end-of-relay trailer (messages_native.go).
// The client keeps a valid Anthropic stream: the open text block is closed
// before the terminal error (D2), no message_stop is fabricated (D1 adapted
// asymmetry), and the request settles exactly once as request.failed with
// the partial usage — half delivery must not break the client or double-bill.
func TestMessages_AdaptedStream_PromptCacheTrailer_DrainFailure(t *testing.T) {
	upstream := breakServer(t,
		// Usage-only chunk: parsed for accounting, suppressed from the
		// client bytes (RM-03); cached_tokens drives the "hit" outcome.
		"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2,\"total_tokens\":11,\"prompt_tokens_details\":{\"cached_tokens\":5}}}\n\n"+
			"data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"par\"}}]}\n\n")
	gw := responsesTestGateway(t, upstream.URL)
	cap := captureAll(t)

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	t.Cleanup(gwServer.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gwServer.URL+"/v1/messages",
		strings.NewReader(`{"model":"m","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "the gateway→client leg ends cleanly even on an upstream break")

	// Parity: the partial usage from before the break rides the trailer,
	// exactly like the native relay's end-of-stream trailer.
	assert.Equal(t, "hit", resp.Trailer.Get(PromptCacheHeader),
		"the adapted drain-failure stream must report the partial provider usage as a real HTTP trailer")

	// The failure stream stays a valid Anthropic stream: terminal error is
	// the last event, the open text block was closed first (D2), and no
	// normal completion was fabricated (D1 adapted asymmetry).
	events := apiformat.ParseSSE(raw)
	if err := apiformat.ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	if len(events) == 0 || events[len(events)-1].Event != "error" {
		t.Fatalf("terminal event must be error:\n%s", raw)
	}
	assert.Contains(t, string(raw), `"par"`, "partial text must reach the client before the failure")
	assert.Contains(t, string(raw), "content_block_stop",
		"the open text block must be closed before the terminal error (D2)")
	assert.NotContains(t, string(raw), "message_stop",
		"a half-delivered adapted stream must not fabricate a normal completion (D1)")

	// Single settlement: exactly one terminal event, request.failed with
	// the partial usage — never request.completed (no double billing).
	cap.waitFor(t, 1)
	var failed *eventpub.Event
	for _, ev := range cap.all() {
		if ev.EventType == "request.failed" {
			if failed != nil {
				t.Fatalf("double settlement: second request.failed event: %+v", ev)
			}
			failed = ev
		}
		if ev.EventType == "request.completed" {
			t.Fatalf("half delivery must not settle as request.completed: %+v", ev)
		}
	}
	require.NotNil(t, failed, "drain failure must produce the request.failed event")
	assert.Equal(t, "messages", failed.Endpoint)
	assert.Equal(t, int64(9), failed.TokensIn, "partial usage: input")
	assert.Equal(t, int64(2), failed.TokensOut, "partial usage: output")
	assert.Contains(t, failed.Error, "stream drain failed")
}
