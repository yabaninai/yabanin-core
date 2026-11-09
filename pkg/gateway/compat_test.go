package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/apiformat"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
)

func TestClientCompat(t *testing.T) {
	t.Run("codex_turn", func(t *testing.T) { runCompatCodex(t) })
	t.Run("claude_code_turn", func(t *testing.T) {
		t.Run("translation", func(t *testing.T) { runCompatClaude(t, false) })
		t.Run("native", func(t *testing.T) { runCompatClaude(t, true) })
	})
	t.Run("opencode_chat", func(t *testing.T) { runCompatOpenCode(t) })
	t.Run("continue_fim", func(t *testing.T) { runCompatContinue(t) })
	t.Run("cline_chat", func(t *testing.T) { runCompatCline(t) })
	t.Run("cline_chat_stream", func(t *testing.T) { runCompatClineStream(t) })
	t.Run("models_list", func(t *testing.T) { runCompatModels(t) })
	t.Run("responses_error", func(t *testing.T) { runCompatResponsesError(t) })
	t.Run("messages_error", func(t *testing.T) { runCompatMessagesError(t) })
	t.Run("chat_error", func(t *testing.T) { runCompatChatError(t) })
}

func runCompatCodex(t *testing.T) {
	t.Helper()
	body := readCompat(t, "codex_turn.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"model\":\"gpt-5-codex\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_patch\",\"type\":\"function\",\"function\":{\"name\":\"apply_patch\",\"arguments\":\"\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"input\\\":\\\"*** Begin Patch\\\"}\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()
	rec, ev := serveCompat(t, server.URL, "openai", http.MethodPost, "/v1/responses", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	events := apiformat.ParseSSE(rec.Body.Bytes())
	if err := apiformat.ValidateResponsesStream(events); err != nil {
		t.Fatalf("%v\n%s", err, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "custom_tool_call") || !strings.Contains(rec.Body.String(), "*** Begin Patch") {
		t.Fatalf("tool call missing:\n%s", rec.Body.String())
	}
	assertUsage(t, ev, "responses")
}

func runCompatClaude(t *testing.T, native bool) {
	t.Helper()
	body := readCompat(t, "claude_code_turn.json")
	provider := "openai"
	if native {
		provider = "anthropic"
	}
	const nativeSSE = "event: ping\ndata: {\"type\":\"ping\"}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":2,\"output_tokens\":1,\"cache_read_input_tokens\":4,\"cache_creation_input_tokens\":0}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if native {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, nativeSSE)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"model\":\"claude-3-5-sonnet\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"On it\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()
	rec, ev := serveCompat(t, server.URL, provider, http.MethodPost, "/v1/messages", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if native {
		if rec.Body.String() != nativeSSE {
			t.Fatalf("native sse %q", rec.Body.String())
		}
		if ev == nil || ev.Endpoint != "messages" || ev.CacheReadTokens != 4 {
			t.Fatalf("event %+v", ev)
		}
		return
	}
	events := apiformat.ParseSSE(rec.Body.Bytes())
	if err := apiformat.ValidateAnthropicStream(events); err != nil {
		t.Fatalf("%v\n%s", err, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"stop_reason":"tool_use"`) {
		t.Fatalf("stop:\n%s", rec.Body.String())
	}
	assertUsage(t, ev, "messages")
}

func runCompatOpenCode(t *testing.T) {
	t.Helper()
	body := readCompat(t, "opencode_chat.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_r\",\"type\":\"function\",\"function\":{\"name\":\"read\",\"arguments\":\"\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"path\\\":\\\"main.go\\\"}\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()
	rec, ev := serveCompat(t, server.URL, "openai", http.MethodPost, "/v1/chat/completions", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if err := apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")); err != nil {
		t.Fatalf("%v\n%s", err, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"name":"read"`) {
		t.Fatalf("tool missing:\n%s", rec.Body.String())
	}
	assertUsage(t, ev, "chat.completions")
}

func runCompatContinue(t *testing.T) {
	t.Helper()
	body := readCompat(t, "continue_fim.json")
	var sawSuffix bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		sawSuffix = strings.Contains(string(raw), `\n}`) || strings.Contains(string(raw), "\n}")
		_, _ = io.WriteString(w, `{"id":"cmpl","choices":[{"text":"fmt.Println()","finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`)
	}))
	defer server.Close()
	rec, ev := serveCompat(t, server.URL, "openai", http.MethodPost, "/v1/completions", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !sawSuffix {
		t.Fatal("suffix was not forwarded")
	}
	if !strings.Contains(rec.Body.String(), "fmt.Println()") {
		t.Fatalf("body %s", rec.Body.String())
	}
	assertUsage(t, ev, "completions")
}

func runCompatCline(t *testing.T) {
	t.Helper()
	body := readCompat(t, "cline_chat.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"c","choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_p","type":"function","function":{"name":"apply_patch","arguments":"{\"input\":\"x\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`)
	}))
	defer server.Close()
	rec, ev := serveCompat(t, server.URL, "openai", http.MethodPost, "/v1/chat/completions", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"name":"apply_patch"`) {
		t.Fatalf("body %s", rec.Body.String())
	}
	assertUsage(t, ev, "chat.completions")
}

// runCompatClineStream closes the Cline-shaped streaming fixture gap
// runCompatCline, but with stream:true and stream_options.include_usage.
// The upstream answers with split tool_call fragments (id+name frame, two
// argument frames sharing index 0), finish_reason:"tool_calls", a separate
// usage-only chunk (the client asked for it, so it must be delivered) and
// [DONE]. The client stream must validate, keep every fragment and the
// finish reason, and record provider usage.
func runCompatClineStream(t *testing.T) {
	t.Helper()
	body := readCompat(t, "cline_chat_stream.json")
	var sawUsage bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_p\",\"type\":\"function\",\"function\":{\"name\":\"apply_patch\",\"arguments\":\"\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"input\\\":\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"x\\\"}\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"tool_calls\"}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()
	rec, ev := serveCompat(t, server.URL, "openai", http.MethodPost, "/v1/chat/completions", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if err := apiformat.ValidateChatStream(strings.Split(out, "\n")); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		`"name":"apply_patch"`,
		`"id":"call_p"`,
		`"arguments":"{\"input\":"`,
		`"arguments":"\"x\"}"`,
		`"finish_reason":"tool_calls"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("client stream missing %s:\n%s", want, out)
		}
	}
	sawUsage = strings.Contains(out, `"prompt_tokens":3`)
	if !sawUsage {
		t.Fatalf("client asked for usage — usage-only chunk must be delivered:\n%s", out)
	}
	assertUsage(t, ev, "chat.completions")
}

func runCompatModels(t *testing.T) {
	t.Helper()
	_ = readCompat(t, "models_list.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("models list must not call upstream")
	}))
	defer server.Close()
	rec, _ := serveCompat(t, server.URL, "openai", http.MethodGet, "/v1/models", nil, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"smart"`) {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func runCompatResponsesError(t *testing.T) {
	t.Helper()
	gw := compatGateway(t, "http://127.0.0.1:1", "openai")
	rec := serveGateway(t, gw, http.MethodPost, "/v1/responses", []byte(`{"model":"m","input":"Hi","previous_response_id":"resp_old"}`), true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "previous_response_not_supported") || !strings.Contains(rec.Body.String(), `"param":null`) {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func runCompatMessagesError(t *testing.T) {
	t.Helper()
	gw := compatGateway(t, "http://127.0.0.1:1", "openai")
	rec := serveGateway(t, gw, http.MethodPost, "/v1/messages", []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"Hi"}]}`), false)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"type":"error"`) || !strings.Contains(rec.Body.String(), "authentication_error") {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func runCompatChatError(t *testing.T) {
	t.Helper()
	gw := compatGateway(t, "http://127.0.0.1:1", "openai")
	rec := serveGateway(t, gw, http.MethodPost, "/v1/chat/completions", []byte(`{"model":"m","messages":[{"role":"user","content":"Hi"}]}`), false)
	body := strings.TrimSpace(rec.Body.String())
	if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(body, `{"error"`) || !strings.Contains(body, "authentication_error") {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func serveCompat(t *testing.T, upstreamURL, provider, method, path string, body []byte, auth bool) (*httptest.ResponseRecorder, *eventpub.Event) {
	t.Helper()
	gw := compatGateway(t, upstreamURL, provider)
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.completed" {
			ev = e
		}
	})
	t.Cleanup(restore)
	return serveGateway(t, gw, method, path, body, auth), ev
}

func serveGateway(t *testing.T, gw *gateway, method, path string, body []byte, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(string(body)))
	if auth {
		req.Header.Set("Authorization", "Bearer test-key")
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

func compatGateway(t *testing.T, upstreamURL, provider string) *gateway {
	t.Helper()
	gw := responsesTestGateway(t, upstreamURL)
	base := resolver.ModelInfo{ModelName: "m", Provider: provider, UpstreamURL: upstreamURL, UpstreamAPIKey: "upstream-key", Enabled: true}
	codex := base
	codex.ModelName = "gpt-5-codex"
	claude := base
	claude.Provider = provider
	if provider == "anthropic" {
		claude.ModelName = "claude-upstream"
	} else {
		claude.ModelName = "claude-3-5-sonnet"
	}
	res := stubModelResolver{"m": base, "gpt-5-codex": codex, "claude-3-5-sonnet": claude}
	gw.res = res
	gw.fallback = router.NewFallbackExecutor(res, 3, gw.log)
	gw.bindModelLister(nil)
	return gw
}

func readCompat(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/compat/" + name) //nolint:gosec // G304: name is a test fixture basename, not user input
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func assertUsage(t *testing.T, ev *eventpub.Event, endpoint string) {
	t.Helper()
	if ev == nil || ev.Endpoint != endpoint || ev.TokensIn+ev.TokensOut == 0 {
		t.Fatalf("event %+v", ev)
	}
}
