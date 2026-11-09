package cli

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/upstream"
)

func responsesTestGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	cfg := config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: upstreamURL, FallbackModel: "smart"}
	info := resolver.ModelInfo{ModelName: "m", Provider: "openai", UpstreamURL: upstreamURL, Enabled: true}
	res := stubModelResolver{
		"m":           info,
		"gpt-5-codex": {ModelName: "gpt-5-codex", Provider: "openai", UpstreamURL: upstreamURL, Enabled: true},
	}
	return &gateway{
		cfg:                  cfg,
		log:                  slog.Default(),
		auth:                 NewAuthMiddleware(cfg, nil),
		res:                  res,
		pool:                 upstream.NewPool(upstream.Options{}),
		fallback:             router.NewFallbackExecutor(res, 3, slog.Default()),
		retryPolicy:          retry.DefaultPolicy(),
		streamUsageProviders: map[string]bool{"openai": true},
	}
}

func postResponses(t *testing.T, gw *gateway, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/responses", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

func TestResponses_CodexTurn_Stream(t *testing.T) {
	fixture, err := os.ReadFile("testdata/compat/codex_turn.json")
	if err != nil {
		t.Fatal(err)
	}
	var sawUsage bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"include_usage":true`) {
			t.Errorf("chat request missing include_usage: %s", raw)
		} else {
			sawUsage = true
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"model\":\"gpt-5-codex\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_patch\",\"type\":\"function\",\"function\":{\"name\":\"apply_patch\",\"arguments\":\"\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"input\\\":\\\"*** Begin Patch…\\\"}\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"tool_calls\"}]}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	gw := responsesTestGateway(t, server.URL)
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.completed" {
			ev = e
		}
	})
	t.Cleanup(restore)

	rec := postResponses(t, gw, string(fixture))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !sawUsage {
		t.Fatal("upstream did not see include_usage")
	}
	events := apiformat.ParseSSE(rec.Body.Bytes())
	if err := apiformat.ValidateResponsesStream(events); err != nil {
		t.Fatalf("%v\n%s", err, rec.Body.String())
	}
	var doc struct {
		Response struct {
			Output []struct {
				Type  string `json:"type"`
				Name  string `json:"name"`
				Input string `json:"input"`
			} `json:"output"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(events[len(events)-1].Data), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Response.Output) != 1 || doc.Response.Output[0].Type != "custom_tool_call" || doc.Response.Output[0].Input != "*** Begin Patch…" {
		t.Fatalf("output %#v\n%s", doc.Response.Output, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "custom_tool_call_input.delta") {
		t.Fatal("missing custom_tool_call_input.delta")
	}
	if ev == nil || ev.Endpoint != "responses" {
		t.Fatalf("event %+v", ev)
	}
}

func TestResponses_NonStream_Text(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"c","created":1700000000,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`)
	}))
	defer server.Close()
	gw := responsesTestGateway(t, server.URL)
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, Enabled: true}}
	rec := postResponses(t, gw, `{"model":"m","input":"Hi"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Output []struct {
			Type    string `json:"type"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Output) != 1 || doc.Output[0].Type != "message" || doc.Output[0].Content[0].Text != "Hello" {
		t.Fatalf("%+v", doc)
	}
}

func TestResponses_WhitelistDeny_403_ResponsesError(t *testing.T) {
	gw := responsesTestGateway(t, "http://127.0.0.1:1")
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", Enabled: true}}
	gw.wl = fakeAccess{allowed: false}
	rec := postResponses(t, gw, `{"model":"m","input":"Hi"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if errorType(t, rec) != "permission_denied_error" {
		t.Fatalf("body %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"param":null`) {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestResponses_PreviousResponseID_400(t *testing.T) {
	gw := responsesTestGateway(t, "http://127.0.0.1:1")
	rec := postResponses(t, gw, `{"model":"m","input":"Hi","previous_response_id":"resp_old"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Code != "previous_response_not_supported" {
		t.Fatalf("body %s", rec.Body.String())
	}
}

// TestResponses_PreviousResponseID_IDShapes_UniformBothRoutes pins the T03
// boundary: a continuation attempt is refused with the identical 400 on the
// adapted and the native passthrough route for every JSON shape the field
// can arrive in — string response ids, approval-operation / task ids
// (I58's durable operation identifiers are NOT conversation response ids
// and unlock nothing), tool-call and reasoning item ids the gateway itself
// surfaced in an earlier turn, and non-string shapes that a string-only
// probe used to let through to the provider. No shape reaches the upstream
// (no implicit previous_response_id support via provider pass-through).
func TestResponses_PreviousResponseID_IDShapes_UniformBothRoutes(t *testing.T) {
	values := []string{
		`"resp_9d2f31"`,
		`"op_7c1e55a0"`,
		`"task_42"`,
		`"call_0519"`,
		`"ctc_0a1b2c"`,
		`"rs_9d2f31c0ffee"`,
		`123`,
		`true`,
		`{"id":"op_1"}`,
		`["resp_9d2f31"]`,
	}
	for _, tc := range []struct{ name, providers string }{
		{"adapted", ""},
		{"native", "openai"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamHits atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamHits.Add(1)
				_, _ = io.WriteString(w, `{}`)
			}))
			defer upstream.Close()

			gw := responsesTestGateway(t, upstream.URL)
			gw.cfg.ResponsesNativeProviders = nil
			if tc.providers != "" {
				gw.cfg.ResponsesNativeProviders = []string{tc.providers}
			}
			gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
			for _, raw := range values {
				body := `{"model":"m","input":"Continue","previous_response_id":` + raw + `}`
				rec := postResponses(t, gw, body)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("previous_response_id=%s: status %d body %s", raw, rec.Code, rec.Body.String())
				}
				var env struct {
					Error struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
					t.Fatalf("previous_response_id=%s: %v", raw, err)
				}
				if env.Error.Code != "previous_response_not_supported" {
					t.Fatalf("previous_response_id=%s: body %s", raw, rec.Body.String())
				}
				if !strings.Contains(env.Error.Message, "send the full conversation in input") {
					t.Fatalf("previous_response_id=%s: remediation missing: %s", raw, rec.Body.String())
				}
			}
			if n := upstreamHits.Load(); n != 0 {
				t.Fatalf("continuation attempts must never reach the provider, saw %d upstream hits", n)
			}
		})
	}
}

func TestResponses_UnsupportedHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"c","created":1,"model":"m","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()
	gw := responsesTestGateway(t, server.URL)
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, Enabled: true}}
	rec := postResponses(t, gw, `{"model":"m","input":"Hi","tools":[{"type":"web_search"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("X-Yabanin-Unsupported"), "tool:web_search") {
		t.Fatalf("unsupported %q", rec.Header().Get("X-Yabanin-Unsupported"))
	}
	if rec.Header().Get("X-Yabanin-Dropped") != "" {
		t.Fatalf("legacy header must not be set on /v1/responses: %q", rec.Header().Get("X-Yabanin-Dropped"))
	}
}

// TestResponses_UnsupportedHeader_ReasoningEffort pins the named example of
// the ratified D2: reasoning.effort is dropped by the translation and the
// drop is announced in X-Yabanin-Unsupported, never silent.
func TestResponses_UnsupportedHeader_ReasoningEffort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"c","created":1,"model":"m","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()
	gw := responsesTestGateway(t, server.URL)
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, Enabled: true}}
	rec := postResponses(t, gw, `{"model":"m","input":"Hi","reasoning":{"effort":"high"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("X-Yabanin-Unsupported"), "reasoning") {
		t.Fatalf("unsupported %q", rec.Header().Get("X-Yabanin-Unsupported"))
	}
}

// TestResponses_PreviousResponseID_NativePath_400 pins the ratified D1
// (stateless resend everywhere): the native passthrough path refuses
// previous_response_id with the same explicit 400 the translated path has.
func TestResponses_PreviousResponseID_NativePath_400(t *testing.T) {
	gw := responsesTestGateway(t, "http://127.0.0.1:1")
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: "http://127.0.0.1:1", Enabled: true}}
	rec := postResponses(t, gw, `{"model":"m","input":"Hi","previous_response_id":"resp_old"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Code != "previous_response_not_supported" {
		t.Fatalf("body %s", rec.Body.String())
	}
	if !strings.Contains(env.Error.Message, "send the full conversation in input") {
		t.Fatalf("body %s", rec.Body.String())
	}
}

// TestResponses_PreviousResponseID_NativeUpstreamUntouched pins the D1
// negative criterion (no implicit continuation support via provider
// pass-through): with native dispatch fully armed — provider listed, model
// resolvable, live upstream — a continuation id is still refused at the
// endpoint and the request body never leaves the gateway. Complements
// TestResponses_PreviousResponseID_Precedence, which has no resolver entry
// and therefore never actually arms the native route.
func TestResponses_PreviousResponseID_NativeUpstreamUntouched(t *testing.T) {
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	rec := postResponses(t, gw, `{"model":"m","input":"Hi","previous_response_id":"resp_old"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "previous_response_not_supported") {
		t.Fatalf("body %s", rec.Body.String())
	}
	if n := upstreamHits.Load(); n != 0 {
		t.Fatalf("continuation id must never reach the provider, saw %d upstream hits", n)
	}
}
