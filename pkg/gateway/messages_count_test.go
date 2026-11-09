package cli

import (
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

func TestCountTokens_PassthroughEstimateAndDeny(t *testing.T) {
	const upstreamBody = `{"input_tokens":17}`
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if r.Header.Get("anthropic-version") == "" {
			t.Error("missing anthropic-version")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, upstreamBody)
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	var published atomic.Bool
	restore := observeEvent(func(*eventpub.Event) { published.Store(true) })
	t.Cleanup(restore)

	rec := postCount(t, gw, `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"Hi"}]}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("passthrough status %d %s", rec.Code, rec.Body.String())
	}
	if path != "/v1/messages/count_tokens" {
		t.Fatalf("path %s", path)
	}
	if rec.Body.String() != upstreamBody {
		t.Fatalf("body %s", rec.Body.String())
	}
	if rec.Header().Get("X-Yabanin-Estimated") != "" {
		t.Fatal("native count must not be marked estimated")
	}
	if published.Load() {
		t.Fatal("count_tokens must not publish an event")
	}

	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, Enabled: true}}
	body := `{"model":"m","system":"sys","messages":[{"role":"user","content":"Hi"}],"tools":[{"name":"echo"}]}`
	var doc struct {
		System   json.RawMessage `json:"system"`
		Messages json.RawMessage `json:"messages"`
		Tools    json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	want := int(math.Ceil(float64(len(doc.System)+len(doc.Messages)+len(doc.Tools)) / 4))
	rec = postCount(t, gw, body, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("estimate status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Yabanin-Estimated") != "true" {
		t.Fatalf("estimated header %q", rec.Header().Get("X-Yabanin-Estimated"))
	}
	var got struct {
		Input int `json:"input_tokens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Input != want {
		t.Fatalf("tokens %d want %d", got.Input, want)
	}

	gw.wl = fakeAccess{allowed: false}
	rec = postCount(t, gw, body, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("deny status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"type":"error"`) {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func postCount(t *testing.T, gw *gateway, body string, anthropic bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	if anthropic {
		req.Header.Set("anthropic-version", "2023-06-01")
	}
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}
