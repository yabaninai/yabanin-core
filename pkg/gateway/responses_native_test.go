package cli

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

func TestResponsesNative_JSONAndSSEAndRetryAfter(t *testing.T) {
	jsonBody := []byte(`{"id":"resp_1","output":[{"type":"message"}],"usage":{"input_tokens":10,"output_tokens":2,"input_tokens_details":{"cached_tokens":4}}}`)
	sseBody := []byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":2,\"input_tokens_details\":{\"cached_tokens\":4}}}}\n\n")

	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"model":"m"`) {
			t.Errorf("upstream body %s", raw)
		}
		switch r.Header.Get("Accept") {
		default:
		}
		if strings.Contains(string(raw), `"stream":true`) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write(sseBody)
			return
		}
		if r.URL.Query().Get("fail") == "" && strings.Contains(string(raw), `"fail":true`) {
			w.Header().Set("Retry-After", "7")
			w.Header().Set("X-Request-Id", "req-429")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"slow"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonBody)
	}))
	defer server.Close()

	gw := responsesTestGateway(t, server.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, Enabled: true}}

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.completed" {
			ev = e
		}
	})
	t.Cleanup(restore)

	rec := postResponses(t, gw, `{"model":"m","input":"Hi"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if path != "/v1/responses" {
		t.Fatalf("path %s", path)
	}
	if rec.Body.String() != string(jsonBody) {
		t.Fatalf("body %s", rec.Body.String())
	}
	if ev == nil || ev.Endpoint != "responses" || ev.TokensIn != 10 || ev.TokensOut != 2 || ev.CacheReadTokens != 4 {
		t.Fatalf("event %+v", ev)
	}

	ev = nil
	rec = postResponses(t, gw, `{"model":"m","input":"Hi","stream":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("stream status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != string(sseBody) {
		t.Fatalf("sse %q", rec.Body.String())
	}
	if ev == nil || ev.TokensIn != 10 || ev.CacheReadTokens != 4 {
		t.Fatalf("stream event %+v", ev)
	}

	rec = postResponses(t, gw, `{"model":"m","input":"Hi","fail":true}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "7" || rec.Header().Get("X-Request-Id") != "req-429" {
		t.Fatalf("headers %v", rec.Header())
	}
	if rec.Body.String() != `{"error":"slow"}` {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestResponsesNative_DenyPolicyUsesTranslation(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = io.WriteString(w, `{"id":"c","created":1,"model":"m","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()
	gw := responsesTestGateway(t, server.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, Enabled: true}}
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("shell")}}, time.Minute)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"m","input":"Hi"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-Id", "org-1")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	if path != "/v1/chat/completions" {
		t.Fatalf("path %s body %s", path, rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func TestResponsesNative_StreamOutlivesTimeout(t *testing.T) {
	for _, tc := range nativeStreamSurvivalVariants() {
		t.Run(tc.name, func(t *testing.T) {
			var want strings.Builder
			for i := 0; i < tc.chunks; i++ {
				fmt.Fprintf(&want, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"chunk-%d\"}\n\n", i)
			}
			want.WriteString("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n")

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				flusher := w.(http.Flusher)
				for i := 0; i < tc.chunks; i++ {
					_, _ = fmt.Fprintf(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"chunk-%d\"}\n\n", i)
					flusher.Flush()
					time.Sleep(tc.chunkInterval)
				}
				_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n")
			}))
			defer server.Close()

			gw := responsesTestGateway(t, server.URL)
			gw.cfg.ResponsesNativeProviders = []string{"openai"}
			gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, UpstreamTimeout: tc.upstreamTimeout, Enabled: true}}

			rec := postResponses(t, gw, `{"model":"m","input":"Hi","stream":true}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if got := rec.Body.String(); got != want.String() {
				t.Fatalf("stream truncated: got %d bytes, want %d; tail %q", len(got), want.Len(), got[max(0, len(got)-200):])
			}
		})
	}
}

func TestResponsesNative_NonStreamUpstreamTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = io.WriteString(w, `{"id":"resp_1","output":[]}`)
	}))
	defer server.Close()

	gw := responsesTestGateway(t, server.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, UpstreamTimeout: time.Second, Enabled: true}}

	rec := postResponses(t, gw, `{"model":"m","input":"Hi"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "upstream request failed") {
		t.Fatalf("body %s", rec.Body.String())
	}
}
