package cli

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// TestPreview2PaidRouteControls pins the Preview2 durable admission gate on
// every newly wired inference route — embeddings, legacy completions (JSON
// and SSE), moderations and rerank (realtime rides
// TestRealtime_TerminalBoundaryHoldShapes). Three controls per route:
//
//   - healthy: exactly one admission and one terminal-facts row joined by
//     invocation id, billing the real upstream usage (7 in / 3 out where
//     the route reports completions);
//   - unconfirmed start (admitErr): 503 history_unavailable naming the
//     refused dispatch BEFORE any provider arrival and with no durable rows;
//   - terminal write failure (factsErr) after a dispatched call: the
//     upstream answer never surfaces as a payable success — buffered routes
//     withhold the body behind a 500 accounting_commit_failed with
//     X-Should-Retry: false, the SSE route replaces the held [DONE] with
//     the accounting error frame and [DONE].
func TestPreview2PaidRouteControls(t *testing.T) {
	cases := []struct {
		name           string
		path, body     string
		upstreamBody   string
		upstreamStream bool   // upstream answers text/event-stream
		stream         bool   // client asked for SSE
		marker         string // substring unique to the upstream answer
		wantTokensOut  string
	}{
		{"embeddings", "/v1/embeddings", `{"model":"m","input":"hello"}`,
			`{"object":"list","data":[{"embedding":[0.1],"index":0}],"usage":{"prompt_tokens":7,"total_tokens":7}}`,
			false, false, `"embedding":[0.1]`, "0"},
		{"completions_json", "/v1/completions", `{"model":"m","prompt":"abc","max_tokens":8}`,
			`{"id":"cmpl","choices":[{"text":"world"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`,
			false, false, `"text":"world"`, "3"},
		{"completions_sse", "/v1/completions", `{"model":"m","prompt":"fn","stream":true}`,
			"data: {\"choices\":[{\"text\":\"hi\"}]}\n\n" +
				"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10}}\n\n" +
				"data: [DONE]\n\n",
			true, true, `"text":"hi"`, "3"},
		{"moderations", "/v1/moderations", `{"model":"m","input":"some text to classify"}`,
			`{"id":"mod-1","model":"omni-moderation-canon","results":[{"flagged":false}],"usage":{"prompt_tokens":7,"total_tokens":7}}`,
			false, false, `"flagged":false`, "0"},
		{"rerank", "/v1/rerank", `{"model":"m","query":"q","documents":["d1","d2"]}`,
			`{"id":"rr-1","model":"rerank-v1-canon","results":[{"index":0,"relevance_score":0.9}],"usage":{"prompt_tokens":7,"total_tokens":7}}`,
			false, false, `"relevance_score":0.9`, "0"},
	}
	for _, tc := range cases {
		for _, variant := range []struct {
			name  string
			store *fakeInvocationStore
		}{
			{"healthy", &fakeInvocationStore{}},
			{"unconfirmed_start", &fakeInvocationStore{admitErr: errors.New("database unavailable")}},
			{"terminal_write_failure", &fakeInvocationStore{factsErr: errors.New("terminal write unavailable")}},
		} {
			t.Run(tc.name+"/"+variant.name, func(t *testing.T) {
				var hits atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					if tc.upstreamStream {
						w.Header().Set("Content-Type", "text/event-stream")
					} else {
						w.Header().Set("Content-Type", "application/json")
					}
					_, _ = w.Write([]byte(tc.upstreamBody))
				}))
				defer server.Close()

				info := resolver.ModelInfo{ModelName: "canon-model", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
				gw := &gateway{
					cfg:         config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
					log:         slog.New(slog.DiscardHandler),
					auth:        NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-test", nil)),
					res:         stubModelResolver{"m": info},
					pool:        upstream.NewPool(upstream.Options{}),
					invocations: variant.store,
				}
				if tc.stream {
					gw.streamUsageProviders = map[string]bool{"openai": true}
				}

				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tc.path, strings.NewReader(tc.body))
				req.Header.Set("Authorization", "Bearer test-key")
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				r := chi.NewRouter()
				gw.routes(r)
				r.ServeHTTP(rec, req)

				switch variant.name {
				case "unconfirmed_start":
					if rec.Code != http.StatusServiceUnavailable {
						t.Fatalf("status %d %s", rec.Code, rec.Body.String())
					}
					body := rec.Body.String()
					if !strings.Contains(body, "history_unavailable") || !strings.Contains(body, "the paid call was not sent") {
						t.Fatalf("refusal envelope %q", body)
					}
					if hits.Load() != 0 {
						t.Fatal("an unconfirmed durable start must precede all provider traffic")
					}
					if n := len(variant.store.admitted); n != 0 {
						t.Fatalf("admitted rows %d", n)
					}
					if n := len(variant.store.facts); n != 0 {
						t.Fatalf("facts rows %d", n)
					}
					return
				case "terminal_write_failure":
					// Exactly one paid dispatch, one admitted invocation —
					// and no success answer for it.
					if hits.Load() != 1 {
						t.Fatalf("provider hits %d", hits.Load())
					}
					if n := len(variant.store.admitted); n != 1 {
						t.Fatalf("admitted rows %d", n)
					}
					body := rec.Body.String()
					if !strings.Contains(body, "accounting_commit_failed") || !strings.Contains(body, "NOT safe to retry") {
						t.Fatalf("accounting failure envelope %q", body)
					}
					if tc.stream {
						// A stream's content frames were truthfully delivered
						// live; what the failure withholds is the success
						// terminator — the held [DONE] is replaced by the
						// accounting frame and only then closed.
						if rec.Code != http.StatusOK {
							t.Fatalf("stream status %d %s", rec.Code, body)
						}
						if !strings.HasSuffix(body, "data: [DONE]\n\n") {
							t.Fatalf("stream must end on [DONE] after the accounting frame: %q", body)
						}
					} else {
						if strings.Contains(body, tc.marker) {
							t.Fatalf("upstream answer surfaced after losing the terminal facts row: %q", body)
						}
						if rec.Code != http.StatusInternalServerError {
							t.Fatalf("status %d %s", rec.Code, body)
						}
						if got := rec.Header().Get("X-Should-Retry"); got != "false" {
							t.Fatalf("X-Should-Retry %q", got)
						}
					}
					return
				default: // healthy
					if rec.Code != http.StatusOK {
						t.Fatalf("status %d %s", rec.Code, rec.Body.String())
					}
					if hits.Load() != 1 {
						t.Fatalf("provider hits %d", hits.Load())
					}
					if !strings.Contains(rec.Body.String(), tc.marker) {
						t.Fatalf("upstream answer missing: %q", rec.Body.String())
					}
					if n := len(variant.store.admitted); n != 1 {
						t.Fatalf("admitted rows %d", n)
					}
					if n := len(variant.store.facts); n != 1 {
						t.Fatalf("facts rows %d", n)
					}
					a, f := variant.store.admitted[0], variant.store.facts[0]
					if a.InvocationID != f.InvocationID {
						t.Fatalf("admission %s not joined to facts %s", a.InvocationID, f.InvocationID)
					}
					if a.OrgID != "org-test" || f.OrgID != "org-test" {
						t.Fatalf("tenant attribution lost: admit %+v facts %+v", a, f)
					}
					if got := f.Fields["tokens_in"]; got != "7" {
						t.Fatalf("tokens_in %q want 7 (real upstream usage, D3)", got)
					}
					if got := f.Fields["tokens_out"]; got != tc.wantTokensOut {
						t.Fatalf("tokens_out %q want %q", got, tc.wantTokensOut)
					}
				}
			})
		}
	}
}
