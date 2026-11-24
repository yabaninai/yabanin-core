package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

type paidRouteControl struct {
	name           string
	path, body     string
	upstreamBody   string
	upstreamStream bool   // upstream answers text/event-stream
	stream         bool   // client asked for SSE
	marker         string // substring unique to the upstream answer
	wantTokensOut  string
}

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
	cases := []paidRouteControl{
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
		t.Run(tc.name+"/healthy", func(t *testing.T) {
			store := &fakeInvocationStore{}
			rec, hits := tc.serve(t, store)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.EqualValues(t, 1, hits)
			require.Contains(t, rec.Body.String(), tc.marker)
			require.Len(t, store.admitted, 1)
			require.Len(t, store.facts, 1)
			a, f := store.admitted[0], store.facts[0]
			require.NotEmpty(t, a.InvocationID)
			require.Equal(t, a.InvocationID, f.InvocationID)
			require.Equal(t, "org-test", a.OrgID)
			require.Equal(t, "org-test", f.OrgID)
			require.Equal(t, "7", f.Fields["tokens_in"])
			require.Equal(t, tc.wantTokensOut, f.Fields["tokens_out"])
		})
		t.Run(tc.name+"/unconfirmed_start", func(t *testing.T) {
			store := &fakeInvocationStore{admitErr: errors.New("database unavailable")}
			rec, hits := tc.serve(t, store)
			require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), "history_unavailable")
			require.Contains(t, rec.Body.String(), "the paid call was not sent")
			require.Zero(t, hits)
			require.Empty(t, store.admitted)
			require.Empty(t, store.facts)
		})
		t.Run(tc.name+"/terminal_write_failure", func(t *testing.T) {
			store := &fakeInvocationStore{factsErr: errors.New("terminal write unavailable")}
			rec, hits := tc.serve(t, store)
			require.EqualValues(t, 1, hits)
			require.Len(t, store.admitted, 1)
			require.Empty(t, store.facts)
			body := rec.Body.String()
			require.Contains(t, body, "accounting_commit_failed")
			require.Contains(t, body, "NOT safe to retry")
			if tc.stream {
				require.Equal(t, http.StatusOK, rec.Code)
				require.Contains(t, body, tc.marker)
				require.Equal(t, 1, strings.Count(body, "data: [DONE]"))
				require.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"), body)
				return
			}
			require.NotContains(t, body, tc.marker)
			require.Equal(t, http.StatusInternalServerError, rec.Code)
			require.Equal(t, "false", rec.Header().Get("X-Should-Retry"))
		})
	}
}

func (tc paidRouteControl) serve(t *testing.T, store *fakeInvocationStore) (*httptest.ResponseRecorder, int64) {
	t.Helper()
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
	t.Cleanup(server.Close)

	info := resolver.ModelInfo{ModelName: "canon-model", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := &gateway{
		cfg:         config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:         slog.New(slog.DiscardHandler),
		auth:        NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-test", nil)),
		res:         stubModelResolver{"m": info},
		pool:        upstream.NewPool(upstream.Options{}),
		invocations: store,
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

	return rec, hits.Load()
}

func TestNativePaidStartRefusal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, string, *fakeInvocationStore, *bodyBoundsEvents) *gateway
		post  func(*testing.T, *gateway, string) *httptest.ResponseRecorder
		body  string
	}{
		{"messages", bodyBoundsMessagesGateway, postMessages, `{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello"}],"max_tokens":8,"stream":%t}`},
		{"responses", bodyBoundsResponsesGateway, postResponses, `{"model":"m","input":"hello","stream":%t}`},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", tc.name, stream), func(t *testing.T) {
				var contacts atomic.Int32
				provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					contacts.Add(1)
					w.WriteHeader(http.StatusTeapot)
				}))
				defer provider.Close()
				store := &fakeInvocationStore{admitErr: errors.New("start unavailable")}
				capture := &bodyBoundsEvents{}
				gw := tc.setup(t, provider.URL, store, capture)
				rec := tc.post(t, gw, fmt.Sprintf(tc.body, stream))
				require.Equal(t, http.StatusServiceUnavailable, rec.Code)
				var reply struct {
					Error struct {
						Code    string `json:"code"`
						Message string `json:"message"`
						Type    string `json:"type"`
					} `json:"error"`
				}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &reply))
				if tc.name == "messages" {
					require.Equal(t, "overloaded_error", reply.Error.Type)
					require.True(t, strings.HasPrefix(reply.Error.Message, "[history_unavailable] "), "%s", reply.Error.Message)
				} else {
					require.Equal(t, "history_unavailable", reply.Error.Code)
				}
				require.Zero(t, contacts.Load())
				require.Empty(t, store.admitted)
				require.Empty(t, store.facts)
				require.Zero(t, capture.len())
			})
		}
	}
}
