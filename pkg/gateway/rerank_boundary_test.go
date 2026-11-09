package cli

// boundary stage — rerank failure/boundary rows from the contract's
// negative decomposition: upstream 4xx/5xx surfaced via MapUpstreamStatus
// with exactly one upstream call (no retry that could double-charge),
// payload-size caps on both sides (10 MiB request cap → 413,
// rerankResponseLimit → 502, never a silent truncation), malformed bodies
// refused without echoing request bytes, and recovery invariants (a failure
// never publishes request.completed).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// markers that must never appear in a gateway-generated error envelope.
const (
	rerankMarkerQuery = "gateway-echo-marker-r105-query"
	rerankMarkerDoc   = "gateway-echo-marker-r105-doc"
)

// TestRerank_UpstreamErrorMatrix: every upstream 4xx/5xx is surfaced through
// apierrors.MapUpstreamStatus with exactly ONE upstream call, no
// request.completed event, and an envelope that never echoes the query or
// document bytes embedded in the upstream error body.
func TestRerank_UpstreamErrorMatrix(t *testing.T) {
	cases := []struct {
		name           string
		upstreamStatus int
		wantStatus     int
		wantType       string
	}{
		{"upstream 400 invalid input", 400, http.StatusBadRequest, "invalid_request_error"},
		{"upstream 401 masked", 401, http.StatusBadGateway, "api_error"},
		{"upstream 403 permission", 403, http.StatusForbidden, "permission_denied_error"},
		{"upstream 404", 404, http.StatusNotFound, "not_found_error"},
		{"upstream 429 rate limit", 429, http.StatusTooManyRequests, "rate_limit_exceeded"},
		{"upstream 500", 500, http.StatusBadGateway, "api_error"},
		{"upstream 503", 503, http.StatusBadGateway, "api_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.upstreamStatus)
				_, _ = w.Write([]byte(`{"error":{"message":"rejected ` + rerankMarkerQuery + ` / ` + rerankMarkerDoc + `"}}`))
			}))
			defer server.Close()

			gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
			gw.eventNote = func(e *eventpub.Event) { t.Errorf("failure path published %+v", e) }

			rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"`+rerankMarkerQuery+`","documents":["`+rerankMarkerDoc+`"]}`, nil)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := errorType(t, rec); got != tc.wantType {
				t.Fatalf("type %q, want %q: %s", got, tc.wantType, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), rerankMarkerQuery) || strings.Contains(rec.Body.String(), rerankMarkerDoc) {
				t.Fatalf("error envelope echoes request bytes: %s", rec.Body.String())
			}
			if calls.Load() != 1 {
				t.Fatalf("upstream called %d times, want exactly 1 (no retry)", calls.Load())
			}
		})
	}
}

// TestRerank_OversizedResponse: an upstream body above rerankResponseLimit
// is refused as 502 (upstream error), never truncated.
func TestRerank_OversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(make([]byte, rerankResponseLimit+1))
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
	rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["a"]}`, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if errorType(t, rec) != "api_error" || !strings.Contains(rec.Body.String(), "upstream response too large") {
		t.Fatalf("body %s", rec.Body.String())
	}
}

// TestRerank_BodyTooLargeThroughMaxBody: a body past the 10 MiB global cap
// through the real httpmw.MaxBody middleware answers 413 before any
func TestRerank_BodyTooLargeThroughMaxBody(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
	r := chi.NewRouter()
	r.Use(httpmw.MaxBody(10 * 1024 * 1024))
	gw.routes(r)

	big := `{"model":"m","query":"` + strings.Repeat("a", 10*1024*1024) + `","documents":["a"]}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/rerank", strings.NewReader(big))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413: %s", rec.Code, rec.Body.String())
	}
	if errorType(t, rec) != "invalid_request_error" {
		t.Fatalf("envelope %s", rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times on oversized body", calls.Load())
	}
}

// TestRerank_UnreachableUpstream: a refused connection is a 502 api_error
// with no completed event — never a hang, never a 200.
func TestRerank_UnreachableUpstream(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamURL: deadURL, Enabled: true})
	var published bool
	gw.eventNote = func(e *eventpub.Event) { published = true }

	rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["a"]}`, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if errorType(t, rec) != "api_error" {
		t.Fatalf("envelope %s", rec.Body.String())
	}
	if published {
		t.Fatal("failed request published an event")
	}
}

// TestRerank_PoolNilRefused: a gateway without an upstream pool refuses 502
// instead of panicking.
func TestRerank_PoolNilRefused(t *testing.T) {
	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", Enabled: true})
	gw.pool = nil
	rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["a"]}`, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

// TestRerank_URLFieldsNeverFetched (contract example 5, SSRF D5 parity with
// images data[].url): URL-bearing fields in the request documents and in the
// upstream response are opaque passthrough. The gateway performs exactly one
// egress — the upstream call — and never dereferences a client-supplied URL
// (the loopback listener must stay at zero hits).
func TestRerank_URLFieldsNeverFetched(t *testing.T) {
	var urlHits atomic.Int64
	urlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		urlHits.Add(1)
	}))
	defer urlServer.Close()

	var upstreamCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"index":0,"relevance_score":1.0,"url":"` + urlServer.URL + `/doc"}]}`))
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})

	rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":[{"text":"d","url":"`+urlServer.URL+`/d1"},"`+urlServer.URL+`/d2"]}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), urlServer.URL+"/doc") {
		t.Fatalf("url not passed through verbatim: %s", rec.Body.String())
	}
	if urlHits.Load() != 0 {
		t.Fatalf("gateway dereferenced url fields %d times — SSRF boundary violated", urlHits.Load())
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls %d, want 1", upstreamCalls.Load())
	}
}

// TestRerank_UsageBlocks (unit): the tolerant usage-block parse across both
// token vocabularies and the malformed variants.
func TestRerank_UsageBlocks(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantSource string
		wantIn     int64
		wantOut    int64
		wantTotal  int64
		wantCached int64
	}{
		{"prompt_tokens style", `{"results":[],"usage":{"prompt_tokens":23,"total_tokens":23}}`, "provider", 23, 0, 23, 0},
		{"input_tokens style", `{"results":[],"usage":{"input_tokens":8,"output_tokens":2,"total_tokens":10}}`, "provider", 8, 2, 10, 0},
		{"cached via input_token_details", `{"results":[],"usage":{"input_tokens":9,"total_tokens":9,"input_token_details":{"cached_tokens":4}}}`, "provider", 9, 0, 9, 4},
		{"cached via prompt_tokens_details", `{"results":[],"usage":{"prompt_tokens":9,"prompt_tokens_details":{"cached_tokens":6}}}`, "provider", 9, 0, 9, 6},
		{"total derived", `{"results":[],"usage":{"input_tokens":5,"output_tokens":5}}`, "provider", 5, 5, 10, 0},
		{"usage empty object", `{"results":[],"usage":{}}`, "provider", 0, 0, 0, 0},
		{"usage null", `{"results":[],"usage":null}`, "none", 0, 0, 0, 0},
		{"usage wrong type", `{"results":[],"usage":"20 tokens"}`, "none", 0, 0, 0, 0},
		{"no usage at all", `{"results":[]}`, "none", 0, 0, 0, 0},
		{"body not json", `garbage`, "none", 0, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := rerankUsage([]byte(tc.body))
			wantSource := tc.wantSource
			if wantSource == "none" {
				if u.Source != "" && u.Source != "none" {
					t.Fatalf("source %q, want none", u.Source)
				}
			} else if u.Source != wantSource {
				t.Fatalf("source %q, want %q", u.Source, wantSource)
			}
			if u.PromptTokens != tc.wantIn || u.CompletionTokens != tc.wantOut || u.TotalTokens != tc.wantTotal || u.CacheReadTokens != tc.wantCached {
				t.Fatalf("usage %+v", u)
			}
		})
	}
}
