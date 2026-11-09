package cli

// passthrough with canonical model override, provider-token usage accounting
// (D3), explicit unsupported provider (D2: openai-compat only), honest
// no_usage without a usage block, and residency refusal before any upstream
// call (tenant isolation, contract example 3).

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// strict key auth, a stub registry ("m" + the canonical name) and a live
// upstream pool pointed at the test server.
func r105TestGateway(t *testing.T, info resolver.ModelInfo) *gateway {
	t.Helper()
	return &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: info.UpstreamURL},
		log:  slog.New(slog.DiscardHandler),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": info, info.ModelName: info},
		pool: upstream.NewPool(upstream.Options{}),
	}
}

func postR105(t *testing.T, gw *gateway, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// TestRerank_HappyPathUsageAndEvent is the contract's working example 1:
// authed key, {model, query, documents} → upstream POST /v1/rerank with the
// canonical model, response passthrough verbatim, admission "rerank",
// reservation reserve+settle, and one request.completed event with the real
// upstream usage (D3 actual billing; unknown_price — no rerank price rows
// exist yet, the cost stays honestly unknown, never a fabricated zero).
func TestRerank_HappyPathUsageAndEvent(t *testing.T) {
	const upstreamBody = `{"id":"rr-1","model":"rerank-v1-canon","results":[` +
		`{"index":2,"relevance_score":0.98},{"index":0,"relevance_score":0.11}],` +
		`"usage":{"prompt_tokens":23,"total_tokens":23}}`
	var upstreamPath atomic.Value
	var upstreamBodyGot atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath.Store(r.URL.Path)
		raw, _ := io.ReadAll(r.Body)
		upstreamBodyGot.Store(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer server.Close()

	info := resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := r105TestGateway(t, info)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"what is the capital of france","documents":["paris","berlin"],"top_n":2}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if strings.TrimSpace(rec.Body.String()) != upstreamBody {
		t.Fatalf("passthrough body %q", rec.Body.String())
	}
	if got := upstreamPath.Load(); got != "/v1/rerank" {
		t.Fatalf("upstream path %v", got)
	}
	if body, _ := upstreamBodyGot.Load().(string); !strings.Contains(body, `"model":"rerank-v1-canon"`) ||
		!strings.Contains(body, `"query":"what is the capital of france"`) {
		t.Fatalf("upstream body %q", body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type %q", got)
	}
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.Endpoint != "rerank" || ev.TokensIn != 23 || ev.TokensOut != 0 {
		t.Fatalf("event endpoint/tokens: %+v", ev)
	}
	if ev.UsageSource != "provider" || ev.CostStatus != "unknown_price" {
		t.Fatalf("event usage source/cost status: %+v", ev)
	}
	if ev.StatusCode != http.StatusOK || ev.ModelUsed != "rerank-v1-canon" || ev.EventType != "request.completed" {
		t.Fatalf("event status/model: %+v", ev)
	}
}

// TestRerank_RequestValidation: missing model/query and every invalid
// documents shape are refused locally with zero upstream calls.
func TestRerank_RequestValidation(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantMessage string
	}{
		{"missing model", `{"query":"q","documents":["a"]}`, "model is required"},
		{"missing query", `{"model":"m","documents":["a"]}`, "query is required"},
		{"missing documents", `{"model":"m","query":"q"}`, "documents is required"},
		{"documents null", `{"model":"m","query":"q","documents":null}`, "documents is required"},
		{"documents empty array", `{"model":"m","query":"q","documents":[]}`, "documents must not be empty"},
		{"documents not an array", `{"model":"m","query":"q","documents":"a"}`, "documents must be an array"},
		{"too many documents", `{"model":"m","query":"q","documents":[` + strings.Repeat(`"d",`, 512) + `"d"]}`, "too many documents"},
		{"empty body", ``, "malformed JSON"},
		{"truncated json", `{"model":"m","query":"q","documents":["a"`, "malformed JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
			}))
			defer server.Close()

			gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
			rec := postR105(t, gw, "/v1/rerank", tc.body, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if errorType(t, rec) != "invalid_request_error" {
				t.Fatalf("envelope %s", rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantMessage) {
				t.Fatalf("message %q, want %q", rec.Body.String(), tc.wantMessage)
			}
			if calls.Load() != 0 {
				t.Fatalf("upstream called %d times", calls.Load())
			}
		})
	}
}

// TestRerank_DocumentsLimitBoundary: 512 documents (the cap) pass local
// validation and reach the upstream; 513 are refused locally.
func TestRerank_DocumentsLimitBoundary(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})

	atCap := `{"model":"m","query":"q","documents":[` + strings.Repeat(`"d",`, rerankMaxDocuments-1) + `"d"]}`
	rec := postR105(t, gw, "/v1/rerank", atCap, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream called %d times", calls.Load())
	}

	overCap := `{"model":"m","query":"q","documents":[` + strings.Repeat(`"d",`, rerankMaxDocuments) + `"d"]}`
	rec = postR105(t, gw, "/v1/rerank", overCap, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "too many documents") {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream called %d times after over-cap refusal", calls.Load())
	}
}

// TestRerank_UnsupportedProvider (contract example 3, D2 ratified
// openai-compat matrix): a non-openai-compat provider is explicitly refused
// with rerank_not_supported_for_provider.
func TestRerank_UnsupportedProvider(t *testing.T) {
	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "claude-3-5-sonnet", Provider: "anthropic", Enabled: true})
	rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["a"]}`, nil)
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
	if env.Error.Code != "rerank_not_supported_for_provider" {
		t.Fatalf("code %q body %s", env.Error.Code, rec.Body.String())
	}
}

// TestRerank_MissingUsageNoUsage (D3): an upstream response without a usage
// block accounts as zero tokens with usage_source none / cost_status
// no_usage — no fabricated estimate.
func TestRerank_MissingUsageNoUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"rr-2","results":[{"index":0,"relevance_score":1.0}]}`))
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["a"]}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.UsageSource != "none" || ev.CostStatus != "no_usage" || ev.TokensIn != 0 || ev.TokensOut != 0 {
		t.Fatalf("event usage accounting: %+v", ev)
	}
}

// TestRerank_ResidencyDeniedBeforeUpstream (contract example 3): a
// residency-denied model for a foreign org is refused 403 before any
// upstream call.
func TestRerank_ResidencyDeniedBeforeUpstream(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
	// The residency contract keys off the auth middleware's RESOLVED org
	// (the client X-Org-Id copy is stripped) — resolve the key to org-eu
	// exactly as production would.
	gw.auth = NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-eu", nil))
	gw.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: false, Region: "EU", Reason: "model not resident"}}

	rec := postR105(t, gw, "/v1/rerank", `{"model":"m","query":"q","documents":["a"]}`, map[string]string{"X-Org-Id": "org-eu"})
	if rec.Code != http.StatusForbidden || errorType(t, rec) != "residency_policy_violation" {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times after residency denial", calls.Load())
	}
}
