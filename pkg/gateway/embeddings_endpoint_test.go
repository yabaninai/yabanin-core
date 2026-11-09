package cli

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

func postEmbeddings(t *testing.T, gw *gateway, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/embeddings", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

func TestEmbeddings_HappyPathUsageAndEvent(t *testing.T) {
	const upstreamBody = `{"object":"list","data":[],"usage":{"prompt_tokens":3,"total_tokens":3}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("path %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"model":"embed-a"`) {
			t.Errorf("body %s", raw)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer server.Close()

	info := resolver.ModelInfo{ModelName: "embed-a", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": info},
		pool: upstream.NewPool(upstream.Options{}),
	}
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postEmbeddings(t, gw, `{"model":"m","input":"hello"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != upstreamBody+"\n" && strings.TrimSpace(rec.Body.String()) != upstreamBody {
		t.Fatalf("body %q", rec.Body.String())
	}
	if ev == nil || ev.Endpoint != "embeddings" || ev.TokensIn != 3 || ev.TokensOut != 0 || ev.UsageSource != "provider" {
		t.Fatalf("event %+v", ev)
	}
}

func TestEmbeddings_UnsupportedProvider(t *testing.T) {
	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key"},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": {ModelName: "m", Provider: "anthropic", Enabled: true}},
	}
	rec := postEmbeddings(t, gw, `{"model":"m","input":"hello"}`)
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
	if env.Error.Code != "embeddings_not_supported_for_provider" {
		t.Fatalf("code %q body %s", env.Error.Code, rec.Body.String())
	}
}

func TestEmbeddings_WhitelistDeny(t *testing.T) {
	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key"},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": {ModelName: "m", Provider: "openai", Enabled: true}},
		wl:   fakeAccess{allowed: false},
	}
	rec := postEmbeddings(t, gw, `{"model":"m","input":"hello"}`)
	if rec.Code != http.StatusForbidden || errorType(t, rec) != "permission_denied_error" {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func TestEmbeddings_Upstream500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer server.Close()
	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
		pool: upstream.NewPool(upstream.Options{}),
	}
	rec := postEmbeddings(t, gw, `{"model":"m","input":"hello"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func TestEmbeddings_ResidencyRemapDenied(t *testing.T) {
	gw := &gateway{
		log:               slog.Default(),
		res:               stubModelResolver{"m": {ModelName: "m", Provider: "openai", Enabled: true}},
		residencyEnforcer: fakeResidency{dec: policy.Decision{Allowed: true, Region: "SG", RemappedModel: "other"}},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/embeddings", strings.NewReader(`{"model":"m","input":"hello"}`))
	req.Header.Set("X-Org-Id", "org-1")
	rec := httptest.NewRecorder()
	gw.embeddings(rec, req)
	if rec.Code != http.StatusForbidden || errorType(t, rec) != "residency_policy_violation" {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

func TestEmbeddings_EstimatedUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()
	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, Enabled: true}},
		pool: upstream.NewPool(upstream.Options{}),
	}
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }
	rec := postEmbeddings(t, gw, `{"model":"m","input":"abcd"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if ev == nil || ev.UsageSource != "estimated" || ev.TokensIn != 2 {
		t.Fatalf("event %+v", ev)
	}
}

// gateway cap answers 413 through the REAL httpmw.MaxBody — parity with the
// audio/images payload-size refusal (previously a blanket 400).
func TestEmbeddings_BodyTooLargeThroughMaxBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("upstream must not be called for a capped body")
	}))
	defer server.Close()

	info := resolver.ModelInfo{ModelName: "embed-a", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": info},
		pool: upstream.NewPool(upstream.Options{}),
	}
	r := chi.NewRouter()
	r.Use(httpmw.MaxBody(10 * 1024 * 1024))
	gw.routes(r)

	big := `{"model":"m","input":"` + strings.Repeat("a", 10*1024*1024) + `"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/embeddings", strings.NewReader(big))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

// Owner decision 2026-10-13: an upstream response above embeddingsResponseLimit
// is refused as 502 (upstream error), never silently truncated — parity with
// images (the gateway never delivers a partial embeddings payload).
func TestEmbeddings_OversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(make([]byte, embeddingsResponseLimit+1))
	}))
	defer server.Close()

	info := resolver.ModelInfo{ModelName: "embed-a", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": info},
		pool: upstream.NewPool(upstream.Options{}),
	}
	rec := postEmbeddings(t, gw, `{"model":"m","input":"hello"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "upstream response too large") {
		t.Fatalf("body %s", rec.Body.String())
	}
}

// At-cap upstream bodies still pass verbatim: the limit+1 probe must not
// reject exactly-at-limit responses.
func TestEmbeddings_AtCapResponsePasses(t *testing.T) {
	payload := make([]byte, embeddingsResponseLimit)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	info := resolver.ModelInfo{ModelName: "embed-a", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: server.URL},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": info},
		pool: upstream.NewPool(upstream.Options{}),
	}
	rec := postEmbeddings(t, gw, `{"model":"m","input":"hello"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if rec.Body.Len() != embeddingsResponseLimit {
		t.Fatalf("body length %d, want exactly the at-cap %d", rec.Body.Len(), embeddingsResponseLimit)
	}
}
