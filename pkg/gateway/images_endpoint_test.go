package cli

import (
	"encoding/base64"
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
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// testTinyPNG is a synthetic 8-byte PNG signature (\x89PNG\r\n\x1a\n): the
// images fixtures carry opaque provider image bytes that the gateway must
// pass through without dereferencing or validating.
var testTinyPNG = []byte{'\x89', 'P', 'N', 'G', '\r', '\n', '\x1a', '\n'}

func postImages(t *testing.T, gw *gateway, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/images/generations", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

func imagesTestGateway(t *testing.T, info resolver.ModelInfo, upstreamURL string) *gateway {
	t.Helper()
	return &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: upstreamURL},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": info},
		pool: upstream.NewPool(upstream.Options{}),
	}
}

// canonical model override, and the provider usage block flows into the
// request.completed event (tokens, usage_source=provider, unknown_price —
// D1: no image pricing basis bundled, cost stays honestly unknown).
func TestImagesGenerations_HappyPathUsageAndEvent(t *testing.T) {
	var upstreamBody = `{"created":1790000000,"data":[{"b64_json":"` +
		base64.StdEncoding.EncodeToString(testTinyPNG) +
		`"}],"usage":{"input_tokens":20,"output_tokens":1424,"total_tokens":1444,` +
		`"input_tokens_details":{"cached_tokens":0}}}`
	var upstreamPath atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath.Store(r.URL.Path)
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"model":"gpt-image-1-canon"`) {
			t.Errorf("upstream body lacks canonical model: %s", raw)
		}
		if !strings.Contains(string(raw), `"prompt":"a single red cube on a white background"`) {
			t.Errorf("upstream body lacks prompt: %s", raw)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer server.Close()

	info := resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := imagesTestGateway(t, info, server.URL)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImages(t, gw, `{"model":"m","prompt":"a single red cube on a white background","n":1,"size":"1024x1024"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if strings.TrimSpace(rec.Body.String()) != upstreamBody {
		t.Fatalf("passthrough body %q", rec.Body.String())
	}
	if got := upstreamPath.Load(); got != "/v1/images/generations" {
		t.Fatalf("upstream path %v", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type %q", got)
	}
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.Endpoint != "images.generation" || ev.TokensIn != 20 || ev.TokensOut != 1424 {
		t.Fatalf("event endpoint/tokens: %+v", ev)
	}
	if ev.UsageSource != "provider" || ev.CostStatus != "unknown_price" {
		t.Fatalf("event usage source/cost status: %+v", ev)
	}
	if ev.StatusCode != http.StatusOK || ev.ModelUsed != "gpt-image-1-canon" {
		t.Fatalf("event status/model: %+v", ev)
	}
}

// and zero upstream calls.
func TestImagesGenerations_MissingPrompt(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)
	rec := postImages(t, gw, `{"model":"m"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	// The contract example writes type "invalid_request"; the canonical
	// envelope vocabulary (pkg/errors wire golden, contract §error-envelope)
	// emits "invalid_request_error" for ErrorCodeInvalidRequest.
	if env.Error.Type != "invalid_request_error" || !strings.Contains(env.Error.Message, "prompt is required") {
		t.Fatalf("envelope %s", rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times", calls.Load())
	}
}

// provider is explicitly refused — images are not promised for it.
func TestImagesGenerations_UnsupportedProvider(t *testing.T) {
	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "claude-3-5-sonnet", Provider: "anthropic", Enabled: true}, "")
	rec := postImages(t, gw, `{"model":"m","prompt":"x"}`)
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
	if env.Error.Code != "images_not_supported_for_provider" {
		t.Fatalf("code %q body %s", env.Error.Code, rec.Body.String())
	}
}

// (e) + D4 default: an upstream response without a usage block is
// accounted as no_usage with zero tokens — no fabricated estimate.
func TestImagesGenerations_MissingUsageNoUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1790000000,"data":[{"url":"https://img.example/x.png"}]}`))
	}))
	defer server.Close()

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImages(t, gw, `{"model":"m","prompt":"x"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.Endpoint != "images.generation" || ev.TokensIn != 0 || ev.TokensOut != 0 {
		t.Fatalf("event endpoint/tokens: %+v", ev)
	}
	if ev.UsageSource != "none" || ev.CostStatus != "no_usage" {
		t.Fatalf("event usage source/cost status: %+v", ev)
	}
}

// 502 (embeddings-parity upstream-error accounting), not truncated silently.
func TestImagesGenerations_OversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(make([]byte, imagesResponseLimit+1))
	}))
	defer server.Close()

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)
	rec := postImages(t, gw, `{"model":"m","prompt":"x"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if errorType(t, rec) != "api_error" {
		t.Fatalf("body %s", rec.Body.String())
	}
}

// Unsupported surface is explicitly not promised: no edits route (404) and
// no GET on the generations path (chi 405). The gateway never adds a
// secondary fetch for data[].url items (D5).
func TestImagesGenerations_UnsupportedRoutesRefused(t *testing.T) {
	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", Enabled: true}, "")
	r := chi.NewRouter()
	gw.routes(r)

	edits := httptest.NewRecorder()
	r.ServeHTTP(edits, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/images/edits", strings.NewReader(`{}`)))
	if edits.Code != http.StatusNotFound {
		t.Fatalf("edits status %d", edits.Code)
	}

	get := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/images/generations", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	r.ServeHTTP(get, req)
	if get.Code != http.StatusMethodNotAllowed {
		t.Fatalf("get status %d", get.Code)
	}
}
