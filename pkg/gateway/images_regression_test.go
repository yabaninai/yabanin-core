package cli

//   - contract example 1 working path with its full observable set, including
//     the X-Residency-Region admit-pipeline header (admission.go:352) and
//     verbatim n/size passthrough (upstream-owned semantics);
//   - a NON-zero input_tokens_details.cached_tokens mapping to the event's
//     cache_read_tokens (all earlier fixtures exercised cached=0/absent);
//   - a multi-image data[] response (n>1 shape, upstream-owned) delivered
//     verbatim with the single provider usage block accounted exactly once.

import (
	"encoding/base64"
	"io"
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
)

func postImagesWithHeaders(t *testing.T, gw *gateway, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/images/generations", strings.NewReader(body))
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

// verbatim request and response fixtures from the contract — must surface
// every promised observable: 200 application/json passthrough, the admit
// pipeline's X-Residency-Region header, and one request.completed event with
// provider tokens and an honest unknown_price (D1). The images pipeline
// rides the shared admit pipeline, so the residency observable is inherited,
// not optional.
func TestImagesGenerations_ContractExample1_WorkingPath(t *testing.T) {
	const request = `{"model":"gpt-image-1","prompt":"a single red cube on a white background","n":1,"size":"1024x1024"}`
	upstreamBody := `{"created":1790000000,"data":[{"b64_json":"` +
		base64.StdEncoding.EncodeToString(testTinyPNG) +
		`"}],"usage":{"input_tokens":20,"output_tokens":1424,"total_tokens":1444,` +
		`"input_tokens_details":{"cached_tokens":0}}}`

	var sawUpstreamBody atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		sawUpstreamBody.Store(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer server.Close()

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}, server.URL)
	// The residency contract keys off the auth middleware's RESOLVED org (the
	// client X-Org-Id copy is stripped), so the harness resolves the gateway
	// key to org-images exactly as production would.
	gw.auth = NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-images", nil))
	gw.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: true, Region: "SG"}}
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImagesWithHeaders(t, gw, request, map[string]string{"X-Org-Id": "org-images"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type %q", got)
	}
	if rec.Body.String() != upstreamBody {
		t.Fatalf("passthrough altered: %q", rec.Body.String())
	}
	if got, _ := sawUpstreamBody.Load().(string); !strings.Contains(got, `"n":1`) || !strings.Contains(got, `"size":"1024x1024"`) {
		t.Fatalf("upstream body lost contract n/size passthrough: %s", got)
	}
	if got := rec.Header().Get("X-Residency-Region"); got != "SG" {
		t.Fatalf("X-Residency-Region %q, want SG (contract example 1 observable)", got)
	}
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.Endpoint != "images.generation" || ev.TokensIn != 20 || ev.TokensOut != 1424 || ev.CacheReadTokens != 0 {
		t.Fatalf("event tokens: %+v", ev)
	}
	if ev.UsageSource != "provider" || ev.CostStatus != "unknown_price" {
		t.Fatalf("event usage source/cost status: %+v", ev)
	}
}

// the promised usage mapping (contract: cached_tokens → CacheReadTokens).
// Every earlier fixture exercised cached=0 or an absent details block; this
// pins the non-zero value flowing from the provider block into the event.
func TestImagesGenerations_CachedTokensAccounted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1,"data":[{"b64_json":"aGk="}],` +
			`"usage":{"input_tokens":20,"output_tokens":1424,"total_tokens":1444,` +
			`"input_tokens_details":{"cached_tokens":410}}}`))
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
	if ev.UsageSource != "provider" || ev.CostStatus != "unknown_price" {
		t.Fatalf("event usage source/cost status: %+v", ev)
	}
	if ev.TokensIn != 20 || ev.TokensOut != 1424 || ev.CacheReadTokens != 410 {
		t.Fatalf("cached_tokens must map to cache_read_tokens: %+v", ev)
	}
}

// with a multi-item data[] array (mixed b64_json and url items) is delivered
// verbatim — the gateway never collapses, reorders or fetches items — and
// the single provider usage block is accounted exactly once.
func TestImagesGenerations_MultiImageResponseAccountedOnce(t *testing.T) {
	secondB64 := base64.StdEncoding.EncodeToString([]byte("second-opaque-image-payload"))
	upstreamBody := `{"created":1790000001,"data":[` +
		`{"b64_json":"` + base64.StdEncoding.EncodeToString(testTinyPNG) + `"},` +
		`{"url":"https://img.example/multi.png"},` +
		`{"b64_json":"` + secondB64 + `"}],` +
		`"usage":{"input_tokens":30,"output_tokens":3000,"total_tokens":3030,` +
		`"input_tokens_details":{"cached_tokens":15}}}`

	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer server.Close()

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImages(t, gw, `{"model":"m","prompt":"x","n":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != upstreamBody {
		t.Fatalf("multi-image passthrough altered:\n got %q\nwant %q", rec.Body.String(), upstreamBody)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream called %d times, want 1", calls.Load())
	}
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.TokensIn != 30 || ev.TokensOut != 3000 || ev.CacheReadTokens != 15 {
		t.Fatalf("usage block must be accounted exactly once: %+v", ev)
	}
	if ev.UsageSource != "provider" || ev.CostStatus != "unknown_price" {
		t.Fatalf("event usage source/cost status: %+v", ev)
	}
}

// path — an org whose residency decision denies the model is rejected 403
// before any upstream call (parity with embeddings; the images contract
// promises no residency bypass).
func TestImagesGenerations_ResidencyDeniedBeforeUpstream(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)
	gw.auth = NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-images", nil))
	gw.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: false, Region: "SG", Reason: "model not allowed in region"}}

	rec := postImagesWithHeaders(t, gw, `{"model":"m","prompt":"x"}`, map[string]string{"X-Org-Id": "org-images"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if errorType(t, rec) != "residency_policy_violation" {
		t.Fatalf("envelope %s", rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("residency-denied images request reached upstream %d times", calls.Load())
	}
}
