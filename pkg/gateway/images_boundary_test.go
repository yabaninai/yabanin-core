package cli

// images endpoint failure/boundary stage. Every test here pins a
// refusal or boundary from the contract's negative decomposition:
// invalid mime/type (upstream-owned, surfaced via MapUpstreamStatus),
// payload size (request-side 10 MiB MaxBody cap, response-side
// imagesResponseLimit), SSRF-risky links (never dereferenced, D5), and the
// error/recovery invariants (no completed event on failure — a partial or
// unknown state must never read as success; no retry that could double-charge
// an image generation; error envelopes never echo prompt/image bytes).

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// markers that must never appear in any gateway-generated error envelope.
const (
	boundaryMarkerPrompt = "gateway-echo-marker-7f3a-prompt"
	boundaryMarkerB64    = "cGF5bG9hZC1tYXJrZXItN2YzYS1pbWFnZQ=="
)

func boundaryUpstreamHandler(t *testing.T, calls *atomic.Int64, write func(w http.ResponseWriter)) http.HandlerFunc {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		write(w)
	})
}

// (payload size, lower boundary): an upstream body of EXACTLY
// imagesResponseLimit bytes is delivered verbatim as 200 — the limit is
// inclusive on the success side. The over-limit side (limit+1 → 502) is
func TestImagesGenerations_ResponseLimitExactBoundary(t *testing.T) {
	prefix := `{"created":1790000000,"data":[{"b64_json":"`
	suffix := `"}],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}`
	body := prefix + strings.Repeat("A", imagesResponseLimit-len(prefix)-len(suffix)) + suffix
	if len(body) != imagesResponseLimit {
		t.Fatalf("fixture construction: %d bytes, want %d", len(body), imagesResponseLimit)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImages(t, gw, `{"model":"m","prompt":"x"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, strings.TrimSpace(rec.Body.String())[:120])
	}
	if rec.Body.Len() != imagesResponseLimit || rec.Body.String() != body {
		t.Fatalf("passthrough altered at the exact-limit boundary: got %d bytes", rec.Body.Len())
	}
	if ev == nil || ev.TokensIn != 1 || ev.TokensOut != 2 || ev.UsageSource != "provider" {
		t.Fatalf("event %+v", ev)
	}
}

// mime allowlist; every upstream 4xx/5xx is surfaced through
// apierrors.MapUpstreamStatus with exactly ONE upstream call (no retry that
// could double-charge a generation), no request.completed event, and an
// envelope that never echoes the upstream payload (prompt or image bytes).
func TestImagesGenerations_UpstreamErrorMatrix(t *testing.T) {
	cases := []struct {
		name           string
		upstreamStatus int
		wantStatus     int
		wantType       string
	}{
		// Upstream mime/payload validation failure (e.g. invalid
		// data:image/... input) surfaces as the diagnosable upstream 400.
		{"upstream 400 invalid input", 400, http.StatusBadRequest, "invalid_request_error"},
		// Upstream auth failures are masked, never leaked to the client.
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
			server := httptest.NewServer(boundaryUpstreamHandler(t, &calls, func(w http.ResponseWriter) {
				// The upstream error body embeds the prompt and image
				// bytes; the gateway envelope must not carry them over.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.upstreamStatus)
				_, _ = w.Write([]byte(`{"error":{"message":"mime image/junk rejected for ` +
					boundaryMarkerPrompt + ` payload ` + boundaryMarkerB64 + `"}}`))
			}))
			defer server.Close()

			gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)
			var ev *eventpub.Event
			gw.eventNote = func(e *eventpub.Event) { ev = e }

			rec := postImages(t, gw, `{"model":"m","prompt":"`+boundaryMarkerPrompt+`","image":"data:image/png;base64,`+boundaryMarkerB64+`"}`)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := errorType(t, rec); got != tc.wantType {
				t.Fatalf("type %q, want %q: %s", got, tc.wantType, rec.Body.String())
			}
			env := rec.Body.String()
			if strings.Contains(env, boundaryMarkerPrompt) || strings.Contains(env, boundaryMarkerB64) {
				t.Fatalf("error envelope echoes prompt/image bytes: %s", env)
			}
			if calls.Load() != 1 {
				t.Fatalf("upstream called %d times, want exactly 1 (no retry)", calls.Load())
			}
			if ev != nil {
				t.Fatalf("failure path published %+v — partial state must not read as success", ev)
			}
		})
	}
}

// verbatim (raw passthrough contract); the unparseable usage block falls
// back to no_usage/zero tokens (D4) — never an estimate, never a fabricated
// success-shaped accounting beyond what the provider actually sent.
func TestImagesGenerations_MalformedUpstreamJSONPassthrough(t *testing.T) {
	const garbage = `{"created":1,"data":[{"b64_json":"` + boundaryMarkerB64 + `"`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(garbage))
	}))
	defer server.Close()

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImages(t, gw, `{"model":"m","prompt":"x"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != garbage {
		t.Fatalf("passthrough altered: %q", rec.Body.String())
	}
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.UsageSource != "none" || ev.CostStatus != "no_usage" || ev.TokensIn != 0 || ev.TokensOut != 0 {
		t.Fatalf("malformed upstream JSON must account as no_usage/zero: %+v", ev)
	}
}

// (usage boundaries, unit level): partial or malformed usage blocks
// A present-but-partial block is provider truth (source=provider, missing
// details default to zero cached tokens); a wrong-typed or null block is
func TestImagesUsage_PartialAndMalformedBlocks(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantSource string
		wantIn     int64
		wantOut    int64
		wantTotal  int64
		wantCached int64
	}{
		{"usage without input_tokens_details", `{"data":[],"usage":{"input_tokens":20,"output_tokens":1424,"total_tokens":1444}}`, "provider", 20, 1424, 1444, 0},
		{"empty usage object", `{"data":[],"usage":{}}`, "provider", 0, 0, 0, 0},
		{"usage null", `{"data":[],"usage":null}`, "none", 0, 0, 0, 0},
		{"usage wrong type", `{"data":[],"usage":"20 tokens"}`, "none", 0, 0, 0, 0},
		{"usage array", `{"data":[],"usage":[1,2]}`, "none", 0, 0, 0, 0},
		{"body not json at all", `garbage`, "none", 0, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, source := imagesUsage([]byte(tc.body))
			if source != tc.wantSource {
				t.Fatalf("source %q, want %q", source, tc.wantSource)
			}
			if u.PromptTokens != tc.wantIn || u.CompletionTokens != tc.wantOut || u.TotalTokens != tc.wantTotal || u.CacheReadTokens != tc.wantCached {
				t.Fatalf("usage %+v", u)
			}
		})
	}
}

// the partial usage block flows to the event as provider-sourced
// with zero cached tokens and an honest unknown_price (D1 default) — the
// missing optional detail must not downgrade the whole block to no_usage.
func TestImagesGenerations_PartialUsageEvent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1,"data":[{"b64_json":"aGk="}],"usage":{"input_tokens":5,"output_tokens":7,"total_tokens":12}}`))
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
	if ev.UsageSource != "provider" || ev.TokensIn != 5 || ev.TokensOut != 7 || ev.CacheReadTokens != 0 {
		t.Fatalf("event %+v", ev)
	}
	if ev.CostStatus != "unknown_price" {
		t.Fatalf("cost status %q, want unknown_price", ev.CostStatus)
	}
}

// never observe a request.completed event — no usage accounting, no cost
// attributed for an image the consumer never received.
func TestImagesGenerations_ClientCancelMidResponse(t *testing.T) {
	upstreamWrote := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1,"data":[{"b64_json":"`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		close(upstreamWrote)
		select {
		case <-release:
		case <-r.Context().Done():
		}
		_, _ = w.Write([]byte("truncated-after-cancel\"}]}"))
	}))
	defer server.Close()
	defer close(release) // unblock the handler if the gateway never cancels it

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Safety net: never let a plumbing regression hang the suite.
	timer := time.AfterFunc(10*time.Second, cancel)
	defer timer.Stop()

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"m","prompt":"x"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.ServeHTTP(rec, req)
	}()

	<-upstreamWrote
	time.Sleep(50 * time.Millisecond) // let the gateway block reading the body
	cancel()
	<-done

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502: %s", rec.Code, rec.Body.String())
	}
	if got := errorType(t, rec); got != "api_error" {
		t.Fatalf("type %q body %s", got, rec.Body.String())
	}
	if ev != nil {
		t.Fatalf("cancelled request published %+v — must never read as success", ev)
	}
	if !strings.Contains(rec.Body.String(), "failed to read upstream response") {
		t.Fatalf("body %s", rec.Body.String())
	}
}

// through the real httpmw.MaxBody middleware answers 413 before any
func TestImagesGenerations_BodyTooLargeThroughMaxBody(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)

	r := chi.NewRouter()
	r.Use(httpmw.MaxBody(10 * 1024 * 1024))
	gw.routes(r)

	big := `{"model":"m","prompt":"` + strings.Repeat("a", 10*1024*1024) + `"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/images/generations", strings.NewReader(big))
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

// The gateway performs exactly one egress — the upstream call — and never
// fetches the URL (loopback listener must stay at zero hits).
func TestImagesGenerations_URLPassthroughNeverFetched(t *testing.T) {
	var imgHits atomic.Int64
	imgServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		imgHits.Add(1)
	}))
	defer imgServer.Close()

	urlBody := `{"created":1,"data":[{"url":"` + imgServer.URL + `/img.png"}]}`
	var upstreamCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(urlBody))
	}))
	defer server.Close()

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImages(t, gw, `{"model":"m","prompt":"x"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), imgServer.URL+"/img.png") {
		t.Fatalf("url not passed through verbatim: %s", rec.Body.String())
	}
	if imgHits.Load() != 0 {
		t.Fatalf("gateway dereferenced data[].url %d times — SSRF boundary violated", imgHits.Load())
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls %d, want 1", upstreamCalls.Load())
	}
	if ev == nil || ev.UsageSource != "none" || ev.CostStatus != "no_usage" {
		t.Fatalf("event %+v", ev)
	}
}

// api_error with no completed event — never a hang, never a 200.
func TestImagesGenerations_UnreachableUpstream(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // free the port: connections are refused from here on

	gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: deadURL, Enabled: true}, deadURL)
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImages(t, gw, `{"model":"m","prompt":"x"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if errorType(t, rec) != "api_error" {
		t.Fatalf("envelope %s", rec.Body.String())
	}
	if ev != nil {
		t.Fatalf("failed request published %+v", ev)
	}
}

func TestImagesGenerations_PoolNilRefused(t *testing.T) {
	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key"},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": {ModelName: "gpt-image-1-canon", Provider: "openai", Enabled: true}},
	}
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postImages(t, gw, `{"model":"m","prompt":"x"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if ev != nil {
		t.Fatalf("pool-nil refusal published %+v", ev)
	}
}

// refused locally with zero upstream calls, and the envelope never echoes
// request bytes (prompt or embedded image payload).
func TestImagesGenerations_InvalidRequestBodyNoEcho(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantMessage string
	}{
		{"missing model", `{"model":"","prompt":"` + boundaryMarkerPrompt + `"}`, "model is required"},
		{"empty body", ``, "malformed JSON"},
		{"truncated json with payload", `{"model":"m","prompt":"` + boundaryMarkerPrompt + `","image":"data:image/png;base64,` + boundaryMarkerB64 + `"`, "malformed JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
			}))
			defer server.Close()

			gw := imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true}, server.URL)
			rec := postImages(t, gw, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if errorType(t, rec) != "invalid_request_error" {
				t.Fatalf("envelope %s", rec.Body.String())
			}
			var env struct {
				Error struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(env.Error.Message, tc.wantMessage) {
				t.Fatalf("message %q, want prefix %q", env.Error.Message, tc.wantMessage)
			}
			if strings.Contains(rec.Body.String(), boundaryMarkerPrompt) || strings.Contains(rec.Body.String(), boundaryMarkerB64) {
				t.Fatalf("error envelope echoes request payload: %s", rec.Body.String())
			}
			if calls.Load() != 0 {
				t.Fatalf("upstream called %d times on invalid input", calls.Load())
			}
		})
	}
}
