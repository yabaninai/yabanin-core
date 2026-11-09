package cli

// boundary stage — moderations failure/boundary rows from the
// contract's negative decomposition: upstream 4xx/5xx surfaced via
// MapUpstreamStatus with exactly one upstream call, payload-size caps on
// both sides (10 MiB request cap → 413, moderationsResponseLimit → 502,
// never a silent truncation), malformed bodies refused without echoing the
// classified input, and recovery invariants (a failure never publishes
// request.completed).

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

const moderationsMarkerInput = "gateway-echo-marker-r105-input"

// TestModerations_UpstreamErrorMatrix: every upstream 4xx/5xx is surfaced
// through apierrors.MapUpstreamStatus with exactly ONE upstream call, no
// request.completed event, and an envelope that never echoes the classified
// input embedded in the upstream error body.
func TestModerations_UpstreamErrorMatrix(t *testing.T) {
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
				_, _ = w.Write([]byte(`{"error":{"message":"cannot classify ` + moderationsMarkerInput + `"}}`))
			}))
			defer server.Close()

			gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
			gw.eventNote = func(e *eventpub.Event) { t.Errorf("failure path published %+v", e) }

			rec := postR105(t, gw, "/v1/moderations", `{"model":"m","input":"`+moderationsMarkerInput+`"}`, nil)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := errorType(t, rec); got != tc.wantType {
				t.Fatalf("type %q, want %q: %s", got, tc.wantType, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), moderationsMarkerInput) {
				t.Fatalf("error envelope echoes request bytes: %s", rec.Body.String())
			}
			if calls.Load() != 1 {
				t.Fatalf("upstream called %d times, want exactly 1 (no retry)", calls.Load())
			}
		})
	}
}

// TestModerations_OversizedResponse: an upstream body above
// moderationsResponseLimit is refused as 502, never truncated.
func TestModerations_OversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(make([]byte, moderationsResponseLimit+1))
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
	rec := postR105(t, gw, "/v1/moderations", `{"model":"m","input":"x"}`, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if errorType(t, rec) != "api_error" || !strings.Contains(rec.Body.String(), "upstream response too large") {
		t.Fatalf("body %s", rec.Body.String())
	}
}

// TestModerations_BodyTooLargeThroughMaxBody: a body past the 10 MiB global
// cap through the real httpmw.MaxBody middleware answers 413 before any
// upstream call.
func TestModerations_BodyTooLargeThroughMaxBody(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
	r := chi.NewRouter()
	r.Use(httpmw.MaxBody(10 * 1024 * 1024))
	gw.routes(r)

	big := `{"model":"m","input":"` + strings.Repeat("a", 10*1024*1024) + `"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/moderations", strings.NewReader(big))
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

// TestModerations_UnreachableUpstream: a refused connection is a 502
// api_error with no completed event.
func TestModerations_UnreachableUpstream(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", UpstreamURL: deadURL, Enabled: true})
	var published bool
	gw.eventNote = func(e *eventpub.Event) { published = true }

	rec := postR105(t, gw, "/v1/moderations", `{"model":"m","input":"x"}`, nil)
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

// TestModerations_PoolNilRefused: no upstream pool → 502, no panic.
func TestModerations_PoolNilRefused(t *testing.T) {
	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", Enabled: true})
	gw.pool = nil
	rec := postR105(t, gw, "/v1/moderations", `{"model":"m","input":"x"}`, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

// TestModerations_URLInputNeverFetched (contract example 5, SSRF D5 parity):
// a URL inside the classified input (string or array form) is opaque
// passthrough — the gateway performs exactly one egress, the upstream call,
// and never dereferences the client-supplied URL.
func TestModerations_URLInputNeverFetched(t *testing.T) {
	var urlHits atomic.Int64
	urlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		urlHits.Add(1)
	}))
	defer urlServer.Close()

	var upstreamCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"mod","results":[]}`))
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})

	for _, body := range []string{
		`{"model":"m","input":"` + urlServer.URL + `/inline"}`,
		`{"model":"m","input":["` + urlServer.URL + `/arr0", "plain text"]}`,
	} {
		rec := postR105(t, gw, "/v1/moderations", body, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
	}
	if urlHits.Load() != 0 {
		t.Fatalf("gateway dereferenced input urls %d times — SSRF boundary violated", urlHits.Load())
	}
	if upstreamCalls.Load() != 2 {
		t.Fatalf("upstream calls %d, want 2", upstreamCalls.Load())
	}
}

// TestModerations_MalformedUpstreamJSONPassthrough: a 200 upstream body that
// is not valid JSON passes through verbatim; the usage parse falls back to
// no_usage/zero (D3) — never an estimate.
func TestModerations_MalformedUpstreamJSONPassthrough(t *testing.T) {
	const garbage = `{"id":"mod","results":[{"flagged":`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(garbage))
	}))
	defer server.Close()

	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "omni-moderation-canon", Provider: "openai", UpstreamURL: server.URL, Enabled: true})
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postR105(t, gw, "/v1/moderations", `{"model":"m","input":"x"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != garbage {
		t.Fatalf("passthrough altered: %q", rec.Body.String())
	}
	if ev == nil || ev.UsageSource != "none" || ev.CostStatus != "no_usage" {
		t.Fatalf("malformed upstream JSON must account as no_usage: %+v", ev)
	}
}
