package cli

// ratified contract (D1 realtime in, D4 SSE-only): byte-honest SSE relay
// with actual usage accounting from the session events (D3), WebSocket
// upgrade explicitly refused, upstream errors answered with the JSON
// envelope before the SSE commit point, and residency refusal before any
// upstream call.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// Cancel-settle fixtures: an enforce-mode plan with a zero Reservation keeps
// gate.finalize side-effect free (budget.Finalize early-returns on an
// unreserved tuple) while still stamping the termination on the event — the
// G3 observable under test.
var planEnforceStub = budget.Plan{Mode: budget.ModeEnforce}
var reservationStub = budget.Reservation{}

// realtimeTestModel is the stub registry entry for the realtime tests.
func realtimeTestModel(upstreamURL string) resolver.ModelInfo {
	return resolver.ModelInfo{
		ModelName:      "gpt-4o-realtime-canon",
		Provider:       "openai",
		UpstreamURL:    upstreamURL,
		UpstreamAPIKey: "up-key",
		Enabled:        true,
	}
}

// TestRealtime_HappyPathSSEPassthroughAndUsage: the upstream session event
// stream is relayed byte-identically with SSE headers, the canonical model
// override reaches the upstream, and the last usage-bearing event
// (response.usage on response.done) bills as provider tokens with an honest
// unknown_price (D3).
func TestRealtime_HappyPathSSEPassthroughAndUsage(t *testing.T) {
	const upstreamStream = "event: session.created\n" +
		`data: {"type":"session.created","session":{"id":"sess_1","model":"gpt-4o-realtime-canon"}}` + "\n\n" +
		"event: response.done\n" +
		`data: {"type":"response.done","response":{"id":"resp_1","usage":{"input_tokens":42,"output_tokens":7,"total_tokens":49,"input_token_details":{"cached_tokens":5}}}}` + "\n\n"

	var upstreamPath atomic.Value
	var upstreamBodyGot atomic.Value
	var gotStreamFlag atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath.Store(r.URL.Path)
		raw, _ := io.ReadAll(r.Body)
		upstreamBodyGot.Store(string(raw))
		if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			gotStreamFlag.Store(true)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(upstreamStream))
	}))
	defer server.Close()

	gw := r105TestGateway(t, realtimeTestModel(server.URL))
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postR105(t, gw, "/v1/realtime", `{"model":"m","session":{"voice":"alloy"},"input":"hello"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content type %q", got)
	}
	if rec.Body.String() != upstreamStream {
		t.Fatalf("relay altered the stream:\n%q\nwant\n%q", rec.Body.String(), upstreamStream)
	}
	if got := upstreamPath.Load(); got != "/v1/realtime" {
		t.Fatalf("upstream path %v", got)
	}
	if body, _ := upstreamBodyGot.Load().(string); !strings.Contains(body, `"model":"gpt-4o-realtime-canon"`) ||
		!strings.Contains(body, `"voice":"alloy"`) {
		t.Fatalf("upstream body %q", body)
	}
	if !gotStreamFlag.Load() {
		t.Fatal("upstream request did not carry the SSE accept header")
	}
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.Endpoint != "realtime" || ev.EventType != "request.completed" {
		t.Fatalf("event type/endpoint: %+v", ev)
	}
	if ev.TokensIn != 42 || ev.TokensOut != 7 || ev.CacheReadTokens != 5 {
		t.Fatalf("event tokens: %+v", ev)
	}
	if ev.UsageSource != "provider" || ev.CostStatus != "unknown_price" {
		t.Fatalf("event usage source/cost status: %+v", ev)
	}
	if ev.StatusCode != http.StatusOK || ev.ModelUsed != "gpt-4o-realtime-canon" {
		t.Fatalf("event status/model: %+v", ev)
	}
}

// TestRealtime_TopLevelUsageLastWins (D3): chat-style frames with a
// top-level usage block are accepted and the LAST usage-bearing event wins
// (carryStreamUsage parity with the chat stream accumulator).
func TestRealtime_TopLevelUsageLastWins(t *testing.T) {
	stream := "data: " + `{"usage":{"input_tokens":10,"total_tokens":10}}` + "\n\n" +
		"data: " + `{"usage":{"input_tokens":30,"output_tokens":4,"total_tokens":34}}` + "\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(stream))
	}))
	defer server.Close()

	gw := r105TestGateway(t, realtimeTestModel(server.URL))
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postR105(t, gw, "/v1/realtime", `{"model":"m"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if ev == nil || ev.TokensIn != 30 || ev.TokensOut != 4 {
		t.Fatalf("event usage (last block must win): %+v", ev)
	}
}

// TestRealtime_WebSocketUpgradeRefused (ratified D4, SSE-only): an upgrade
// request is refused 400 unsupported_feature before admission — zero
// upstream calls, zero admission work.
func TestRealtime_WebSocketUpgradeRefused(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := r105TestGateway(t, realtimeTestModel(server.URL))
	rec := postR105(t, gw, "/v1/realtime", `{"model":"m"}`, map[string]string{
		"Upgrade":    "websocket",
		"Connection": "Upgrade",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Code != "unsupported_feature" || !strings.Contains(env.Error.Message, "SSE-only") {
		t.Fatalf("envelope %s", rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times on websocket upgrade", calls.Load())
	}
}

// TestRealtime_UnsupportedProvider (D2 ratified openai-compat matrix).
func TestRealtime_UnsupportedProvider(t *testing.T) {
	gw := r105TestGateway(t, resolver.ModelInfo{ModelName: "claude-3-5-sonnet", Provider: "anthropic", Enabled: true})
	rec := postR105(t, gw, "/v1/realtime", `{"model":"m"}`, nil)
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
	if env.Error.Code != "realtime_not_supported_for_provider" {
		t.Fatalf("code %q body %s", env.Error.Code, rec.Body.String())
	}
}

// TestRealtime_RequestValidation: missing model, empty body and malformed
// JSON are refused locally with zero upstream calls.
func TestRealtime_RequestValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing model", `{"session":{}}`},
		{"empty body", ``},
		{"truncated json", `{"model":"m"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
			}))
			defer server.Close()

			gw := r105TestGateway(t, realtimeTestModel(server.URL))
			rec := postR105(t, gw, "/v1/realtime", tc.body, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if errorType(t, rec) != "invalid_request_error" {
				t.Fatalf("envelope %s", rec.Body.String())
			}
			if calls.Load() != 0 {
				t.Fatalf("upstream called %d times", calls.Load())
			}
		})
	}
}

// TestRealtime_UpstreamErrorJSONEnvelope: upstream failures before the SSE
// commit point answer the mapped JSON envelope (MapUpstreamStatus), publish
// no request.completed success event and issue exactly one upstream call.
func TestRealtime_UpstreamErrorJSONEnvelope(t *testing.T) {
	cases := []struct {
		name           string
		upstreamStatus int
		wantStatus     int
		wantType       string
	}{
		{"upstream 400", 400, http.StatusBadRequest, "invalid_request_error"},
		{"upstream 401 masked", 401, http.StatusBadGateway, "api_error"},
		{"upstream 403", 403, http.StatusForbidden, "permission_denied_error"},
		{"upstream 404", 404, http.StatusNotFound, "not_found_error"},
		{"upstream 429", 429, http.StatusTooManyRequests, "rate_limit_exceeded"},
		{"upstream 500", 500, http.StatusBadGateway, "api_error"},
		{"upstream 503", 503, http.StatusBadGateway, "api_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.upstreamStatus)
				_, _ = w.Write([]byte(`{"error":{"message":"boom marker-payload"}}`))
			}))
			defer server.Close()

			gw := r105TestGateway(t, realtimeTestModel(server.URL))
			var ev *eventpub.Event
			gw.eventNote = func(e *eventpub.Event) { ev = e }

			rec := postR105(t, gw, "/v1/realtime", `{"model":"m"}`, nil)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := errorType(t, rec); got != tc.wantType {
				t.Fatalf("type %q, want %q", got, tc.wantType)
			}
			if got := rec.Header().Get("Content-Type"); got == "text/event-stream" {
				t.Fatalf("error path must not commit SSE headers, got %q", got)
			}
			if calls.Load() != 1 {
				t.Fatalf("upstream called %d times", calls.Load())
			}
			if ev != nil {
				t.Fatalf("failure path published %+v", ev)
			}
		})
	}
}

// TestRealtime_ResidencyDeniedBeforeUpstream (contract example 3).
func TestRealtime_ResidencyDeniedBeforeUpstream(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := r105TestGateway(t, realtimeTestModel(server.URL))
	gw.auth = NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-eu", nil))
	gw.residencyEnforcer = fakeResidency{dec: policy.Decision{Allowed: false, Region: "EU", Reason: "model not resident"}}

	rec := postR105(t, gw, "/v1/realtime", `{"model":"m"}`, map[string]string{"X-Org-Id": "org-eu"})
	if rec.Code != http.StatusForbidden || errorType(t, rec) != "residency_policy_violation" {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times after residency denial", calls.Load())
	}
}

// TestRealtime_MethodNotAllowed: the realtime surface is POST-only (chi
// 405) — no GET session channel exists in the SSE-only subset.
func TestRealtime_MethodNotAllowed(t *testing.T) {
	gw := r105TestGateway(t, realtimeTestModel(""))
	r := chi.NewRouter()
	gw.routes(r)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/realtime", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
}

// TestRealtime_ClientCancelSettlesConsumedPrefix is contract example 4 /
// G3 parity: a client disconnect mid-SSE settles the consumed prefix — the
// usage already reported by the upstream bills, the reservation settles
// with TerminationClientCancel, and no request.completed success event is
// published ("отмена realtime не теряет usage"). The in-process recorder
// harness (images cancel parity) keeps the reservation gate on the request
// context; the disconnect is the request context cancel.
func TestRealtime_ClientCancelSettlesConsumedPrefix(t *testing.T) {
	prefixSent := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: response.done\n" +
			`data: {"type":"response.done","response":{"usage":{"input_tokens":11,"output_tokens":3,"total_tokens":14}}}` + "\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		close(prefixSent)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)

	gw := r105TestGateway(t, realtimeTestModel(server.URL))
	gate := &reservationGate{gw: gw, plan: &planEnforceStub, rsv: &reservationStub}
	var ev *eventpub.Event
	evCh := make(chan *eventpub.Event, 1)
	gw.eventNote = func(e *eventpub.Event) { evCh <- e }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(10*time.Second, cancel) // safety net: never hang the suite
	defer timer.Stop()
	ctx = withReservationGate(ctx, gate)

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/realtime", strings.NewReader(`{"model":"m"}`))
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

	select {
	case <-prefixSent:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never produced the prefix")
	}
	// Let the relay block on the next upstream read, then walk away.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	select {
	case ev = <-evCh:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel settled no event — usage would be lost")
	}
	if ev.EventType != "request.failed" {
		t.Fatalf("event type %q, want request.failed", ev.EventType)
	}
	if ev.Endpoint != "realtime" {
		t.Fatalf("endpoint %q", ev.Endpoint)
	}
	// The consumed prefix must not lose its usage.
	if ev.TokensIn != 11 || ev.TokensOut != 3 {
		t.Fatalf("partial usage lost: %+v", ev)
	}
	if ev.UsageSource != "provider" {
		t.Fatalf("usage source %q", ev.UsageSource)
	}
	if ev.Termination != "client_cancel" {
		t.Fatalf("termination %q, want client_cancel", ev.Termination)
	}
	if !strings.Contains(rec.Body.String(), "input_tokens") {
		t.Fatalf("consumed prefix not relayed: %q", rec.Body.String())
	}
}
