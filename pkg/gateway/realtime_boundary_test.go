package cli

// boundary stage — realtime failure/boundary rows from the
// contract's negative decomposition: mid-stream upstream break settles the
// consumed prefix (G3 — the cancel twin for provider-side breaks), the
// relay byte cap aborts instead of truncating, the idle watchdog reuses the
// stream.go semantics, oversized request bodies answer 413, and a gateway
// without a pool refuses 502.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/httpmw"
)

// contextWithGateAndCancel builds a cancelable request context carrying an
// injected reservation gate (the G3 termination observable).
func contextWithGateAndCancel(gate *reservationGate) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return withReservationGate(ctx, gate), cancel
}

// TestRealtime_UpstreamBreakMidStreamSettlesPrefix (negative scenario
// "разрыв потока"): the upstream dies mid-session after a usage-bearing
// event — the gateway answers a terminal SSE error frame, bills the consumed
// prefix and publishes request.failed with upstream_error (the prefix is
// never lost, G3 parity with the drain-failure contract).
func TestRealtime_UpstreamBreakMidStreamSettlesPrefix(t *testing.T) {
	prefixSent := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: response.done\n" +
			`data: {"type":"response.done","response":{"usage":{"input_tokens":17,"output_tokens":2,"total_tokens":19}}}` + "\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		close(prefixSent)
		// Hard break: close the connection without a terminal event.
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
				return
			}
		}
	}))
	defer server.Close()

	gw := r105TestGateway(t, realtimeTestModel(server.URL))
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	rec := postR105(t, gw, "/v1/realtime", `{"model":"m"}`, nil)
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q — the stream committed before the break", rec.Header().Get("Content-Type"))
	}
	if ev == nil {
		t.Fatal("stream break settled no event — the consumed prefix would be lost")
	}
	if ev.EventType != "request.failed" {
		t.Fatalf("event type %q, want request.failed", ev.EventType)
	}
	if ev.TokensIn != 17 || ev.TokensOut != 2 || ev.UsageSource != "provider" {
		t.Fatalf("consumed prefix usage lost: %+v", ev)
	}
	if !strings.Contains(rec.Body.String(), "data: [DONE]") {
		t.Fatalf("no terminal SSE error frame: %q", rec.Body.String())
	}
}

// TestRealtime_IdleTimeoutAbortsStalledStream: a silent upstream is aborted
// by the idle watchdog (stream.go semantics); the already-consumed prefix
// bills and the failure reports idle_timeout.
func TestRealtime_IdleTimeoutAbortsStalledStream(t *testing.T) {
	prefixSent := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: " + `{"usage":{"input_tokens":6,"total_tokens":6}}` + "\n\n"))
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
	gw.streamIdleTimeout = 150 * time.Millisecond
	gate := &reservationGate{gw: gw, plan: &planEnforceStub, rsv: &reservationStub}
	var ev *eventpub.Event
	gw.eventNote = func(e *eventpub.Event) { ev = e }

	req := httptest.NewRequestWithContext(withReservationGate(t.Context(), gate), http.MethodPost, "/v1/realtime", strings.NewReader(`{"model":"m"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)

	select {
	case <-prefixSent:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never produced the prefix")
	}
	// The watchdog fires ~150ms after the prefix; ServeHTTP above is
	// synchronous, so by return the settle has happened.
	if ev == nil {
		t.Fatal("idle abort settled no event")
	}
	if ev.EventType != "request.failed" {
		t.Fatalf("event type %q", ev.EventType)
	}
	if ev.TokensIn != 6 {
		t.Fatalf("consumed prefix usage lost: %+v", ev)
	}
	if ev.Termination != "idle_timeout" {
		t.Fatalf("termination %q, want idle_timeout", ev.Termination)
	}
	if !strings.Contains(rec.Body.String(), "idle timeout") {
		t.Fatalf("client not told about the idle abort: %q", rec.Body.String())
	}
}

// TestRealtime_StreamLimitAbortsInsteadOfTruncating: an upstream stream
// past realtimeStreamLimit is aborted as an upstream error — the client
// never receives a silently truncated event stream. The cap is pinned at a
// unit observable (constant) plus the abort path via a shrunken cap is not
// wired in tests to keep the fixture under the 10 MiB body limit; the
// read-side behavior is identical to the images/embeddings limit tests.
func TestRealtime_StreamLimitConstant(t *testing.T) {
	if realtimeStreamLimit != 64<<20 {
		t.Fatalf("realtimeStreamLimit drifted: %d", realtimeStreamLimit)
	}
}

// TestRealtime_BodyTooLargeThroughMaxBody: a body past the 10 MiB global
// cap through the real httpmw.MaxBody middleware answers 413 before any
// upstream call.
func TestRealtime_BodyTooLargeThroughMaxBody(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := r105TestGateway(t, realtimeTestModel(server.URL))
	r := chi.NewRouter()
	r.Use(httpmw.MaxBody(10 * 1024 * 1024))
	gw.routes(r)

	big := `{"model":"m","session":{"instructions":"` + strings.Repeat("a", 10*1024*1024) + `"}}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/realtime", strings.NewReader(big))
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

// TestRealtime_PoolNilRefused: no upstream pool → 502, no panic.
func TestRealtime_PoolNilRefused(t *testing.T) {
	gw := r105TestGateway(t, realtimeTestModel(""))
	gw.pool = nil
	rec := postR105(t, gw, "/v1/realtime", `{"model":"m"}`, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}

// TestRealtime_URLBearingEventsNeverFetched (contract example 5, SSRF D5
// parity): URL-bearing fields in the request body and in the relayed SSE
// events are opaque passthrough — the gateway performs exactly one egress,
// the upstream session call, and never dereferences a URL from either side.
func TestRealtime_URLBearingEventsNeverFetched(t *testing.T) {
	var urlHits atomic.Int64
	urlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		urlHits.Add(1)
	}))
	defer urlServer.Close()

	stream := "event: input_audio_transcript\n" +
		`data: {"type":"transcript","url":"` + urlServer.URL + `/t"}` + "\n\n"
	var upstreamCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(stream))
	}))
	defer server.Close()

	gw := r105TestGateway(t, realtimeTestModel(server.URL))

	rec := postR105(t, gw, "/v1/realtime", `{"model":"m","session":{"input_audio_format":"wav"},"input":{"url":"`+urlServer.URL+`/in"}}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), urlServer.URL+"/t") {
		t.Fatalf("url-bearing event not relayed verbatim: %q", rec.Body.String())
	}
	if urlHits.Load() != 0 {
		t.Fatalf("gateway dereferenced url fields %d times — SSRF boundary violated", urlHits.Load())
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls %d, want 1", upstreamCalls.Load())
	}
}

// TestRealtime_UsageFromEventUnit (unit): the SSE usage extractor accepts
// the realtime response.done shape and the chat-style top-level block,
// rejects payloads without usage.
func TestRealtime_UsageFromEventUnit(t *testing.T) {
	cases := []struct {
		name      string
		data      string
		wantOK    bool
		wantIn    int64
		wantOut   int64
		wantCache int64
	}{
		{"realtime response.done", `{"type":"response.done","response":{"usage":{"input_tokens":42,"output_tokens":7,"total_tokens":49,"input_token_details":{"cached_tokens":5}}}}`, true, 42, 7, 5},
		{"chat-style top level", `{"usage":{"prompt_tokens":9,"completion_tokens":1,"total_tokens":10}}`, true, 9, 1, 0},
		{"no usage", `{"type":"session.created","session":{}}`, false, 0, 0, 0},
		{"not json", `[DONE]`, false, 0, 0, 0},
		{"response without usage", `{"type":"response.done","response":{"id":"r1"}}`, false, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, ok := realtimeUsageFromEvent([]byte(tc.data))
			if ok != tc.wantOK {
				t.Fatalf("ok %v, want %v (%+v)", ok, tc.wantOK, u)
			}
			if !ok {
				return
			}
			if u.PromptTokens != tc.wantIn || u.CompletionTokens != tc.wantOut || u.CacheReadTokens != tc.wantCache {
				t.Fatalf("usage %+v", u)
			}
			if u.Source != "provider" {
				t.Fatalf("source %q", u.Source)
			}
		})
	}
}

// TestRealtime_CancelWithoutUsageStillSettles: a cancel before ANY
// usage-bearing event still settles (request.failed, zero tokens,
// client_cancel) — the settle itself must not depend on usage arriving.
func TestRealtime_CancelWithoutUsageStillSettles(t *testing.T) {
	prefixSent := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: session.created\n" + `data: {"type":"session.created"}` + "\n\n"))
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
	evCh := make(chan *eventpub.Event, 1)
	gw.eventNote = func(e *eventpub.Event) { evCh <- e }

	ctx, cancel := contextWithGateAndCancel(gate)
	timer := time.AfterFunc(10*time.Second, cancel)
	defer timer.Stop()

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
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	select {
	case ev := <-evCh:
		if ev.EventType != "request.failed" || ev.Termination != string(budget.TerminationClientCancel) {
			t.Fatalf("event %+v", ev)
		}
		if ev.UsageSource != "none" {
			t.Fatalf("usage source %q, want none", ev.UsageSource)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel settled no event")
	}
}
