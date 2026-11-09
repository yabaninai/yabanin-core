package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// tickReader emits one byte per interval, blocking in between — a stand-in
// for an upstream that trickles SSE chunks. The tick pacing is the point of
// TestIdleReader_ResetsOnData (data must keep arriving faster than the real
// idle window), so it stays time-based by design.
type tickReader struct {
	remaining int
	interval  time.Duration
}

func (r *tickReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	time.Sleep(r.interval)
	p[0] = 'x'
	r.remaining--
	return 1, nil
}

func TestIdleReader_FiresAfterSilence(t *testing.T) {
	fired := make(chan struct{})
	ir := newIdleReader(strings.NewReader(""), 50*time.Millisecond, func() { close(fired) })
	defer ir.Stop()

	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("idle watchdog did not fire on a silent reader")
	}
	if !ir.Fired() {
		t.Fatal("Fired() must be true after the watchdog fired")
	}
}

func TestIdleReader_ResetsOnData(t *testing.T) {
	fired := make(chan struct{})
	tr := &tickReader{remaining: 12, interval: 25 * time.Millisecond} // 300ms of flow
	ir := newIdleReader(tr, 100*time.Millisecond, func() { close(fired) })
	defer ir.Stop()

	done := make(chan int, 1)
	go func() {
		var total int
		buf := make([]byte, 4)
		for total < 12 {
			n, err := ir.Read(buf)
			total += n
			if err != nil {
				break
			}
		}
		done <- total
	}()

	select {
	case <-fired:
		t.Fatal("idle watchdog fired while data was flowing")
	case total := <-done:
		if total != 12 {
			t.Fatalf("read %d bytes, want 12", total)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader stalled")
	}
	assert.False(t, ir.Fired(), "watchdog must not fire while bytes keep arriving")
}

// TestServeStream_IdleUpstreamGetsIdleError: an upstream that goes silent
// mid-stream (first chunk, then nothing) is aborted by the idle watchdog and
// the client gets a distinct terminal error frame — not an eternal hang.
func TestServeStream_IdleUpstreamGetsIdleError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n")
		w.(http.Flusher).Flush()
		// Real-timeout stall: the silent stretch must comfortably outlast the
		// 80ms idle timeout below so the abort wins the race against chunk 2.
		time.Sleep(400 * time.Millisecond)
		_, _ = fmt.Fprint(w, "data: {\"id\":\"2\",\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamIdleTimeout = 80 * time.Millisecond

	info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}
	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "gpt-4", "hi"), false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	body := rec.Body.String()
	assert.Contains(t, body, "upstream stream idle timeout",
		"idle abort must be reported distinctly to the client")
	assert.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"),
		"terminal [DONE] frame expected, got %q", body)
	assert.NotContains(t, body, "\"content\":\"b\"",
		"bytes after the idle abort must not reach the client")
}

// TestServeStream_LongerThanRequestTimeout: a stream that outlives the base
// YABANIN_GATEWAY_REQUEST_TIMEOUT must survive — /v1/ routes run under the
// stream_max_duration ceiling, not the JSON default. Regression for the
// "long agent streams die at 60s" defect.
func TestServeStream_LongerThanRequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 1; i <= 6; i++ {
			_, _ = fmt.Fprintf(w, "data: {\"id\":\"%d\",\"choices\":[{\"delta\":{\"content\":\"c%d\"}}]}\n\n", i, i)
			w.(http.Flusher).Flush()
			// Real-timeout pacing: the stream must keep flowing past the
			// 100ms base request timeout (6 chunks ≈ 240ms) to prove the
			// stream_max_duration ceiling governs, not the JSON default.
			time.Sleep(40 * time.Millisecond)
		}
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamIdleTimeout = 5 * time.Second // idle watchdog wide open — not under test here

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}
		gw.serveStream(w, r.Context(), info, streamBody(t, "gpt-4", "hi"), false,
			"sess", "org", "", "task", "req", testLogger(), routingDecision{}, "", 0, "", "", "", false)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", handler)
	top := httpmw.TimeoutByPrefix(100*time.Millisecond, 2*time.Second, "/v1/")(mux)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", nil)
	top.ServeHTTP(rec, req)

	body := rec.Body.String()
	for i := 1; i <= 6; i++ {
		require.Contains(t, body, fmt.Sprintf("\"content\":\"c%d\"", i),
			"chunk %d must survive the base request timeout", i)
	}
	assert.Contains(t, body, "data: [DONE]")
	assert.NotContains(t, body, "request timeout",
		"the 504 timeout body must not be injected into a live stream")
}
