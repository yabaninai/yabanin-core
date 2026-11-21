package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	const (
		window     = 100 * time.Millisecond
		tick       = 25 * time.Millisecond
		totalBytes = 12 // ≈300ms of flow, well past the first window
		// A fire is legitimate only when the reader goroutine was actually
		// descheduled past the window AHEAD OF THAT FIRE (runner load can
		// do that). Every fire is accounted individually against the gap
		// between its own instant and the previous beat; a fire amid
		// healthy ~25ms ticks means the reset contract broke — the
		// regression behind CI run 44814334185, which fired while beat
		// gaps stayed at ~25ms. One global max-gap pass would excuse such
		// a fire via an unrelated later deschedule, so none is taken.
		fireGapThreshold = window - 20*time.Millisecond
	)

	fired := make(chan struct{})
	callbackDone := make(chan struct{})
	tr := &tickReader{remaining: totalBytes, interval: tick}
	var (
		mu      sync.Mutex
		anchor  = time.Now() // arming instant
		beats   []time.Time  // post-read timestamps
		fireLog []time.Time
	)
	ir := newIdleReader(tr, window, func() {
		mu.Lock()
		fireLog = append(fireLog, time.Now())
		mu.Unlock()
		// Fired() flips before this body runs, so callbackDone is the join
		// point that proves the body completed — an empty fireLog alone
		// proves nothing about an in-flight callback (invisible to the
		// race detector).
		close(callbackDone)
		// Deliberately not sync.Once-guarded: a second callback run must
		// panic here (close of closed channel) exactly like it panicked the
		// CI binary — pins the double-close defect.
		close(fired)
	})
	defer ir.Stop()

	idleDrainTotal(t, ir, totalBytes, func() {
		mu.Lock()
		beats = append(beats, time.Now())
		mu.Unlock()
	})

	// Observation ends at the final read: no fire can start after Stop
	// runs, and an already-dispatched callback is joined before its log is
	// inspected.
	if !ir.Fired() {
		mu.Lock()
		defer mu.Unlock()
		if len(fireLog) != 0 {
			t.Fatalf("fireLog populated without Fired(): %v", fireLog)
		}
		return // healthy flow: the watchdog never fired
	}
	select {
	case <-callbackDone:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog fired but the callback body never completed")
	}
	mu.Lock()
	defer mu.Unlock()
	justifyIdleFires(t, anchor, beats, fireLog, fireGapThreshold)
}

// idleDrainTotal reads totalBytes through ir on a background goroutine,
// invoking onBeat after every delivered byte, and fails the test if the
// drain stalls or comes up short.
func idleDrainTotal(t *testing.T, ir io.Reader, totalBytes int, onBeat func()) {
	t.Helper()
	done := make(chan int, 1)
	go func() {
		var total int
		buf := make([]byte, 4)
		for total < totalBytes {
			n, err := ir.Read(buf)
			total += n
			if n > 0 {
				onBeat()
			}
			if err != nil {
				break
			}
		}
		done <- total
	}()
	var total int
	select {
	case total = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reader stalled")
	}
	if total != totalBytes {
		t.Fatalf("read %d bytes, want %d", total, totalBytes)
	}
}

// justifyIdleFires accounts every recorded fire against the beats that
// preceded it: the gap between a fire and the previous beat (or the arming
// anchor) must have crossed the idle-window threshold, or the watchdog
// fired while data still flowed within the window — the reset contract
// broke, no matter what unrelated gaps the rest of the run contained.
func justifyIdleFires(t *testing.T, anchor time.Time, beats, fireLog []time.Time, threshold time.Duration) {
	t.Helper()
	for _, fire := range fireLog {
		prev := anchor
		for _, beat := range beats {
			if !beat.Before(fire) {
				break
			}
			prev = beat
		}
		gap := fire.Sub(prev)
		if gap >= threshold {
			continue
		}
		t.Fatalf("idle watchdog fired amid healthy reads: fire %v, previous beat %v (anchor %v), gap %v < %v; beats %v, fires %v",
			fire, prev, anchor, gap, threshold, beats, fireLog)
	}
}

// TestIdleReader_CallbackDeliveredExactlyOnce pins the CI run 44814334185
// double-delivery defect deterministically. The reader holds still past the
// first window — a guaranteed fire — then keeps flowing SLOWER than the
// window: every post-fire read attempts a deadline reset, and because the
// next read is always a full window away, each attempt leaves an un-reset
// stretch that a guard-less build turns into a second callback delivery.
// With both production guards intact (the fired CAS in the callback path
// and the Read-side re-arm suppression) exactly one delivery is possible,
// whatever the runner load does to the timing.
func TestIdleReader_CallbackDeliveredExactlyOnce(t *testing.T) {
	const (
		window   = 40 * time.Millisecond
		tick     = 50 * time.Millisecond // post-fire ticks slower than the window
		holdFor  = 2 * window            // silence across the first window: the fire
		postFire = 3
	)

	deliveries := make(chan struct{}, 10)
	tr := &silentThenFlowReader{holdFor: holdFor, tick: tick, remaining: postFire + 1}
	ir := newIdleReader(tr, window, func() {
		// Buffered: a runaway duplicate delivery must not wedge the
		// watchdog goroutine before the count is asserted.
		deliveries <- struct{}{}
	})
	defer ir.Stop()

	idleDrainTotal(t, ir, postFire+1, func() {})
	if !ir.Fired() {
		t.Fatal("watchdog did not fire during the deliberate silence")
	}
	// The one legitimate delivery, joined before counting.
	select {
	case <-deliveries:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog fired but the callback was never delivered")
	}
	// With the guard intact no second dispatch can exist at all; a
	// guard-less build delivers again within one window of the last
	// post-fire read, so a 2×window straggler bound surfaces it even under
	// timer-goroutine delay.
	select {
	case <-deliveries:
		t.Fatal("idle callback delivered more than once (CI run 44814334185 double-delivery regression)")
	case <-time.After(2 * window):
	}
}

// silentThenFlowReader holds still across one full idle window (the
// deliberate fire), then emits one byte per tick — replaying the CI run
// 44814334185 shape: a legitimate fire followed by a stream that keeps
// flowing well past the original deadline.
type silentThenFlowReader struct {
	holdFor   time.Duration
	tick      time.Duration
	remaining int
	started   bool
}

func (r *silentThenFlowReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if !r.started {
		r.started = true
		time.Sleep(r.holdFor)
	} else {
		time.Sleep(r.tick)
	}
	p[0] = 'x'
	r.remaining--
	return 1, nil
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
