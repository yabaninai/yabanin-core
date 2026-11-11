package httpmw

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTimeout_RecoversFromHandlerPanic(t *testing.T) {
	panicked := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("scan nil dest")
	})
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := Timeout(time.Second)(panicked)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/api-keys", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 after panic, got %d", rec.Code)
	}

	handler = Timeout(time.Second)(ok)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected process to keep serving after panic, got %d", rec.Code)
	}
}

func TestTimeout_SucceedsBeforeDeadline(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := Timeout(500 * time.Millisecond)(next)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestTimeout_Returns504OnExceed(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	handler := Timeout(50 * time.Millisecond)(next)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("expected 504, got %d", rec.Code)
	}

	body := strings.TrimSpace(rec.Body.String())
	if body != `{"error":"request timeout"}` {
		t.Errorf("unexpected body: %s", body)
	}

	if retryAfter := rec.Header().Get("Retry-After"); retryAfter != "1" {
		t.Errorf("expected Retry-After=1, got %q", retryAfter)
	}
}

func TestTimeout_ConceleContextWhenDone(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		w.WriteHeader(http.StatusOK)
	})
	handler := Timeout(5 * time.Second)(next)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Context was cancelled — good
	case <-time.After(2 * time.Second):
		t.Fatal("context was not cancelled after handler completed")
	}
}

func TestTimeout_StoresDurationInContext(t *testing.T) {
	var storedTime time.Duration
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.Context().Value(TimeoutKey)
		if val == nil {
			t.Fatal("expected timeout duration in context")
		}
		storedTime = val.(time.Duration)
		w.WriteHeader(http.StatusOK)
	})
	handler := Timeout(42 * time.Second)(next)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if storedTime != 42*time.Second {
		t.Errorf("expected %v in context, got %v", 42*time.Second, storedTime)
	}
}

func TestWithTimeout_CustomTimeout(t *testing.T) {
	handler := WithTimeout(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, 500*time.Millisecond)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestWithTimeout_HonorsContextCancellation(t *testing.T) {
	handler := WithTimeout(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		// WithTimeout doesn't auto-return 504 (designed for streaming endpoints).
		// The handler itself should check ctx. Here we verify the context deadline was reached.
		select {
		case <-r.Context().Done():
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		default:
		}
		w.WriteHeader(http.StatusOK)
	}, 50*time.Millisecond)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("expected 504, got %d", rec.Code)
	}
}

func TestTimeout_ChainPreservesContext(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("expected deadline in chained context")
		}
		_ = time.Until(deadline)
		w.WriteHeader(http.StatusOK)
	})
	handler := Timeout(1 * time.Second)(next)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// TestTimeout_PreservesFlusherContract: the timeout middleware's writer must
// keep the http.Flusher contract so streaming (SSE) handlers can flush through
// it. Regression: without Flush() on timeoutWriter, serveStream's
// `w.(http.Flusher)` assertion failed and every streaming request 501'd.
func TestTimeout_PreservesFlusherContract(t *testing.T) {
	var flushed int32
	rec := &flushingRecorder{flushed: &flushed}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("middleware writer does not implement http.Flusher (streaming would 501)")
		}
		if _, err := w.Write([]byte("data: chunk1\n\n")); err != nil {
			t.Fatalf("write chunk1: %v", err)
		}
		f.Flush()
		if _, err := w.Write([]byte("data: [DONE]\n\n")); err != nil {
			t.Fatalf("write [DONE]: %v", err)
		}
		f.Flush()
	})
	handler := Timeout(2 * time.Second)(next)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	if rec.body.Len() == 0 {
		t.Errorf("no body written: %q", rec.body.String())
	}
	if flushed != 2 {
		t.Errorf("flushes = %d, want 2 (Flush must forward to the underlying writer)", flushed)
	}
}

// flushingRecorder is an http.ResponseWriter + http.Flusher test double.
type flushingRecorder struct {
	body    strings.Builder
	flushed *int32
}

func (r *flushingRecorder) Header() http.Header         { return http.Header{} }
func (r *flushingRecorder) Write(p []byte) (int, error) { return r.body.Write(p) }
func (r *flushingRecorder) WriteHeader(int)             {}
func (r *flushingRecorder) Flush()                      { *r.flushed = *r.flushed + 1 }

// TestTimeout_StartedStreamIsNotCorrupted: once the handler has started the
// response (SSE stream), a deadline overrun must NOT inject a 504 body into
// the middle of the stream, and the handler's late writes must fail with
// http.ErrHandlerTimeout instead of racing on the ResponseWriter.
func TestTimeout_StartedStreamIsNotCorrupted(t *testing.T) {
	lateWriteErr := make(chan error, 1)
	handlerDone := make(chan struct{})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("data: chunk1\n\n")); err != nil {
			t.Errorf("write chunk1: %v", err)
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(80 * time.Millisecond) // past the 30ms deadline
		_, err := w.Write([]byte("data: chunk2\n\n"))
		lateWriteErr <- err
		close(handlerDone)
	})
	handler := Timeout(30 * time.Millisecond)(next)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Wait for the handler goroutine so reads of rec below are race-free.
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handler goroutine did not finish")
	}
	select {
	case err := <-lateWriteErr:
		if !errors.Is(err, http.ErrHandlerTimeout) {
			t.Fatalf("late write: want http.ErrHandlerTimeout, got %v", err)
		}
	default:
		t.Fatal("late write did not report an error")
	}

	body := rec.Body.String()
	if !strings.Contains(body, "data: chunk1") {
		t.Errorf("started stream lost its first chunk: %q", body)
	}
	if strings.Contains(body, "request timeout") {
		t.Errorf("504 body injected into a started stream: %q", body)
	}
	if strings.Contains(body, "data: chunk2") {
		t.Errorf("late write reached the client after timeout: %q", body)
	}
}

// TestTimeout_LateWriteAfterTimeoutIsRejected: when the deadline fires
// before any byte was written, the client gets 504 (+Retry-After), and the
// handler's late writes are rejected with http.ErrHandlerTimeout without
// touching the already-finished response.
func TestTimeout_LateWriteAfterTimeoutIsRejected(t *testing.T) {
	lateWriteErr := make(chan error, 1)
	handlerDone := make(chan struct{})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond) // past the 30ms deadline, nothing written
		_, err := w.Write([]byte("data: late\n\n"))
		lateWriteErr <- err
		close(handlerDone)
	})
	handler := Timeout(30 * time.Millisecond)(next)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected 504, got %d", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"error":"request timeout"}` {
		t.Fatalf("unexpected body: %s", body)
	}
	if retryAfter := rec.Header().Get("Retry-After"); retryAfter != "1" {
		t.Fatalf("expected Retry-After=1, got %q", retryAfter)
	}

	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handler goroutine did not finish")
	}
	select {
	case err := <-lateWriteErr:
		if !errors.Is(err, http.ErrHandlerTimeout) {
			t.Fatalf("late write: want http.ErrHandlerTimeout, got %v", err)
		}
	default:
		t.Fatal("late write did not report an error")
	}
	if strings.Contains(rec.Body.String(), "data: late") {
		t.Fatalf("late write reached the client: %q", rec.Body.String())
	}
}

// TestTimeoutByPrefix_OverrideForV1: routes under the prefixes get the
// override deadline (long-lived SSE streams), every other route keeps the
// base deadline.
func TestTimeoutByPrefix_OverrideForV1(t *testing.T) {
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond) // > base deadline, < override
		w.WriteHeader(http.StatusOK)
	})
	mw := TimeoutByPrefix(50*time.Millisecond, time.Second, "/v1/")

	rec := httptest.NewRecorder()
	mw(slow).ServeHTTP(rec,
		httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/: expected 200 under stream override, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	mw(slow).ServeHTTP(rec,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("/healthz: expected 504 under base timeout, got %d", rec.Code)
	}
}

// TestTimeout_ClientCancelLatchesWriter pins the client-cancel branch of
// timeoutHandler: when the REQUEST context is canceled (client gone, not the
// deadline), the middleware returns without writing anything, but latches
// the writer so the still-running handler goroutine's late writes are
// rejected with ErrHandlerTimeout instead of racing conn teardown on the
// real ResponseWriter (data race exposed by the audio cancel wire
// test; fixed 2026-10-13). Covers both late Write and late WriteHeader.
//
// Wakeup race and why this test WAITS for the latch instead of assuming it:
// cancelParent() wakes two goroutines at once with no happens-before edge
// between them — the middleware's select goroutine (latches tw.timedOut
// under tw.mu, cancel branch of timeoutHandler) and this handler goroutine
// (late Write). If the handler wins the mutex, the write is still
// structurally SAFE in production: it completes under tw.mu strictly before
// the middleware's latch (mutex handoff), which precedes the middleware's
// ServeHTTP return, which precedes any server-side response teardown — and
// the cancel branch itself never writes the real writer, so there is no
// write-write race either. Both interleavings are correct production
// behavior; only the test's old assumption "latch observed by the time the
// late write happens" was racy (fleet flake «late Write ... got <nil>»).
// The test is therefore deterministic by construction: before the late
// writes, it polls tw.timedOut under tw.mu (same-package white-box) until
// the latch is OBSERVED, bounded by a deadline so a latch regression fails
// visibly instead of hanging. After the latch, ErrHandlerTimeout rejection
// is the only legal outcome — the assertions keep their teeth.
func TestTimeout_ClientCancelLatchesWriter(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	r := httptest.NewRequestWithContext(parent, http.MethodPost, "/v1/chat/completions", nil)

	late := make(chan error, 2)
	inner := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		<-req.Context().Done() // client gone → Canceled, not DeadlineExceeded

		// Determinism point: wait until the middleware's cancel branch has
		// actually latched the writer before attempting the late writes (see
		// the doc comment above). A failure here is a middleware regression
		// (cancel branch stopped latching) — reported and the late writes
		// still run, so the rejection assertions below fail loudly rather
		// than deadlocking on the channels.
		tw, ok := w.(*timeoutWriter)
		if !ok {
			t.Errorf("middleware writer is %T, want *timeoutWriter", w)
		} else if !awaitTimeoutLatch(t, tw, 5*time.Second) {
			t.Error("timeoutWriter.timedOut was never latched after client cancel (cancel-branch regression)")
		}
		_, err := w.Write([]byte("late body"))
		late <- err
		w.WriteHeader(http.StatusInternalServerError)
		late <- nil // WriteHeader does not report an error; arrival is the signal
	})

	rec := httptest.NewRecorder()
	h := TimeoutByPrefix(time.Hour, time.Hour)(inner)
	served := make(chan struct{})
	go func() {
		defer close(served)
		h.ServeHTTP(rec, r)
	}()

	cancelParent()
	if err := <-late; !errors.Is(err, http.ErrHandlerTimeout) {
		t.Fatalf("late Write after client cancel must be rejected with ErrHandlerTimeout, got %v", err)
	}
	if err := <-late; err != nil { // WriteHeader arrival signal; nil by contract
		t.Errorf("WriteHeader signal must be nil, got %v", err)
	}
	<-served

	if rec.Body.Len() != 0 {
		t.Fatalf("real writer must stay untouched on client cancel, got %q", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("no header may reach the real writer after cancel, got code %d", rec.Code)
	}
}

// awaitTimeoutLatch blocks until tw.timedOut is observed true under tw.mu, or
// until the given wait budget is exhausted. Polling under the writer's own
// mutex is race-free and gives the middleware's cancel branch time to win
// its wakeup race with the handler goroutine. Bounded by design: a latch
// regression must surface as a fast, visible test failure — never a hang.
func awaitTimeoutLatch(t *testing.T, tw *timeoutWriter, wait time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(wait)
	for {
		tw.mu.Lock()
		latched := tw.timedOut
		tw.mu.Unlock()
		if latched {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(200 * time.Microsecond)
	}
}
