package httpmw

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// timeoutKey is the unexported type used for context values.
type timeoutKey struct{}

// TimeoutKey is the key under which the timeout duration is stored in the request context.
var TimeoutKey timeoutKey

// timeoutWriter wraps http.ResponseWriter with a mutex to prevent concurrent writes
// between the handler goroutine and the timeout detection goroutine.
//
// Once the deadline fires, timedOut is set and every handler write is
// rejected with http.ErrHandlerTimeout: net/http allows writes only until
// ServeHTTP returns, and the middleware returns as soon as the timeout
// response (if any) has been written. Rejecting late writes — instead of
// forwarding them — keeps the still-running handler goroutine from racing
// on, or corrupting, the already-finished response.
type timeoutWriter struct {
	mu          sync.Mutex
	w           http.ResponseWriter
	hijack      func() (net.Conn, *bufio.ReadWriter, error)
	timedOut    bool
	wroteHeader bool
}

func (tw *timeoutWriter) Header() http.Header { return tw.w.Header() }

func (tw *timeoutWriter) Write(p []byte) (int, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.timedOut {
		return 0, http.ErrHandlerTimeout
	}
	tw.wroteHeader = true // Write implies an implicit WriteHeader(200)
	return tw.w.Write(p)
}

func (tw *timeoutWriter) WriteHeader(statusCode int) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.timedOut {
		return
	}
	tw.wroteHeader = true
	tw.w.WriteHeader(statusCode)
}

// Flush forwards to the underlying writer when it supports it, so streaming
// (SSE) endpoints keep their http.Flusher contract through this middleware.
// Without this, serveStream's `w.(http.Flusher)` assertion fails and every
// streaming request 501s.
func (tw *timeoutWriter) Flush() {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.timedOut {
		return
	}
	if f, ok := tw.w.(http.Flusher); ok {
		f.Flush()
	}
}

func (tw *timeoutWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if tw.hijack != nil {
		return tw.hijack()
	}
	return nil, nil, errors.New("hijacking not supported")
}

// Timeout returns middleware that enforces a per-request timeout.
//
// Behavior:
//   - Wraps r.Context() with context.WithTimeout(timeout).
//   - On timeout before the response has started: writes a 504 Gateway
//     Timeout response with JSON body and Retry-After header. If the handler
//     already started the response (SSE stream), no byte is injected — the
//     late handler writes are rejected with http.ErrHandlerTimeout instead.
//   - Cancels the derived context when the handler completes (success or error).
//   - Stores the timeout duration in the request context under TimeoutKey for downstream
//     handlers to inspect.
//
// Usage:
//
//	r.Use(httpmw.Timeout(30 * time.Second)) // global 30s timeout
//	r.Get("/stream", httpmw.WithTimeout(handler, 5*time.Minute).ServeHTTP) // override
func Timeout(timeout time.Duration) func(http.Handler) http.Handler {
	return timeoutHandler(timeout)
}

// TimeoutByPrefix returns timeout middleware with a per-route duration:
// requests whose path starts with any of the prefixes get the override
// deadline, everything else keeps the base one. Streaming endpoints (/v1/
// SSE proxying) need a far longer ceiling than JSON endpoints while still
// sharing the rest of the middleware stack.
func TimeoutByPrefix(base, override time.Duration, prefixes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		baseH := timeoutHandler(base)(next)
		overrideH := timeoutHandler(override)(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, p := range prefixes {
				if strings.HasPrefix(r.URL.Path, p) {
					overrideH.ServeHTTP(w, r)
					return
				}
			}
			baseH.ServeHTTP(w, r)
		})
	}
}

// timeoutHandler is the Timeout middleware core for one fixed duration.
func timeoutHandler(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			r = r.Clone(ctx)
			r = r.WithContext(context.WithValue(ctx, TimeoutKey, timeout))

			tw := &timeoutWriter{w: w}
			if hj, ok := w.(http.Hijacker); ok {
				tw.hijack = hj.Hijack
			}

			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if rec := recover(); rec != nil {
						slog.Error("http handler panic", "panic", rec)
						tw.mu.Lock()
						defer tw.mu.Unlock()
						if tw.timedOut || tw.wroteHeader {
							// The response is already gone (timeout) or
							// started (mid-stream) — writing a 500 here would
							// corrupt it; the panic is logged, nothing more.
							return
						}
						tw.wroteHeader = true
						http.Error(tw.w, `{"error":"internal server error"}`, http.StatusInternalServerError)
					}
				}()
				next.ServeHTTP(tw, r)
			}()

			select {
			case <-ctx.Done():
				tw.mu.Lock()
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					tw.timedOut = true
					if !tw.wroteHeader {
						tw.wroteHeader = true
						tw.w.Header().Set("Retry-After", "1")
						http.Error(tw.w, `{"error":"request timeout"}`, http.StatusGatewayTimeout)
					}
					tw.mu.Unlock()
					// Return without waiting for the handler goroutine: it
					// may be blocked on a stuck upstream; every write it
					// attempts from now on is rejected above.
				} else {
					// Client cancel: the response will never be read, but
					// the handler goroutine may still be running — latch the
					// writer so its late writes are rejected here instead of
					// racing conn teardown on the real ResponseWriter (data
					// Race exposed by the audio cancel wire test
					// under -race). Same no-wait rationale as above.
					tw.timedOut = true
					tw.mu.Unlock()
				}
			case <-done:
				// Handler completed normally — nothing to do
			}
		})
	}
}

// WithTimeout wraps a single handler with a custom timeout. Useful for routes
// that need a different timeout than the global default (e.g., streaming endpoints).
func WithTimeout(next http.HandlerFunc, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		r = r.Clone(ctx)
		r = r.WithContext(context.WithValue(ctx, TimeoutKey, timeout))

		next(w, r)
	}
}
