package httpmw

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// hammerLateHeaders mutates the (possibly still exposed) response header map
// after the middleware has latched, mirroring a handler that ignores its
// canceled context and keeps decorating the response — the exact pattern of
// the live concurrent-map fatal in the admin server.
func hammerLateHeaders(w http.ResponseWriter) {
	for i := 0; i < 400; i++ {
		w.Header().Set("X-Late", strconv.Itoa(i))
		runtime.Gosched()
	}
}

// TestTimeout_LateHeaderMutationAfterDeadlineIsIsolated covers the deadline
// branch: the middleware writes the 504 and returns without waiting for the
// handler goroutine. A late handler must never mutate the real response
// header map that net/http clones while finishing the response; its late
// headers must stay isolated from the 504 the client received.
func TestTimeout_LateHeaderMutationAfterDeadlineIsIsolated(t *testing.T) {
	h := Timeout(20 * time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		hammerLateHeaders(w)
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatalf("504 must keep the Retry-After header")
	}
	if got := resp.Header.Get("X-Late"); got != "" {
		t.Fatalf("late handler header leaked into the 504: %q", got)
	}
	time.Sleep(50 * time.Millisecond) // keep the late hammer overlapping the server finish path
}

// TestTimeout_LateHeaderMutationAfterClientCancelIsIsolated reproduces the
// live crash window: the client cancels, the client-cancel branch returns
// without writing a header, and net/http's finishRequest clones the real
// header map (default 200) while the still-running handler mutates it.
func TestTimeout_LateHeaderMutationAfterClientCancelIsIsolated(t *testing.T) {
	h := Timeout(30 * time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		hammerLateHeaders(w)
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := srv.Client().Do(req) // expected to fail once the client ctx is canceled
		if err == nil {
			resp.Body.Close()
		}
	}()
	time.Sleep(30 * time.Millisecond) // let the handler park on its context
	cancel()
	<-done
	time.Sleep(50 * time.Millisecond)
}

// TestTimeout_PublishesHandlerHeadersOnNormalResponse guards the positive
// contract of the writer-owned header map: headers set before the first
// write must reach the client on a normal (non-timeout) response.
func TestTimeout_PublishesHandlerHeadersOnNormalResponse(t *testing.T) {
	h := Timeout(5 * time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "yes")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Custom"); got != "yes" {
		t.Fatalf("X-Custom = %q, want yes", got)
	}
}

// TestTimeout_AnnouncedTrailerSetAfterFirstWriteSurvives guards the post-start
// trailer contract (request_export sets X-Export-Error after streaming began):
// the done-branch rescue must carry announced trailer values to the wire.
func TestTimeout_AnnouncedTrailerSetAfterFirstWriteSurvives(t *testing.T) {
	h := Timeout(5 * time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Trailer", "X-Export-Error")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("row1\n"))
		w.Header().Set("X-Export-Error", "row_limit")
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Trailer.Get("X-Export-Error"); got != "row_limit" {
		t.Fatalf("trailer X-Export-Error = %q, want row_limit (declared: %q, header: %q)", got, resp.Trailer, resp.Header.Get("Trailer"))
	}
}

// TestTimeout_HeaderBeforeFlushReachesTheWire guards the stream contract:
// headers set before the first Flush must be snapshotted together with the
// response start, not attached after the flush already committed it.
func TestTimeout_HeaderBeforeFlushReachesTheWire(t *testing.T) {
	h := Timeout(5 * time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Pre-Flush", "yes")
		w.(http.Flusher).Flush()
		w.Write([]byte("chunk"))
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "chunk" {
		t.Fatalf("body = %q, want chunk", body)
	}
	if got := resp.Header.Get("X-Pre-Flush"); got != "yes" {
		t.Fatalf("X-Pre-Flush = %q, want yes", got)
	}
}

// TestTimeout_TrailerWithStreamedFlushKeepsCompatibility covers the SSE-like
// pattern: a trailer declared before the first flush, a header set right
// before it, and a trailer value assigned after streaming began — everything
// must survive the flush-committed response start.
func TestTimeout_TrailerWithStreamedFlushKeepsCompatibility(t *testing.T) {
	h := Timeout(5 * time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Trailer", "X-Stream-Error")
		f := w.(http.Flusher)
		w.Header().Set("X-Stream-State", "open")
		f.Flush()
		w.Write([]byte("ev1\n"))
		f.Flush()
		w.Header().Set("X-Stream-Error", "upstream_reset")
		w.Write([]byte("ev2\n"))
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if got := resp.Header.Get("X-Stream-State"); got != "open" {
		t.Fatalf("X-Stream-State = %q, want open", got)
	}
	if got := resp.Trailer.Get("X-Stream-Error"); got != "upstream_reset" {
		t.Fatalf("trailer X-Stream-Error = %q, want upstream_reset", got)
	}
}
