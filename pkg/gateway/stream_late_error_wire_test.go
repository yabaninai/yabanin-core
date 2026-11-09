package cli

// N03-P01-T05 (review F1, deliverables 1 and 3b): the remaining late-error
// flavour and the real-transport boundary.
//
//   - TestServeStream_UpstreamDisconnectAfterDoneNoSecondTerminal covers the
//     read-error flavour the idle test (T02) and the cancel test (T04) do
//     not: the upstream transport dies (connection reset mid-chunked-body)
//     AFTER the [DONE] terminator was relayed, with the idle watchdog
//     disabled. The wire must end at the first [DONE]; the failure stays a
//     single request.failed analytics event.//
//   - TestWireStreamClientTCPCloseMidStreamSingleFailedEvent pins the
//     mid-stream client hang-up on a real TCP connection served through the
//     production server factory (newGatewayHTTPServer): the upstream is
//     drained, exactly one analytics event records the death, and the server
//     keeps serving.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// TestServeStream_UpstreamDisconnectAfterDoneNoSecondTerminal: the upstream
// hijacks its raw connection and answers with a complete SSE payload —
// content frame plus [DONE] — inside one chunked-body chunk, then closes the
// connection WITHOUT the terminating 0-chunk. The relay is parked in its
// next fill after relaying [DONE] and gets io.ErrUnexpectedEOF: a drain
// failure that lands after clientSawDone, with the idle watchdog disabled
// (streamIdleTimeout 0) and no client cancel involved. The finisher must
// keep the wire silent — no error frame, no second [DONE] — and record the
// failure as exactly one request.failed event.
func TestServeStream_UpstreamDisconnectAfterDoneNoSecondTerminal(t *testing.T) {
	var (
		mu     sync.Mutex
		events []*eventpub.Event
	)
	restore := observeEvent(func(e *eventpub.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	defer restore()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		payload := chunkFrame("1", "a") + "data: [DONE]\n\n"
		// Raw chunked framing: one data chunk carrying the whole SSE
		// payload, then the connection dies before the terminal 0-chunk.
		// A short dwell lets the relay park in its next fill first; the
		// close itself is what produces the read error.
		_, _ = fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/event-stream\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: close\r\n"+
			"\r\n%x\r\n%s\r\n", len(payload), payload)
		_ = rw.Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(150 * time.Millisecond):
		}
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamIdleTimeout = 0 // production-optional config: no idle watchdog

	rec := httptest.NewRecorder()
	info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}
	gw.serveStream(rec, context.Background(), info, streamBody(t, "gpt-4", "hi"), false,
		"sess", "org", "", "task", "req", testLogger(), routingDecision{},
		"", 0, "", "", "", false)

	// The wire ends exactly at the first [DONE]: nothing may follow it.
	want := chunkFrame("1", "a") + "data: [DONE]\n\n"
	require.Equal(t, want, rec.Body.String(),
		"the body must be byte-identical to what the upstream sent — the late disconnect must add nothing")
	assertSingleTerminal(t, rec.Body.String(), false)

	// The failure really happened and stayed off the wire: one analytics
	// event carries the drain read error. (Termination classification is
	// stamped only under an active reservation gate — reservation_gate_test
	// pins that attach contract — so a gateless harness asserts the
	// gate-independent fields.)
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 1, "exactly one analytics event for the failed stream, got %d", len(events))
	ev := events[0]
	require.Equal(t, "request.failed", ev.EventType)
	require.Contains(t, ev.Error, "stream read failed",
		"the recorded error must be the drain read failure the client never saw, got %q", ev.Error)
}

// wireStreamRequest renders one raw HTTP/1.1 stream request with an exact
// Content-Length (the raw client never uses chunked uploads here).
func wireStreamRequest(t *testing.T) []byte {
	t.Helper()
	body := string(streamBody(t, "gpt-4", "hi"))
	return []byte(fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\n"+
		"Host: wire\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n%s", len(body), body))
}

// TestWireStreamClientTCPCloseMidStreamSingleFailedEvent: a client opens a
// real TCP connection through the production server factory, reads two
// complete SSE frames of a paced stream, then hangs up mid-stream (unread
// buffered bytes make Close send an RST). The contract:
//
//  1. the upstream is drained — its paced handler observes the disconnect;
//  2. exactly ONE analytics event records the killed request as
//     request.failed (the write error and the context cancel race for the
//     drain-failure classification; the event count is the wire contract);
//  3. the server stays healthy: a fresh connection streams a full request
//     to completion, producing exactly one request.completed event.
func TestWireStreamClientTCPCloseMidStreamSingleFailedEvent(t *testing.T) {
	var (
		mu     sync.Mutex
		events []*eventpub.Event
	)
	restore := observeEvent(func(e *eventpub.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	defer restore()

	// upstreamReturned fires when the FIRST upstream handler returns — the
	// killed request's. The follow-up request also runs this handler, so the
	// close must be idempotent (a second close would panic inside the
	// handler and abort the follow-up's upstream response mid-body).
	upstreamReturned := make(chan struct{})
	var closeUpstreamReturned sync.Once
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer closeUpstreamReturned.Do(func() { close(upstreamReturned) })
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < 400; i++ { // ~8s paced; the hang-up ends it far earlier
			if _, err := fmt.Fprint(w, chunkFrame("1", fmt.Sprintf("chunk-%d", i))); err != nil {
				return
			}
			flusher.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
		// A real OpenAI-compatible upstream terminates its SSE body with
		// [DONE]; the gateway relays it rather than fabricating one.
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer up.Close()

	gw := streamTestGateway(up.URL)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}
		gw.serveStream(w, r.Context(), info, body, false,
			"sess", "org", "", "task", "req", testLogger(), routingDecision{},
			"", 0, "", "", "", false)
	})

	// The production server factory: the same tuning the real gateway
	// serves with (no WriteTimeout — streams must never be truncated).
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	front, err := newGatewayHTTPServer(ln.Addr().String(), mux)
	require.NoError(t, err)
	go func() { _ = front.Serve(ln) }()
	t.Cleanup(func() { _ = front.Close() })

	killConn := func() {
		d := &net.Dialer{Timeout: 2 * time.Second}
		conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		_, err = conn.Write(wireStreamRequest(t))
		require.NoError(t, err)

		// Read until two complete SSE frames arrived, then hang up with
		// the connection mid-stream.
		buf := make([]byte, 16<<10)
		var got []byte
		for strings.Count(string(got), "\n\n") < 2 {
			n, rerr := conn.Read(buf)
			got = append(got, buf[:n]...)
			if rerr != nil {
				break
			}
		}
		require.GreaterOrEqual(t, strings.Count(string(got), "\n\n"), 2,
			"at least two complete frames must arrive before the hang-up, got:\n%s", got)
		// Unread bytes in the kernel buffer force an RST on Close — the
		// server's next write fails outright instead of draining cleanly.
	}
	killConn()

	// (1) The upstream felt the hang-up: its paced handler returned.
	select {
	case <-upstreamReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream handler did not observe the client disconnect within 5s — the gateway never closed the stream")
	}

	// (2) Exactly one event for the killed request, classified as failed.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(events) >= 1
	}, 5*time.Second, 10*time.Millisecond, "the killed request must publish its event")
	mu.Lock()
	first := events[0]
	mu.Unlock()
	require.Equal(t, "request.failed", first.EventType)
	// Termination is stamped only under an active reservation gate
	// (reservation_gate_test pins that attach contract); this gateless wire
	// harness pins the event count and class instead.

	// (3) The server stays healthy: a fresh connection streams a full
	// request to completion, and the event ledger holds exactly one failed
	// plus one completed event — no double-publish for the killed request.
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(context.Background(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Write(wireStreamRequest(t))
	require.NoError(t, err)

	buf := make([]byte, 16<<10)
	var out []byte
	for {
		n, rerr := conn.Read(buf)
		out = append(out, buf[:n]...)
		if rerr != nil {
			break // EOF: the server closes after answering a Connection: close request
		}
	}
	// De-chunk exactly like a real HTTP client: the raw socket body carries
	// chunked transfer framing around the SSE payload.
	raw := string(out)
	head, wire, ok := strings.Cut(raw, "\r\n\r\n")
	require.True(t, ok, "response must contain a header block, got:\n%s", raw)
	require.Contains(t, head, "200")
	require.True(t, strings.HasSuffix(wire, "0\r\n\r\n"),
		"the chunked response must be complete, got tail:\n%q", wire[max(0, len(wire)-64):])
	dechunked, err := io.ReadAll(httputil.NewChunkedReader(strings.NewReader(wire)))
	require.NoError(t, err)
	full := string(dechunked)
	require.Contains(t, full, "data: [DONE]", "the healthy follow-up must complete, got:\n%s", full)
	assertSingleTerminal(t, full, false)

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(events) >= 2
	}, 5*time.Second, 10*time.Millisecond, "the follow-up request must publish its completion event")
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 2,
		"exactly one failed event for the killed request and one completed for the follow-up, got %d", len(events))
	require.Equal(t, "request.completed", events[1].EventType)
}
