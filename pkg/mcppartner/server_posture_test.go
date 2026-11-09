package mcp

// N01-P06 remainder closure — the MCP SSE listener previously carried
// ReadHeaderTimeout only. These tests pin the full deadline posture, the
// shared env header cap, and — at test scale on the REAL mcp-go SSE handler
// stack — the stdlib interaction the posture relies on: ReadTimeout bounds
// reading the request but cannot truncate a bodyless GET stream (net/http
// clears the connection read deadline once the empty body is consumed),
// while WriteTimeout=0 is what keeps SSE streams unbounded. (Empirically
// probed on go1.27.3: ReadTimeout=1s/WriteTimeout=0 delivers a 2.4s stream;
// WriteTimeout=1s truncates it at ~1s with unexpected EOF.)

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

// TestMCPSSEHTTPServerPosture pins the production constructor fields: the
// gateway deadline posture (10s header, 15s read, WriteTimeout disabled for
// SSE, 60s idle) plus the shared YABANIN_HTTP_MAX_HEADER_BYTES cap.
func TestMCPSSEHTTPServerPosture(t *testing.T) {
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "2048")
	srv, err := newMCPSSEHTTPServer("127.0.0.1:0", http.NewServeMux())
	if err != nil {
		t.Fatal(err)
	}
	if srv.MaxHeaderBytes != 2048 {
		t.Fatalf("SSE MaxHeaderBytes=%d, want 2048", srv.MaxHeaderBytes)
	}
	if srv.ReadHeaderTimeout != 10*time.Second || srv.ReadTimeout != 15*time.Second ||
		srv.IdleTimeout != 60*time.Second {
		t.Fatalf("SSE deadlines %v/%v/%v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.IdleTimeout)
	}
	if srv.WriteTimeout != 0 {
		t.Fatalf("SSE WriteTimeout=%v, want 0 (a write deadline truncates streams)", srv.WriteTimeout)
	}

	// Fail-closed construction on invalid overrides, like every listener.
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "not-a-number")
	if _, err := newMCPSSEHTTPServer("127.0.0.1:0", http.NewServeMux()); err == nil {
		t.Fatal("invalid YABANIN_HTTP_MAX_HEADER_BYTES must fail SSE server construction")
	}
}

// TestMCPMaxHeaderBytesDefault pins the unset override to the shared 1 MiB
// default.
func TestMCPMaxHeaderBytesDefault(t *testing.T) {
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "")
	got, err := mcpMaxHeaderBytes()
	if err != nil {
		t.Fatalf("default must not fail: %v", err)
	}
	if got != 1<<20 {
		t.Fatalf("default MaxHeaderBytes=%d, want %d", got, 1<<20)
	}
	for _, value := range []string{"0", "-1", "not-a-number", "16777217"} {
		t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", value)
		if _, err := mcpMaxHeaderBytes(); err == nil {
			t.Errorf("invalid override %q was accepted", value)
		}
	}
}

// sseStand wires the REAL mcp-go SSE handler exactly as ServeHTTP does (but
// on a fresh mux, and without the advertised-URL baseURL so the endpoint
// frame stays relative) and serves it with the given deadlines at test scale.
func sseStand(t *testing.T, readTimeout time.Duration) string {
	t.Helper()
	mcpServer := NewMCPHandler(NewGatewayClient("", "", "", ""))
	sseSrv := server.NewSSEServer(mcpServer, server.WithSSEDisableLocalhostProtection(true))
	mux := http.NewServeMux()
	mux.HandleFunc(sseSrv.CompleteSsePath(), sseSrv.SSEHandler().ServeHTTP)
	mux.HandleFunc(sseSrv.CompleteMessagePath(), sseSrv.MessageHandler().ServeHTTP)

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 200 * time.Millisecond,
		ReadTimeout:       readTimeout,
		WriteTimeout:      0,
		IdleTimeout:       500 * time.Millisecond,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// TestSSEStreamSurvivesReadTimeout pins the posture's load-bearing stdlib
// interaction on the real handler stack at test scale: a bodyless GET stream
// (the SSE session) stays OPEN well past ReadTimeout, the session still
// accepts POST /messages afterwards, AND a server push through the stream
// succeeds (an idle stream alone would survive a nonzero WriteTimeout — the
// deadline kills the connection only at the next write, so the push is the
// real observable). With the old constructor (ReadHeaderTimeout only) this
// test cannot fail; it fails if someone adds a nonzero WriteTimeout or if a
// future Go stops clearing the read deadline for bodyless GETs — both would
// truncate every SSE session.
func TestSSEStreamSurvivesReadTimeout(t *testing.T) {
	const readTimeout = 300 * time.Millisecond
	addr := sseStand(t, readTimeout)

	// Raw-TCP SSE GET (no client-side buffering surprises), read the
	// endpoint frame.
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "GET /sse HTTP/1.1\r\nHost: mcp.test\r\nAccept: text/event-stream\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	frame := make([]byte, 1024)
	n, err := conn.Read(frame)
	if err != nil {
		t.Fatalf("no SSE endpoint frame: %v", err)
	}
	endpointFrame := string(frame[:n])
	if !strings.Contains(endpointFrame, "event: endpoint") || !strings.Contains(endpointFrame, "sessionId=") {
		t.Fatalf("unexpected first SSE frame: %q", endpointFrame)
	}
	// The status line must be 200 text/event-stream.
	if !strings.Contains(endpointFrame, "200") {
		t.Fatalf("SSE GET must answer 200, got %q", endpointFrame)
	}
	dataLine := ""
	for _, line := range strings.Split(endpointFrame, "\n") {
		if strings.HasPrefix(line, "data: ") {
			dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data: "))
			break
		}
	}
	if dataLine == "" {
		t.Fatalf("endpoint frame missing data line: %q", endpointFrame)
	}

	// Stay connected past ReadTimeout: the stream must NOT be closed.
	time.Sleep(readTimeout + 400*time.Millisecond)
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 64)
	_, readErr := conn.Read(buf)
	if readErr == io.EOF {
		t.Fatalf("SSE stream was closed after ReadTimeout=%v — the read deadline must not apply to the stream body", readTimeout)
	}
	// Any timeout-flavored error is GOOD (stream open, no data); a real
	// error would have surfaced above as a non-timeout failure.
	if readErr != nil && !isTimeoutErr(readErr) {
		t.Fatalf("unexpected read error on the open stream: %v", readErr)
	}

	// The session survived: POST /messages answers 202 (quick-return), and
	// the JSON-RPC request response is PUSHED through the SSE stream — the
	// push is the write-path proof (WriteTimeout=0 lets it through no matter
	// how long the session has been open). The endpoint frame data is the
	// relative message path with the session id (no baseURL advertised in
	// this stand).
	postURL := dataLine
	if !strings.HasPrefix(postURL, "/") {
		postURL = "/" + postURL
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+addr+postURL,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST /messages after ReadTimeout failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /messages after ReadTimeout = %d, want 202 (session must survive)", resp.StatusCode)
	}

	// The pushed ping response must arrive on the still-open stream.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var pushed strings.Builder
	pushBuf := make([]byte, 512)
	for {
		m, rerr := conn.Read(pushBuf)
		if rerr != nil {
			t.Fatalf("SSE stream truncated after %v open (read %q): %v — a deadline killed the push", readTimeout, pushed.String(), rerr)
		}
		pushed.Write(pushBuf[:m])
		if strings.Contains(pushed.String(), "event: message") && strings.Contains(pushed.String(), `"id":1`) {
			break
		}
		if pushed.Len() > 8192 {
			t.Fatalf("no ping response on the SSE stream: %q", pushed.String())
		}
	}
}

func isTimeoutErr(err error) bool {
	type timeout interface{ Timeout() bool }
	if t, ok := err.(timeout); ok {
		return t.Timeout()
	}
	if t, ok := err.(*net.OpError); ok {
		return t.Timeout()
	}
	return strings.Contains(err.Error(), "i/o timeout")
}
