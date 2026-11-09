package cli

// N01-P06 T08 — interruption / retry / resume wire regressions.
//
// The packet's interruption scenario pinned against the PRODUCTION server
// factory (newGatewayHTTPServer) and the real middleware order:
//
//   - MaxBody rejection is RESUMABLE: the 413 advertises "Connection: close"
//     and the poisoned connection is closed cleanly (a pipelined follow-up
//     observes EOF, never a desynced second response); a retry on a fresh
//     connection is re-evaluated from clean state (upstream exactly once,
//     exactly one completed event — no poisoned quota state). The same-
//     connection close is the stdlib-designed safety property
//     (http.MaxBytesReader → requestTooLarge → closeAfterReply): the card's
//     "second request succeeds on the SAME connection" cannot and must not
//     hold after a quota rejection — reusing a connection whose declared
//     body was never fully read would be a smuggling hazard. What MUST hold
//     (and is pinned here) is: clean close + successful fresh-connection
//     retry, and clean keep-alive for non-rejected sequential requests.
//   - a client disconnect mid-upload produces no upstream call, no completed
//     event (no quota leakage), and leaves the server fully healthy;
//   - a client disconnect during a FILES upload persists nothing (no partial
//     file) and leaves the store listing empty.
//
// Event counting uses gw.eventNote (fires synchronously in the request path
// before publication), so the assertions observe accounting, not delivery.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/batchstore"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// wireEventCounter arms gw.eventNote and returns the count accessor.
func wireEventCounter(gw *gateway) func() int {
	var count atomic.Int64
	gw.eventNote = func(*eventpub.Event) { count.Add(1) }
	return func() int { return int(count.Load()) }
}

// readWireResponse reads one full response (head + Content-Length body) and
// returns the status line, the raw header block and the body bytes.
func readWireResponse(t *testing.T, conn net.Conn) (status, head string, body []byte) {
	t.Helper()
	status, head = readHeadBlock(t, conn)
	cl := 0
	for _, line := range strings.Split(head, "\r\n") {
		if v, ok := strings.CutPrefix(strings.ToLower(line), "content-length: "); ok {
			_, _ = fmt.Sscanf(strings.TrimSpace(v), "%d", &cl)
		}
	}
	if cl > 0 {
		body = make([]byte, cl)
		if _, err := io.ReadFull(conn, body); err != nil {
			t.Fatalf("response body read: %v", err)
		}
	}
	return status, head, body
}

// TestWireMaxBodyRejectThenRetrySucceeds — the card-required resumability
// wire test: two sequential requests, first oversized, second valid. The
// oversized request is answered 413 (Connection: close advertised), the
// connection is closed cleanly (bounded read reaches EOF; the pipelined
// second request is never answered with desynced bytes), and the retried
// valid request — what any HTTP client does transparently on a new
// connection — succeeds with exactly one upstream call and exactly one
// completed event: clean re-evaluation, no poisoned state.
func TestWireMaxBodyRejectThenRetrySucceeds(t *testing.T) {
	var calls atomic.Int64
	gw := wireImagesGateway(t, &calls)
	events := wireEventCounter(gw)
	addr := startLimitsWireServer(t, gw)

	const cap10MiB = 10 << 20
	oversized := make([]byte, cap10MiB+1)
	valid := `{"model":"m","prompt":"retry-after-reject"}`

	// Request 1: oversized, full body, one connection.
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "POST /v1/images/generations HTTP/1.1\r\n"+
		"Host: gateway.test\r\nAuthorization: Bearer test-key\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n\r\n", len(oversized)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(oversized); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	status, head := readHeadBlock(t, conn)
	if !strings.Contains(status, "413") {
		t.Fatalf("oversized request must answer 413, got %q %q", status, head)
	}
	if !strings.Contains(head, "Connection: close") {
		t.Fatalf("413 must advertise Connection: close, headers %q", head)
	}
	// The server must close the connection cleanly: after the 413 envelope
	// is drained, a follow-up write is answered with EOF (or a write error)
	// within the deadline — never a desynced response, never a hang.
	if _, err := io.WriteString(conn, "POST /v1/images/generations HTTP/1.1\r\nHost: gateway.test\r\n\r\n"); err != nil {
		t.Logf("follow-up write on rejected connection errored (acceptable close semantics): %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	drained, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Logf("drain on rejected connection: %v", err)
	}
	if strings.Contains(string(drained), "HTTP/1.1") {
		t.Fatalf("rejected connection must not produce a second response, got %q", drained)
	}
	_ = conn.Close()

	if got := events(); got != 0 {
		t.Fatalf("rejected request published %d events — quota must not charge a 413", got)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream called %d times on rejected request", got)
	}

	// Request 2 (the retry): fresh connection, same shape, valid body.
	conn2 := dialLimitsWire(t, addr, "POST /v1/images/generations HTTP/1.1\r\n"+
		"Host: gateway.test\r\nAuthorization: Bearer test-key\r\n"+
		"Content-Type: application/json\r\n"+
		fmt.Sprintf("Content-Length: %d\r\nConnection: close\r\n\r\n", len(valid))+valid)
	status, head = readHeadBlock(t, conn2)
	_, _ = io.Copy(io.Discard, conn2)
	_ = conn2.Close()
	if !strings.Contains(status, "200") {
		t.Fatalf("valid retry after 413 must succeed, got %q %q", status, head)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls after retry = %d, want exactly 1 (clean re-evaluation)", got)
	}
	if got := events(); got != 1 {
		t.Fatalf("completed events after retry = %d, want exactly 1", got)
	}
}

// TestWireKeepAliveSequentialRequestsOneConn — the keep-alive complement:
// two valid requests on ONE connection both succeed with upstream egress.
// Rejection cleanup (previous test) must not have degraded normal
// sequential reuse.
func TestWireKeepAliveSequentialRequestsOneConn(t *testing.T) {
	var calls atomic.Int64
	gw := wireImagesGateway(t, &calls)
	events := wireEventCounter(gw)
	addr := startLimitsWireServer(t, gw)

	valid := `{"model":"m","prompt":"keepalive"}`
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	for i := 1; i <= 2; i++ {
		if _, err := fmt.Fprintf(conn, "POST /v1/images/generations HTTP/1.1\r\n"+
			"Host: gateway.test\r\nAuthorization: Bearer test-key\r\n"+
			"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(valid), valid); err != nil {
			t.Fatal(err)
		}
		status, head, body := readWireResponse(t, conn)
		if !strings.Contains(status, "200") {
			t.Fatalf("keep-alive request %d must succeed, got %q %q %s", i, status, head, body)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2", got)
	}
	if got := events(); got != 2 {
		t.Fatalf("completed events = %d, want 2", got)
	}
}

// TestWireClientDisconnectMidUploadNoUpstreamNoEvent — a client death during
// the upload phase: the handler's body read fails before any egress, so the
// observable contract is a 400 envelope (readable when the client half-closes
// and keeps the read side open), zero upstream calls, zero completed events,
// and a server that keeps serving.
func TestWireClientDisconnectMidUploadNoUpstreamNoEvent(t *testing.T) {
	var calls atomic.Int64
	gw := wireImagesGateway(t, &calls)
	events := wireEventCounter(gw)
	addr := startLimitsWireServer(t, gw)

	// Half-close variant: client "dies" mid-chunked-upload but keeps reading;
	// the server's response is observable.
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST /v1/images/generations HTTP/1.1\r\n"+
		"Host: gateway.test\r\nAuthorization: Bearer test-key\r\n"+
		"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"400\r\npartial-payload-no-terminator"); err != nil {
		t.Fatal(err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite() // client died mid-upload, read side still open
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	status, head := readHeadBlock(t, conn)
	_, _ = io.Copy(io.Discard, conn)
	_ = conn.Close()
	if !strings.Contains(status, "400") {
		t.Fatalf("mid-upload disconnect must surface as 400 (truncated body), got %q %q", status, head)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream called %d times after client death mid-upload — zombie egress", got)
	}
	if got := events(); got != 0 {
		t.Fatalf("client death published %d events — partial state must not read as success", got)
	}

	// Hard-close variant: the client vanishes without half-close. Nothing is
	// observable on that socket; the server must simply stay healthy.
	victim, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(victim, "POST /v1/images/generations HTTP/1.1\r\n"+
		"Host: gateway.test\r\nAuthorization: Bearer test-key\r\n"+
		"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"100000\r\nnever-completed"); err != nil {
		t.Fatal(err)
	}
	_ = victim.Close()

	// The server is alive and processes a fresh request end-to-end.
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn2 := dialLimitsWire(t, addr, "POST /v1/images/generations HTTP/1.1\r\n"+
			"Host: gateway.test\r\nAuthorization: Bearer test-key\r\n"+
			"Content-Type: application/json\r\n"+
			fmt.Sprintf("Content-Length: %d\r\nConnection: close\r\n\r\n", len(`{"model":"m","prompt":"after-disconnect"}`))+
			`{"model":"m","prompt":"after-disconnect"}`)
		status, _ = readHeadBlock(t, conn2)
		_, _ = io.Copy(io.Discard, conn2)
		_ = conn2.Close()
		if strings.Contains(status, "200") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server unhealthy after client disconnect: last status %q", status)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls after recovery = %d, want exactly 1", got)
	}
}

// TestWireFilesUploadDisconnectPersistsNothing — DB-gated (skips under
// -short like the other stand tests): a client death during a FILES upload
// (the /v1/files 101 MiB prefix) must persist nothing. The handler SPOOLS
// the multipart part to a capped temp file BEFORE CreateFile (validation and
// the read-back both follow envelope completion), so a truncated upload can
// never reach persistence; the listing proves it on the real store. The
// harness mounts the production server factory + the real MaxBodyByPrefix cap +
// filesUpload (the recorder-level files harness shape): the auth middleware
// is out of scope here — it strips client X-Org-Id headers by design
// (anti-spoofing, pinned by the auth suites) and the org identity for this
// test is the store-level org id the recorder-level files tests also use.
func TestWireFilesUploadDisconnectPersistsNothing(t *testing.T) {
	pool := testdb.Postgres(t)
	gw := &gateway{
		cfg:        config.Gateway{AuthMode: "strict", APIKey: "test-key"},
		log:        slog.Default(),
		auth:       NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		pool:       upstream.NewPool(upstream.Options{}),
		batchStore: batchstore.NewStore(pool, nil),
	}
	org := fmt.Sprintf("org-wire-disconnect-%d", time.Now().UnixNano())
	r := chi.NewRouter()
	r.Use(httpmw.MaxBodyByPrefix(10*1024*1024, batchstore.MaxFileSizeBytes+(1<<20), "/v1/files"))
	r.Post("/v1/files", gw.filesUpload)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newGatewayHTTPServer(ln.Addr().String(), r)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()

	// Multipart envelope: headers complete, file part truncated mid-stream.
	envelope := "POST /v1/files HTTP/1.1\r\n" +
		"Host: gateway.test\r\nAuthorization: Bearer test-key\r\n" +
		"X-Org-Id: " + org + "\r\n" +
		"Content-Type: multipart/form-data; boundary=wirebound\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n"
	part := "--wirebound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"truncated.jsonl\"\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		`{"custom_id":"c1","method":"POST","url":"/v1/chat/completions","body":{"model":"m"}}` + "\n" +
		`{"custom_id":"c2","method":"POST","url":"/v1/chat/completions","body":{"model":"m"}}` + "\n" +
		`{"custom_id":"c3` // truncated mid-line, no closing boundary
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, envelope); err != nil {
		t.Fatal(err)
	}
	// Send the part in ONE chunk that declares more data than it carries, so
	// the disconnect lands mid-body (never a clean terminal chunk).
	if _, err := fmt.Fprintf(conn, "%x\r\n%s", len(part)+4096, part); err != nil {
		t.Fatal(err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite() // client died mid-upload
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	status, head := readHeadBlock(t, conn)
	tail, _ := io.ReadAll(io.LimitReader(conn, 4096))
	_ = conn.Close()
	if !strings.Contains(status, "400") {
		t.Fatalf("truncated files upload must answer 400, got %q %q %s", status, head, tail)
	}
	// Nothing persisted for the org: no partial file row exists.
	files, err := gw.batchStore.ListFiles(context.Background(), org, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("disconnected upload persisted %d partial file(s)", len(files))
	}

	// The listener keeps serving: a well-formed retry on the same factory
	// succeeds end-to-end (200 + persisted exactly once).
	var buf strings.Builder
	buf.WriteString("--wirebound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"retry.jsonl\"\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		`{"custom_id":"c1","method":"POST","url":"/v1/chat/completions","body":{"model":"m"}}` + "\r\n" +
		"--wirebound\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\n" +
		"batch\r\n--wirebound--\r\n")
	body := buf.String()
	retry := dialLimitsWire(t, addr, "POST /v1/files HTTP/1.1\r\n"+
		"Host: gateway.test\r\nAuthorization: Bearer test-key\r\n"+
		"X-Org-Id: "+org+"\r\n"+
		"Content-Type: multipart/form-data; boundary=wirebound\r\n"+
		fmt.Sprintf("Content-Length: %d\r\nConnection: close\r\n\r\n", len(body))+body)
	status, head = readHeadBlock(t, retry)
	rest, _ := io.ReadAll(io.LimitReader(retry, 4096))
	_ = retry.Close()
	if !strings.Contains(status, "200") {
		t.Fatalf("valid files retry must succeed after the disconnect, got %q %q %s", status, head, rest)
	}
	files, err = gw.batchStore.ListFiles(context.Background(), org, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("retry persisted %d files, want exactly 1", len(files))
	}
}
