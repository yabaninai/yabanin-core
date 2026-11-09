package cli

// N01-P06 T05/T06 wire-level negative regressions.
//
// The packet's negative scenario — "chunked or compressed payload does not
// bypass the quota; a wrong proxy IP is not trusted" — is pinned here against
// the PRODUCTION server factory (newGatewayHTTPServer) and the real
// middleware order (MaxBodyByPrefix → routes), not a bare recorder:
//
//   - a chunked request (unknown length) whose wire payload exceeds the cap
//     is answered 413 BEFORE admission/upstream (quota counts read bytes);
//   - a gzip body whose WIRE size exceeds the cap is rejected at the wire
//     limit — the gateway never decompresses request bodies, so no inflated
//     buffer is ever allocated (the ~200 MiB bomb below is neutralized by
//     the ~10 MiB wire cap);
//   - ambiguous request framing (Content-Length + Transfer-Encoding,
//     conflicting duplicate Content-Length, conflicting Transfer-Encoding
//     values) is resolved or rejected by net/http before any handler runs —
//     no request-smuggling desync reaches the application.
//
// The untrusted-proxy half of the negative scenario is pinned at the unit
// layer where the trust decision lives: clientip.TestExtract_UntrustedProxy,
// TestExtract_RightmostUntrustedHop (spoofed leftmost hop) and
// httpmw.TestRateLimiter_UntrustedProxy_XFFIgnored reuse as evidence.
//
// N01-P06 T07 extends this file with the boundary corpus AT the caps (the
// inclusive exact-cap side, chunk/T-E framing corners, URL-normalization
// reclassification attempts, decompression-ratio extremes and the default
// header-byte cap) — observable statuses probed empirically on this exact
// factory before pinning (comments record the probed contract).

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/batchstore"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// startLimitsWireServer mounts the production middleware order on the
// production server factory: MaxBodyByPrefix with the same caps
// RunGatewayServerWithJWT wires (10 MiB general, 101 MiB /v1/files prefix),
// then the real route tree, served through newGatewayHTTPServer on a real
// loopback listener.
func startLimitsWireServer(t *testing.T, gw *gateway) string {
	t.Helper()
	r := chi.NewRouter()
	r.Use(httpmw.MaxBodyByPrefix(10*1024*1024, batchstore.MaxFileSizeBytes+(1<<20), "/v1/files"))
	gw.routes(r)
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
	return ln.Addr().String()
}

// wireImagesGateway builds the same harness gateway the recorder-level
// images boundary tests use, pointed at a counting mock upstream.
func wireImagesGateway(t *testing.T, calls *atomic.Int64) *gateway {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1,"data":[{"b64_json":"aGk="}]}`))
	}))
	t.Cleanup(up.Close)
	return &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: up.URL},
		log:  slog.Default(),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": {ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: up.URL, Enabled: true}},
		pool: upstream.NewPool(upstream.Options{}),
	}
}

// T05: chunked framing cannot hide the body size. The header carries no
// Content-Length; 10 MiB+1 bytes stream through in chunks. The route cap
// answers 413 and the mock upstream counts zero calls: admission and
// upstream never see an oversized body regardless of framing.
func TestWireChunkedOversizedBodyRejectedBeforeUpstream(t *testing.T) {
	var calls atomic.Int64
	gw := wireImagesGateway(t, &calls)
	addr := startLimitsWireServer(t, gw)

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	head := "POST /v1/images/generations HTTP/1.1\r\n" +
		"Host: gateway.test\r\n" +
		"Authorization: Bearer test-key\r\n" +
		"Content-Type: application/json\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatal(err)
	}
	// Exactly cap+1 wire bytes: 10 full 1 MiB chunks plus a 1-byte chunk.
	chunk := make([]byte, 1<<20)
	for i := 0; i < 10; i++ {
		if _, err := fmt.Fprintf(conn, "%x\r\n", len(chunk)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(chunk); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, "\r\n"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := io.WriteString(conn, "1\r\nx\r\n0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := readStatusLine(conn)
	if err != nil {
		t.Fatalf("no response to oversized chunked body: %v", err)
	}
	if !strings.Contains(line, "413") {
		t.Fatalf("oversized chunked body must answer 413, got %q", line)
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times on oversized chunked body", calls.Load())
	}
}

// T02/T05: the compressed bomb. The gzip member carries ~10.5 MiB of
// incompressible bytes (pushing the WIRE size past the 10 MiB cap) plus
// ~190 MiB of zeros (inflating to ~200 MiB if anyone ever expanded it).
// The gateway never decompresses request bodies, so the quota that applies
// is the wire quota: 413 at the wire limit, zero upstream calls, and no
// inflated buffer anywhere on the reject path. The fixture asserts its own
// wire size so a future compression change cannot silently flip the case
// under the cap.
func TestWireGzipBombRejectedAtWireLimitBeforeUpstream(t *testing.T) {
	var calls atomic.Int64
	gw := wireImagesGateway(t, &calls)
	addr := startLimitsWireServer(t, gw)
	base := "http://" + addr

	const wireCap = 10 << 20
	// Wire-heavy: 10.5 MiB of incompressible bytes push the compressed size
	// past the cap; inflate-heavy: 190 MiB of zeros push the inflated size to
	// ~200 MiB if anything ever expands it.
	bomb := buildGzipBomb(t, 10<<20+512<<10, 190<<20)
	if len(bomb) <= wireCap {
		t.Fatalf("fixture: bomb wire size %d must exceed the %d-byte cap to exercise the quota", len(bomb), wireCap)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/v1/images/generations", bytes.NewReader(bomb))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("wire request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("~200 MiB bomb with >cap wire size must answer 413, got %d", resp.StatusCode)
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times on compressed bomb", calls.Load())
	}
}

// buildGzipBomb returns a gzip member whose compressed (wire) size is pushed
// past any cap by randomBytes and whose inflated size is randomBytes+zeroBytes.
func buildGzipBomb(t *testing.T, randomBytes, zeroBytes int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 1<<20)
	var written int64
	for written < randomBytes {
		n := int64(len(random))
		if left := randomBytes - written; left < n {
			n = left
		}
		if _, err := rand.Read(random[:n]); err != nil {
			t.Fatal(err)
		}
		if _, err := zw.Write(random[:n]); err != nil {
			t.Fatal(err)
		}
		written += n
	}
	zeroChunk := make([]byte, 1<<20)
	for written-randomBytes < zeroBytes {
		n := int64(len(zeroChunk))
		if left := zeroBytes - (written - randomBytes); left < n {
			n = left
		}
		if _, err := zw.Write(zeroChunk[:n]); err != nil {
			t.Fatal(err)
		}
		written += n
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// T04: request-smuggling framing is resolved or rejected by net/http BEFORE
// any application handler runs (pinned here on the production factory):
//   - Content-Length together with Transfer-Encoding: chunked → the chunked
//     interpretation wins (RFC 9112 §6.3), the handler runs EXACTLY ONCE
//     with the chunked body — no double interpretation;
//   - conflicting duplicate Content-Length values → 400 before the handler;
//   - conflicting Transfer-Encoding values → 501 before the handler.
func TestWireAmbiguousFramingResolvedBeforeHandler(t *testing.T) {
	var handlerCalls atomic.Int64
	var sawTE atomic.Value // []string
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newGatewayHTTPServer(ln.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalls.Add(1)
		te := make([]string, len(r.TransferEncoding))
		copy(te, r.TransferEncoding)
		sawTE.Store(te)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64))
		if string(body) != "hello" {
			t.Errorf("handler body %q, want unambiguous chunked payload %q", body, "hello")
		}
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	target := ln.Addr().String()

	send := func(raw string) string {
		t.Helper()
		conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		if _, err := io.WriteString(conn, raw); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, err := readStatusLine(conn)
		if err != nil {
			t.Fatalf("no response: %v", err)
		}
		return line
	}

	// CL+TE: exactly one handler invocation, chunked wins, body "hello".
	if line := send("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"); !strings.Contains(line, "200") {
		t.Fatalf("CL+TE must resolve to the chunked interpretation, got %q", line)
	}
	if got := handlerCalls.Load(); got != 1 {
		t.Fatalf("CL+TE handler calls = %d, want exactly 1 (no desync double-execution)", got)
	}
	if te, ok := sawTE.Load().([]string); !ok || len(te) != 1 || te[0] != "chunked" {
		t.Fatalf("CL+TE must present the body as chunked to the handler, saw %v", sawTE.Load())
	}

	before := handlerCalls.Load()
	// Conflicting duplicate Content-Length: rejected before the handler.
	if line := send("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"); !strings.Contains(line, "400") {
		t.Fatalf("conflicting duplicate Content-Length must answer 400, got %q", line)
	}
	// Conflicting Transfer-Encoding values: rejected before the handler.
	if line := send("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\n"); !strings.Contains(line, "501") {
		t.Fatalf("conflicting Transfer-Encoding values must answer 501, got %q", line)
	}
	if got := handlerCalls.Load(); got != before {
		t.Fatalf("ambiguous framing reached the handler (%d → %d calls)", before, got)
	}
}

func readStatusLine(conn net.Conn) (string, error) {
	var buf [1]byte
	line := make([]byte, 0, 64)
	for {
		_, err := conn.Read(buf[:])
		if err != nil {
			return string(line), err
		}
		if buf[0] == '\n' {
			return strings.TrimRight(string(line), "\r"), nil
		}
		line = append(line, buf[0])
		if len(line) > 256 {
			return string(line), nil
		}
	}
}

// ---------------------------------------------------------------------------
// N01-P06 T07 — boundary corpus AT the caps.
//
// Three aspects, one corpus, all against the production factory:
//  1. body / header / decompression limits — the inclusive exact-cap side
//     (10 MiB exactly must be ACCEPTED in both framings; the merged T05
//     tests pin the cap+1 rejection side), chunk-size corners, and the
//     decompression-ratio extreme (tiny wire, huge inflated);
//  2. header bytes at the 1 MiB default cap (plus the stdlib's documented
//     +4096 bufio slop — net/http server.go initialReadLimitSize);
//  3. request smuggling / URL normalization — obfuscated paths must never
//     reclassify a request into a different cap class or reach a route.
// ---------------------------------------------------------------------------

// readHeadBlock reads the status line plus header block (up to the blank
// line) with a bounded deadline, so close-after-response behavior stays
// observable without ever hanging the corpus.
func readHeadBlock(t *testing.T, conn net.Conn) (status string, head string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := conn.Read(buf[:])
		if err != nil {
			return sb.String(), sb.String()
		}
		sb.WriteByte(buf[0])
		s := sb.String()
		if strings.HasSuffix(s, "\r\n\r\n") {
			lines := strings.SplitN(s, "\r\n", 2)
			return lines[0], s
		}
		if sb.Len() > 16<<10 {
			return sb.String(), sb.String()
		}
		_ = n
	}
}

// dialLimitsWire dials the wire server, sends raw bytes and sets a read
// deadline. It deliberately does NOT half-close the write side: a client FIN
// after the request makes net/http's background read cancel the request
// context, which would abort legitimate egress — requests carry
// "Connection: close" instead, so the server closes after responding.
func dialLimitsWire(t *testing.T, addr, raw string) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	return conn
}

// T07 (aspect 1): the cap is INCLUSIVE on the success side. A JSON body of
// EXACTLY 10 MiB — in both framings, Content-Length and chunked — must be
// delivered to the handler in full and proxied upstream exactly once. The
// rejection side (cap+1 → 413, upstream 0) is pinned by the T05 tests above.
func TestWireBodyExactCapAccepted(t *testing.T) {
	var calls atomic.Int64
	gw := wireImagesGateway(t, &calls)
	addr := startLimitsWireServer(t, gw)

	const cap10MiB = 10 << 20
	prefix := `{"model":"m","prompt":"`
	suffix := `"}`
	pad := strings.Repeat("a", cap10MiB-len(prefix)-len(suffix))
	body := prefix + pad + suffix
	if len(body) != cap10MiB {
		t.Fatalf("fixture: body is %d bytes, want exactly %d", len(body), cap10MiB)
	}

	// Content-Length framing at the exact cap.
	conn := dialLimitsWire(t, addr, "POST /v1/images/generations HTTP/1.1\r\n"+
		"Host: gateway.test\r\n"+
		"Authorization: Bearer test-key\r\n"+
		"Content-Type: application/json\r\n"+
		fmt.Sprintf("Content-Length: %d\r\nConnection: close\r\n\r\n", len(body))+body)
	status, head := readHeadBlock(t, conn)
	_ = conn.Close()
	if !strings.Contains(status, "200") {
		t.Fatalf("exact-cap body (CL framing) must be accepted with 200, got %q %q", status, head)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 for exact-cap CL body", got)
	}

	// Chunked framing at the exact cap: the JSON body split into ten 1 MiB
	// chunks plus the terminal zero chunk — exactly 10 MiB of payload data.
	calls.Store(0)
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	head2 := "POST /v1/images/generations HTTP/1.1\r\n" +
		"Host: gateway.test\r\n" +
		"Authorization: Bearer test-key\r\n" +
		"Content-Type: application/json\r\n" +
		"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, head2); err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(body); off += 1 << 20 {
		end := off + (1 << 20)
		if end > len(body) {
			end = len(body)
		}
		if _, err := fmt.Fprintf(conn, "%x\r\n", end-off); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte(body[off:end])); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, "\r\n"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := io.WriteString(conn, "0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	status, _ = readHeadBlock(t, conn)
	if !strings.Contains(status, "200") {
		t.Fatalf("exact-cap chunked body must be accepted with 200, got %q", status)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 for exact-cap chunked body", got)
	}
}

// T07 (aspect 1): the over-cap side arrives EARLY. With a declared
// Content-Length far above the cap, the gateway must answer 413 after
// reading only cap+ε bytes — it must never wait for (or buffer toward) the
// declared length. The 413 advertises Connection: close: the connection is
// deliberately not reused after a quota rejection.
func TestWireBodyCapPlusOneRejectedEarly(t *testing.T) {
	var calls atomic.Int64
	gw := wireImagesGateway(t, &calls)
	addr := startLimitsWireServer(t, gw)

	const cap10MiB = 10 << 20
	over := make([]byte, cap10MiB+2)

	// Full over-cap body (CL = cap+2): 413, zero upstream calls.
	conn := dialLimitsWire(t, addr, "POST /v1/images/generations HTTP/1.1\r\n"+
		"Host: gateway.test\r\n"+
		"Authorization: Bearer test-key\r\n"+
		"Content-Type: application/json\r\n"+
		fmt.Sprintf("Content-Length: %d\r\nConnection: close\r\n\r\n", len(over))+string(over))
	status, head := readHeadBlock(t, conn)
	_, _ = io.Copy(io.Discard, io.LimitReader(conn, 1<<20))
	_ = conn.Close()
	if !strings.Contains(status, "413") {
		t.Fatalf("cap+2 body must answer 413, got %q %q", status, head)
	}
	if !strings.Contains(head, "Connection: close") {
		t.Fatalf("413 must advertise Connection: close, headers: %q", head)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream called %d times on over-cap body", got)
	}

	// Early reject: declare 30 MiB, send only cap+2 bytes. The response must
	// arrive without the remaining ~20 MiB ever being sent.
	calls.Store(0)
	conn = dialLimitsWire(t, addr, "POST /v1/images/generations HTTP/1.1\r\n"+
		"Host: gateway.test\r\n"+
		"Authorization: Bearer test-key\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: 31457280\r\nConnection: close\r\n\r\n"+string(over))
	start := time.Now()
	status, _ = readHeadBlock(t, conn)
	_ = conn.Close()
	if !strings.Contains(status, "413") {
		t.Fatalf("declared 30 MiB with cap+2 sent must answer 413 early, got %q", status)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("early reject took %s — server appears to wait for the declared length", elapsed)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream called %d times on early-rejected body", got)
	}
}

// T07 (aspect 1, chunk corners): chunk EXTENSIONS are ignored (the payload
// is delivered, te=[chunked], exactly once); a huge DECLARED chunk size
// grants nothing — the wire cap still rules and the body is rejected 413
// after cap+1 actual bytes (no allocation toward the declared size).
func TestWireChunkBoundaryCorpus(t *testing.T) {
	var handlerCalls atomic.Int64
	var sawTE atomic.Value // []string
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newGatewayHTTPServer(ln.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalls.Add(1)
		te := make([]string, len(r.TransferEncoding))
		copy(te, r.TransferEncoding)
		sawTE.Store(te)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64))
		if string(body) != "hello" {
			t.Errorf("chunk-extension payload %q, want %q", body, "hello")
		}
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// Chunk extension: `5;x=y` declares 5 data bytes plus an extension.
	conn := dialLimitsWire(t, ln.Addr().String(),
		"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5;x=y\r\nhello\r\n0\r\n\r\n")
	status, _ := readHeadBlock(t, conn)
	_ = conn.Close()
	if !strings.Contains(status, "200") {
		t.Fatalf("chunk extension must be ignored, got %q", status)
	}
	if got := handlerCalls.Load(); got != 1 {
		t.Fatalf("handler calls = %d, want 1", got)
	}
	if te, ok := sawTE.Load().([]string); !ok || len(te) != 1 || te[0] != "chunked" {
		t.Fatalf("chunk-extension request must present te=[chunked], saw %v", sawTE.Load())
	}

	// Huge declared chunk size against the REAL capped route: the declared
	// size cannot allocate or bypass anything; only actual wire bytes count.
	const cap10MiB = 10 << 20
	var calls atomic.Int64
	gw := wireImagesGateway(t, &calls)
	addr := startLimitsWireServer(t, gw)
	c2, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	if _, err := io.WriteString(c2, "POST /v1/images/generations HTTP/1.1\r\n"+
		"Host: gateway.test\r\nAuthorization: Bearer test-key\r\n"+
		"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n7fffffffffffffff\r\n"); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 1<<20)
	for sent := 0; sent <= cap10MiB; sent += len(big) {
		if _, err := c2.Write(big); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := io.WriteString(c2, "xx"); err != nil { // cap+1 bytes inside the declared chunk
		t.Fatal(err)
	}
	if tc, ok := c2.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	status, _ = readHeadBlock(t, c2)
	if !strings.Contains(status, "413") {
		t.Fatalf("huge declared chunk size must still answer 413 at the wire cap, got %q", status)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream called %d times on huge-declared-chunk body", got)
	}
}

// T07 (aspect 3, framing corners beyond the T04 pins): unsupported transfer
// codings answer 501 with Connection: close BEFORE any handler (RFC 9112
// §7.1 via net/http), and a comma-separated duplicate Content-Length answers
// 400. Empirically probed on this factory before pinning.
func TestWireTransferEncodingCorpus(t *testing.T) {
	var handlerCalls atomic.Int64
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newGatewayHTTPServer(ln.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	target := ln.Addr().String()

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "TE identity with Content-Length",
			raw:  "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
			want: "501",
		},
		{
			name: "TE gzip,chunked stack",
			raw:  "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			want: "501",
		},
		{
			name: "comma-separated duplicate Content-Length",
			raw:  "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 5\r\nConnection: close\r\n\r\nhello",
			want: "400",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := dialLimitsWire(t, target, tc.raw)
			status, _ := readHeadBlock(t, conn)
			_ = conn.Close()
			if !strings.Contains(status, tc.want) {
				t.Fatalf("status %q, want %q", status, tc.want)
			}
		})
	}
	if got := handlerCalls.Load(); got != 0 {
		t.Fatalf("framing-corner requests reached the handler %d times", got)
	}
}

// T07 (aspect 3, URL normalization): chi does not clean or redirect request
// paths (probed: every obfuscated variant answers 404), so a request can
// only reach a route under its canonical path — path tricks can never move a
// body from the 10 MiB class into the /v1/files 101 MiB class or vice versa,
// and no obfuscated path ever reaches upstream.
func TestWireURLNormalizationCannotReclassifyCap(t *testing.T) {
	var calls atomic.Int64
	gw := wireImagesGateway(t, &calls)
	addr := startLimitsWireServer(t, gw)

	paths := []string{
		"/v1/images/generations/",            // trailing slash
		"//v1/images/generations",            // double slash
		"/v1/images/../v1/files",             // climb into the files prefix
		"/v1/images/./generations",           // single-dot
		"/v1/files%2fx",                      // encoded slash (decodes into the files prefix)
		"/v1/files/../v1/images/generations", // files prefix + climb back
		"/v1/IMAGES/generations",             // case trick
		"/v1/files/",                         // trailing slash on the privileged prefix
	}
	for _, p := range paths {
		conn := dialLimitsWire(t, addr, "POST "+p+" HTTP/1.1\r\n"+
			"Host: gateway.test\r\nAuthorization: Bearer test-key\r\n"+
			"Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
		status, _ := readHeadBlock(t, conn)
		_ = conn.Close()
		if !strings.Contains(status, "404") {
			t.Fatalf("obfuscated path %s must not route (404), got %q", p, status)
		}
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream called %d times from obfuscated paths", got)
	}
}

// T07 (aspect 1, decompression ratio extreme): the mirror image of the T05
// gzip-bomb pin. Here the WIRE size is tiny (~tens of KiB) but the member
// inflates to 64 MiB — far under the wire cap, so the wire quota correctly
// does NOT reject it. The invariant under test: the gateway never decompresses
// request bodies, so the inflated size is irrelevant — the real route sees
// opaque non-JSON wire bytes and answers 400 with zero upstream calls, in
// bounded time and without allocating the inflated size.
func TestWireGzipRatioExtremeNotDecompressed(t *testing.T) {
	var calls atomic.Int64
	gw := wireImagesGateway(t, &calls)
	addr := startLimitsWireServer(t, gw)

	bomb := buildGzipBomb(t, 0, 64<<20)
	const cap10MiB = 10 << 20
	if len(bomb) >= cap10MiB {
		t.Fatalf("fixture: bomb wire size %d must stay under the %d-byte cap", len(bomb), cap10MiB)
	}

	conn := dialLimitsWire(t, addr, "POST /v1/images/generations HTTP/1.1\r\n"+
		"Host: gateway.test\r\nAuthorization: Bearer test-key\r\n"+
		"Content-Type: application/json\r\nContent-Encoding: gzip\r\n"+
		fmt.Sprintf("Content-Length: %d\r\nConnection: close\r\n\r\n", len(bomb))+string(bomb))
	status, head := readHeadBlock(t, conn)
	_, _ = io.Copy(io.Discard, conn)
	_ = conn.Close()
	if !strings.Contains(status, "400") {
		t.Fatalf("tiny-wire/huge-inflated gzip must pass the wire cap and be answered 400 by the JSON route (no decompression), got %q %q", status, head)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream called %d times on compressed non-JSON body", got)
	}
}

// T07 (aspect 2): the default 1 MiB header cap on the production factory.
// Observable boundary per net/http server.go: the 431 threshold is
// MaxHeaderBytes + 4096 (initialReadLimitSize "bufio slop"). A header block
// just under the cap is accepted; past cap+slop the server answers 431 and
// closes. The default-cap side (no env override) is the posture production
// runs with.
func TestWireHeaderCapDefaultBoundary(t *testing.T) {
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "") // production default: 1 MiB
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newGatewayHTTPServer(ln.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if srv.MaxHeaderBytes != defaultGatewayMaxHeaderBytes {
		t.Fatalf("default MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, defaultGatewayMaxHeaderBytes)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	target := ln.Addr().String()

	// Under the observable threshold (1 MiB + 4096): accepted.
	pad := strings.Repeat("x", defaultGatewayMaxHeaderBytes-128)
	conn := dialLimitsWire(t, target, "GET / HTTP/1.1\r\nHost: gateway.test\r\nX-Pad: "+pad+"\r\nConnection: close\r\n\r\n")
	status, _ := readHeadBlock(t, conn)
	_ = conn.Close()
	if !strings.Contains(status, "200") {
		t.Fatalf("header block under the default cap must be accepted, got %q", status)
	}

	// Past the threshold: 431 (the merged T02 test pins the same contract at
	// a 2048 override; this pins the DEFAULT production posture).
	pad = strings.Repeat("x", defaultGatewayMaxHeaderBytes+(8<<10))
	conn = dialLimitsWire(t, target, "GET / HTTP/1.1\r\nHost: gateway.test\r\nX-Pad: "+pad+"\r\nConnection: close\r\n\r\n")
	status, _ = readHeadBlock(t, conn)
	_ = conn.Close()
	if !strings.Contains(status, "431") {
		t.Fatalf("header block past default cap+slop must answer 431, got %q", status)
	}
}
