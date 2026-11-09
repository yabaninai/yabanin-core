package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGatewayMaxHeaderBytesConfiguration(t *testing.T) {
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "2048")
	got, err := gatewayMaxHeaderBytes()
	if err != nil || got != 2048 {
		t.Fatalf("override=%d err=%v", got, err)
	}
	for _, value := range []string{"0", "-1", "not-a-number", "16777217"} {
		t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", value)
		if _, err := gatewayMaxHeaderBytes(); err == nil {
			t.Errorf("invalid override %q was accepted", value)
		}
	}
	// T07 boundary: the maximum override is INCLUSIVE — exactly 16 MiB is
	// accepted, 16 MiB+1 is rejected (covered by "16777217" above).
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "16777216")
	got, err = gatewayMaxHeaderBytes()
	if err != nil || got != maxGatewayMaxHeaderBytes {
		t.Fatalf("16 MiB override: got=%d err=%v, want exactly %d accepted", got, err, maxGatewayMaxHeaderBytes)
	}
}

// The in-process admin listener must carry the same server-level hardening
// as the main listener: the configured header-byte cap (identical override
// semantics, startup failure on invalid values) and the caller's deadlines.
func TestGatewayAdminServerSharesHeaderCap(t *testing.T) {
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "2048")
	srv, err := newGatewayAdminServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		15*time.Second, 15*time.Second, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if srv.MaxHeaderBytes != 2048 {
		t.Fatalf("admin listener MaxHeaderBytes=%d, want 2048", srv.MaxHeaderBytes)
	}
	if srv.ReadHeaderTimeout != 15*time.Second || srv.ReadTimeout != 15*time.Second ||
		srv.WriteTimeout != 15*time.Second || srv.IdleTimeout != 60*time.Second {
		t.Fatalf("admin listener deadlines %v/%v/%v/%v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}

	// Same fail-closed contract as the main listener: an invalid override
	// must fail construction, not silently fall back to a default cap.
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "not-a-number")
	if _, err := newGatewayAdminServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		15*time.Second, 15*time.Second, 60*time.Second); err == nil {
		t.Fatal("invalid YABANIN_HTTP_MAX_HEADER_BYTES must fail admin server construction")
	}
}

func TestGatewayServerRejectsOversizedAggregateHeaders(t *testing.T) {
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "2048")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newGatewayHTTPServer(ln.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	if err != nil {
		t.Fatal(err)
	}
	if srv.MaxHeaderBytes != 2048 {
		t.Fatalf("production gateway MaxHeaderBytes=%d, want 2048", srv.MaxHeaderBytes)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nX-Oversized: %s\r\n\r\n", strings.Repeat("x", 16<<10))
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	// The raw-wire regression pins the 431 contract for a valid request whose
	// aggregate header size exceeds the configured cap.
	if !strings.Contains(line, "431") {
		t.Fatalf("oversized headers must answer 431, got response line %q", line)
	}
}
