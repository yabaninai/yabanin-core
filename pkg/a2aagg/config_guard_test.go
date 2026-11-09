package a2aagg

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

// TestClientTransportRejectsReservedTargetAtDial pins the dial-time
// guard: the send client's transport must reject connections whose target
// is (or resolves to) a reserved address, with an SSRF policy error that
// does not leak the forbidden address. This closes the DNS-rebinding
// window between ValidateURLAtInvoke and the actual dial.
func TestClientTransportRejectsReservedTargetAtDial(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.ConnectTimeout = 300 * time.Millisecond
	client := cfg.Client()

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", client.Transport)
	}

	for _, target := range []string{"169.254.169.254:80", "127.0.0.1:80", "10.0.0.5:443"} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			start := time.Now()
			conn, err := tr.DialContext(ctx, "tcp", target)
			if err == nil {
				_ = conn.Close()
				t.Fatalf("dial %s was not rejected", target)
			}
			if !strings.Contains(err.Error(), "ssrf") {
				t.Fatalf("dial %s error is not an SSRF policy rejection: %v", target, err)
			}
			if !errors.Is(err, ssrf.ErrReservedTarget) {
				t.Fatalf("dial %s error is not ErrReservedTarget: %v", target, err)
			}
			if strings.Contains(err.Error(), target) {
				t.Fatalf("dial %s error leaks the forbidden address: %v", target, err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("rejection took %v — looks like a real connect attempt, not a policy reject", elapsed)
			}
		})
	}
}

// TestClientTransportTestSeamKeepsLoopback pins that the httptest seam
// (testAllowHTTP) also disables the dial-time guard, so loopback test
// upstreams keep working — production never sets the seam.
func TestClientTransportTestSeamKeepsLoopback(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen local: %v", err)
	}
	defer func() { _ = ln.Close() }()

	cfg := NewDefaultConfig()
	cfg.testAllowHTTP = true
	client := cfg.Client()
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", client.Transport)
	}

	conn, err := tr.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("loopback dial must stay available behind the test seam: %v", err)
	}
	_ = conn.Close()
}
