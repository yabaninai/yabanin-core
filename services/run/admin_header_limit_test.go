package run

import (
	"net/http"
	"testing"
	"time"
)

// TestAdminMaxHeaderBytesConfiguration pins the override semantics shared with
// pkg/gateway: a valid YABANIN_HTTP_MAX_HEADER_BYTES wins, every invalid value
// fails closed instead of falling back to a default.
func TestAdminMaxHeaderBytesConfiguration(t *testing.T) {
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "2048")
	got, err := adminMaxHeaderBytes()
	if err != nil || got != 2048 {
		t.Fatalf("override=%d err=%v", got, err)
	}
	for _, value := range []string{"0", "-1", "not-a-number", "16777217"} {
		t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", value)
		if _, err := adminMaxHeaderBytes(); err == nil {
			t.Errorf("invalid override %q was accepted", value)
		}
	}
}

// TestAdminMaxHeaderBytesDefault pins the unset/empty override to the same
// 1 MiB default the gateway uses.
func TestAdminMaxHeaderBytesDefault(t *testing.T) {
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "")
	got, err := adminMaxHeaderBytes()
	if err != nil {
		t.Fatalf("default must not fail: %v", err)
	}
	if got != 1<<20 {
		t.Fatalf("default MaxHeaderBytes=%d, want %d", got, 1<<20)
	}
}

// TestAdminHTTPServerCarriesHeaderCap pins the admin panel listener's
// server-level hardening: the configured header-byte cap plus the admin
// surface's read/write/idle deadlines, and the fail-closed construction
// contract on invalid overrides.
func TestAdminHTTPServerCarriesHeaderCap(t *testing.T) {
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "2048")
	srv, err := newAdminHTTPServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatal(err)
	}
	if srv.MaxHeaderBytes != 2048 {
		t.Fatalf("admin panel MaxHeaderBytes=%d, want 2048", srv.MaxHeaderBytes)
	}
	if srv.ReadHeaderTimeout != 10*time.Second || srv.ReadTimeout != 10*time.Second ||
		srv.WriteTimeout != 15*time.Second || srv.IdleTimeout != 60*time.Second {
		t.Fatalf("admin panel deadlines %v/%v/%v/%v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}

	// Same fail-closed contract as the gateway: an invalid override must fail
	// server construction, not silently fall back to a default cap.
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "not-a-number")
	if _, err := newAdminHTTPServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); err == nil {
		t.Fatal("invalid YABANIN_HTTP_MAX_HEADER_BYTES must fail admin server construction")
	}
}
