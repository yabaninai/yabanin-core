package run

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestLoggerdHTTPServerCarriesHeaderCap pins the loggerd health/metrics
// listener's server-level hardening (N01-P06 remainder closure — the
// listener previously carried ReadHeaderTimeout only): the same env-driven
// header-byte cap as the gateway and admin listeners plus the full deadline
// posture (10s header/read, 15s write, 60s idle — the admin panel values;
// the surface is bounded request/response, no streaming), and the fail-closed
// construction contract on invalid overrides.
func TestLoggerdHTTPServerCarriesHeaderCap(t *testing.T) {
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "2048")
	srv, err := newLoggerdHTTPServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatal(err)
	}
	if srv.MaxHeaderBytes != 2048 {
		t.Fatalf("loggerd MaxHeaderBytes=%d, want 2048", srv.MaxHeaderBytes)
	}
	if srv.ReadHeaderTimeout != 10*time.Second || srv.ReadTimeout != 10*time.Second ||
		srv.WriteTimeout != 15*time.Second || srv.IdleTimeout != 60*time.Second {
		t.Fatalf("loggerd deadlines %v/%v/%v/%v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}

	// Same fail-closed contract as the gateway/admin: an invalid override
	// must fail server construction, not silently fall back to a default cap.
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "not-a-number")
	if _, err := newLoggerdHTTPServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); err == nil {
		t.Fatal("invalid YABANIN_HTTP_MAX_HEADER_BYTES must fail loggerd server construction")
	}
}

// TestLoggerdHTTPServerServesUnderDeadlines — the listener with its real
// /healthz shape answers within its deadlines (a posture that only bounds
// must still serve; a constructor typo like a zero WriteTimeout paired with
// a broken handler would otherwise pass the field assertions above).
func TestLoggerdHTTPServerServesUnderDeadlines(t *testing.T) {
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "")
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv, err := newLoggerdHTTPServer("127.0.0.1:0", mux)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+ln.Addr().String()+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", resp.StatusCode)
	}
}
