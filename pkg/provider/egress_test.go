package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

func TestTrustedExactHostPin(t *testing.T) {
	t.Parallel()
	// Literal-IP authority: exactly that address is waived.
	literal := trustedExactHostPin("http://127.0.0.1:9000")
	if !literal("127.0.0.1") {
		t.Fatal("literal-IP pin must waive the exact address")
	}
	if literal("127.0.0.2") {
		t.Fatal("a different address must not be waived")
	}
	// Hostname authority: never waived (DNS answer is not operator-pinned).
	hostname := trustedExactHostPin("https://login.microsoftonline.com")
	if hostname("login.microsoftonline.com") {
		t.Fatal("hostname authority must never waive the dial verdict")
	}
	// Multiple authorities: only listed literals waive.
	multi := trustedExactHostPin("https://login.microsoftonline.com", "http://10.20.30.40:8080")
	if !multi("10.20.30.40") || multi("10.20.30.41") {
		t.Fatal("exact literal pin set mismatch")
	}
	// Invalid / scheme-less authorities contribute no pins (strict guard).
	strict := trustedExactHostPin("not a url", "")
	if strict("127.0.0.1") {
		t.Fatal("unparseable authority must not create a pin")
	}
}

// sberTokenServer builds an httptest server answering the Sber OAuth
// exchange, returning the server URL and a call counter.
func sberTokenServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT-guard","expires_at":4102444800000}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &calls
}

// N01-P07 regression: the Sber token-exchange client must run the dial-time
// SSRF guard. A hostname target that resolves into a reserved range is
// refused even though the same address is reachable (loopback httptest),
// because a hostname is never an exact literal pin.
func TestSber_TokenDialGuard_RefusesHostnameIntoReservedRange(t *testing.T) {
	srv, calls := sberTokenServer(t)
	hostPort := strings.TrimPrefix(srv.URL, "http://127.0.0.1")
	s := mustProductionSber(t)
	_, err := s.PrepareRequest(context.Background(), "http://localhost"+hostPort, sberChatPath, []byte(`{"model":"gigachat"}`), "secret", false)
	if err == nil {
		t.Fatal("expected guarded dialer to refuse hostname resolving into the reserved range")
	}
	if !errors.Is(err, ssrf.ErrReservedTarget) {
		t.Fatalf("expected ErrReservedTarget, got: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("token endpoint must not have been reached, calls=%d", calls.Load())
	}
}

// The D-4 waiver: the operator-configured base URL given as an exact IP
// literal keeps working (loopback test rigs and on-prem literal pins).
func TestSber_TokenDialGuard_WaivesExactLiteralPin(t *testing.T) {
	srv, calls := sberTokenServer(t)
	s := mustProductionSber(t)
	if _, err := s.PrepareRequest(context.Background(), srv.URL, sberChatPath, []byte(`{"model":"gigachat"}`), "secret", false); err != nil {
		t.Fatalf("literal-IP base URL must stay reachable: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly one token exchange, got %d", calls.Load())
	}
}

// The Sber token client must ignore environment proxy settings (pkg/ssrf
// forbids env proxies as a substitute for allow-list-checked URLs): the
// exchange still reaches the direct httptest target with a poison proxy
// configured.
func TestSber_TokenDialGuard_IgnoresEnvProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	srv, calls := sberTokenServer(t)
	s := mustProductionSber(t)
	if _, err := s.PrepareRequest(context.Background(), srv.URL, sberChatPath, []byte(`{"model":"gigachat"}`), "secret", false); err != nil {
		t.Fatalf("literal-IP base URL must stay reachable and ignore env proxy: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly one token exchange, got %d", calls.Load())
	}
}

// The Entra exchange must run the same guarded dial: a hostname override
// resolving into the reserved range is refused, the literal-IP test rig
// keeps working, and environment proxy settings are ignored.
func TestAzure_TokenDialGuard_RefusesHostnameIntoReservedRange(t *testing.T) {
	srv, calls := azureTokenServer(t)
	hostPort := strings.TrimPrefix(srv.URL, "http://127.0.0.1")
	a := NewAzureOpenAIWithClient(nil, "http://localhost"+hostPort)
	_, err := a.PrepareRequest(context.Background(), srv.URL, a.Path(false), azureGuardChatBody(), testAzureCreds(), false)
	if err == nil {
		t.Fatal("expected guarded dialer to refuse hostname resolving into the reserved range")
	}
	if !errors.Is(err, ssrf.ErrReservedTarget) {
		t.Fatalf("expected ErrReservedTarget, got: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("entra endpoint must not have been reached, calls=%d", calls.Load())
	}
}

func TestAzure_TokenDialGuard_WaivesExactLiteralPin_AndIgnoresEnvProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	srv, calls := azureTokenServer(t)
	a := NewAzureOpenAIWithClient(nil, srv.URL)
	if _, err := a.PrepareRequest(context.Background(), srv.URL, a.Path(false), azureGuardChatBody(), testAzureCreds(), false); err != nil {
		t.Fatalf("literal-IP authority must stay reachable and ignore env proxy: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly one entra exchange, got %d", calls.Load())
	}
}

func azureTokenServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/test-tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT-entra","expires_in":3600}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &calls
}

func azureGuardChatBody() []byte {
	return []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"ping"}]}`)
}

func testAzureCreds() string {
	return `{"tenant_id":"test-tenant","client_id":"guard-client","client_secret":"guard-fixture-not-a-real-secret"}`
}

func mustProductionSber(t *testing.T) *Sber {
	t.Helper()
	s, err := NewSber()
	if err != nil {
		t.Fatalf("NewSber: %v", err)
	}
	return s
}
