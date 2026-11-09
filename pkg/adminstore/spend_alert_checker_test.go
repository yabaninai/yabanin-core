package adminstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

// TestSpendAlertDialerRejectsReservedLiteralIPs verifies the delivery dialer
// refuses reserved literal targets without hitting the network. Regression
// for the SSRF gap where fireWebhook sent to a user-supplied URL with no
// guard.
func TestSpendAlertDialerRejectsReservedLiteralIPs(t *testing.T) {
	dial := spendAlertDialer()
	ctx := context.Background()

	unsafeAddrs := []string{
		"127.0.0.1:443",
		"169.254.169.254:80",
		"10.0.0.5:8443",
		"192.168.1.1:443",
		"0.0.0.0:443",
		"[::1]:443",
		"100.64.0.1:443",
		"224.0.0.1:443",
	}
	for _, addr := range unsafeAddrs {
		_, err := dial(ctx, "tcp", addr)
		if !errors.Is(err, ssrf.ErrReservedTarget) {
			t.Errorf("dial(%q) = %v; want ssrf.ErrReservedTarget", addr, err)
		}
	}
}

// TestSpendAlertDialerAllowsPublicLiteralIP: a public IP should pass the
// guard. We expect a connection error (nothing listening / no route in CI)
// but NOT an SSRF policy rejection.
func TestSpendAlertDialerAllowsPublicLiteralIP(t *testing.T) {
	dial := spendAlertDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := dial(ctx, "tcp", "8.8.8.8:443")
	if errors.Is(err, ssrf.ErrReservedTarget) {
		t.Fatalf("dial(8.8.8.8:443) rejected as reserved target, should be allowed: %v", err)
	}
}

// TestSpendAlertDialerRejectsLoopbackDomain pins the DNS-rebinding guard at
// dial time: every resolved answer of the hostname is checked before the
// pinned IP is dialed, so a domain pointing at loopback is a policy
// rejection regardless of what validation-time resolution returned.
func TestSpendAlertDialerRejectsLoopbackDomain(t *testing.T) {
	dial := spendAlertDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// "localhost" resolves to 127.0.0.1/::1 — must be rejected.
	_, err := dial(ctx, "tcp", "localhost:443")
	if !errors.Is(err, ssrf.ErrReservedTarget) {
		t.Fatalf("dial(localhost:443) = %v; want ssrf.ErrReservedTarget", err)
	}
}
