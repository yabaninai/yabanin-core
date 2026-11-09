package ssrf

// Unit coverage for the D-4 exact-pin posture
// surface that master f42f402e shipped uncovered — the constructors,
// the dial-time predicate, and the validate-layer waiver semantics. The
// posture is scoped to IP-LITERAL pins only: a hostname (even exactly
// window stays closed at both guard layers.

import (
	"context"
	"net"
	"testing"
)

func TestNewAllowListTrustingExactPins(t *testing.T) {
	al, err := NewAllowListTrustingExactPins([]string{"127.0.0.1", "10.20.30.40", "api.example.test"})
	if err != nil {
		t.Fatalf("NewAllowListTrustingExactPins: %v", err)
	}
	if !al.Contains("127.0.0.1") || !al.Contains("api.example.test") {
		t.Fatal("the trusting constructor must keep the plain membership semantics")
	}
	if _, err := NewAllowListTrustingExactPins([]string{"bad*wild"}); err == nil {
		t.Fatal("an invalid entry must be rejected")
	}
}

func TestNewAllowListWithResolverAndExactPins(t *testing.T) {
	if _, err := NewAllowListWithResolverAndExactPins([]string{"api.example.test"}, nil); err == nil {
		t.Fatal("expected error for nil resolver")
	}
	lookupPublic := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	al, err := NewAllowListWithResolverAndExactPins([]string{"api.example.test"}, lookupPublic)
	if err != nil {
		t.Fatalf("NewAllowListWithResolverAndExactPins: %v", err)
	}
	if al.TrustsExactPin("api.example.test") {
		t.Fatal("a DNS-name entry must never become an exact pin")
	}
}

// TestTrustsExactPin_LiteralOnlyPins: the predicate admits exactly the
// IP-literal entries of a trusting list; hostnames, wildcard matches,
// unpinned literals, and the default (non-trusting) posture all stay false.
func TestTrustsExactPin_LiteralOnlyPins(t *testing.T) {
	trusting, err := NewAllowListTrustingExactPins([]string{
		"127.0.0.1", "10.20.30.40", "api.example.test", "*.wild.test",
	})
	if err != nil {
		t.Fatalf("NewAllowListTrustingExactPins: %v", err)
	}
	cases := []struct {
		hostname string
		want     bool
		note     string
	}{
		{"127.0.0.1", true, "a pinned literal is an exact pin"},
		{"  127.0.0.1  ", true, "the predicate normalizes surrounding space"},
		{"10.20.30.40", true, "a second pinned literal"},
		{"10.20.30.41", false, "a neighboring literal is not pinned"},
		{"::1", false, "an unpinned IPv6 literal is not a pin"},
		{"api.example.test", false, "an exact DNS-name entry is never a pin"},
		{"sub.wild.test", false, "a wildcard match is never a pin"},
		{"", false, "an empty hostname is not a pin"},
	}
	for _, tc := range cases {
		if got := trusting.TrustsExactPin(tc.hostname); got != tc.want {
			t.Errorf("TrustsExactPin(%q) = %v, want %v (%s)", tc.hostname, got, tc.want, tc.note)
		}
	}

	deflt, err := NewAllowList([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("NewAllowList: %v", err)
	}
	if deflt.TrustsExactPin("127.0.0.1") {
		t.Fatal("the default posture must never waive the reserved verdict")
	}

	empty, err := NewAllowListTrustingExactPins(nil)
	if err != nil {
		t.Fatalf("NewAllowListTrustingExactPins(nil): %v", err)
	}
	if empty.TrustsExactPin("127.0.0.1") {
		t.Fatal("an empty trusting list pins nothing")
	}
}

// TestValidateUpstream_TrustingExactPinsWaivesOnlyLiteralPins: the literal
// pin's reserved-range verdict is waived at the validate layer; the same
// reserved answer behind a DNS-name entry (even exactly listed, even in the
// trusting mode) is still refused.
func TestValidateUpstream_TrustingExactPinsWaivesOnlyLiteralPins(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]net.IP, error) {
		if host == "api.example.test" {
			return []net.IP{net.ParseIP("10.0.0.7")}, nil // RFC1918 answer
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	trusting, err := NewAllowListWithResolverAndExactPins(
		[]string{"127.0.0.1", "api.example.test"}, lookup)
	if err != nil {
		t.Fatalf("NewAllowListWithResolverAndExactPins: %v", err)
	}
	if err := trusting.ValidateUpstream("127.0.0.1"); err != nil {
		t.Fatalf("the pinned literal must be admitted despite the reserved range: %v", err)
	}
	if err := trusting.ValidateUpstream("api.example.test"); err == nil {
		t.Fatal("a reserved answer behind a DNS-name entry must stay refused")
	}
	if err := trusting.ValidateUpstream("other.example.test"); err == nil {
		t.Fatal("a host outside the allow-list must stay refused")
	}

	deflt, err := NewAllowListWithResolver([]string{"127.0.0.1"}, lookup)
	if err != nil {
		t.Fatalf("NewAllowListWithResolver: %v", err)
	}
	if err := deflt.ValidateUpstream("127.0.0.1"); err == nil {
		t.Fatal("the default posture must refuse the reserved literal")
	}
}
