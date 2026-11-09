package clientip

import (
	"net"
	"testing"
)

func TestExtract_NoTrustedProxies(t *testing.T) {
	var trustedProxies []string

	// XFF should be ignored when no trusted proxies configured
	result := Extract("10.0.0.1:1234", "192.168.1.1, 10.0.0.5", "1.2.3.4", trustedProxies)
	if result != "10.0.0.1:1234" {
		t.Fatalf("expected remote addr, got %q", result)
	}

	result = Extract("10.0.0.1", "", "", trustedProxies)
	if result != "10.0.0.1" {
		t.Fatalf("expected remote addr, got %q", result)
	}
}

func TestExtract_WithTrustedProxies_IPMatch(t *testing.T) {
	trustedProxies := []string{"192.168.1.1"}

	// Rightmost non-trusted hop wins: 10.0.0.1 is the client, 203.0.113.5
	// is an untrusted intermediate hop reported by the client.
	result := Extract("192.168.1.1:8080", "203.0.113.5, 10.0.0.1", "", trustedProxies)
	if result != "10.0.0.1" {
		t.Fatalf("expected rightmost untrusted XFF IP, got %q", result)
	}

	result = Extract("192.168.1.1:8080", "", "1.2.3.4", trustedProxies)
	if result != "1.2.3.4" {
		t.Fatalf("expected X-Real-IP, got %q", result)
	}

	// XFF preferred over X-Real-IP
	result = Extract("192.168.1.1:8080", "203.0.113.5", "1.2.3.4", trustedProxies)
	if result != "203.0.113.5" {
		t.Fatalf("expected XFF over X-Real-IP, got %q", result)
	}
}

func TestExtract_WithTrustedProxies_CIDRMatch(t *testing.T) {
	trustedProxies := []string{"10.0.0.0/8"}

	result := Extract("10.255.255.1:8080", "203.0.113.5", "", trustedProxies)
	if result != "203.0.113.5" {
		t.Fatalf("expected first XFF IP for CIDR match, got %q", result)
	}

	result = Extract("172.16.0.1:8080", "203.0.113.5", "", trustedProxies)
	if result == "203.0.113.5" {
		t.Fatal("should not trust XFF from non-trusted proxy 172.16.0.1")
	}
}

func TestExtract_UntrustedProxy(t *testing.T) {
	trustedProxies := []string{"192.168.1.1"}

	// Non-trusted proxy sending XFF should not have it honored
	result := Extract("203.0.113.5:1234", "1.2.3.4, 5.6.7.8", "", trustedProxies)
	if result != "203.0.113.5:1234" {
		t.Fatalf("expected remote addr for untrusted proxy, got %q", result)
	}
}

func TestExtract_RightmostUntrustedHop(t *testing.T) {
	// (a) trusted proxy 5.6.7.8 appended the real client 1.2.3.4
	if got := Extract("5.6.7.8:443", "1.2.3.4, 5.6.7.8", "", []string{"5.6.7.8"}); got != "1.2.3.4" {
		t.Fatalf("expected client 1.2.3.4, got %q", got)
	}

	// (b) double proxy: 9.9.9.9 is a client-controlled spoof prepended by
	// 1.2.3.4; the rightmost non-trusted hop must win.
	if got := Extract("5.6.7.8:443", "9.9.9.9, 1.2.3.4, 5.6.7.8", "", []string{"5.6.7.8"}); got != "1.2.3.4" {
		t.Fatalf("expected client 1.2.3.4, got %q (spoofed leftmost 9.9.9.9 must not win)", got)
	}

	// (c) unknown remote (not a trusted proxy) sending XFF: headers ignored
	if got := Extract("203.0.113.99:1234", "9.9.9.9, 5.6.7.8", "6.6.6.6", []string{"5.6.7.8"}); got != "203.0.113.99:1234" {
		t.Fatalf("expected remote addr for unknown sender, got %q", got)
	}

	// every XFF entry trusted: fall back to RemoteAddr
	if got := Extract("5.6.7.8:443", "10.0.0.9, 5.6.7.8", "", []string{"5.6.7.8", "10.0.0.9"}); got != "5.6.7.8:443" {
		t.Fatalf("expected remote addr when all XFF entries are trusted, got %q", got)
	}
}

func TestExtract_EmptyTrustedProxies(t *testing.T) {
	var trustedProxies []string = nil

	result := Extract("10.0.0.1:1234", "203.0.113.5", "", trustedProxies)
	if result != "10.0.0.1:1234" {
		t.Fatalf("expected remote addr with nil trusted proxies, got %q", result)
	}

	trustedProxies = []string{}
	result = Extract("10.0.0.1:1234", "203.0.113.5", "", trustedProxies)
	if result != "10.0.0.1:1234" {
		t.Fatalf("expected remote addr with empty trusted proxies, got %q", result)
	}
}

func TestExtract_IPv6(t *testing.T) {
	trustedProxies := []string{"::1", "fd00::/8"}

	result := Extract("[::1]:8080", "2001:db8::1", "", trustedProxies)
	if result != "2001:db8::1" {
		t.Fatalf("expected IPv6 XFF, got %q", result)
	}

	result = Extract("[fd00::1]:8080", "2001:db8::2", "", trustedProxies)
	if result != "2001:db8::2" {
		t.Fatalf("expected IPv6 CIDR match, got %q", result)
	}
}

func TestExtract_WhitespaceTrimming(t *testing.T) {
	trustedProxies := []string{"192.168.1.1"}

	result := Extract("192.168.1.1:8080", "  203.0.113.5  ,  10.0.0.1  ", "", trustedProxies)
	if result != "10.0.0.1" {
		t.Fatalf("expected trimmed rightmost untrusted XFF IP, got %q", result)
	}

	result = Extract("192.168.1.1:8080", "", "  1.2.3.4  ", trustedProxies)
	if result != "1.2.3.4" {
		t.Fatalf("expected trimmed X-Real-IP, got %q", result)
	}
}

func TestParseCIDRs(t *testing.T) {
	input := []string{"192.168.1.0/24", "10.0.0.1", "invalid", "172.16.0.0/12"}

	networks, ips := ParseCIDRs(input)

	if len(networks) != 2 {
		t.Fatalf("expected 2 networks, got %d", len(networks))
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected IP 10.0.0.1, got %v", ips[0])
	}
}

// Edge branches added for the coverage ratchet: malformed XFF entries,
// unparseable trusted entries, IPv6 in the trusted set, and RemoteAddr
// without a port.
func TestRightmostUntrustedHop_MalformedEntries(t *testing.T) {
	trusted := []string{"10.0.0.1"}
	// Malformed (non-IP) entries are untrusted hops — a proxy chain that
	// injects garbage must not make the walk skip the real client.
	if got := rightmostUntrustedHop("1.2.3.4, not-an-ip, 10.0.0.1", trusted); got != "not-an-ip" {
		t.Fatalf("got %q, want not-an-ip", got)
	}
	// Empty entries between commas are skipped, not returned.
	if got := rightmostUntrustedHop("1.2.3.4, , 10.0.0.1", trusted); got != "1.2.3.4" {
		t.Fatalf("got %q, want 1.2.3.4", got)
	}
	// All-trusted XFF falls through to the RemoteAddr in Extract.
	if got := Extract("10.0.0.1:80", "10.0.0.1, 10.0.0.1", "", trusted); got != "10.0.0.1:80" {
		t.Fatalf("got %q, want remote addr", got)
	}
}

func TestIsTrustedProxy_Branches(t *testing.T) {
	// RemoteAddr without a port still matches.
	if !isTrustedProxy("10.0.0.1", []string{"10.0.0.0/8"}) {
		t.Fatal("port-less remote addr in trusted CIDR must match")
	}
	// Unparseable trusted entries are ignored, not fatal.
	if isTrustedProxy("10.0.0.1:80", []string{"::garbage::"}) {
		t.Fatal("unparseable trusted entry must not match everything")
	}
	// IPv6 exact trust.
	if !isTrustedProxy("[2001:db8::1]:443", []string{"2001:db8::1"}) {
		t.Fatal("IPv6 trusted proxy must match")
	}
	if !isTrustedIP("2001:db8::5", []string{"2001:db8::/64"}) {
		t.Fatal("IPv6 CIDR containment must match")
	}
}

// N01-P06 T07 boundary corpus for the trusted-proxy aspect: the decision
// edges of the rightmost-untrusted walk — the all-trusted fallback ordering,
// CIDR containment at the exact range edge, and the precedence of a
// client-controlled X-Real-IP against a trusted XFF chain.
func TestExtract_AllTrustedFallbackOrdering(t *testing.T) {
	trusted := []string{"5.6.7.8", "10.0.0.9"}

	// All XFF hops trusted AND X-Real-IP present: the walk yields "", so
	// X-Real-IP is honored next — but ONLY because the direct peer is a
	// trusted proxy; an untrusted peer never reaches this fallback.
	if got := Extract("5.6.7.8:443", "10.0.0.9, 5.6.7.8", "1.2.3.4", trusted); got != "1.2.3.4" {
		t.Fatalf("all-trusted XFF must fall back to X-Real-IP, got %q", got)
	}

	// Same shape with an UNTRUSTED peer: both headers are ignored, even
	// though the header values are identical — trust is per-connection.
	if got := Extract("203.0.113.5:443", "10.0.0.9, 5.6.7.8", "1.2.3.4", trusted); got != "203.0.113.5:443" {
		t.Fatalf("untrusted peer must get RemoteAddr despite headers, got %q", got)
	}
}

func TestExtract_CIDRRangeEdge(t *testing.T) {
	// The /24 boundary: the last address of the trusted range is trusted,
	// the first address of the NEXT range is not — off-by-one trust
	// expansion at the CIDR edge must not happen.
	trusted := []string{"198.51.100.0/24"}
	if got := Extract("198.51.100.255:443", "203.0.113.7", "", trusted); got != "203.0.113.7" {
		t.Fatalf("last address of trusted /24 must be trusted, got %q", got)
	}
	if got := Extract("198.51.101.0:443", "203.0.113.7", "", trusted); got != "198.51.101.0:443" {
		t.Fatalf("first address of the adjacent /24 must NOT be trusted, got %q", got)
	}
	// The same edge inside the XFF walk: a proxy at the exact range end may
	// vouch for the client, the adjacent address may not.
	if got := Extract("198.51.100.255:443", "203.0.113.7, 198.51.100.255", "", trusted); got != "203.0.113.7" {
		t.Fatalf("range-end proxy must be skipped in the walk, got %q", got)
	}
}

func TestExtract_XRealIPCannotOverrideTrustedXFF(t *testing.T) {
	// A trusted proxy chain vouches for the client; X-Real-IP carries a
	// spoofed value. XFF wins when it yields a non-empty client — the
	// fallback ordering must not let a spoofed X-Real-IP displace the
	// rightmost-untrusted verdict.
	trusted := []string{"5.6.7.8"}
	if got := Extract("5.6.7.8:443", "1.2.3.4, 5.6.7.8", "9.9.9.9", trusted); got != "1.2.3.4" {
		t.Fatalf("trusted XFF chain must beat spoofed X-Real-IP, got %q", got)
	}
	// IPv4-mapped IPv6 spellings of the same address resolve identically
	// (net.IP.Equal semantics) — the boundary is by address, not spelling.
	if got := Extract("5.6.7.8:443", "::ffff:1.2.3.4, 5.6.7.8", "", trusted); got != "::ffff:1.2.3.4" {
		t.Fatalf("4-in-6 XFF entry resolves through the same walk, got %q", got)
	}
}
