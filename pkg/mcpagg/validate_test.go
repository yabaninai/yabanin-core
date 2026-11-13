package mcpagg

import (
	"context"
	"net"
	"testing"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

// testAllow builds an allow-list with the given domains.
func testAllow(t *testing.T, domains ...string) ssrf.AllowList {
	t.Helper()
	al, err := ssrf.NewAllowList(domains)
	if err != nil {
		t.Fatalf("testAllow: %v", err)
	}
	return al
}

// testAllowResolved builds an allow-list whose DNS answers are fixed by the
// seam (QG2-D3): the SSRF happy path and the rebind vector become
// deterministic — no external resolver, no skips.
func testAllowResolved(t *testing.T, domain string, ips ...string) ssrf.AllowList {
	t.Helper()
	al, err := ssrf.NewAllowListWithResolver([]string{domain},
		func(_ context.Context, _ string) ([]net.IP, error) {
			out := make([]net.IP, 0, len(ips))
			for _, s := range ips {
				ip := net.ParseIP(s)
				if ip == nil {
					t.Fatalf("bad fixture ip %q", s)
				}
				out = append(out, ip)
			}
			return out, nil
		})
	if err != nil {
		t.Fatalf("testAllowResolved: %v", err)
	}
	return al
}

func TestValidateServerName(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "knowledge", false},
		{"valid with dash", "my-server", false},
		{"valid with underscore", "my_server", false},
		{"valid digit start", "9lives", false},
		{"empty", "", true},
		{"uppercase", "Knowledge", true},
		{"starts with dash", "-server", true},
		{"starts with underscore", "_server", true},
		{"internal dot", "my.server", true},
		{"space", "my server", true},
		{"too long", "a234567890123456789012345678901234567890123456789012345678901234567890", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateServerName(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateServerName(%q) err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestValidateTransport(t *testing.T) {
	if err := ValidateTransport(TransportHTTP); err != nil {
		t.Fatalf("http-sse should be valid: %v", err)
	}
	if err := ValidateTransport("stdio"); err == nil {
		t.Fatal("stdio must be rejected (non-goal: no process spawning)")
	}
	if err := ValidateTransport(""); err == nil {
		t.Fatal("empty transport must be rejected")
	}
}

func TestValidateAllowedTools(t *testing.T) {
	if err := ValidateAllowedTools(nil); err != nil {
		t.Fatalf("nil (all tools) should be valid: %v", err)
	}
	if err := ValidateAllowedTools([]string{"search", "fetch"}); err != nil {
		t.Fatalf("valid list: %v", err)
	}
	if err := ValidateAllowedTools([]string{"a", "a"}); err == nil {
		t.Fatal("duplicate tool must be rejected")
	}
	if err := ValidateAllowedTools([]string{""}); err == nil {
		t.Fatal("empty tool name must be rejected")
	}
}

// TestValidateServerURL_SSRFCoverage pins the registration-time SSRF guard
// (docs/mcp-gateway.md §6 R1, §7 invariant 1). Every case that must be
// rejected is a real SSRF vector: metadata endpoints, loopback, RFC1918,
// link-local, CGNAT, DNS rebinding to a reserved IP, non-https, credentials.
func TestValidateServerURL_SSRFCoverage(t *testing.T) {
	t.Parallel()

	// Hermetic resolver (QG2-D3): github.com answers a fixed public IP.
	allow := testAllowResolved(t, "github.com", "140.82.121.3")
	// Production mode: the full guard (https-only + allow-list + reserved-IP).
	validate := func(u string) error { return validateServerURL(context.Background(), u, allow, false) }

	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// IP-literal hosts: no DNS needed, the reserved-IP check is decisive.
		{"loopback ip host", "https://127.0.0.1/mcp", true},
		{"aws metadata ip", "https://169.254.169.254/latest/meta-data/", true},
		{"rfc1918 ip", "https://10.0.0.5/mcp", true},
		{"cg nat ip", "https://100.64.0.1/mcp", true},
		{"ipv6 loopback", "https://[::1]/mcp", true},
		// Domain checks that do not require a successful DNS answer.
		{"non-https rejected", "http://mcp.example.com/mcp", true},
		{"domain not in allow-list", "https://other.example.com/mcp", true},
		{"credentials in url", "https://user:pass@mcp.example.com/mcp", true},
		{"empty host", "https://", true},
		{"garbage", "not a url", true},
		// A real public domain that resolves to a non-reserved IP.
		{"public allowed domain", "https://github.com/mcp", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validate(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateServerURL(%q) err=%v, wantErr=%v", tc.url, err, tc.wantErr)
			}
		})
	}
	// Rebind vector (deterministic via the seam): the allow-listed domain
	// now answers a reserved IP and must still be rejected — the reserved-IP
	// check is independent of the domain list.
	rebind := testAllowResolved(t, "github.com", "169.254.169.254")
	if err := ValidateServerURL("https://github.com/mcp", rebind); err == nil {
		t.Fatal("registration guard must reject a rebind to the metadata endpoint")
	}

	// The exported wrapper must be production mode (full guard).
	if err := ValidateServerURL("https://github.com/mcp", allow); err != nil {
		t.Fatalf("ValidateServerURL must pass an allowed https url: %v", err)
	}
	if err := ValidateServerURL("http://127.0.0.1:1/mcp", allow); err == nil {
		t.Fatal("ValidateServerURL must reject non-https (production mode)")
	}
}

// TestValidateServerURL_DNSRebindToReserved simulates a domain that resolves
// to a reserved IP (the rebind vector). A custom allow-list entry whose DNS
// answer is a loopback IP must be rejected at registration.
func TestValidateServerURL_DNSRebindToReserved(t *testing.T) {
	t.Parallel()

	// We cannot easily fake DNS per-host without a resolver override, so we
	// assert the invariant directly on the production guard core: a reserved
	// IP-literal host fails even when the operator allow-lists it — the
	// reserved check is independent of the domain list.
	allow := testAllow(t, "127.0.0.1") // even if the operator allow-lists it...
	err := validateServerURL(context.Background(), "https://127.0.0.1/mcp", allow, false)
	if err == nil {
		t.Fatal("reserved IP must be rejected even if allow-listed (reserved check is independent of the domain list)")
	}
	// And the exported wrapper agrees (production mode): metadata endpoint
	// is reserved regardless of the (empty) allow-list.
	if err := ValidateServerURL("https://169.254.169.254/latest/meta-data/", testAllow(t)); err == nil {
		t.Fatal("metadata endpoint must be rejected by the exported guard")
	}
}

// TestValidateURLAtInvoke_SecondLayer pins the per-invoke re-validation
// (R1 rebind window): the same guards run, so a URL whose answer changed to
// a reserved IP between registration and invoke is blocked.
func TestValidateURLAtInvoke_SecondLayer(t *testing.T) {
	t.Parallel()
	allow := testAllowResolved(t, "github.com", "140.82.121.3")
	// Production mode (allowTestHTTP=false): the full guard re-runs at invoke
	// (R1 rebind window).
	if err := ValidateURLAtInvoke("https://github.com/mcp", allow, false); err != nil {
		t.Fatalf("allowed https url must pass at invoke: %v", err)
	}
	// Rebind at invoke: the allow-listed domain now answers a reserved IP —
	// the second layer must block it.
	rebind := testAllowResolved(t, "github.com", "169.254.169.254")
	if err := ValidateURLAtInvoke("https://github.com/mcp", rebind, false); err == nil {
		t.Fatal("invoke layer must reject a rebind to the metadata endpoint")
	}
	if err := ValidateURLAtInvoke("http://127.0.0.1:1/mcp", allow, false); err == nil {
		t.Fatal("non-https must fail at invoke too")
	}
	if err := ValidateURLAtInvoke("https://169.254.169.254/", allow, false); err == nil {
		t.Fatal("reserved IP must fail at invoke too (rebind window)")
	}
	// Test seam (allowTestHTTP=true): relaxed for httptest loopback.
	if err := ValidateURLAtInvoke("http://127.0.0.1:1234/mcp", allow, true); err != nil {
		t.Fatalf("test seam must relax the guard for httptest: %v", err)
	}
}

// TestNewDefaultConfig pins the safe defaults (OFF, bounded timeouts,
// redirect-following disabled on the built client).
func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg.Enabled {
		t.Fatal("default config must be OFF (YABANIN_MCP_GATEWAY gates it)")
	}
	if cfg.ConnectTimeout <= 0 || cfg.ReadTimeout <= 0 {
		t.Fatal("timeouts must be positive")
	}
	if cfg.MaxResponseBytes <= 0 {
		t.Fatal("max response bytes must be positive")
	}
	c := cfg.Client()
	if c.CheckRedirect == nil {
		t.Fatal("built client must disable redirect following (R1)")
	}
	// CheckRedirect must return an error (do not follow).
	err := c.CheckRedirect(nil, nil)
	if err == nil {
		t.Fatal("CheckRedirect must refuse to follow")
	}
}
