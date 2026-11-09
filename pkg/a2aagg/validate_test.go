package a2aagg

// Validation guards: name rules, and the SSRF/transport core (https-only,
// allow-list, reserved-IP answers, the DNS-rebind vector) — mirrored from
// the mcpagg coverage with a hermetic resolver (QG2-D3 pattern), so the
// suite is deterministic offline with no skips.

import (
	"context"
	"net"
	"testing"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

// testAllowResolved builds an allow-list whose DNS answers are the fixture
// IPs (hermetic seam, same as mcpagg).
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
		t.Fatalf("allowlist: %v", err)
	}
	return al
}

func TestValidateAgentName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"simple", "helper", false},
		{"dashes and digits", "support-bot-v2", false},
		{"underscore", "internal_agent", false},
		{"empty", "", true},
		{"uppercase", "Helper", true},
		{"leading dash", "-helper", true},
		{"dots", "helper.test", true},
		{"spaces", "helper bot", true},
		{"too long", string(make([]byte, 65)), true}, // 65 zero-bytes: long + invalid chars
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAgentName(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateAgentName(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			}
		})
	}
}

func TestValidateAgentURL_SSRFCoverage(t *testing.T) {
	t.Parallel()

	// Hermetic resolver: agent.example.com answers a fixed public IP.
	allow := testAllowResolved(t, "agent.example.com", "203.0.113.10")
	validate := func(u string) error { return validateAgentURL(u, allow, false) }

	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// IP-literal hosts: no DNS needed, the reserved-IP check is decisive.
		{"loopback ip host", "https://127.0.0.1/", true},
		{"aws metadata ip", "https://169.254.169.254/latest/meta-data/", true},
		{"rfc1918 ip", "https://10.0.0.5/", true},
		{"cg nat ip", "https://100.64.0.1/", true},
		{"ipv6 loopback", "https://[::1]/", true},
		// Domain checks that do not require a successful DNS answer.
		{"non-https rejected", "http://agent.example.com/", true},
		{"domain not in allow-list", "https://other.example.com/", true},
		{"credentials in url", "https://user:pass@agent.example.com/", true},
		{"empty host", "https://", true},
		{"garbage", "not a url", true},
		// The allowed domain resolving to a public IP passes.
		{"public allowed domain", "https://agent.example.com/a2a", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validate(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateAgentURL(%q) err=%v, wantErr=%v", tc.url, err, tc.wantErr)
			}
		})
	}

	// Rebind vector (deterministic via the seam): the allow-listed domain
	// now answers a reserved IP and must still be rejected — the reserved-IP
	// check is independent of the domain list.
	rebind := testAllowResolved(t, "agent.example.com", "169.254.169.254")
	if err := ValidateAgentURL("https://agent.example.com/a2a", rebind); err == nil {
		t.Fatal("registration guard must reject a rebind to the metadata endpoint")
	}

	// The exported wrappers must be production mode (full guard).
	if err := ValidateAgentURL("https://agent.example.com/a2a", allow); err != nil {
		t.Fatalf("ValidateAgentURL must pass an allowed https url: %v", err)
	}
	if err := ValidateAgentURL("http://127.0.0.1:1/", allow); err == nil {
		t.Fatal("ValidateAgentURL must reject non-https (production mode)")
	}
	if err := ValidateURLAtSend("https://127.0.0.1/", allow, false); err == nil {
		t.Fatal("per-send guard must reject loopback in production mode")
	}
	// The test seam only relaxes scheme+resolution, and only in-package.
	if err := ValidateURLAtSend("http://127.0.0.1:1/", allow, true); err != nil {
		t.Fatalf("test seam must allow httptest loopback: %v", err)
	}
}

func TestNewDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := NewDefaultConfig()
	if cfg.Enabled {
		t.Fatal("default config must be disabled")
	}
	if cfg.ReadTimeout <= 0 || cfg.ConnectTimeout <= 0 || cfg.MaxResponseBytes <= 0 {
		t.Fatalf("default timeouts/limits must be positive: %+v", cfg)
	}
	// The default client must refuse redirects (guard-bypass invariant).
	client := cfg.Client()
	if client.CheckRedirect == nil {
		t.Fatal("default client must disable redirects")
	}
}
