package ssrf

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestIsReserved(t *testing.T) {
	tests := []struct {
		ip     string
		expect bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.255", true},
		{"::1", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"169.254.0.1", true},
		{"169.254.169.254", true}, // cloud metadata
		{"0.0.0.0", true},
		{"0.0.0.1", true},                // 0.0.0.0/8
		{"0.255.255.255", true},          // 0.0.0.0/8
		{"100.64.0.1", true},             // CGNAT
		{"100.100.0.5", true},            // Aliyun metadata, inside CGNAT range
		{"198.18.0.1", true},             // benchmarking
		{"224.0.0.1", true},              // multicast
		{"fc00::1", true},                // ULA fc00::/7
		{"fd12:3456::1", true},           // ULA fc00::/7
		{"fe80::1", true},                // link-local
		{"::ffff:169.254.169.254", true}, // IPv4-mapped metadata
		{"2606:4700:4700::1111", false},  // public IPv6 (Cloudflare DNS)
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false}, // example.com
		{"142.250.80.46", false}, // google.com
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid IP: %s", tt.ip)
			}
			if got := IsReserved(ip); got != tt.expect {
				t.Errorf("IsReserved(%q) = %v, want %v", tt.ip, got, tt.expect)
			}
		})
	}
}

// TestIsInternalNetwork pins the internal-network subset webhooks use for
// on-prem allowPrivate mode: RFC 1918, ULA, CGNAT — and nothing else.
func TestIsInternalNetwork(t *testing.T) {
	cases := []struct {
		ip    string
		want  bool
		label string
	}{
		{"10.1.2.3", true, "rfc1918 10/8"},
		{"172.16.0.1", true, "rfc1918 172.16/12"},
		{"192.168.1.1", true, "rfc1918 192.168/16"},
		{"fc00::1", true, "ULA fc00::/7"},
		{"fd12:3456::1", true, "ULA fd00::/8"},
		{"100.64.0.1", true, "CGNAT 100.64/10"},
		{"100.100.0.5", true, "Aliyun metadata inside CGNAT"},
		{"127.0.0.1", false, "loopback never internal-allowed"},
		{"169.254.169.254", false, "cloud metadata never internal-allowed"},
		{"fe80::1", false, "link-local never internal-allowed"},
		{"224.0.0.1", false, "multicast"},
		{"0.0.0.0", false, "this-network"},
		{"198.18.0.1", false, "benchmarking"},
		{"8.8.8.8", false, "public"},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("invalid IP: %s", tc.ip)
			}
			if got := IsInternalNetwork(ip); got != tc.want {
				t.Errorf("IsInternalNetwork(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestDomainParse(t *testing.T) {
	tests := []struct {
		entry   string
		wantErr bool
	}{
		{"api.openai.com", false},
		{"*.openai.com", false},
		{"*", true},
		{"*.", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			d, err := ParseDomain(tt.entry)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDomain(%q) error = %v, wantErr %v", tt.entry, err, tt.wantErr)
			}
			if !tt.wantErr {
				if d.pattern != tt.entry {
					t.Errorf("pattern = %q, want %q", d.pattern, tt.entry)
				}
			}
		})
	}
}

func TestDomainMatches(t *testing.T) {
	d, _ := ParseDomain("*.openai.com")

	tests := []struct {
		host string
		want bool
	}{
		{"api.openai.com", true},
		{"chat.openai.com", true},
		{"openai.com", false},      // wildcard doesn't match bare domain
		{"evil-openai.com", false}, // must be suffix match
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := d.Matches(tt.host); got != tt.want {
				t.Errorf("Matches(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}

	exact, _ := ParseDomain("api.openai.com")
	if !exact.Matches("api.openai.com") {
		t.Error("exact match failed for api.openai.com")
	}
	if exact.Matches("chat.openai.com") {
		t.Error("exact should not match different subdomain")
	}
}

func TestAllowList(t *testing.T) {
	al, _ := NewAllowList([]string{"api.openai.com", "*.anthropic.com"})

	tests := []struct {
		host string
		want bool
	}{
		{"api.openai.com", true},
		{"api.anthropic.com", true},
		{"chat.anthropic.com", true},
		{"openai.com", false},
		{"evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := al.Contains(tt.host); got != tt.want {
				t.Errorf("Contains(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

// TestValidateUpstream is hermetic (resolver seam): the historical live
// httpbin.org probe skipped whenever the network/DNS was unavailable — an
// unexplained skip fails the quality run. The seam pins the same allow/deny
// behavior deterministically.
func TestValidateUpstream(t *testing.T) {
	al, err := NewAllowListWithResolver([]string{"httpbin.org"},
		func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("140.82.121.3")}, nil // non-reserved
		})
	if err != nil {
		t.Fatal(err)
	}

	err = al.ValidateUpstream("httpbin.org")
	if err != nil {
		t.Errorf("allowed domain with non-reserved answer must pass: %v", err)
	}

	err = al.ValidateUpstream("evil.com")
	if err == nil {
		t.Error("expected error for non-allowed domain")
	}
}

func TestValidateUpstreamEmpty(t *testing.T) {
	al, _ := NewAllowList([]string{"example.com"})
	err := al.ValidateUpstream("")
	if err == nil {
		t.Error("expected error for empty hostname")
	}
}

// TestMustParseCIDRPanics pins the init-time guard: a malformed CIDR entry
// must panic loudly at startup, not silently skip a reserved range.
func TestMustParseCIDRPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustParseCIDR did not panic on a malformed CIDR")
		}
	}()
	mustParseCIDR("not-a-cidr")
}

// TestNewAllowListInvalidEntry covers the buildAllowList error path: an
// invalid allow-list entry fails construction instead of degrading.
func TestNewAllowListInvalidEntry(t *testing.T) {
	if _, err := NewAllowList([]string{"api.openai.com", "bad*entry"}); err == nil {
		t.Fatal("expected error for invalid allow-list entry")
	}
}

// TestNewAllowListWithResolver covers the deterministic-test seam end to
// end: nil-reject, lookup error, empty answers, reserved answers, and the
// passing public path — without any network dependency.
func TestNewAllowListWithResolver(t *testing.T) {
	if _, err := NewAllowListWithResolver([]string{"api.example.test"}, nil); err == nil {
		t.Fatal("expected error for nil resolver")
	}

	lookupPublic := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}

	al, err := NewAllowListWithResolver([]string{"api.example.test", "*.outside.test"}, lookupPublic)
	if err != nil {
		t.Fatalf("NewAllowListWithResolver: %v", err)
	}

	if err := al.ValidateUpstream("api.example.test"); err != nil {
		t.Fatalf("public answer must pass: %v", err)
	}
	if err := al.ValidateUpstream("nope.example.test"); err == nil {
		t.Fatal("host outside the allow-list must fail")
	}
}

// TestValidateUpstreamSeamFailures covers the resolver-dependent branches
// of ValidateUpstream (error, empty answer set, reserved answer) through
// the NewAllowListWithResolver seam.
func TestValidateUpstreamSeamFailures(t *testing.T) {
	cases := []struct {
		name   string
		lookup func(context.Context, string) ([]net.IP, error)
		want   string
	}{
		{"lookup-error", func(context.Context, string) ([]net.IP, error) {
			return nil, errors.New("resolver dead")
		}, "failed to resolve"},
		{"no-ips", func(context.Context, string) ([]net.IP, error) {
			return nil, nil
		}, "no IPs resolved"},
		{"reserved-ip", func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.7")}, nil
		}, "reserved IP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			al, err := NewAllowListWithResolver([]string{"api.example.test"}, tc.lookup)
			if err != nil {
				t.Fatalf("NewAllowListWithResolver: %v", err)
			}
			err = al.ValidateUpstream("api.example.test")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q in error, got: %v", tc.want, err)
			}
		})
	}
}

// TestValidateUpstream_ExactPinTrustPosture pins the D-4 fix semantics
// (owner decision 2026-10-13): in the trusting posture an allow-list entry
// that IS an IP literal is an explicit operator pin for that exact address,
// so a loopback/RFC1918 endpoint is admitted — while wildcard entries and
// DNS-NAME entries (whose answers can rebind) keep the reserved
// refusal, and the default (non-trusting) constructor keeps the historical
// refusal the MCP/A2A registration guards pin.
func TestValidateUpstream_ExactPinTrustPosture(t *testing.T) {
	t.Parallel()

	hermetic := func(entries []string, ip string) AllowList {
		al, err := NewAllowListWithResolverAndExactPins(entries,
			func(ctx context.Context, host string) ([]net.IP, error) {
				return []net.IP{net.ParseIP(ip)}, nil
			})
		if err != nil {
			t.Fatalf("allow list %v: %v", entries, err)
		}
		return al
	}

	t.Run("IP-literal pin admits the reserved address", func(t *testing.T) {
		t.Parallel()
		al := hermetic([]string{"127.0.0.1"}, "127.0.0.1")
		if err := al.ValidateUpstream("127.0.0.1"); err != nil {
			t.Fatalf("an IP-literal operator pin must dial even into a reserved range (D-4): %v", err)
		}
	})

	t.Run("DNS-name entry resolving to a reserved IP is still refused", func(t *testing.T) {
		t.Parallel()
		al := hermetic([]string{"llamacpp.internal"}, "10.1.2.3")
		err := al.ValidateUpstream("llamacpp.internal")
		if err == nil || !strings.Contains(err.Error(), "reserved IP") {
			t.Fatalf("a name's answer can rebind (IMP-86): want reserved-IP refusal even for an exactly listed name, got %v", err)
		}
	})

	t.Run("wildcard entry resolving to a reserved IP is still refused", func(t *testing.T) {
		t.Parallel()
		al := hermetic([]string{"*.corp.example"}, "10.1.2.3")
		err := al.ValidateUpstream("gpu.corp.example")
		if err == nil || !strings.Contains(err.Error(), "reserved IP") {
			t.Fatalf("wildcard entries are never trusted; want reserved-IP refusal, got %v", err)
		}
	})

	t.Run("default mode keeps refusing reserved ranges even for literal entries", func(t *testing.T) {
		t.Parallel()
		al, err := NewAllowListWithResolver([]string{"127.0.0.1"},
			func(ctx context.Context, host string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		if err := al.ValidateUpstream("127.0.0.1"); err == nil {
			t.Fatal("the default constructor must keep the reserved-IP refusal the MCP/A2A guards pin")
		}
	})
}

// TestValidateUpstream_ResolutionFailures pins the resolver-error and
// empty-answer refusals (bounded at the validate layer): a lookup error and
// a zero-answer lookup must both refuse with diagnosable errors — the D-4
// trusting posture does not weaken them.
func TestValidateUpstream_ResolutionFailures(t *testing.T) {
	t.Parallel()

	failing := func(ctx context.Context, host string) ([]net.IP, error) {
		return nil, errors.New("resolver down")
	}
	al, err := NewAllowListWithResolverAndExactPins([]string{"gpu.internal"}, failing)
	if err != nil {
		t.Fatal(err)
	}
	err = al.ValidateUpstream("gpu.internal")
	if err == nil || !strings.Contains(err.Error(), "failed to resolve") {
		t.Fatalf("lookup error must refuse with a resolve diagnostic, got %v", err)
	}

	empty, err := NewAllowListWithResolverAndExactPins([]string{"gpu.internal"},
		func(ctx context.Context, host string) ([]net.IP, error) {
			return nil, nil // resolved to nothing
		})
	if err != nil {
		t.Fatal(err)
	}
	err = empty.ValidateUpstream("gpu.internal")
	if err == nil || !strings.Contains(err.Error(), "no IPs resolved") {
		t.Fatalf("empty answer must refuse with the no-IPs diagnostic, got %v", err)
	}
}

// TestValidateUpstream_DefaultResolverBranches pins the default-resolution
// error and empty-answer refusals through the package seam (the live-network
// probe that used to cover them was made hermetic on 2026-10-15).
func TestValidateUpstream_DefaultResolverBranches(t *testing.T) {
	al, err := NewAllowList([]string{"gpu.internal"})
	if err != nil {
		t.Fatal(err)
	}

	orig := defaultResolverLookup
	t.Cleanup(func() { defaultResolverLookup = orig })

	defaultResolverLookup = func(_ context.Context, hostname string) ([]net.IP, error) {
		return nil, errors.New("resolver down")
	}
	if err := al.ValidateUpstream("gpu.internal"); err == nil || !strings.Contains(err.Error(), "failed to resolve") {
		t.Fatalf("default-resolver error must refuse with the resolve diagnostic, got %v", err)
	}

	defaultResolverLookup = func(_ context.Context, hostname string) ([]net.IP, error) {
		return nil, nil
	}
	if err := al.ValidateUpstream("gpu.internal"); err == nil || !strings.Contains(err.Error(), "no IPs resolved") {
		t.Fatalf("empty default-resolver answer must refuse with the no-IPs diagnostic, got %v", err)
	}
}

// TestDefaultResolverLookup_LocalHostResolution executes the REAL bounded
// system-resolution path (the package var's body): localhost resolves via
// the hosts file with no network dependency, so the default branch of
// ValidateUpstream keeps full statement coverage after the seam extraction.
// Non-parallel by design: the var is patched by the (sequential) branches
// test above.
func TestDefaultResolverLookup_LocalHostResolution(t *testing.T) {
	ips, err := defaultResolverLookup(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("localhost must resolve through the hosts file: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("localhost resolution returned no IPs")
	}
}
