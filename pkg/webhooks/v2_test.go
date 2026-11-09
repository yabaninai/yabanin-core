package webhooks

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestSignVerify_RoundTrip(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"type":"event.test"}`)
	ts := time.Now()

	sigT, sig := Sign(secret, ts, body)
	header := SignatureHeader(sigT, sig)

	err := Verify(secret, header, string(body), 2*time.Hour)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_ReplayOutsideTolerance_Rejected(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"type":"event.test"}`)
	historicalTS := time.Now().Add(-3 * time.Hour)

	sigT, sig := Sign(secret, historicalTS, body)
	header := sigT + ",v1=" + sig

	err := Verify(secret, header, string(body), 2*time.Hour)
	if err == nil {
		t.Error("expected error for expired signature")
	}
}

func TestVerify_BadSecret_Rejected(t *testing.T) {
	sigT, sig := Sign("correct-secret", time.Now(), []byte(`{"type":"x"}`))
	header := sigT + ",v1=" + sig

	err := Verify("wrong-secret", header, `{"type":"x"}`, 2*time.Hour)
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestValidateURL_RejectsHTTPAndPrivate(t *testing.T) {
	tests := []struct {
		url          string
		allowPrivate bool
		expectError  bool
	}{
		// Public IP literals exercise the scheme + IP-class logic without a DNS
		// lookup, so the test is deterministic and does not depend on the
		// network. (A domain here would trigger a live DNS lookup and make the
		// test flaky in offline environments.)
		{"https://8.8.8.8/webhook", false, false},     // public IP, https -> allowed
		{"http://8.8.8.8/webhook", false, true},       // public IP, http -> rejected (SaaS)
		{"http://192.168.1.1:8080/hook", false, true}, // private IP -> rejected
		{"https://10.0.0.1:443/hook", false, true},    // private IP -> rejected
		{"https://8.8.8.8/hook", true, false},         // public IP, allowPrivate -> allowed
		{"http://127.0.0.1:9090/hook", true, true},    // loopback always rejected
	}

	for _, tc := range tests {
		err := ValidateURL(tc.url, tc.allowPrivate)
		if tc.expectError && err == nil {
			t.Errorf("ValidateURL(%q, allowPrivate=%v): expected error but got none", tc.url, tc.allowPrivate)
		}
		if !tc.expectError && err != nil {
			t.Errorf("ValidateURL(%q, allowPrivate=%v): unexpected error: %v", tc.url, tc.allowPrivate, err)
		}
	}
}

// TestValidateURL_RejectsEveryReservedRange covers every ssrf ReservedCIDR
// entry (plus IPv4-mapped forms) via literal-IP URLs, so the SaaS-mode guard
// rejects each range without any DNS dependency.
func TestValidateURL_RejectsEveryReservedRange(t *testing.T) {
	reserved := []string{
		"https://127.0.0.1/hook",                // loopback v4
		"https://[::1]/hook",                    // loopback v6
		"https://10.10.0.5/hook",                // RFC1918 10/8
		"https://172.16.31.5/hook",              // RFC1918 172.16/12
		"https://192.168.0.5/hook",              // RFC1918 192.168/16
		"https://0.0.0.0/hook",                  // this-network 0.0.0.0/8
		"https://0.1.2.3/hook",                  // this-network 0.0.0.0/8 (non-zero host part)
		"https://169.254.169.254/hook",          // link-local (cloud metadata)
		"https://[fe80::1]/hook",                // link-local v6
		"https://[fc00::1]/hook",                // ULA fc00::/7
		"https://[fd12:3456::1]/hook",           // ULA fd00::/8 (inside fc00::/7)
		"https://224.0.0.1/hook",                // multicast v4
		"https://[ff02::1]/hook",                // multicast v6
		"https://[::]/hook",                     // unspecified
		"https://198.18.0.1/hook",               // benchmarking 198.18.0.0/15
		"https://198.19.255.1/hook",             // benchmarking upper half
		"https://100.64.0.1/hook",               // CGNAT 100.64/10
		"https://100.100.0.5/hook",              // Aliyun metadata, inside CGNAT
		"https://[::ffff:169.254.169.254]/hook", // IPv4-mapped metadata
		"https://[::ffff:10.0.0.5]/hook",        // IPv4-mapped private
	}
	for _, rawURL := range reserved {
		t.Run(rawURL, func(t *testing.T) {
			if err := ValidateURL(rawURL, false); err == nil {
				t.Errorf("ValidateURL(%q, false): expected rejection of reserved target", rawURL)
			}
		})
	}

	public := []string{
		"https://8.8.8.8/hook",
		"https://[2606:4700:4700::1111]/hook",
	}
	for _, rawURL := range public {
		t.Run(rawURL, func(t *testing.T) {
			if err := ValidateURL(rawURL, false); err != nil {
				t.Errorf("ValidateURL(%q, false): public target rejected: %v", rawURL, err)
			}
		})
	}
}

// TestValidateURL_OnPremModeRangeSemantics pins allowPrivate=true: internal
// networks (RFC1918, ULA, CGNAT) open up with HTTP, while loopback,
// link-local/metadata, multicast, this-network, unspecified, and benchmarking
// stay rejected in every mode.
func TestValidateURL_OnPremModeRangeSemantics(t *testing.T) {
	allowed := []string{
		"http://10.1.2.3:8080/hook",
		"http://172.16.0.1/hook",
		"http://192.168.1.1/hook",
		"http://[fc00::1]/hook",
		"https://100.64.0.1/hook",
		"https://8.8.8.8/hook",
	}
	rejected := []string{
		"http://127.0.0.1:9090/hook",
		"https://[::1]/hook",
		"https://169.254.169.254/hook",
		"https://[fe80::1]/hook",
		"https://0.0.0.0/hook",
		"https://[::]/hook",
		"https://224.0.0.1/hook",
		"https://[ff02::1]/hook",
		"https://198.18.0.1/hook",
	}
	for _, rawURL := range allowed {
		t.Run(rawURL, func(t *testing.T) {
			if err := ValidateURL(rawURL, true); err != nil {
				t.Errorf("ValidateURL(%q, true): internal target rejected: %v", rawURL, err)
			}
		})
	}
	for _, rawURL := range rejected {
		t.Run(rawURL, func(t *testing.T) {
			if err := ValidateURL(rawURL, true); err == nil {
				t.Errorf("ValidateURL(%q, true): expected rejection even in on-prem mode", rawURL)
			}
		})
	}
}

// TestValidateURLWithResolver exercises the domain-resolution branch
// hermetically: reserved answers, mixed answer sets, lookup errors, and
// empty answer sets are all rejected (fail-closed), public answers pass,
// and on-prem mode accepts internal answers.
func TestValidateURLWithResolver(t *testing.T) {
	static := func(ips ...string) func(context.Context, string) ([]net.IP, error) {
		parsed := make([]net.IP, 0, len(ips))
		for _, s := range ips {
			parsed = append(parsed, net.ParseIP(s))
		}
		return func(context.Context, string) ([]net.IP, error) {
			return parsed, nil
		}
	}

	cases := []struct {
		name         string
		rawURL       string
		allowPrivate bool
		lookup       func(context.Context, string) ([]net.IP, error)
		wantErr      bool
	}{
		{"public passes", "https://hooks.example.test/hook", false, static("93.184.216.34"), false},
		{"metadata rejected", "https://hooks.example.test/hook", false, static("169.254.169.254"), true},
		{"loopback rejected", "https://hooks.example.test/hook", false, static("127.0.0.1"), true},
		{"cgnat rejected in saas", "https://hooks.example.test/hook", false, static("100.64.0.1"), true},
		{"mixed public+reserved rejected", "https://hooks.example.test/hook", false, static("93.184.216.34", "10.0.0.7"), true},
		{"lookup error fail-closed", "https://hooks.example.test/hook", false, func(context.Context, string) ([]net.IP, error) {
			return nil, errors.New("resolver dead")
		}, true},
		{"empty answer fail-closed", "https://hooks.example.test/hook", false, static(), true},
		{"on-prem internal passes", "http://hooks.internal.test/hook", true, static("10.0.0.7"), false},
		{"on-prem metadata still rejected", "http://hooks.internal.test/hook", true, static("169.254.169.254"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateURLWithResolver(context.Background(), tc.rawURL, tc.allowPrivate, tc.lookup)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestVerifyAt_TimestampWindow pins the symmetric skew semantics with a
// fixed clock: signatures within tolerance on either side pass, older ones
// are expired, and signatures dated in the future beyond tolerance are
func TestVerifyAt_TimestampWindow(t *testing.T) {
	secret := "whsec_test"
	body := `{"type":"event.test"}`
	now := time.Unix(1_800_000_000, 0)
	tolerance := 2 * time.Hour

	sigT, sig := Sign(secret, now, []byte(body))
	header := SignatureHeader(sigT, sig)

	cases := []struct {
		name     string
		nowShift time.Duration
		wantErr  bool
	}{
		{"current time", 0, false},
		{"slightly old within tolerance", 90 * time.Minute, false},
		{"slightly future within tolerance", -90 * time.Minute, false},
		{"expired beyond tolerance (replay)", 3 * time.Hour, true},
		{"future beyond tolerance", -3 * time.Hour, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyAt(secret, header, body, tolerance, now.Add(tc.nowShift))
			if tc.wantErr && err == nil {
				t.Fatalf("expected rejection for signature %v off the clock", tc.nowShift)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestVerifyAt_ReplayedSignatureRejected is the deterministic replay case:
// a signature valid at sign time must stop verifying once it ages past the
// tolerance window.
func TestVerifyAt_ReplayedSignatureRejected(t *testing.T) {
	secret := "whsec_test"
	body := `{"type":"event.test"}`
	t0 := time.Unix(1_800_000_000, 0)

	sigT, sig := Sign(secret, t0, []byte(body))
	header := SignatureHeader(sigT, sig)

	if err := VerifyAt(secret, header, body, 5*time.Minute, t0); err != nil {
		t.Fatalf("first verification failed: %v", err)
	}
	if err := VerifyAt(secret, header, body, 5*time.Minute, t0.Add(10*time.Minute)); err == nil {
		t.Fatal("replayed signature outside tolerance was accepted")
	}
}

func TestVerify_ForgedBodyRejected(t *testing.T) {
	secret := "whsec_test"
	sigT, sig := Sign(secret, time.Now(), []byte(`{"type":"event.test"}`))
	header := SignatureHeader(sigT, sig)

	if err := Verify(secret, header, `{"type":"event.tampered"}`, 2*time.Hour); err == nil {
		t.Fatal("forged body accepted")
	}
}

// TestVerify_MalformedTimestampFailClosed pins fail-closed parsing: an
// unparseable or missing timestamp (or signature part) must never fall
// through to acceptance.
func TestVerify_MalformedTimestampFailClosed(t *testing.T) {
	body := `{"type":"event.test"}`
	headers := []string{
		"t=not-a-number,v1=abcd",
		"t=,v1=abcd",
		"t=123",
		"v1=abcd",
		"garbage",
	}
	for _, header := range headers {
		t.Run(header, func(t *testing.T) {
			if err := Verify("whsec_test", header, body, 2*time.Hour); err == nil {
				t.Fatalf("malformed header %q accepted", header)
			}
		})
	}
}
