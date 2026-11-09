// Package webhooks provides Stripe-style webhook signing, delivery, and verification
// with mode-aware SSRF protection (strict for SaaS, relaxed for on-prem).
package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

// Sign creates a Stripe-style HMAC signature: t=<unix-ts>,v1=<hex-hmac>.
func Sign(secret string, ts time.Time, body []byte) (string, string) {
	t := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(t + "." + string(body)))
	return t, hex.EncodeToString(mac.Sum(nil))
}

// SignatureHeader builds the full signature header from components.
func SignatureHeader(sigT, sig string) string {
	return "t=" + sigT + ",v1=" + sig
}

// Verify checks an HMAC signature against a secret with timestamp tolerance.
// Tolerance is symmetric: signatures older than tolerance are expired, and
// signatures dated in the future beyond tolerance are rejected as well.
// Unparseable or missing timestamps are rejected (fail-closed).
func Verify(secret, sigHeader, body string, tolerance time.Duration) error {
	return VerifyAt(secret, sigHeader, body, tolerance, time.Now())
}

// VerifyAt is Verify with an injectable clock so the timestamp window is
// testable deterministically.
func VerifyAt(secret, sigHeader, body string, tolerance time.Duration, now time.Time) error {
	parts := strings.Split(sigHeader, ",")
	if len(parts) < 2 {
		return fmt.Errorf("invalid signature format: %q", sigHeader)
	}

	var ts int64
	var expectedSig string
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			parsed, err := strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid signature timestamp %q", kv[1])
			}
			ts = parsed
		case "v1":
			expectedSig = kv[1]
		}
	}

	if ts == 0 || expectedSig == "" {
		return fmt.Errorf("invalid signature: missing t or v1")
	}

	sigTime := time.Unix(ts, 0)
	age := now.Sub(sigTime)
	if age > tolerance {
		return fmt.Errorf("signature expired: %v old", age)
	}
	if age < -tolerance {
		return fmt.Errorf("signature is %v in the future", -age)
	}

	actualT := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(actualT + "." + body))
	actualSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expectedSig), []byte(actualSig)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// ValidateURL checks if a URL is safe for webhook delivery.
// In SaaS mode: requires HTTPS + public IPs only.
// In on-prem mode (allowPrivate=true): allows HTTP + internal-network IPs
// (RFC 1918, ULA, CGNAT) for internal VPC delivery; loopback, link-local
// (cloud metadata), multicast, and every other reserved range stay rejected.
func ValidateURL(rawURL string, allowPrivate bool) error {
	return ValidateURLWithContext(context.Background(), rawURL, allowPrivate)
}

// ValidateURLWithContext is the context-aware form of ValidateURL. The caller's
// context bounds the DNS lookup, so a caller that cancels (request timeout,
// service shutdown) stops the validation promptly.
func ValidateURLWithContext(ctx context.Context, rawURL string, allowPrivate bool) error {
	return ValidateURLWithResolver(ctx, rawURL, allowPrivate, nil)
}

// ValidateURLWithResolver validates a webhook URL, resolving hostnames through
// lookup. A nil lookup means the default resolver (production); a non-nil one
// is a deterministic test seam. It never disables the reserved-IP checks.
func ValidateURLWithResolver(ctx context.Context, rawURL string, allowPrivate bool, lookup func(ctx context.Context, host string) ([]net.IP, error)) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}

	// Scheme check.
	if !allowPrivate && parsed.Scheme != "https" {
		return fmt.Errorf("webhook URLs must use HTTPS in SaaS mode")
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("empty hostname")
	}

	if ip := net.ParseIP(host); ip != nil {
		if ipNotAllowed(ip, allowPrivate) {
			return fmt.Errorf("webhook target IP %s is in a reserved range", host)
		}
		return nil
	}

	// Domain name — resolve and check. The lookup is bounded: an unbounded
	// DNS call here would let a webhook pointed at a slow/blocked DNS name stall
	// the request (and hang callers, including tests) indefinitely.
	// If the caller's context has no deadline, impose a 5s ceiling.
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var ips []net.IP
	if lookup == nil {
		ipAddrs, lookupErr := (&net.Resolver{}).LookupIPAddr(lookupCtx, host)
		if lookupErr != nil {
			return fmt.Errorf("DNS lookup failed: %w", lookupErr)
		}
		ips = make([]net.IP, 0, len(ipAddrs))
		for _, addr := range ipAddrs {
			ips = append(ips, addr.IP)
		}
	} else {
		var lookupErr error
		ips, lookupErr = lookup(lookupCtx, host)
		if lookupErr != nil {
			return fmt.Errorf("DNS lookup failed: %w", lookupErr)
		}
	}
	if len(ips) == 0 {
		return fmt.Errorf("domain %s has no addresses", host)
	}
	for _, ip := range ips {
		if ipNotAllowed(ip, allowPrivate) {
			return fmt.Errorf("domain %s resolves to reserved IP %s", host, ip)
		}
	}
	return nil
}

// ipNotAllowed reports whether ip is a forbidden webhook target: any
// ssrf-reserved range, except the internal-network subset when the caller
// runs in on-prem mode (allowPrivate).
func ipNotAllowed(ip net.IP, allowPrivate bool) bool {
	return ssrf.IsReserved(ip) && (!allowPrivate || !ssrf.IsInternalNetwork(ip))
}
