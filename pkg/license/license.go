// Package license verifies offline Ed25519-signed activation tokens.
// No phone-home: the vendor public key is embedded at build time (keys.go).
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Claims is the decoded license payload.
type Claims struct {
	OrgID string `json:"org_id"`
	// Seats is inert legacy metadata from the superseded per-seat model
	// (owner answers I16–I20, cancelled by I22). Core has no account-count
	// limit: human, service, agent and CI accounts are not billing units and
	// provisioning is never gated on this value. Consumers must not read it
	// for access, enforcement or provisioning decisions.
	Seats     int       `json:"seats"`
	Features  []string  `json:"features"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
	Nonce     string    `json:"nonce"`
}

// GracePeriod allows clock-drift past expiry before hard-expire (degraded
// mode). It applies ONLY to activation tokens (Verify/State below): it is a
// clock-drift allowance for activation state, never a maintenance/renewal
// extension and never part of the I24 continued-operation semantics for
// paid-module entitlements (see maintenance.go — that path has no clock
// input at all, so this constant cannot leak into it).
const GracePeriod = 7 * 24 * time.Hour

// Verify parses + signature-checks a license token. VendorPublicKey is
// embedded at build time (keys.go). Returns parsed Claims.
func Verify(token string) (Claims, error) {
	var c Claims
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		return c, fmt.Errorf("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return c, fmt.Errorf("decode payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return c, fmt.Errorf("decode sig: %w", err)
	}
	if !ed25519.Verify(VendorPublicKey, payload, sig) {
		return c, fmt.Errorf("invalid license signature")
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, fmt.Errorf("unmarshal claims: %w", err)
	}
	if time.Now().After(c.ExpiresAt.Add(GracePeriod)) {
		return c, fmt.Errorf("license hard-expired (grace exhausted)")
	}
	return c, nil
}

// State describes current activation for the gateway's /healthz.
type State struct {
	Active bool   `json:"active"`
	OrgID  string `json:"org_id"`
	// Seats mirrors Claims.Seats verbatim. It is inert legacy metadata
	// (superseded per-seat model, cancelled by I22): no UI, no API and no
	// background enforcement may derive any account-count limit from it.
	Seats       int      `json:"seats"`
	Features    []string `json:"features"`
	Expired     bool     `json:"expired"`      // past ExpiresAt but within grace
	HardExpired bool     `json:"hard_expired"` // past grace — rate-limit
	ExpiresAt   string   `json:"expires_at"`
}

// StateFromClaims builds a State, marking expired/hard-expired.
func StateFromClaims(c Claims) State {
	now := time.Now()
	return State{
		Active:      now.Before(c.ExpiresAt.Add(GracePeriod)),
		OrgID:       c.OrgID,
		Seats:       c.Seats,
		Features:    c.Features,
		Expired:     now.After(c.ExpiresAt) && now.Before(c.ExpiresAt.Add(GracePeriod)),
		HardExpired: now.After(c.ExpiresAt.Add(GracePeriod)),
		ExpiresAt:   c.ExpiresAt.Format(time.RFC3339),
	}
}
