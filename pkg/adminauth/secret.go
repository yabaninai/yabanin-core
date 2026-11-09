package adminauth

// Admin session-secret policy. The cookie-signing secret must never
// be a constant: when it is not configured, a fresh random secret is
// generated at startup; a weak configured secret (too short, or a well-known
// dev placeholder) is refused in production and replaced (with a warning via
// the returned generated flag) in dev/test.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// MinSessionSecretLen is the minimum acceptable session-secret length in
// bytes: 32 random bytes (256 bits).
const MinSessionSecretLen = 32

// sessionSecretEntropy is how much randomness a generated secret carries.
const sessionSecretEntropy = 32

// knownDevSecrets are placeholder secrets that ship in examples and local
// setups. They must never sign production cookies.
var knownDevSecrets = []string{
	"changeme",
	"change-me",
	"secret",
	"dev-secret",
	"password",
	"insecure",
}

// GenerateSessionSecret returns a fresh random secret: 32 crypto/rand bytes,
// hex-encoded to 64 characters.
func GenerateSessionSecret() (string, error) {
	b := make([]byte, sessionSecretEntropy)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// WeakSessionSecret reports whether a configured secret is below the entropy
// floor (fewer than MinSessionSecretLen bytes) or is a well-known dev
// placeholder (case-insensitive).
func WeakSessionSecret(configured string) bool {
	configured = strings.TrimSpace(configured)
	if len(configured) < MinSessionSecretLen {
		return true
	}
	for _, dev := range knownDevSecrets {
		if strings.EqualFold(configured, dev) {
			return true
		}
	}
	return false
}

// ResolveSessionSecret enforces the startup policy for the session secret.
// An unset secret is generated (all modes). A weak secret is refused in
// production; in dev/test it is replaced by a generated one. generated=true
// tells the caller to warn (the secret is not operator-controlled and will
// not survive a restart).
func ResolveSessionSecret(configured string, production bool) (secret string, generated bool, err error) {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		secret, err = GenerateSessionSecret()
		return secret, true, err
	}
	if WeakSessionSecret(configured) {
		if production {
			return "", false, fmt.Errorf(
				"admin: session secret rejected: configured secret is weak (shorter than %d bytes or a known dev placeholder); set YABANIN_SESSION_KEY to a fresh random secret of at least %d bytes",
				MinSessionSecretLen, MinSessionSecretLen)
		}
		secret, err = GenerateSessionSecret()
		return secret, true, err
	}
	return configured, false, nil
}
