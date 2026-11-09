package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// SessionKeyPrefix marks a short-lived session key minted from a parent yb_ key.
const SessionKeyPrefix = "ybs_"

// SessionKeyLen is prefix plus 64 hex characters (32 random bytes).
const SessionKeyLen = 68

// GenerateSessionKey returns "ybs_" plus 64 hex characters. The plaintext is
// shown once; only HashKey is stored.
func GenerateSessionKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session key: %w", err)
	}
	return SessionKeyPrefix + hex.EncodeToString(buf), nil
}

// IsSessionKey reports a well-formed session key. Prefix alone is not enough:
// a short or overlong token must not take the session resolve path.
func IsSessionKey(key string) bool {
	if len(key) != SessionKeyLen || len(key) < len(SessionKeyPrefix) {
		return false
	}
	if key[:len(SessionKeyPrefix)] != SessionKeyPrefix {
		return false
	}
	for _, c := range key[len(SessionKeyPrefix):] {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
