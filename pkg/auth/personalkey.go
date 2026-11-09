package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// PersonalKeyPrefix marks a developer-portal key. Session keys (ybs_) are
// AT-14 and must not be issued here.
const PersonalKeyPrefix = "yb_"

// GeneratePersonalKey returns "yb_" plus 64 hex characters (32 random bytes).
// The plaintext is shown once; only its sha256 is stored.
func GeneratePersonalKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate personal key: %w", err)
	}
	return PersonalKeyPrefix + hex.EncodeToString(buf), nil
}
