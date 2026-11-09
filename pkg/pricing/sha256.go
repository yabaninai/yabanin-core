package pricing

import (
	"crypto/sha256"
	"fmt"
)

// sha256Hex returns the hex-encoded SHA256 of b (provenance fingerprint).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%x", sum)
}
