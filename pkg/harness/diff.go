package harness

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var secretKey = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:key|token|secret|password|auth)[A-Za-z0-9_.-]*)(\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)`)

// MaskSecrets replaces values whose key name contains key, token, secret, password, or auth.
func MaskSecrets(content []byte) []byte {
	return secretKey.ReplaceAllFunc(content, func(match []byte) []byte {
		parts := secretKey.FindSubmatch(match)
		if len(parts) != 4 {
			return match
		}
		return []byte(string(parts[1]) + string(parts[2]) + "***")
	})
}

// Diff is a unified diff of two blobs after secret masking.
func Diff(path string, before, after []byte) string {
	left := strings.Split(string(MaskSecrets(before)), "\n")
	right := strings.Split(string(MaskSecrets(after)), "\n")
	var b bytes.Buffer
	fmt.Fprintf(&b, "--- %s\n+++ %s\n", path, path)
	for i := 0; i < len(left) || i < len(right); i++ {
		var l, r string
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		if i < len(left) && i < len(right) && l == r {
			fmt.Fprintf(&b, " %s\n", l)
			continue
		}
		if i < len(left) {
			fmt.Fprintf(&b, "-%s\n", l)
		}
		if i < len(right) {
			fmt.Fprintf(&b, "+%s\n", r)
		}
	}
	return b.String()
}
