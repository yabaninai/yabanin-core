package labels

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Size and wire limits for a label set.
const (
	MaxKeyLen      = 63
	MaxValueLen    = 128
	MaxPerSource   = 20
	MaxEffective   = 32
	MaxHeaderBytes = 4096
	ReservedPrefix = "yabanin."
	HeaderName     = "X-Yabanin-Labels"
	PerKeyPrefix   = "X-Yabanin-Label-"
)

// Set is a normalized label map.
type Set map[string]string

// DropReason is why a label was discarded. Empty means the value was accepted.
type DropReason string

// Drop reasons stored on a discarded label.
const (
	DropInvalidKey    DropReason = "invalid_key"
	DropInvalidValue  DropReason = "invalid_value"
	DropValueTooLong  DropReason = "value_too_long"
	DropReserved      DropReason = "reserved"
	DropTooMany       DropReason = "too_many"
	DropSecretLike    DropReason = "secret_like"
	DropLocked        DropReason = "locked"
	DropNotAllowed    DropReason = "not_allowed"
	DropHeaderTooLong DropReason = "header_too_long"
)

// Dropped is one discarded label.
type Dropped struct {
	Key    string     `json:"key"`
	Reason DropReason `json:"reason"`
}

var labelKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$`)

// NormalizeKey trims, lowercases, and checks the label key grammar.
func NormalizeKey(raw string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(raw))
	if key == "" || len(key) > MaxKeyLen || strings.Contains(key, "%") {
		return "", false
	}
	if !labelKeyPattern.MatchString(key) {
		return "", false
	}
	return key, true
}

// NormalizeValue percent-decodes and checks a label value.
// An empty reason means the value is acceptable.
func NormalizeValue(raw string) (string, DropReason) {
	decoded, err := url.PathUnescape(raw)
	if err != nil || !utf8.ValidString(decoded) {
		return "", DropInvalidValue
	}
	decoded = strings.TrimSpace(decoded)
	if decoded == "" {
		return "", DropInvalidValue
	}
	if len(decoded) > MaxValueLen {
		return "", DropValueTooLong
	}
	for _, r := range decoded {
		if r <= 0x1f || r == 0x7f {
			return "", DropInvalidValue
		}
	}
	return decoded, ""
}

func reservedKey(key string) bool {
	return strings.HasPrefix(key, ReservedPrefix)
}
