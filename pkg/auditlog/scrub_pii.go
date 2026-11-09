package auditlog

// Profile-driven PII scrubbing primitives (packet N13-P05-T03).
//
// These helpers mask personally identifiable shapes — email addresses, JWTs,
// IPv4 addresses and international phone numbers — in free diagnostic text.
// They are consumed by the trcli support-bundle scrub-by-profile layer and are
// kept here so the durable audit redaction (redact.go) and any future
// diagnostic surface share one implementation.
//
// Deliberate scope limits (documented limitations, not oversights):
//   - Operational identifiers (request IDs, trace IDs, UUIDs, hex digests) are
//     NOT masked: they are exactly what an incident bundle needs to correlate
//     events, and a bundle stripped of them cannot reproduce an incident.
//   - Only international (+-prefixed) phone shapes are masked; national
//     formats are too ambiguous (they collide with ordinary digit runs).
//   - IP-address-shaped version strings (four dotted octets, e.g. "1.2.3.4")
//     are masked too: fail-safe beats precise here, and the mask counter
//     makes the cost visible in the bundle.
//
// The scrubber is idempotent: applying it to already-masked text neither
// changes the text nor increases the hit count.

import (
	"regexp"
	"strconv"
	"strings"
)

// ScrubMaskedValue is the single fixed mask sentinel used across the
// credential (redact.go) and PII (this file) scrubbers.
const ScrubMaskedValue = "[REDACTED]"

// ScrubProfile selects how aggressively diagnostic text is scrubbed.
//   - minimal: credentials only; PII and customer content survive.
//   - standard (default): credentials + PII masks; customer-content fields
//     are dropped by the caller.
//   - strict: no customer-owned text survives (the caller masks all string
//     values; PII scrubbing is implied).
type ScrubProfile string

// Profile values emitted in bundles and accepted by ParseScrubProfile.
const (
	ScrubProfileMinimal  ScrubProfile = "minimal"
	ScrubProfileStandard ScrubProfile = "standard"
	ScrubProfileStrict   ScrubProfile = "strict"
)

// ParseScrubProfile resolves a profile value the same fail-closed way the
// process-env content profile is resolved: trimmed, case-insensitive, empty
// and unknown values resolve to the safer default (standard for empty,
// strict for unknown). Callers that need to reject typos outright (CLI
// flags) validate the raw value before calling this.
func ParseScrubProfile(value string) ScrubProfile {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(ScrubProfileMinimal):
		return ScrubProfileMinimal
	case string(ScrubProfileStandard), "":
		return ScrubProfileStandard
	default:
		return ScrubProfileStrict
	}
}

var (
	scrubEmailPattern = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	scrubJWTPattern   = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	scrubIPv4Pattern  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	scrubPhonePattern = regexp.MustCompile(`\+\d{1,3}[ -]?\(?\d{1,4}\)?(?:[ -]?\d{1,4}){2,4}\b`)
)

// ScrubPII masks PII-shaped substrings in text and returns the scrubbed text
// plus the number of individual masks applied. Empty text is returned
// unchanged. Safe to apply repeatedly (idempotent).
func ScrubPII(text string) (string, int) {
	if strings.TrimSpace(text) == "" {
		return text, 0
	}
	hits := 0
	out := scrubEmailPattern.ReplaceAllStringFunc(text, func(match string) string {
		hits++
		return ScrubMaskedValue
	})
	out = scrubJWTPattern.ReplaceAllStringFunc(out, func(match string) string {
		if strings.Contains(match, ScrubMaskedValue) {
			return match
		}
		hits++
		return ScrubMaskedValue
	})
	out = scrubPhonePattern.ReplaceAllStringFunc(out, func(match string) string {
		if strings.Contains(match, ScrubMaskedValue) {
			return match
		}
		hits++
		return ScrubMaskedValue
	})
	out = scrubIPv4Pattern.ReplaceAllStringFunc(out, func(match string) string {
		if strings.Contains(match, ScrubMaskedValue) {
			return match
		}
		if !scrubValidIPv4(match) {
			return match
		}
		hits++
		return ScrubMaskedValue
	})
	return out, hits
}

// scrubValidIPv4 reports whether every dotted octet parses to 0..255.
func scrubValidIPv4(match string) bool {
	for _, octet := range strings.Split(match, ".") {
		value, err := strconv.Atoi(octet)
		if err != nil || value < 0 || value > 255 {
			return false
		}
	}
	return true
}
