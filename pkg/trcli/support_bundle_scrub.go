package trcli

// Support-bundle scrub-by-profile (packet N13-P05-T03): the operator selects
// how aggressively credentials, PII and customer content are scrubbed from
// the diagnostics log entries.
//
// Profiles (pkg/auditlog.ParseScrubProfile, fail-closed):
//
//   - minimal:  credentials only — byte-identical to the N13-P05-T02
//     behavior (structural + textual secret masks, redaction_hits counter).
//     Customer content fields and PII survive (still credential-scrubbed).
//   - standard (default): minimal + PII masks (email, JWT, IPv4,
//     international phone) + customer-content fields dropped from entries,
//     each counted.
//   - strict: standard's content-field drops, credentials masked, and every
//     remaining JSON string value replaced by the fixed sentinel — only keys,
//     numbers, booleans and nulls survive. The operator's explicit choice for
//     machines where no customer-owned text may leave the host.
//
// Invariants carried over from T02 and preserved here:
//
//   - Org scoping runs BEFORE scrubbing: foreign-org and non-JSON lines are
//     excluded exactly as before, never emitted in any profile.
//   - Lines that undergo no change keep their original bytes (evidence
//     fidelity); every change is reflected in the counters.
//   - The profile is recorded in logs.scrub_profile of the emitted bundle, so
//     the archive documents what was applied.
//   - No timestamps, sorted-key re-marshal only, fully deterministic.
//
// The customer-content key list matches the loggerd wire vocabulary
// (payload / upstream_payload / upstream_response) plus common capture shapes
// (prompt, messages, completion, content, body variants, input/output,
// system). prompt_hash is deliberately NOT dropped: it is a digest and the
// correlation handle an incident bundle needs. Operational identifiers
// (request/trace IDs, UUIDs, hex digests) are deliberately not masked by the
// PII layer for the same reason — see pkg/auditlog/scrub_pii.go.

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/reireirei/yabanin/pkg/auditlog"
)

// supportDiagContentKey matches JSON object keys whose values are customer
// conversation content under the standard and strict profiles. Exact-key
// match: prompt_hash and system_fingerprint are never dropped.
var supportDiagContentKey = regexp.MustCompile(`(?i)^(payload|upstream_payload|upstream_response|prompt|prompt_text|messages|completion|content|request_body|response_body|body|system|input|output)$`)

// supportDiagScrubFlagError is the fixed failure category for an unknown
// explicit --scrub-profile value. Unlike the process-env content-profile
// parse (which degrades silently), a CLI flag typo refuses to produce a
// bundle: the operator must see the mismatch instead of silently receiving a
// different scrub level than intended.
const supportDiagScrubFlagError = "--scrub-profile must be one of minimal, standard, strict"

// supportDiagParseScrubFlag validates an explicit --scrub-profile value
// (trimmed, case-insensitive like the env content-profile parse) and returns
// the normalized profile. Empty resolves to the default (standard).
func supportDiagParseScrubFlag(value string) (auditlog.ScrubProfile, error) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch trimmed {
	case "", string(auditlog.ScrubProfileMinimal), string(auditlog.ScrubProfileStandard), string(auditlog.ScrubProfileStrict):
		return auditlog.ParseScrubProfile(trimmed), nil
	default:
		return "", errors.New(supportDiagScrubFlagError)
	}
}

// scrubSupportDiagLineByProfile applies the profile's scrub layers to one log
// line. Callers pass only JSON-object lines (org scoping already filtered the
// rest); non-object input falls back to the credentials-only redactor so the
// scrub layers can never become a bypass.
// Returns the scrubbed line, credential hits (redaction_hits semantics),
// content masks (PII under standard, full-value masks under strict) and the
// number of dropped customer-content fields.
func scrubSupportDiagLineByProfile(line string, profile auditlog.ScrubProfile) (out string, credHits, contentMasks, contentDropped int) {
	switch profile {
	case auditlog.ScrubProfileMinimal:
		out, credHits = redactSupportDiagLine(line)
		return out, credHits, 0, 0
	case auditlog.ScrubProfileStrict:
		return scrubSupportDiagLineStrict(line)
	default:
		return scrubSupportDiagLineStandard(line)
	}
}

// scrubSupportDiagLineStandard: content-field drops → structural + textual
// credential masks (T02 semantics) → PII masks over the marshaled text.
func scrubSupportDiagLineStandard(line string) (string, int, int, int) {
	credHits, contentDropped := 0, 0
	var tree map[string]any
	if err := json.Unmarshal([]byte(line), &tree); err != nil || tree == nil {
		// Unreachable through the collection path (org scoping only passes
		// JSON objects); credentials-only keeps the layer non-bypassable.
		out, hits := redactSupportDiagLine(line)
		return out, hits, 0, 0
	}
	supportDiagDropContentFields(tree, &contentDropped)
	masked, structurallyMasked := supportDiagMaskJSON(tree, &credHits)
	// Re-marshal whenever the tree changed at all: a content-only drop with
	// zero credential masks must still re-encode the line, or the original
	// bytes (with the dropped payload) would leak into the bundle.
	if contentDropped > 0 || structurallyMasked {
		// Marshal of a tree produced by json.Unmarshal cannot fail (no
		// unsupported value types can arise); on the defensive path the
		// textual passes below still apply to the current bytes.
		if encoded, err := json.Marshal(masked); err == nil {
			line = string(encoded)
		}
	}
	line = supportDiagMaskText(line, &credHits)
	line, piiMasks := auditlog.ScrubPII(line)
	return line, credHits, piiMasks, contentDropped
}

// scrubSupportDiagLineStrict: content-field drops → credential masks → every
// remaining JSON string value masked. Numbers, booleans, nulls and key names
// survive; no customer-owned text does.
func scrubSupportDiagLineStrict(line string) (string, int, int, int) {
	credHits, contentMasks, contentDropped := 0, 0, 0
	var tree map[string]any
	if err := json.Unmarshal([]byte(line), &tree); err != nil || tree == nil {
		out, hits := redactSupportDiagLine(line)
		return out, hits, 0, 0
	}
	supportDiagDropContentFields(tree, &contentDropped)
	supportDiagMaskJSON(tree, &credHits) // mutates the tree in place
	masked := supportDiagMaskAllStrings(tree, &contentMasks)
	encoded, err := json.Marshal(masked)
	if err != nil {
		// Unreachable for JSON-object input; fail closed to credentials-only
		// rather than emit partially scrubbed text.
		out, hits := redactSupportDiagLine(line)
		return out, hits, 0, 0
	}
	return string(encoded), credHits, contentMasks, contentDropped
}

// supportDiagDropContentFields removes every customer-content field from the
// tree, counting each removal. Descending stops at a removed value: a dropped
// subtree's internals are never walked (and never counted) — the whole value
// is gone.
func supportDiagDropContentFields(node any, removed *int) {
	switch typed := node.(type) {
	case map[string]any:
		for key, child := range typed {
			if supportDiagContentKey.MatchString(key) {
				delete(typed, key)
				*removed++
				continue
			}
			supportDiagDropContentFields(child, removed)
		}
	case []any:
		for _, child := range typed {
			supportDiagDropContentFields(child, removed)
		}
	}
}

// supportDiagMaskAllStrings replaces every non-empty string scalar that is
// not already the sentinel with the fixed mask, counting each replacement.
// Map keys, numbers, booleans and nulls are preserved.
func supportDiagMaskAllStrings(node any, masks *int) any {
	switch typed := node.(type) {
	case map[string]any:
		for key, child := range typed {
			typed[key] = supportDiagMaskAllStrings(child, masks)
		}
		return typed
	case []any:
		for i, child := range typed {
			typed[i] = supportDiagMaskAllStrings(child, masks)
		}
		return typed
	case string:
		if typed == "" || typed == auditlog.ScrubMaskedValue {
			return typed
		}
		*masks++
		return auditlog.ScrubMaskedValue
	default:
		return node
	}
}
