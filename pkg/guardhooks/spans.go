package guardhooks

// FIX-01 (CA-01, audit 2026-10-23): redact-mode mutation must honor every
// validated evaluator span, not only the matches the built-in regexes find
// again. Custom pack findings previously produced a hit (secret:redact) while
// the secret stayed in the forwarded text.
//
// Safety contract of this file:
//   - hit-eligible findings (the same filter as hit accounting in HookScan /
//     Hook.Apply) become replacement spans on the original text;
//   - overlapping or touching spans merge into deterministic unions, so no
//     fragment survives between two findings and the output never depends on
//     detector ordering;
//   - a span that cannot be replaced safely (out of range, zero-width, or a
//     boundary that would split a multi-byte UTF-8 rune) fails the whole
//     redaction closed — the caller denies instead of emitting corrupted bytes
//     or an unchanged secret labelled as redacted;
//   - when the input is a valid JSON document, a mutation that would no longer
//     be valid JSON is refused, keeping payloads and tool arguments intact.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// scanConfidence is the finding-confidence threshold shared by hit accounting
// (Hook.Scan / Hook.Apply) and span redaction: only findings at or above it
// count. Keeping both on one constant guarantees every reported redact hit has
// a corresponding redaction span.
const scanConfidence = 0.9

// redactionSpan is a half-open byte interval [start,end) of the scanned text
// with the replacement token for its category.
type redactionSpan struct {
	start, end int
	repl       string
}

// redactByFindings replaces every hit-eligible detector finding span in text
// with its category token and returns the mutated text. It is the pack-span
// half of redact-mode mutation; built-in regexes still run afterwards (in
// Hook.Redact) for credential-keyed values (key-preserving, MC-2) and
// sub-threshold formats. An error means "unsafe to mutate": the caller must
// fail closed, never forward text as a successful redaction.
func redactByFindings(text string, findings []Finding) (string, error) {
	spans := redactionSpans(text, findings)
	if len(spans) == 0 {
		return text, nil
	}
	merged := mergeRedactionSpans(spans)
	for _, span := range merged {
		if err := validateRedactionSpan(text, span); err != nil {
			return "", err
		}
	}
	mutated := applyRedactionSpans(text, merged)
	if !json.Valid([]byte(text)) {
		return mutated, nil
	}
	if !json.Valid([]byte(mutated)) {
		return "", fmt.Errorf("guard redaction: mutation would corrupt JSON document (merged spans %v)", merged)
	}
	return mutated, nil
}

// redactionSpans collects replacement spans for hit-eligible findings using
// the same filter as hit accounting: confidence >= scanConfidence, the INN
// checksum filter for the legacy 10/12-digit namespace, and categories that
// have a redaction token. CatCredential is excluded: credential-keyed values
// are mutated by the key-preserving mutator in Redact (MC-2), not raw spans.
func redactionSpans(text string, findings []Finding) []redactionSpan {
	spans := make([]redactionSpan, 0, len(findings))
	for _, f := range findings {
		if f.Confidence < scanConfidence {
			continue
		}
		if f.Category == CatCredential {
			continue
		}
		repl, ok := redactions[f.Category]
		if !ok {
			// Categories without a token never produce hits either, so there
			// is no reported redaction that a span would need to honor.
			continue
		}
		// The 12-digit card checksum is not the legacy INN check; a number the
		// existing detector rejects must stay unredacted (same rule as hits).
		// Out-of-range spans skip the checksum here on purpose: the validator
		// below rejects them closed instead of silently keeping the span.
		if (f.Detector == "ru:inn10" || f.Detector == "ru:inn12") &&
			f.Start >= 0 && f.End <= len(text) && f.End >= f.Start &&
			!validateINN(text[f.Start:f.End]) {
			continue
		}
		spans = append(spans, redactionSpan{start: f.Start, end: f.End, repl: repl})
	}
	return spans
}

// mergeRedactionSpans sorts spans deterministically and merges overlapping or
// touching intervals into unions. The earliest-starting (then longest, then
// lexicographically smallest token) span's replacement wins, so the output
// never depends on detector registration or finding order.
func mergeRedactionSpans(spans []redactionSpan) []redactionSpan {
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		if spans[i].end != spans[j].end {
			return spans[i].end > spans[j].end
		}
		return spans[i].repl < spans[j].repl
	})
	merged := make([]redactionSpan, 0, len(spans))
	current := spans[0]
	for _, next := range spans[1:] {
		if next.start <= current.end {
			if next.end > current.end {
				current.end = next.end
			}
			continue // current keeps its replacement: the deterministic winner
		}
		merged = append(merged, current)
		current = next
	}
	return append(merged, current)
}

// validateRedactionSpan rejects spans a byte replacement cannot apply safely:
// bounds outside the text, zero-width intervals, and boundaries that would
// split a multi-byte UTF-8 rune. Findings are byte offsets (see Finding); a
// boundary byte must therefore start a rune to cut there.
func validateRedactionSpan(text string, span redactionSpan) error {
	if span.start < 0 || span.end > len(text) || span.start >= span.end {
		return fmt.Errorf("guard redaction: detector span [%d,%d) out of range for %d-byte text", span.start, span.end, len(text))
	}
	if !utf8.RuneStart(text[span.start]) {
		return fmt.Errorf("guard redaction: span start %d splits a multi-byte rune", span.start)
	}
	if span.end < len(text) && !utf8.RuneStart(text[span.end]) {
		return fmt.Errorf("guard redaction: span end %d splits a multi-byte rune", span.end)
	}
	return nil
}

// applyRedactionSpans replaces merged, validated spans left to right in one
// pass over the original offsets.
func applyRedactionSpans(text string, spans []redactionSpan) string {
	var b strings.Builder
	b.Grow(len(text))
	prev := 0
	for _, span := range spans {
		b.WriteString(text[prev:span.start])
		b.WriteString(span.repl)
		prev = span.end
	}
	b.WriteString(text[prev:])
	return b.String()
}

// unsafeCredentialFindings implements the MC-2 owner decision (2026-10-24,
// wave-10 gate: fail-closed deny — never leave a secret under a redact
// claim). CatCredential is excluded from span redaction (redactionSpans):
// credential-keyed values are mutated only by the key-preserving built-in
// mutator (credentialKeyRe). A custom-pack credential finding whose span is
// not fully covered by one built-in key-value match would survive that
// mutator while a credential:redact hit was reported, so redact mode must
// deny the request instead of forwarding a reported-but-unredacted secret.
// Built-in credential findings are always exact key-value matches, so this
// never fires for them. Sub-threshold findings are skipped on purpose: they
// produce no hit and must never widen audit into enforcement.
func unsafeCredentialFindings(text string, findings []Finding) bool {
	matches := credentialKeyRe.FindAllStringIndex(text, -1)
	for _, f := range findings {
		if f.Category != CatCredential || f.Confidence < scanConfidence {
			continue
		}
		if !credentialShapeCovers(matches, f.Start, f.End) {
			return true
		}
	}
	return false
}

// credentialShapeCovers reports whether the byte span [start,end) lies fully
// inside one of the built-in credential-key matches (sorted, non-overlapping,
// as FindAllStringIndex returns them). Empty spans are never covered: a
// reported credential that no mutation addresses must fail closed.
func credentialShapeCovers(matches [][]int, start, end int) bool {
	if start >= end {
		return false
	}
	i := sort.Search(len(matches), func(i int) bool { return matches[i][1] > start })
	return i < len(matches) && matches[i][0] <= start && end <= matches[i][1]
}
