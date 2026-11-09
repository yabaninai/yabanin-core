package dataclass

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// ErrUnknownType is the fail-closed refusal of the type sniffer: the input
// is empty, carries no classifiable identity, or satisfies the signal
// thresholds of more than one type at once. Ambiguity is NEVER resolved by
// guessing a default (dispatch E04-P01-W01-C03 AC).
var ErrUnknownType = errors.New("dataclass: text type is unknown or ambiguous")

// DetectType sniffs the type of an already-validated text payload
// (ValidateText runs first at the caller). It is a pure, deterministic
// best-effort classifier over structural signals:
//
//   - json:    the payload is valid JSON with an object or array at the
//     root (scalar-root JSON — bare strings/numbers — has no structural
//     identity and is not claimed; it falls through to the plain rules);
//   - markdown: at least two of {ATX heading line, fenced block line,
//     list (>=2 bullet/numbered lines), inline link};
//   - code:    at least two of {>=2 semicolon-terminated lines, >=2
//     C-style comment lines, a brace block spanning lines, an
//     unambiguous starter keyword line (func/def/class/package/import)};
//   - plain:   no structural signals at all AND at least one letter.
//
// When exactly one category reaches its threshold, that type is returned.
// When two or more do, the verdict is ErrUnknownType (a Markdown document
// with an embedded fenced code block is the canonical honest ambiguity).
// When none do, a letter-bearing text is plain; everything else — empty,
// whitespace-only, digits/punctuation-only — is ErrUnknownType.
//
// TextTypeForm is NEVER returned: form payloads have no structural
// signature the sniffer could trust, so the type is caller-declared only.
func DetectType(text string) (SupportedTextType, error) {
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("%w: empty or whitespace-only input", ErrUnknownType)
	}
	isJSON := json.Valid([]byte(text)) && jsonRootIsObjectOrArray(text)
	isMarkdown := markdownSignalCount(text) >= 2
	isCode := codeSignalCount(text) >= 2

	hits := 0
	for _, hit := range []bool{isJSON, isMarkdown, isCode} {
		if hit {
			hits++
		}
	}
	switch hits {
	case 0:
		if hasLetter(text) {
			return TextTypePlain, nil
		}
		return "", fmt.Errorf("%w: no letters and no structural signal", ErrUnknownType)
	case 1:
		switch {
		case isJSON:
			return TextTypeJSON, nil
		case isMarkdown:
			return TextTypeMarkdown, nil
		default:
			return TextTypeCode, nil
		}
	default:
		return "", fmt.Errorf("%w: %d type thresholds matched at once", ErrUnknownType, hits)
	}
}

// jsonRootIsObjectOrArray reports whether the first non-space byte of the
// payload opens a JSON object or array. json.Valid has already accepted
// the payload when this runs.
func jsonRootIsObjectOrArray(text string) bool {
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// markdownSignalCount counts the independent Markdown structural signals
// present in the text (each signal counts at most once).
func markdownSignalCount(text string) int {
	signals := 0
	listLines := 0
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		switch {
		case isATXHeading(trimmed):
			signals |= 1 << 0
		case strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~"):
			signals |= 1 << 1
		}
		if isListLine(trimmed) {
			listLines++
		}
		if hasInlineLink(line) {
			signals |= 1 << 2
		}
	}
	if listLines >= 2 {
		signals |= 1 << 3
	}
	return bitsSetCount(signals)
}

// codeSignalCount counts the independent code structural signals present
// in the text (each signal counts at most once). Prose starters like
// "if …" / "for example" are deliberately NOT signals: they occur in
// ordinary chat and would misclassify plain text.
func codeSignalCount(text string) int {
	signals := 0
	semicolonLines, commentLines := 0, 0
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, ";") {
			semicolonLines++
		}
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			commentLines++
		}
		if isCodeStarterLine(trimmed) {
			signals |= 1 << 0
		}
	}
	if semicolonLines >= 2 {
		signals |= 1 << 1
	}
	if commentLines >= 2 {
		signals |= 1 << 2
	}
	if hasMultilineBraceBlock(text) {
		signals |= 1 << 3
	}
	return bitsSetCount(signals)
}

// isATXHeading: '#', '##' … '######' followed by a space (or a lone run of
// '#'s at end of line, the empty-heading form). A '#' glued to text
// ('#tag') is chat, not a heading.
func isATXHeading(line string) bool {
	hashes := 0
	for hashes < len(line) && line[hashes] == '#' {
		hashes++
	}
	if hashes == 0 || hashes > 6 {
		return false
	}
	rest := line[hashes:]
	return rest == "" || strings.HasPrefix(rest, " ")
}

// isListLine: a bullet item ("- ", "* ", "+ ") or an ordered item
// ("1. ", "23) ") after leading whitespace.
func isListLine(line string) bool {
	if line == "" {
		return false
	}
	if len(line) >= 2 && (line[0] == '-' || line[0] == '*' || line[0] == '+') && line[1] == ' ' {
		return true
	}
	digits := 0
	for digits < len(line) && line[digits] >= '0' && line[digits] <= '9' {
		digits++
	}
	if digits == 0 || digits > 9 || digits == len(line) {
		return false
	}
	return line[digits] == '.' || line[digits] == ')'
}

// hasInlineLink: a "[text](url)" construct on the line.
func hasInlineLink(line string) bool {
	closeIdx := strings.Index(line, "](")
	if closeIdx <= 0 {
		return false
	}
	return strings.Contains(line[:closeIdx], "[")
}

// isCodeStarterLine: unambiguous code declarations — keywords that do not
// open ordinary prose lines.
func isCodeStarterLine(line string) bool {
	for _, kw := range []string{"func ", "def ", "class ", "package ", "import ", "fn ", "pub fn "} {
		if strings.HasPrefix(line, kw) {
			return true
		}
	}
	return false
}

// hasMultilineBraceBlock: some '{' is closed by a '}' on a LATER line —
// block structure, not an inline brace pair.
func hasMultilineBraceBlock(text string) bool {
	type open struct {
		line int
	}
	var stack []open
	for lineNo, line := range strings.Split(text, "\n") {
		for _, r := range line {
			switch r {
			case '{':
				stack = append(stack, open{line: lineNo})
			case '}':
				if len(stack) > 0 {
					last := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					if last.line < lineNo {
						return true
					}
				}
			}
		}
	}
	return false
}

// hasLetter: at least one Unicode letter (Latin or Cyrillic alike) — the
// minimum identity a "plain" verdict requires.
func hasLetter(text string) bool {
	for _, r := range text {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func bitsSetCount(v int) int {
	n := 0
	for v != 0 {
		v &= v - 1
		n++
	}
	return n
}
