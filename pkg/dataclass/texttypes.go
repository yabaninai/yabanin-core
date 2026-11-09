// Package dataclass implements the E04-P01 contextual classification
// substrate: the supported text-type model (this file), the capability
// matrix watchdog, best-effort type detection, the org-scoped label
// taxonomy and its store. The package is core-Apache additive (dispatch
// E04-P01 §0); it reads other packages' public APIs only (pkg/labels,
// pkg/guardhooks) and owns no external transport.
package dataclass

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// SupportedTextType is one of the five text types the classification
// pipeline accepts (dispatch E04-P01-W01-C01). The set is closed: values
// outside it are refused with ErrUnsupportedType, never coerced.
type SupportedTextType string

const (
	// TextTypePlain is unstructured prose (chat, notes, descriptions).
	TextTypePlain SupportedTextType = "plain"
	// TextTypeMarkdown is Markdown-formatted prose.
	TextTypeMarkdown SupportedTextType = "markdown"
	// TextTypeJSON is a JSON document (object or array at the root).
	TextTypeJSON SupportedTextType = "json"
	// TextTypeCode is source code or configuration in a textual format.
	TextTypeCode SupportedTextType = "code"
	// TextTypeForm is structured key/value form input (web forms,
	// query-like payloads). It is never produced by DetectType — it is a
	// caller-declared type only, because "form" has no distinguishing
	// structural signature the sniffer can trust.
	TextTypeForm SupportedTextType = "form"
)

// Per-type byte limits. Limits are in BYTES of the raw UTF-8 payload, not
// runes: a RU multibyte sample consumes 2 bytes per Cyrillic rune and the
// limit is enforced on len(text). Each constant is pinned row-for-row by
// the capability matrix (W01-TEXT-TYPES-2026-11-07.md) through
// texttypes_matrix_test.go — changing one without the other fails the
// watchdog.
const (
	// MaxTextBytesPlain bounds plain prose: conversational payloads are
	// small; anything larger is a modeling smell, not prose.
	MaxTextBytesPlain = 64 * 1024
	// MaxTextBytesMarkdown bounds Markdown documents (long-form docs stay
	// under a quarter-megabyte).
	MaxTextBytesMarkdown = 256 * 1024
	// MaxTextBytesJSON bounds JSON documents (machine-generated, keeps
	// parser cost bounded).
	MaxTextBytesJSON = 256 * 1024
	// MaxTextBytesCode bounds code/config blobs (the largest of the set:
	// dumps and bundles live here).
	MaxTextBytesCode = 512 * 1024
	// MaxTextBytesForm bounds form payloads: same modeling assumption as
	// plain, fields arrive separately.
	MaxTextBytesForm = 64 * 1024
)

// Typed refusals for text validation. Every refusal is a typed error
// (never a panic, never a silent empty result) so callers can branch on
// the refusal class.
var (
	// ErrUnsupportedType: the caller-declared type is outside the closed
	// five-type set.
	ErrUnsupportedType = errors.New("dataclass: unsupported text type")
	// ErrTooLarge: the payload exceeds its type's byte limit. The boundary
	// is inclusive: len(text) == limit passes, limit+1 refuses.
	ErrTooLarge = errors.New("dataclass: text exceeds the type's byte limit")
	// ErrNotUTF8: the payload is not valid UTF-8.
	ErrNotUTF8 = errors.New("dataclass: text is not valid UTF-8")
	// ErrEmpty: the payload is empty or whitespace-only. Whitespace-only
	// input carries no classifiable signal and is refused rather than
	// treated as a valid empty document.
	ErrEmpty = errors.New("dataclass: text is empty or whitespace-only")
)

// SupportedTextTypes returns the closed type set in canonical order. The
// order is pinned by the matrix watchdog (row order in the artifact must
// match).
func SupportedTextTypes() []SupportedTextType {
	return []SupportedTextType{
		TextTypePlain,
		TextTypeMarkdown,
		TextTypeJSON,
		TextTypeCode,
		TextTypeForm,
	}
}

// ParseTextType validates s as one of the five supported types and returns
// it normalized. Anything else is ErrUnsupportedType.
func ParseTextType(s string) (SupportedTextType, error) {
	switch SupportedTextType(s) {
	case TextTypePlain, TextTypeMarkdown, TextTypeJSON, TextTypeCode, TextTypeForm:
		return SupportedTextType(s), nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedType, s)
	}
}

// MaxTextBytes returns the byte limit for the given type. Unknown types
// are refused with ErrUnsupportedType — a limit is never invented for an
// out-of-set type.
func MaxTextBytes(t SupportedTextType) (int, error) {
	switch t {
	case TextTypePlain:
		return MaxTextBytesPlain, nil
	case TextTypeMarkdown:
		return MaxTextBytesMarkdown, nil
	case TextTypeJSON:
		return MaxTextBytesJSON, nil
	case TextTypeCode:
		return MaxTextBytesCode, nil
	case TextTypeForm:
		return MaxTextBytesForm, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedType, t)
	}
}

// ValidateText validates a caller-declared payload against its type:
// first that the type is in the closed set, then that the payload is valid
// UTF-8, then that it fits the type's byte limit (bytes, inclusive
// boundary), and finally that it is not empty or whitespace-only. The
// order is fixed and observable: an unknown type wins over every payload
// concern, and a non-UTF-8 payload is reported as such even when it is
// also oversized. All refusals are typed errors.
func ValidateText(t SupportedTextType, text string) error {
	limit, err := MaxTextBytes(t)
	if err != nil {
		return err
	}
	if !utf8.ValidString(text) {
		return ErrNotUTF8
	}
	if len(text) > limit {
		return fmt.Errorf("%w: %d bytes > %d for %q", ErrTooLarge, len(text), limit, t)
	}
	if strings.TrimSpace(text) == "" {
		return ErrEmpty
	}
	return nil
}
