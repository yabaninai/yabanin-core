package dataclass

import (
	"errors"
	"strings"
	"testing"
)

// E04-P01-W01-C01 unit battery. Acceptance (dispatch §10):
//   - allowed scenario: every one of the five types is valid and parses;
//   - empty/unavailable: empty string, whitespace-only, oversized and
//     non-UTF-8 inputs are typed refusals — never a panic, never a silent
//     empty-result;
//   - limit boundaries are tested exactly at the value (== limit passes,
//     limit+1 refuses).

func TestTextTypes_AllFiveParseAndValidate(t *testing.T) {
	samples := map[SupportedTextType]string{
		TextTypePlain:    "Quarterly review notes",
		TextTypeMarkdown: "# Heading\n\n- item",
		TextTypeJSON:     `{"k":[1,2]}`,
		TextTypeCode:     "func main() {}",
		TextTypeForm:     "name=Ada&role=admin",
	}
	for _, ty := range SupportedTextTypes() {
		t.Run(string(ty), func(t *testing.T) {
			parsed, err := ParseTextType(string(ty))
			if err != nil {
				t.Fatalf("supported type %q must parse: %v", ty, err)
			}
			if parsed != ty {
				t.Fatalf("round-trip mismatch: got %q want %q", parsed, ty)
			}
			if _, err := MaxTextBytes(ty); err != nil {
				t.Fatalf("supported type %q must have a limit: %v", ty, err)
			}
			sample, ok := samples[ty]
			if !ok {
				t.Fatalf("missing valid sample for %q", ty)
			}
			if err := ValidateText(ty, sample); err != nil {
				t.Fatalf("allowed scenario: valid %q sample must validate: %v", ty, err)
			}
		})
	}
}

func TestTextTypes_ParseRefusesUnknown(t *testing.T) {
	for _, s := range []string{"", "plain ", "PLAIN", "Plain", "html", "binary", "plain\n"} {
		if _, err := ParseTextType(s); !errors.Is(err, ErrUnsupportedType) {
			t.Errorf("ParseTextType(%q) error = %v, want ErrUnsupportedType", s, err)
		}
	}
}

func TestTextTypes_LimitsExactBoundary(t *testing.T) {
	cases := []struct {
		typ   SupportedTextType
		limit int
	}{
		{TextTypePlain, MaxTextBytesPlain},
		{TextTypeMarkdown, MaxTextBytesMarkdown},
		{TextTypeJSON, MaxTextBytesJSON},
		{TextTypeCode, MaxTextBytesCode},
		{TextTypeForm, MaxTextBytesForm},
	}
	for _, tc := range cases {
		t.Run(string(tc.typ), func(t *testing.T) {
			got, err := MaxTextBytes(tc.typ)
			if err != nil {
				t.Fatalf("MaxTextBytes(%q): %v", tc.typ, err)
			}
			if got != tc.limit {
				t.Fatalf("MaxTextBytes(%q) = %d, want %d", tc.typ, got, tc.limit)
			}
			// Exactly at the limit: passes (inclusive boundary).
			if err := ValidateText(tc.typ, strings.Repeat("a", tc.limit)); err != nil {
				t.Fatalf("len == limit must pass for %q: %v", tc.typ, err)
			}
			// One byte over: typed refusal.
			err = ValidateText(tc.typ, strings.Repeat("a", tc.limit+1))
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("len == limit+1 for %q: error = %v, want ErrTooLarge", tc.typ, err)
			}
			// One byte under: passes.
			if err := ValidateText(tc.typ, strings.Repeat("a", tc.limit-1)); err != nil {
				t.Fatalf("len == limit-1 must pass for %q: %v", tc.typ, err)
			}
		})
	}
}

func TestTextTypes_LimitIsBytesNotRunes(t *testing.T) {
	// "ф" encodes to 2 bytes in UTF-8: 32768 Cyrillic runes = 65536 bytes —
	// exactly MaxTextBytesPlain, and it must refuse even though the RUNE
	// count (32768) is well under 65536. The RU/EN multibyte note from the
	// capability matrix, pinned as behavior.
	const runes = MaxTextBytesPlain / 2
	if err := ValidateText(TextTypePlain, strings.Repeat("ф", runes)); err != nil {
		t.Fatalf("exactly-limit multibyte payload must pass the inclusive boundary: %v", err)
	}
	err := ValidateText(TextTypePlain, strings.Repeat("ф", runes+1))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("65538-byte multibyte payload: error = %v, want ErrTooLarge", err)
	}
	// EN ASCII stays 1 byte per rune at the same boundary.
	if err := ValidateText(TextTypePlain, strings.Repeat("a", MaxTextBytesPlain)); err != nil {
		t.Fatalf("ASCII at limit must pass: %v", err)
	}
}

func TestTextTypes_EmptyAndWhitespaceRefused(t *testing.T) {
	for _, text := range []string{"", " ", "\t", "\n", "  \n\t \r\n "} {
		for _, ty := range SupportedTextTypes() {
			err := ValidateText(ty, text)
			if !errors.Is(err, ErrEmpty) {
				t.Errorf("ValidateText(%q, %q) error = %v, want ErrEmpty", ty, text, err)
			}
		}
	}
}

func TestTextTypes_NonUTF8Refused(t *testing.T) {
	invalid := []string{
		"\xff",                     // lone continuation byte
		"ok\xfeok",                 // embedded invalid byte
		"\xc3\x28",                 // truncated 2-byte sequence
		"\xed\xa0\x80",             // surrogate half (CESU-ish, invalid UTF-8)
		strings.Repeat("\x80", 64), // run of bare continuation bytes
	}
	for _, text := range invalid {
		for _, ty := range SupportedTextTypes() {
			err := ValidateText(ty, text)
			if !errors.Is(err, ErrNotUTF8) {
				t.Errorf("ValidateText(%q, %q) error = %v, want ErrNotUTF8", ty, text, err)
			}
		}
	}
}

func TestTextTypes_CheckOrderIsFixedAndObservable(t *testing.T) {
	// Unknown type wins over every payload concern — including invalid
	// UTF-8 and oversize.
	err := ValidateText(SupportedTextType("vendor"), "\xff"+strings.Repeat("a", 10*1024*1024))
	if !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("unknown type must be reported first, got %v", err)
	}
	// Non-UTF-8 is reported before size, even when the payload is also
	// oversized for its type.
	err = ValidateText(TextTypePlain, "\xff"+strings.Repeat("a", MaxTextBytesPlain+8))
	if !errors.Is(err, ErrNotUTF8) {
		t.Fatalf("non-UTF-8 must be reported before oversize, got %v", err)
	}
	// Oversize is reported before emptiness concerns: an oversized payload
	// of spaces is ErrTooLarge, not ErrEmpty.
	err = ValidateText(TextTypePlain, strings.Repeat(" ", MaxTextBytesPlain+1))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized whitespace must be ErrTooLarge (size before emptiness), got %v", err)
	}
}

func TestTextTypes_TypedErrorsAreDistinct(t *testing.T) {
	all := []error{ErrUnsupportedType, ErrTooLarge, ErrNotUTF8, ErrEmpty}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("distinct refusal classes must not alias: %v covers %v", a, b)
			}
		}
	}
	// The wrapping keeps the class matchable.
	if _, err := ParseTextType("nope"); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("wrapped refusal must stay errors.Is-matchable: %v", err)
	}
	if err := ValidateText(TextTypePlain, strings.Repeat("a", MaxTextBytesPlain+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("wrapped ErrTooLarge must stay errors.Is-matchable: %v", err)
	}
}
