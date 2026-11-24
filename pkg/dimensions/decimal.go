package dimensions

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Working limits for decimal quantities: revisable implementation
// assumptions, not an owner tariff. Inputs are rejected, never silently
// rounded, when they exceed any of them. The fractional-digit and byte
// limits apply to the input as written — trailing zeros buy nothing back.
const (
	maxInputBytes        = 128
	maxSignificantDigits = 38
	maxFractionalDigits  = 18
)

var (
	// ErrSyntax reports a string that is not a plain non-negative decimal.
	ErrSyntax = errors.New("dimensions: malformed decimal quantity")
	// ErrLimit reports an input beyond the working limits (input bytes,
	// significant digits or fractional digits).
	ErrLimit = errors.New("dimensions: decimal quantity exceeds limits")
	// ErrOverflow reports an exact addition whose result would exceed the
	// significant-digit limit; it is never rounded to fit.
	ErrOverflow = errors.New("dimensions: decimal addition exceeds significance limit")
	// ErrJSONNumber reports a decimal delivered as a JSON number: decoding
	// would pass through float64, a forbidden carrier that loses decimal
	// intent. Exact decimals travel only as quoted strings.
	ErrJSONNumber = errors.New("dimensions: decimal quantity must be a quoted JSON string")
)

// Decimal is an exact non-negative decimal: value = digits * 10^-scale,
// stored as normalized ASCII digits. Leading zeros are stripped (zero is
// {"0", 0}) and trailing fraction zeros are removed, so every constructor
// produces one canonical representation. The struct zero value (empty
// digits) is a second representation of zero marking a never-set field:
// == proves representation identity only — use Equal/Compare, which treat
// "" and "0" as the same zero. No float64 ever passes through this type.
type Decimal struct {
	digits string
	scale  int
}

// ParseDecimal converts a plain decimal string ("0.02", "3", ".5", "5.") to
// an exact Decimal. The grammar is digits with at most one '.', integer part
// optional but at least one digit overall. Signs (including '-'), exponents,
// whitespace, commas and any other decoration are ErrSyntax; inputs over 128
// bytes, 38 significant digits (leading zeros stripped) or 18 fractional
// digits are ErrLimit. Callers must treat every error as "unknown quantity",
// never zero. Canonical values round-trip: ParseDecimal(d.String()) == d.
func ParseDecimal(s string) (Decimal, error) {
	if len(s) > maxInputBytes {
		return Decimal{}, fmt.Errorf("%w: input exceeds %d bytes: %q", ErrLimit, maxInputBytes, s)
	}
	intPart, fracPart, err := splitDecimalParts(s)
	if err != nil {
		return Decimal{}, err
	}
	if err := checkDigitLimits(s, intPart, fracPart); err != nil {
		return Decimal{}, err
	}
	return newDecimal(intPart+fracPart, len(fracPart)), nil
}

// splitDecimalParts splits s at its single '.'; "NaN", "Infinity", "0x10",
// exponents, signs and separators fail here on charset.
func splitDecimalParts(s string) (intPart, fracPart string, err error) {
	dot := -1
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
		case c == '.' && dot < 0:
			dot = i
		default:
			return "", "", fmt.Errorf("%w: %q", ErrSyntax, s)
		}
	}
	if dot < 0 {
		if len(s) == 0 {
			return "", "", fmt.Errorf("%w: empty input", ErrSyntax)
		}
		return s, "", nil
	}
	if len(s) == 1 {
		return "", "", fmt.Errorf("%w: %q", ErrSyntax, s)
	}
	return s[:dot], s[dot+1:], nil
}

// checkDigitLimits enforces the input-as-written assumptions: fractional
// digits by literal count, significant digits after stripping leading zeros.
func checkDigitLimits(s, intPart, fracPart string) error {
	if len(fracPart) > maxFractionalDigits {
		return fmt.Errorf("%w: more than %d fractional digits in %q", ErrLimit, maxFractionalDigits, s)
	}
	if significantDigits(intPart, fracPart) > maxSignificantDigits {
		return fmt.Errorf("%w: more than %d significant digits in %q", ErrLimit, maxSignificantDigits, s)
	}
	return nil
}

// significantDigits counts digits with leading zeros stripped: "0.02" has
// one significant digit, "12.34" has four.
func significantDigits(intPart, fracPart string) int {
	all := intPart + fracPart
	for i := 0; i < len(all); i++ {
		if all[i] != '0' {
			return len(all) - i
		}
	}
	return 0
}

// newDecimal normalizes digits*10^-scale into the canonical form so equal
// values have exactly one representation.
func newDecimal(digits string, scale int) Decimal {
	for scale > 0 && len(digits) > 0 && digits[len(digits)-1] == '0' {
		digits = digits[:len(digits)-1]
		scale--
	}
	start := 0
	for start+1 < len(digits) && digits[start] == '0' {
		start++
	}
	digits = digits[start:]
	if digits == "" {
		return Decimal{digits: "0"}
	}
	return Decimal{digits: digits, scale: scale}
}

// String returns the canonical form: trailing fraction zeros stripped
// ("0.0200" → "0.02", "3.0" → "3"), zero as "0".
func (d Decimal) String() string {
	if IsZero(d) {
		return "0"
	}
	if d.scale <= 0 {
		return d.digits
	}
	pos := len(d.digits) - d.scale
	if pos <= 0 {
		return "0." + strings.Repeat("0", -pos) + d.digits
	}
	return d.digits[:pos] + "." + d.digits[pos:]
}

// IsZero reports whether d is the exact value zero (including the struct
// zero value, the never-set marker). An absent quantity is a nil pointer —
// a distinct state this method cannot express.
func IsZero(d Decimal) bool {
	return d.digits == "" || d.digits == "0"
}

// Equal reports whether a and b represent the same exact value.
func Equal(a, b Decimal) bool {
	return Compare(a, b) == 0
}

// Compare returns -1, 0 or 1 by exact numeric order: both values are padded
// with zeros to the larger scale, then compared by digit-string length and
// lexicographically (all values are non-negative).
func Compare(a, b Decimal) int {
	za, zb := IsZero(a), IsZero(b)
	if za || zb {
		switch {
		case za && zb:
			return 0
		case za:
			return -1
		default:
			return 1
		}
	}
	scale := max(a.scale, b.scale)
	ai := alignDigits(a, scale)
	bi := alignDigits(b, scale)
	if len(ai) != len(bi) {
		if len(ai) < len(bi) {
			return -1
		}
		return 1
	}
	return strings.Compare(ai, bi)
}

func alignDigits(d Decimal, scale int) string {
	return d.digits + strings.Repeat("0", scale-d.scale)
}

// Add returns the exact sum a+b. A result beyond maxSignificantDigits is an
// ErrOverflow, never a wrap or a silent rounding.
func Add(a, b Decimal) (Decimal, error) {
	scale := max(a.scale, b.scale)
	sum := addDigitStrings(alignDigits(a, scale), alignDigits(b, scale))
	d := newDecimal(sum, scale)
	if d.significantDigits() > maxSignificantDigits {
		return Decimal{}, fmt.Errorf("%w: %s + %s", ErrOverflow, a, b)
	}
	return d, nil
}

// addDigitStrings adds two non-negative digit strings exactly, right to
// left, carrying as digits require.
func addDigitStrings(a, b string) string {
	out := make([]byte, 0, max(len(a), len(b))+1)
	carry := 0
	i, j := len(a)-1, len(b)-1
	for i >= 0 || j >= 0 || carry > 0 {
		n := carry
		if i >= 0 {
			n += int(a[i] - '0')
			i--
		}
		if j >= 0 {
			n += int(b[j] - '0')
			j--
		}
		out = append(out, byte('0'+n%10))
		carry = n / 10
	}
	if len(out) == 0 {
		return "0"
	}
	for l, r := 0, len(out)-1; l < r; l, r = l+1, r-1 {
		out[l], out[r] = out[r], out[l]
	}
	return string(out)
}

// significantDigits of an already-stored Decimal (leading zeros stripped at
// construction, so this only re-derives the count).
func (d Decimal) significantDigits() int {
	n := 0
	for n < len(d.digits) && d.digits[n] == '0' {
		n++
	}
	return len(d.digits) - n
}

// MarshalJSON emits the canonical form as a quoted JSON string.
func (d Decimal) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON accepts only a quoted decimal string. A JSON number is
// rejected with ErrJSONNumber because encoding/json decodes numbers through
// float64 — a forbidden carrier for exact quantities.
func (d *Decimal) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || data[0] != '"' {
		return fmt.Errorf("%w: %s", ErrJSONNumber, data)
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("dimensions: decimal quantity string: %w", err)
	}
	v, err := ParseDecimal(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}
