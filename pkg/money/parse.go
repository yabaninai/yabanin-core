package money

import (
	"errors"
	"fmt"
	"math"
)

// ErrSyntax reports a string that is not a plain decimal USD amount.
// ParseUSD accepts only optional digits, one optional decimal point and
// fraction digits ("4", "12.34", "0.0075", ".5", "5."); signs other than a
// leading minus, exponents, whitespace, thousands separators and currency
// symbols are syntax errors. Callers that receive strings with such
// decorations must strip them before parsing — a silent partial parse would
// misprice.
var ErrSyntax = errors.New("money: malformed decimal amount")

// maxIntUSD is the largest whole-USD magnitude representable as MicroUSD
// (the integer part of MaxUSD); scaling it by MicroPerUSD stays within int64.
const maxIntUSD int64 = math.MaxInt64 / MicroPerUSD

// maxFracMicro is the largest fraction part (in micro-USD) that keeps
// maxIntUSD*MicroPerUSD + fraction within int64: 9223372036854775807 -
// 9223372036854000000 = 775807.
const maxFracMicro int64 = math.MaxInt64 - maxIntUSD*MicroPerUSD

// ParseUSD converts a decimal USD amount written as text to an exact
// micro-USD amount, rounding half away from zero at the micro boundary.
// It is the exact string entry point for USD amounts that arrive as text
// (configuration literals, quotes carried as decimal strings): unlike
// FromUSD it never passes through a binary-float carrier, so a decimal
// such as "0.0001245" (124.5 µUSD) converts by decimal intent — 125 µUSD —
// where the float64 carrier of the same literal double-rounds to 124 µUSD.
//
// Rounding policy matches the package: half away from zero at the micro
// scale, sticky beyond the seventh fraction digit ("0.000000500000000001"
// rounds up, "0.000000499999999999" rounds down).
//
// Currency: amounts are USD by contract — price files declare currency=USD
// (pkg/pricing validation rejects any other currency), and no other unit may
// enter the micro-USD core under a USD name.
//
// Validity: a leading minus is rejected as ErrNegative (money amounts are
// non-negative; "-0" is a sign assertion, not a zero), amounts beyond the
// exact decimal capacity — including a rounded half that would exceed
// MaxInt64 µUSD, e.g. "9223372036854.7758075" — are rejected as ErrRange,
// and any other malformed input as ErrSyntax. Callers must treat every
// error as "unknown price", not zero.
func ParseUSD(s string) (MicroUSD, error) {
	i := 0
	if i < len(s) && s[i] == '-' {
		return 0, fmt.Errorf("%w: %q", ErrNegative, s)
	}
	var (
		intPart    int64
		intDigits  int
		frac       int64
		fracDigits int
		roundDigit byte = '0'
		sticky     bool
		inFrac     bool
	)
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			d := int64(c - '0')
			if !inFrac {
				// Keep intPart <= maxIntUSD so the final scaling
				// intPart*MicroPerUSD cannot overflow int64.
				if intPart > (maxIntUSD-d)/10 {
					return 0, fmt.Errorf("%w: %q", ErrRange, s)
				}
				intPart = intPart*10 + d
				intDigits++
			} else {
				switch {
				case fracDigits < 6:
					frac = frac*10 + d
				case fracDigits == 6:
					roundDigit = c
				default:
					sticky = sticky || c != '0'
				}
				fracDigits++
			}
		case c == '.' && !inFrac:
			inFrac = true
		default:
			return 0, fmt.Errorf("%w: %q", ErrSyntax, s)
		}
	}
	if intDigits+fracDigits == 0 {
		return 0, fmt.Errorf("%w: %q", ErrSyntax, s)
	}
	// Scale an exact fraction (six digits or fewer) up to the micro scale:
	// "0.004" contributes 4000 µUSD and ".5" contributes 500000 µUSD.
	// Longer fractions already carry their first six digits in frac; the
	// seventh digit decides rounding below.
	for p := fracDigits; p < 6; p++ {
		frac *= 10
	}
	// Half away from zero: the seventh fraction digit alone decides, and an
	// exact half ('5' with nothing nonzero after it) also rounds up.
	if roundDigit >= '5' {
		frac++
	}
	if intPart == maxIntUSD && frac > maxFracMicro {
		return 0, fmt.Errorf("%w: %q", ErrRange, s)
	}
	return MicroUSD(intPart*MicroPerUSD + frac), nil
}
