// Package money provides exact monetary arithmetic for internal cost
// accounting. The internal unit is integer micro-USD
// (1 USD = 1_000_000 µUSD, 1 cent = 10_000 µUSD); public/admin amounts
// remain in integer cents and are a separate, explicitly-converted unit.
//
// Rounding policy: converting a floating-point USD quote to micro-USD rounds
// half away from zero; converting micro-USD to the public cents unit rounds
// half away from zero (matching the historical math.Round projection).
// Sub-cent residue of a charge is never discarded: charges carry the exact
// micro amount and the ledger splits it into whole cents plus a durable
// remainder.
//
// Validity: quotes must be finite, non-negative and within the representable
// range. NaN, ±Inf, negative and out-of-range values are rejected — an
// invalid or missing quote is "unknown price", a distinct state from a
// genuine zero, and must never be billed as either.
package money

import (
	"errors"
	"fmt"
	"math"
)

// MicroUSD is an exact amount in integer micro-USD (1 USD = 1_000_000).
type MicroUSD int64

const (
	// MicroPerCent is the number of micro-USD in one cent.
	MicroPerCent int64 = 10_000
	// MicroPerUSD is the number of micro-USD in one USD.
	MicroPerUSD int64 = 1_000_000
	// MaxUSD is the largest USD magnitude representable as MicroUSD
	// (≈ $9.22e12). Quotes beyond it are rejected as out of range rather
	// than silently overflowing.
	MaxUSD = float64(math.MaxInt64) / float64(MicroPerUSD)
)

var (
	// ErrNonFinite reports a NaN or infinite quote.
	ErrNonFinite = errors.New("money: non-finite amount")
	// ErrNegative reports a negative amount where only non-negative is valid.
	ErrNegative = errors.New("money: negative amount")
	// ErrRange reports a finite amount outside the representable range.
	ErrRange = errors.New("money: amount out of representable range")
)

// FromUSD converts a floating-point USD quote (as carried by events) to an
// exact micro-USD amount, rounding half away from zero. It rejects NaN/Inf
// (ErrNonFinite), negative values (ErrNegative) and amounts beyond MaxUSD
// (ErrRange); callers must treat every error as "unknown price", not zero.
// The exact MaxUSD boundary converts to the largest representable amount
// (MaxInt64 µUSD): at that magnitude the scaled product rounds onto the
// unrepresentable power of two 2^63, so the conversion saturates rather
// than wrapping negative.
func FromUSD(usd float64) (MicroUSD, error) {
	if math.IsNaN(usd) || math.IsInf(usd, 0) {
		return 0, fmt.Errorf("%w: %v", ErrNonFinite, usd)
	}
	if usd < 0 {
		return 0, fmt.Errorf("%w: %v", ErrNegative, usd)
	}
	if usd > MaxUSD {
		return 0, fmt.Errorf("%w: %v", ErrRange, usd)
	}
	m := math.Round(usd * float64(MicroPerUSD))
	// float64(math.MaxInt64) rounds up to 2^63: only the MaxUSD boundary
	// scales onto that value, and converting it to int64 would wrap to the
	// most negative amount. Every smaller product is an exact int64.
	if m >= float64(math.MaxInt64) {
		return MicroUSD(math.MaxInt64), nil
	}
	return MicroUSD(m), nil
}

// FromCents converts an exact integer cents amount to micro-USD. It rejects
// negative values and amounts whose micro representation would overflow.
func FromCents(cents int64) (MicroUSD, error) {
	if cents < 0 {
		return 0, fmt.Errorf("%w: %d", ErrNegative, cents)
	}
	if cents > math.MaxInt64/int64(MicroPerCent) {
		return 0, fmt.Errorf("%w: %d cents", ErrRange, cents)
	}
	return MicroUSD(cents * int64(MicroPerCent)), nil
}

// MustFromCents is FromCents for compile-time constants; it panics on an
// invalid constant so misuse fails at startup, never mid-transaction.
func MustFromCents(cents int64) MicroUSD {
	m, err := FromCents(cents)
	if err != nil {
		panic(err)
	}
	return m
}

// Cents projects the amount onto the public integer-cents unit, rounding
// half away from zero (the historical math.Round(x*100) behavior). This is
// a lossy compatibility projection: exact sub-cent value lives in micro.
func (m MicroUSD) Cents() int64 {
	return roundHalfAwayFromZero(int64(m), int64(MicroPerCent))
}

// Split separates a non-negative amount into whole cents and the sub-cent
// remainder in [0, 10000) micro-USD. cents is truncated toward zero and the
// remainder carries the exact residue: Split() == m for all valid m.
func (m MicroUSD) Split() (cents int64, rem MicroUSD) {
	if m < 0 {
		return 0, 0
	}
	return int64(m) / int64(MicroPerCent), MicroUSD(int64(m) % int64(MicroPerCent))
}

// Valid reports whether the amount is a well-formed non-negative micro-USD
// value (any int64 is finite; the bound is the range check).
func (m MicroUSD) Valid() error {
	if m < 0 {
		return fmt.Errorf("%w: %d", ErrNegative, int64(m))
	}
	return nil
}

// Add returns m+b, rejecting overflow instead of wrapping.
func (m MicroUSD) Add(b MicroUSD) (MicroUSD, error) {
	sum := m + b
	if (m > 0 && b > 0 && sum < 0) || (m < 0 && b < 0 && sum > 0) {
		return 0, fmt.Errorf("%w: %d + %d", ErrRange, int64(m), int64(b))
	}
	return sum, nil
}

// Sub returns m-b, rejecting a negative result or overflow instead of
// wrapping: money amounts in this package are non-negative.
func (m MicroUSD) Sub(b MicroUSD) (MicroUSD, error) {
	diff, err := m.Add(-b)
	if err != nil {
		return 0, err
	}
	if diff < 0 {
		return 0, fmt.Errorf("%w: %d - %d", ErrRange, int64(m), int64(b))
	}
	return diff, nil
}

// roundHalfAwayFromZero divides v by d rounding half away from zero
// (d > 0). For non-negative v this matches math.Round(float64(v)/d).
func roundHalfAwayFromZero(v, d int64) int64 {
	q, r := v/d, v%d
	// Comparing the remainder with ceil(d/2) avoids both doubling it and
	// negating v, either of which can overflow for int64 boundary values.
	half := d/2 + d%2
	if r >= half {
		return q + 1
	}
	if r <= -half {
		return q - 1
	}
	return q
}

// QuoteState is the outcome of reading a price or usage quote from an event.
// Unknown is a distinct state from Zero: a missing, unparseable, non-finite,
// negative or out-of-range quote is "unknown price/usage" and must never be
// billed, but it must also never be reported as a genuine zero-cost event.
type QuoteState int

const (
	// QuoteUnknown marks an absent or invalid quote (not chargeable, not zero).
	QuoteUnknown QuoteState = iota
	// QuoteZero marks a present, valid, exactly-zero quote (unbillable by policy).
	QuoteZero
	// QuotePositive marks a present, valid, chargeable quote.
	QuotePositive
)

// String implements fmt.Stringer for logs and metrics.
func (q QuoteState) String() string {
	switch q {
	case QuoteZero:
		return "zero"
	case QuotePositive:
		return "positive"
	default:
		return "unknown"
	}
}

// QuoteFromUSD classifies a possibly-present floating-point quote: missing
// (present=false), NaN/Inf, negative or out-of-range values are QuoteUnknown;
// a valid zero is QuoteZero; anything else is QuotePositive with the exact
// micro-USD amount. This is the event-boundary validation gate: no quote
// crosses into billing without a QuotePositive classification.
func QuoteFromUSD(usd float64, present bool) (MicroUSD, QuoteState) {
	if !present {
		return 0, QuoteUnknown
	}
	m, err := FromUSD(usd)
	if err != nil {
		return 0, QuoteUnknown
	}
	if m == 0 {
		return 0, QuoteZero
	}
	return m, QuotePositive
}
