package money

// N06-P04-T09 settlement gate (ratified D2, see
// artifacts/internal-delivery-program/N06-P04/contract.md): QuoteFromUSD is the
// event-boundary validator both billing configurations share. An unknown
// outcome — absent, non-finite, negative or out-of-range — is never a
// chargeable amount and never reported as a genuine zero; a present valid
// zero stays distinct (unbillable by policy); only a QuotePositive
// classification may cross into billing.

import (
	"math"
	"testing"
)

func TestQuoteFromUSD_SettlementClassification(t *testing.T) {
	cases := []struct {
		name      string
		usd       float64
		present   bool
		wantState QuoteState
		wantMicro MicroUSD
	}{
		{"absent quote", 0, false, QuoteUnknown, 0},
		{"absent with nonzero fallback", 0.5, false, QuoteUnknown, 0},
		{"NaN", math.NaN(), true, QuoteUnknown, 0},
		{"+Inf", math.Inf(1), true, QuoteUnknown, 0},
		{"-Inf", math.Inf(-1), true, QuoteUnknown, 0},
		{"negative", -0.01, true, QuoteUnknown, 0},
		{"large negative", -1e13, true, QuoteUnknown, 0},
		{"beyond range", MaxUSD * 2, true, QuoteUnknown, 0},
		{"just beyond range", math.Nextafter(MaxUSD, math.Inf(1)), true, QuoteUnknown, 0},
		{"valid zero", 0, true, QuoteZero, 0},
		{"negative zero is a valid zero", math.Copysign(0, -1), true, QuoteZero, 0},
		{"sub-cent rounding to zero", 0.0000004, true, QuoteZero, 0},
		{"sub-cent charge", 0.004, true, QuotePositive, 4000},
		{"one cent", 0.01, true, QuotePositive, 10000},
		{"float noise exact", 0.07, true, QuotePositive, 70000},
		{"one dollar", 1, true, QuotePositive, 1_000_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, state := QuoteFromUSD(tc.usd, tc.present)
			if state != tc.wantState {
				t.Fatalf("QuoteFromUSD(%v, %v) state = %v, want %v", tc.usd, tc.present, state, tc.wantState)
			}
			if got != tc.wantMicro {
				t.Fatalf("QuoteFromUSD(%v, %v) = %d µUSD, want %d", tc.usd, tc.present, int64(got), int64(tc.wantMicro))
			}
		})
	}
}

// Whatever the float value, an unknown classification hands back a zero
// amount: billing code that ignores the state must still not bill, and the
// zero amount must never be confused with a genuine zero-cost event.
func TestQuoteFromUSD_UnknownNeverCarriesAmount(t *testing.T) {
	for _, usd := range []float64{
		math.NaN(),
		math.Inf(1),
		math.Inf(-1),
		-1,
		-0.001,
		-1e13,
		MaxUSD * 2,
		-math.SmallestNonzeroFloat64,
	} {
		got, state := QuoteFromUSD(usd, true)
		if state != QuoteUnknown || got != 0 {
			t.Fatalf("QuoteFromUSD(%v) = (%d, %v), want (0, unknown)", usd, int64(got), state)
		}
	}
}

// Unknown and zero are distinct outcomes at the type level and in every log
// or metric projection: an unknown price must not be reportable as a genuine
// zero-cost event.
func TestQuoteState_UnknownDistinctFromZero(t *testing.T) {
	if QuoteUnknown == QuoteZero {
		t.Fatal("unknown and zero must be distinct states")
	}
	if QuoteUnknown.String() == QuoteZero.String() {
		t.Fatalf("unknown %q and zero %q must project differently", QuoteUnknown, QuoteZero)
	}
}
