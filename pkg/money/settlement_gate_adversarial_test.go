package money

// N06-P04-T10 independent gate verification (contract:
// artifacts/internal-delivery-program/N06-P04/contract.md): QuoteFromUSD is total over
// arbitrary float64 input — it classifies instead of panicking — and its
// outcome never contradicts the FromUSD validator underneath: a rejection is
// exactly an unknown, an unknown never carries an amount, a valid zero stays
// zero, and a positive classification carries exactly the converted amount,
// once, always positive.
//
// The sweep deliberately skips the single point usd == MaxUSD: since the
// boundary saturation landed (FromUSD clamps it to MaxInt64 µUSD instead of
// wrapping), the exact boundary has its own dedicated table in
// TestFromUSD_MaxUSDBoundary / TestQuoteFromUSD_MaxUSDBoundary, and the
// neighbor sweep stays focused on classification over the surrounding
// domain. The nearest valid and invalid neighbors (one ulp below and above,
// double the boundary) are in the sweep and must classify cleanly.

import (
	"math"
	"math/rand"
	"testing"
)

func TestQuoteFromUSD_TotalGateAgreesWithFromUSD(t *testing.T) {
	rng := rand.New(rand.NewSource(20261029)) //nolint:gosec // G404: deterministic sweep — the fixed seed is the contract, no test-time entropy
	values := make([]float64, 0, 4200)
	values = append(values,
		math.NaN(), math.Inf(1), math.Inf(-1), 0, math.Copysign(0, -1),
		math.SmallestNonzeroFloat64, -math.SmallestNonzeroFloat64,
		math.MaxFloat64, -math.MaxFloat64, 1, -1, 0.004, -0.004,
		math.Nextafter(MaxUSD, 0), MaxUSD*2,
	)
	for i := 0; i < 4095; i++ {
		values = append(values,
			rng.NormFloat64()*1e6,
			-rng.ExpFloat64(),
			rng.Float64()*MaxUSD*3,
		)
	}

	for _, usd := range values {
		fromUSD, err := FromUSD(usd)
		got, state := QuoteFromUSD(usd, true)
		switch {
		case err != nil:
			if state != QuoteUnknown || got != 0 {
				t.Fatalf("QuoteFromUSD(%v) = (%d, %v) but FromUSD rejected with %v; a rejection is exactly an unknown carrying zero",
					usd, int64(got), state, err)
			}
		case fromUSD == 0:
			if state != QuoteZero || got != 0 {
				t.Fatalf("QuoteFromUSD(%v) = (%d, %v), want the zero classification", usd, int64(got), state)
			}
		default:
			if state != QuotePositive || got != fromUSD {
				t.Fatalf("QuoteFromUSD(%v) = (%d, %v), want the positive classification carrying exactly %d",
					usd, int64(got), state, int64(fromUSD))
			}
			if got <= 0 {
				t.Fatalf("QuoteFromUSD(%v) positive classification carries %d µUSD, want a positive amount", usd, int64(got))
			}
		}

		absent, absentState := QuoteFromUSD(usd, false)
		if absentState != QuoteUnknown || absent != 0 {
			t.Fatalf("QuoteFromUSD(%v, false) = (%d, %v), want (0, unknown): absence is unknown whatever the value",
				usd, int64(absent), absentState)
		}
	}
}
