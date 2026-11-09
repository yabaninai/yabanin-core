package budget

// N06-P07-T07 boundary corpus — budget seam. Distinct from the T01–T06
// acceptance pins: this file holds the packet's reusable EDGE cases —
//
//	(A) unit-quantity → int64 µUSD representability at the estimator seam:
//	    the fail-closed overflow path (hop exclusion, not clamping) that the
//	    interactive pins never drive;
//	(B) workload-window exact-cap edges at the ledger seam: the endpoint
//	    admission reality is Admit(..., planned=0), so the observable
//	    boundary is "spent == cap refuses a ZERO projection" — while the
//	    planned-side at-cap edge is what ChargeAccrualAndDenial pins.
//
// Float literals are verified float64 products (0.25 USD/image is
// binary-exact); do not "simplify" them.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// t07UnitSource prices one model at one fixed per-unit rate; the token side
// stays unpriced so the unit branch is the only price in play.
type t07UnitSource struct {
	rate float64
}

func (t07UnitSource) Rates(context.Context, PriceScope, string, string, string) (Rates, bool) {
	return Rates{}, false
}

func (s t07UnitSource) UnitRates(context.Context, PriceScope, string, string, string) (UnitRate, bool) {
	return UnitRate{Unit: pricing.UnitPerImage, Rate: s.rate}, true
}

func t07ImageBound(qty float64) (BoundEstimate, error) {
	return EstimateBound(context.Background(), t07UnitSource{rate: 0.25}, PriceScopeWallet, "org-t07", EstimateRequest{
		Chain:    []ChainHop{{Provider: "openai", Model: "img"}},
		UnitKind: pricing.UnitPerImage,
		UnitQty:  &qty,
	})
}

// TestN06P7T07_UnitQtyRepresentabilityBoundary: the unit bound is rate×qty
// in exact µUSD as long as the product fits int64; the first
// non-representable quote excludes the hop (I3 fail-closed) with an empty
// bound instead of wrapping, saturating, or clamping.
func TestN06P7T07_UnitQtyRepresentabilityBoundary(t *testing.T) {
	// 9e12 USD: the largest round bound below money.MaxUSD.
	est, err := t07ImageBound(3.6e13)
	require.NoError(t, err)
	require.Equal(t, money.MicroUSD(9000000000000000000), est.BoundMicroUSD)
	require.Equal(t, []string{"openai:img"}, est.Priced)
	require.Empty(t, est.Unpriced)

	// Still representable, ~223 USD under the ceiling.
	est, err = t07ImageBound(3.6893e13)
	require.NoError(t, err)
	require.Equal(t, money.MicroUSD(9223250000000000000), est.BoundMicroUSD)
	require.Empty(t, est.Unpriced)

	// ~2 963 USD over the ceiling: the hop is excluded (I3) and, being the
	// only chain hop, the estimate fails closed with model_unpriced. The
	// error path returns the zero estimate — bound and hop lists are not
	// observable there; the refusal itself is the contract.
	est, err = t07ImageBound(3.68935e13)
	require.ErrorIs(t, err, ErrUnpricedModel)
	require.Zero(t, int64(est.BoundMicroUSD))

	// A finite-but-absurd quantity overflows the float product to +Inf:
	// the same fail-closed refusal — never a saturated finite bound.
	est, err = t07ImageBound(1e308)
	require.ErrorIs(t, err, ErrUnpricedModel)
	require.Zero(t, int64(est.BoundMicroUSD))
}

// TestN06P7T07_WorkloadWindowExactCapEdges: with the endpoint projection
// (planned=0) the deny rule is spent >= cap, so the last admitted request
// can land the window exactly ON the cap and everything after it is
// refused — while overshooting actuals are still recorded for
// observability, and a neighbor key owns an untouched fresh window.
func TestN06P7T07_WorkloadWindowExactCapEdges(t *testing.T) {
	l := NewWorkloadLedger(money.MicroUSD(100), 0)

	// Below the cap a zero projection admits.
	l.Charge("org", "wl", 99)
	require.Equal(t, money.MicroUSD(99), l.Spent("org", "wl"))
	require.NoError(t, l.Admit("org", "wl", 0))

	// Charging the exact cap flips the next zero-projection admission.
	l.Charge("org", "wl", 1)
	require.Equal(t, money.MicroUSD(100), l.Spent("org", "wl"))
	require.ErrorIs(t, l.Admit("org", "wl", 0), ErrWorkloadBudgetExceeded)

	// The overshooting actual is recorded (the spend happened upstream)
	// and keeps the window closed.
	l.Charge("org", "wl", 5)
	require.Equal(t, money.MicroUSD(105), l.Spent("org", "wl"))
	require.ErrorIs(t, l.Admit("org", "wl", 0), ErrWorkloadBudgetExceeded)

	// A different key under the same org is a fresh window: zero spend,
	// admitting.
	require.NoError(t, l.Admit("org", "wl-neighbor", 0))
	require.Equal(t, money.MicroUSD(0), l.Spent("org", "wl-neighbor"))
}
