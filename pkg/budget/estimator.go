package budget

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// Bound estimation for durable budget reservations (ADR-0001 rev. 3 §4.3):
//
//	bound_S(req) = max over h in planned_chain(req) [ price_S(h).in * in_est + price_S(h).out * out_cap ]
//
// planned_chain is the primary candidate plus failover_models after the
// policy gate; shadow hops and judge calls never enter it (the caller passes
// only the billable chain). price_S is the resale rate for the wallet scope
// and the base rate for budget scopes (I4). An explicitly priced zero is a
// legitimate zero (bound 0); an unpriced candidate is excluded from the chain
// and, when no priced candidate remains, the request is refused (I3).
// Identifiers here deliberately avoid the store vocabulary added by
// NEXT-18a (ScopeKind, ErrInvalidRequest, ...) so both files merge cleanly
// into this package.

// §14 default parameters.
const (
	// InputMargin is the D4 safety margin applied to the byte-derived input
	// estimate: in_est = ceil(input_bytes / 3 * 1.2).
	InputMargin = 1.2
	// ImageTokenEstimate is the flat token cost added per input image (§14).
	ImageTokenEstimate int64 = 1600
	// DefaultOutputCapTokens is the organization default output cap used
	// when the request carries no explicit output limit (D3/D3a).
	DefaultOutputCapTokens int64 = 65536
	// boundK is the §14 multiplier on the per-hop estimate; 1.0 by design,
	// margin is already inside InputMargin and the output default.
	boundK = 1.0
)

// PriceScope names the §4.1 limit area a bound is priced for. String values
// match the reservation store's scope kinds.
type PriceScope string

// §4.1 scopes.
const (
	PriceScopeWallet    PriceScope = "wallet"
	PriceScopeTeamMonth PriceScope = "team_month"
	PriceScopeAgentDay  PriceScope = "agent_day"
	PriceScopeSession   PriceScope = "session"
)

// PriceBasis values recorded with the bound for event analysis (§4.3).
const (
	BasisResale string = "resale"
	BasisBase   string = "base"
)

var (
	// ErrUnpricedModel reports that no candidate of the planned chain has a
	// price for the scope (I3): the gateway maps it to 403 model_unpriced.
	ErrUnpricedModel = errors.New("model_unpriced")
	// ErrInvalidEstimate reports a malformed estimate input (negative bytes,
	// images or token caps); failing closed instead of clamping to a silent
	// under-reserve.
	ErrInvalidEstimate = errors.New("budget: invalid estimate request")
)

// Rates are per-token unit prices in USD per 1M tokens for one model in one
// scope. A present (ok=true) all-zero Rates is an explicit price of zero —
// a legitimate bound of 0, distinct from ok=false (unpriced).
type Rates struct {
	InUSDPerM  float64
	OutUSDPerM float64
}

// UnitRate is a non-token metering rate (N06-P07/T02): USD per one unit of
// the axis named by Unit (pricing.UnitPerAudioSecond, UnitPerCharacter,
// UnitPerImage). A present (ok=true) zero rate is an explicit priced zero.
type UnitRate struct {
	Unit string
	Rate float64
}

// validUnitRate reports whether r is a sane money value: a non-finite or
// negative rate is "unknown price", not zero (money package contract).
func validUnitRate(rate float64) bool {
	return !math.IsNaN(rate) && !math.IsInf(rate, 0) && rate >= 0
}

// UnitRateSource resolves non-token metering rates for a planned-chain
// candidate. Rate sources that only price tokens do not implement it; a
// unit-priced estimate (EstimateRequest.UnitKind) over such a source treats
// every hop as unpriced (fail-closed, I3).
type UnitRateSource interface {
	UnitRates(ctx context.Context, scope PriceScope, orgID, provider, model string) (UnitRate, bool)
}

// RateSource resolves per-scope unit rates for a planned-chain candidate.
// ok=false means the model is unpriced in that scope (I3 exclusion).
type RateSource interface {
	Rates(ctx context.Context, scope PriceScope, orgID, provider, model string) (Rates, bool)
}

// BaseRateSource prices budget scopes at base cost (I4). It wraps any
// pricing.Pricer (static table or DB-backed) plus, optionally, the non-token
// unit side-catalog (T02).
type BaseRateSource struct {
	Pricer pricing.Pricer
	// Units resolves the non-token metering rates (audio seconds /
	// characters / images). nil = no unit catalog wired — unit-priced
	// estimates report every model unpriced (fail-closed).
	Units pricing.UnitPricer
}

// Rates implements RateSource using base prices.
func (s BaseRateSource) Rates(_ context.Context, _ PriceScope, _, provider, model string) (Rates, bool) {
	p, ok := s.Pricer.Lookup(provider, model)
	if !ok {
		return Rates{}, false
	}
	return Rates{InUSDPerM: p.InputPerM, OutUSDPerM: p.OutputPerM}, true
}

// ResaleRateSource prices the wallet scope at resale rates (I4) by deriving
// per-1M-token resale unit prices from the org-aware MarkupPricer (markup or
// fixed-price override both flow through Quote).
type ResaleRateSource struct {
	Markup *pricing.MarkupPricer
}

// Rates implements RateSource using resale prices.
func (s ResaleRateSource) Rates(ctx context.Context, _ PriceScope, orgID, provider, model string) (Rates, bool) {
	q, err := s.Markup.Quote(ctx, orgID, provider, model, 1_000_000, 1_000_000, 0, 0)
	if err != nil {
		return Rates{}, false
	}
	return Rates{InUSDPerM: q.InputResaleUSD, OutUSDPerM: q.OutputResaleUSD}, true
}

// ScopedRateSource implements I4 end to end: wallet scope priced at resale,
// every other scope at base cost. A nil source for the requested scope
// reports the model unpriced (fail-closed).
type ScopedRateSource struct {
	Base   BaseRateSource
	Resale ResaleRateSource
}

// Rates implements RateSource.
func (s ScopedRateSource) Rates(ctx context.Context, scope PriceScope, orgID, provider, model string) (Rates, bool) {
	if scope == PriceScopeWallet {
		if s.Resale.Markup == nil {
			return Rates{}, false
		}
		return s.Resale.Rates(ctx, scope, orgID, provider, model)
	}
	if s.Base.Pricer == nil {
		return Rates{}, false
	}
	return s.Base.Rates(ctx, scope, orgID, provider, model)
}

// UnitRates implements UnitRateSource: the base unit rate applies to EVERY
// scope including the wallet. Non-token workloads have no resale pipeline
// (unit settlement never routes through the markup pricer — the wallet bill
// falls back to the base cost quote), so I4's resale/base split is defined
// only for per-token pricing. A nil Units source reports the model unpriced
// (fail-closed).
func (s ScopedRateSource) UnitRates(_ context.Context, _ PriceScope, _, provider, model string) (UnitRate, bool) {
	if s.Base.Units == nil {
		return UnitRate{}, false
	}
	e, ok := s.Base.Units.LookupUnit(provider, model)
	if !ok || e.Unit == "" || !validUnitRate(e.Rate) {
		return UnitRate{}, false
	}
	return UnitRate{Unit: e.Unit, Rate: e.Rate}, true
}

// ChainHop is one billable candidate of the planned chain (primary plus
// failover_models after the policy gate; no shadow hops, no judge).
type ChainHop struct {
	Provider string
	Model    string
}

// Key renders the hop as "provider:model" for events and error text.
func (h ChainHop) Key() string { return h.Provider + ":" + h.Model }

// EstimateRequest carries the raw inputs of one bound estimate. InputBytes
// must already exclude base64 image payloads (D4); images are counted
// separately and priced flat.
type EstimateRequest struct {
	Chain []ChainHop
	// InputBytes is the request body size in bytes, excluding base64 image
	// content (D4).
	InputBytes int64
	ImageCount int64
	// Explicit output caps from the request, whichever dialect is used.
	// When several are present the largest positive one is taken: the bound
	// must cover the output the provider may allow (conservative choice).
	MaxTokens           *int64
	MaxCompletionTokens *int64
	MaxOutputTokens     *int64
	// Embeddings responses have no generated output: out_cap = 0 (§4.3).
	Embeddings bool
	// DefaultOutCap overrides DefaultOutputCapTokens (org
	// default_output_cap_tokens, D3a); values <= 0 fall back to the default.
	DefaultOutCap int64
	// UnitKind + UnitQty carry a non-token metering request (T02): the
	// metering axis (pricing.UnitPerAudioSecond / UnitPerCharacter /
	// UnitPerImage) and the conservative quantity (audio seconds, input
	// characters, requested image count). When UnitKind is non-empty the
	// bound is priced per unit — rate × qty — and the per-token rates are
	// NOT consulted for the bound (settlement combines them separately).
	// UnitQty must then be non-nil and >= 0; the in/out token estimates
	// stay recorded on BoundEstimate for event analysis but do not feed
	// the bound. Both empty/nil = the per-token path.
	UnitKind string
	UnitQty  *float64
}

// BoundEstimate is the recorded estimate: the per-scope bound plus the
// §4.3 fields written to the request event for violation analysis.
type BoundEstimate struct {
	// BoundMicroUSD is bound_S in exact micro-USD.
	BoundMicroUSD money.MicroUSD
	// InEstTokens is in_est = ceil(input_bytes / 3 * InputMargin) plus
	// ImageTokenEstimate per image.
	InEstTokens int64
	// OutCapTokens is the resolved output cap.
	OutCapTokens int64
	// MaxHop is the "provider:model" whose price produced the maximum
	// (first hop wins ties).
	MaxHop string
	// PriceBasis is BasisResale for the wallet scope, BasisBase otherwise.
	PriceBasis string
	// Priced lists the chain keys priced in this scope, in chain order.
	Priced []string
	// Unpriced lists the chain keys excluded per I3, in chain order.
	Unpriced []string
}

// EstimateInputTokens computes in_est (D4, §14): ceil(bytes / 3 * 1.2) plus
// ImageTokenEstimate per image. The margin is applied in exact integer
// arithmetic — ceil(2*bytes/5) equals ceil(bytes/3*1.2) because 1.2/3 = 2/5 —
// so no floating-point drift can under-estimate the input.
func EstimateInputTokens(inputBytes, imageCount int64) (int64, error) {
	if inputBytes < 0 || imageCount < 0 {
		return 0, fmt.Errorf("%w: negative input bytes/images", ErrInvalidEstimate)
	}
	if inputBytes > math.MaxInt64/2 {
		return 0, fmt.Errorf("%w: input bytes overflow", ErrInvalidEstimate)
	}
	inEst := ceilDiv(inputBytes*2, 5)
	images := imageCount * ImageTokenEstimate
	if images > math.MaxInt64-inEst {
		return 0, fmt.Errorf("%w: image estimate overflow", ErrInvalidEstimate)
	}
	return inEst + images, nil
}

// EstimateOutputCap resolves out_cap (§4.3): the explicit request cap if one
// is passed (the largest positive across the request dialects, covering
// whatever the provider may allow), the organization default only when none
// is, and exactly 0 for embeddings.
func EstimateOutputCap(req EstimateRequest) (int64, error) {
	if req.Embeddings {
		return 0, nil
	}
	explicit := int64(-1)
	for _, p := range []*int64{req.MaxTokens, req.MaxCompletionTokens, req.MaxOutputTokens} {
		if p == nil {
			continue
		}
		if *p < 0 {
			return 0, fmt.Errorf("%w: negative output cap", ErrInvalidEstimate)
		}
		// A zero cap is treated as unset: several providers ignore it and
		// generate up to the model maximum, so the default must cover that.
		if *p > 0 && *p > explicit {
			explicit = *p
		}
	}
	if explicit >= 0 {
		return explicit, nil
	}
	if req.DefaultOutCap > 0 {
		return req.DefaultOutCap, nil
	}
	return DefaultOutputCapTokens, nil
}

// EstimateBound computes bound_S for one scope over the planned chain (ADR-0001
// rev. 3 §4.3). Unpriced candidates are excluded (I3); if no priced candidate
// remains the error wraps ErrUnpricedModel. A priced zero contributes bound 0
// and is a legitimate result (D7 exhaustion checks stay with the caller).
//
// Unit-priced requests (req.UnitKind set, T02) bound per metering unit:
//
//	bound_S(req) = max over h [ unit_rate_S(h) * qty ]
//
// with the rate resolved through UnitRateSource; a source that only prices
// tokens leaves every hop unpriced (fail-closed).
func EstimateBound(ctx context.Context, src RateSource, scope PriceScope, orgID string, req EstimateRequest) (BoundEstimate, error) {
	inEst, err := EstimateInputTokens(req.InputBytes, req.ImageCount)
	if err != nil {
		return BoundEstimate{}, err
	}
	outCap, err := EstimateOutputCap(req)
	if err != nil {
		return BoundEstimate{}, err
	}
	unitQty := 0.0
	unitPriced := req.UnitKind != ""
	if unitPriced {
		if req.UnitQty == nil {
			return BoundEstimate{}, fmt.Errorf("%w: unit kind %q without a quantity", ErrInvalidEstimate, req.UnitKind)
		}
		if *req.UnitQty < 0 || math.IsNaN(*req.UnitQty) || math.IsInf(*req.UnitQty, 0) {
			return BoundEstimate{}, fmt.Errorf("%w: unit quantity %v", ErrInvalidEstimate, *req.UnitQty)
		}
		unitQty = *req.UnitQty
	}
	if len(req.Chain) == 0 {
		return BoundEstimate{}, fmt.Errorf("%w: empty planned chain", ErrUnpricedModel)
	}

	basis := BasisBase
	if scope == PriceScopeWallet {
		basis = BasisResale
	}

	est := BoundEstimate{
		InEstTokens:  inEst,
		OutCapTokens: outCap,
		PriceBasis:   basis,
		Priced:       make([]string, 0, len(req.Chain)),
		Unpriced:     nil,
	}
	for _, hop := range req.Chain {
		var hopUSD float64
		if unitPriced {
			unitSrc, implements := src.(UnitRateSource)
			if !implements {
				est.Unpriced = append(est.Unpriced, hop.Key())
				continue
			}
			ur, ok := unitSrc.UnitRates(ctx, scope, orgID, hop.Provider, hop.Model)
			// A unit mismatch or an unknown (non-finite, negative)
			// rate is "unknown price", not zero: exclude the hop
			// instead of reserving a wrong amount.
			if !ok || ur.Unit != req.UnitKind || !validUnitRate(ur.Rate) {
				est.Unpriced = append(est.Unpriced, hop.Key())
				continue
			}
			hopUSD = boundK * ur.Rate * unitQty
		} else {
			rates, ok := src.Rates(ctx, scope, orgID, hop.Provider, hop.Model)
			if !ok {
				est.Unpriced = append(est.Unpriced, hop.Key())
				continue
			}
			// Unknown (non-finite, negative, out-of-range) per-hop rates are
			// "unknown price", not zero: exclude the hop like any unpriced one
			// instead of reserving a wrong amount (money package contract).
			hopUSD = boundK * (rates.InUSDPerM*float64(inEst) + rates.OutUSDPerM*float64(outCap)) / 1_000_000
		}
		hopBound, convErr := money.FromUSD(hopUSD)
		if convErr != nil {
			est.Unpriced = append(est.Unpriced, hop.Key())
			continue
		}
		est.Priced = append(est.Priced, hop.Key())
		if est.MaxHop == "" || hopBound > est.BoundMicroUSD {
			est.MaxHop = hop.Key()
			est.BoundMicroUSD = hopBound
		}
	}
	if len(est.Priced) == 0 {
		return BoundEstimate{}, fmt.Errorf("%w: %s", ErrUnpricedModel, strings.Join(est.Unpriced, ", "))
	}
	return est, nil
}

// ceilDiv returns ceil(n/d) for non-negative n and positive d.
func ceilDiv(n, d int64) int64 {
	return (n + d - 1) / d
}
