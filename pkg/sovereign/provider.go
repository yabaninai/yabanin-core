package sovereign

import (
	"fmt"
	"strings"
)

// ResidencyDisclosure is the canonical non-claim wording that accompanies
// every routing surface which names a country-bound endpoint or a
// country-scoped exclusion (N09-P05 negative criterion): a country endpoint
// binding is a technical routing control. It MUST NOT be presented — in
// APIs, admin UIs, redirects, logs or errors — as a legal guarantee of data
// residency. Legal residency commitments are contractual matters; this
// package only enforces routing constraints.
//
// pkg/regionrouter aliases this constant as regionrouter.ResidencyDisclosure
// so every surface renders the same sentence from one source of truth.
const ResidencyDisclosure = "country endpoint binding is a technical routing control, not a legal residency guarantee"

// ProviderDenialReason explains WHY a provider/model was excluded from
// routing for an org (N09-P05-T04 facet «объяснение причины исключения
// provider» — an exclusion must carry its reason, never be a bare false).
// The set is closed; every refusal produced by this package names exactly
// one of these reasons.
type ProviderDenialReason string

const (
	// DenialProviderCNFlagged — the model is CN-flagged and the policy does
	// not allow CN-origin models (CN-off default, PB4.8; CNGuard re-asserts
	// this dimension independently).
	DenialProviderCNFlagged ProviderDenialReason = "cn_flagged"
	// DenialProviderCountryExcluded — the model's country is on the org-wide
	// exclusion list.
	DenialProviderCountryExcluded ProviderDenialReason = "country_excluded"
	// DenialProviderVendorExcluded — the vendor HQ jurisdiction is on the
	// org-wide exclusion list.
	DenialProviderVendorExcluded ProviderDenialReason = "vendor_excluded"
	// DenialProviderTierBelowRequired — the model's recognized sovereignty
	// tier ranks below the org's required minimum tier.
	DenialProviderTierBelowRequired ProviderDenialReason = "tier_below_required"
	// DenialProviderTierUnknown — the model carries no recognized sovereignty
	// tier. Rank resolves unknown tiers to the weakest position, so any
	// required tier above foreign denies the model; the reason says that the
	// posture was UNREADABLE rather than merely too weak.
	DenialProviderTierUnknown ProviderDenialReason = "tier_unknown"
	// DenialProviderMetaUnknown — routing metadata for the candidate was not
	// resolvable, so the policy could not be evaluated. This is not a policy
	// verdict about the provider itself; consumers under a restrictive policy
	// must treat it as a fail-closed exclusion (unknown posture may hide a
	// violation), never as a permission.
	DenialProviderMetaUnknown ProviderDenialReason = "meta_unknown"
)

// ProviderDenial is the structured exclusion record for one provider/model.
// It is the explainable payload behind Policy.AllowsExplain, FilterMeta and
// the router fallback-chain filter: logs, admin surfaces and metrics can
// render region/country/kind/rule-grade explanations from it instead of a
// bare refusal (N09-P05-T04).
type ProviderDenial struct {
	// ModelName is the registry model that was excluded ("" when unknown).
	ModelName string
	// Provider is the canonical upstream provider name ("" when unknown).
	Provider string
	// Country is the model's (vendor-declared) country as evaluated.
	Country string
	// VendorHQ is the parent-company jurisdiction as evaluated.
	VendorHQ string
	// Reason is the matched exclusion reason from the closed set above.
	Reason ProviderDenialReason
	// RequiredTier is set on tier denials (tier_below_required /
	// tier_unknown): the minimum tier the org's policy demands.
	RequiredTier Tier
}

// tierKnown reports whether t is one of the four defined tiers.
func tierKnown(t Tier) bool {
	switch t {
	case TierForeign, TierPartial, TierOpenWeights, TierFull:
		return true
	}
	return false
}

// AllowsExplain is Policy.Allows with a structured exclusion reason: the
// boolean answer is IDENTICAL to Allows (single source of truth — Allows
// delegates here), and a negative answer names exactly why the provider was
// excluded. Resolution order (first match wins):
//
//  1. CN-flagged model with CN disallowed      → cn_flagged
//  2. model country on org-wide exclusion list → country_excluded
//  3. vendor HQ on org-wide exclusion list     → vendor_excluded
//  4. tier ranks below the required minimum    → tier_below_required
//     (unknown tier → tier_unknown)
//
// On allow the returned ProviderDenial identifies the model with an empty
// Reason. The comparison semantics (exact string equality on country and
// vendor, no case normalization) match the historical Allows contract and
// are unchanged by this method.
func (p Policy) AllowsExplain(m ModelMeta) (bool, ProviderDenial) {
	ident := ProviderDenial{
		ModelName: m.ModelName,
		Provider:  m.Provider,
		Country:   m.Country,
		VendorHQ:  m.VendorHQ,
	}
	if !p.CNAllowed && m.CNFlagged {
		ident.Reason = DenialProviderCNFlagged
		return false, ident
	}
	for _, c := range p.ExcludedCountries {
		if m.Country == c {
			ident.Reason = DenialProviderCountryExcluded
			return false, ident
		}
		if m.VendorHQ == c {
			ident.Reason = DenialProviderVendorExcluded
			return false, ident
		}
	}
	if Rank(m.Tier) < Rank(p.RequiredTier) {
		ident.Reason = DenialProviderTierBelowRequired
		if !tierKnown(m.Tier) {
			ident.Reason = DenialProviderTierUnknown
		}
		ident.RequiredTier = p.RequiredTier
		return false, ident
	}
	return true, ident
}

// Allows reports whether a model satisfies the policy. It delegates to
// AllowsExplain and keeps its historical boolean contract; use
// AllowsExplain where the exclusion reason is needed.
func (p Policy) Allows(m ModelMeta) bool {
	ok, _ := p.AllowsExplain(m)
	return ok
}

// FilterMeta splits a candidate metadata pool into permitted entries and
// per-provider exclusion records (N09-P05-T04). Order of both outputs
// follows the input order — deterministic for admin surfaces and tests.
func FilterMeta(pol Policy, metas []ModelMeta) (kept []ModelMeta, denied []ProviderDenial) {
	kept = make([]ModelMeta, 0, len(metas))
	for _, m := range metas {
		ok, d := pol.AllowsExplain(m)
		if ok {
			kept = append(kept, m)
			continue
		}
		denied = append(denied, d)
	}
	return kept, denied
}

// ErrProvidersExcluded reports that providers were excluded from routing by
// the org's sovereignty policy, carrying one structured record per excluded
// provider so logs and admin surfaces can explain the refusal (N09-P05-T04).
// The message always carries ResidencyDisclosure: a country-scoped exclusion
// is a technical routing control, not a legal residency guarantee.
type ErrProvidersExcluded struct {
	OrgID    string
	Excluded []ProviderDenial
}

func (e *ErrProvidersExcluded) Error() string {
	denied := "none"
	if len(e.Excluded) > 0 {
		parts := make([]string, 0, len(e.Excluded))
		for _, d := range e.Excluded {
			parts = append(parts, fmt.Sprintf("%s=%s/%s/%s/%s",
				d.ModelName, d.Provider, d.Country, d.VendorHQ, d.Reason))
		}
		denied = strings.Join(parts, ",")
	}
	return fmt.Sprintf("sovereign: providers excluded by policy for org=%s denied=[%s]: %s",
		e.OrgID, denied, ResidencyDisclosure)
}
