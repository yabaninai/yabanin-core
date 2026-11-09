package asiapacks

import (
	"context"

	"github.com/reireirei/yabanin/pkg/policy"
)

// IndiaPack implements the DPDP Act 2023 + RBI Storage of Payment System Data
// (Apr 2018) residency policy for India.
//
// Regulatory grounding:
//   - DPDP Act 2023 §16: cross-border transfer is allowed EXCEPT for countries
//     on the Central Government negative-list (blacklist).
//   - RBI: end-to-end payment-system data MUST be stored only in India.
type IndiaPack struct{}

// NewIndiaPack returns a ready-to-register India pack.
func NewIndiaPack() *IndiaPack { return &IndiaPack{} }

// ID returns the stable pack identifier.
func (p *IndiaPack) ID() string { return "in_dpdp_rbi" }

// Region returns the governed jurisdiction.
func (p *IndiaPack) Region() policy.Region { return policy.Region("IN") }

// DefaultRules returns the built-in DPDP/RBI rule set.
func (p *IndiaPack) DefaultRules() policy.ResidencyRule {
	return policy.ResidencyRule{
		// IN primary; SG accepted as comparable.
		AllowedJurisdictions: []policy.Region{"IN", "SG"},
		AllowedModelFamilies: []string{"openai", "azure-openai", "anthropic", "sovereign_in", "open_weights"},
		DataResidency:        policy.Region("IN"), // RBI localisation
		CrossBorderAllowed:   true,
		// DPDP negative-list risk — CN is a conservatively blacklisted example.
		BlacklistedCountries: []policy.Region{"CN"},
	}
}

// Evaluate applies DPDP/RBI rules. The blacklist is checked FIRST and is a
// hard-deny (fail-closed) regardless of family or override relaxations on
// jurisdiction — the blacklist cannot be relaxed by an allowed-jurisdiction
// override.
func (p *IndiaPack) Evaluate(_ context.Context, in policy.EvalContext, override *policy.ResidencyRule) policy.Decision {
	rules := p.DefaultRules()
	if override != nil {
		rules = *override
	}
	d := policy.Decision{Region: p.Region(), PackID: p.ID()}

	// 1. Blacklist (hard-deny, fail-closed).
	if blacklisted(in.ModelRegion, rules.BlacklistedCountries) {
		d.Allowed = false
		d.Reason = "model upstream region is on the DPDP government blacklist"
		d.Violations = append(d.Violations, "blacklist:"+string(in.ModelRegion))
		return d
	}
	// 2. Jurisdiction check.
	if !regionAllowed(in.ModelRegion, rules.AllowedJurisdictions) {
		d.Allowed = false
		d.Reason = "model upstream region not in DPDP/RBI allowed jurisdictions"
		d.Violations = append(d.Violations, "jurisdiction:"+string(in.ModelRegion))
		return d
	}
	// 3. Family whitelist check.
	if !familyAllowed(in.UpstreamFamily, rules.AllowedModelFamilies) {
		d.Allowed = false
		d.Reason = "model family not whitelisted for IN pack"
		d.Violations = append(d.Violations, "family:"+in.UpstreamFamily)
		return d
	}
	d.Allowed = true
	return d
}
