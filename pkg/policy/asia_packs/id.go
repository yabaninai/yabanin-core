package asiapacks

import (
	"context"

	"github.com/reireirei/yabanin/pkg/policy"
)

// IndonesiaPack implements the UU PDP (Law No. 27/2022) + PP 71/2019 / Kominfo
// PSE residency policy for Indonesia.
//
// Regulatory grounding:
//   - UU PDP §56: cross-border transfer requires equivalence + separate consent.
//   - PP 71/2019 + Kominfo PSE: overseas operators serving ID users must
//     register as a PSE.
type IndonesiaPack struct{}

// NewIndonesiaPack returns a ready-to-register Indonesia pack.
func NewIndonesiaPack() *IndonesiaPack { return &IndonesiaPack{} }

// ID returns the stable pack identifier.
func (p *IndonesiaPack) ID() string { return "id_pdp" }

// Region returns the governed jurisdiction.
func (p *IndonesiaPack) Region() policy.Region { return policy.Region("ID") }

// DefaultRules returns the built-in UU PDP rule set.
func (p *IndonesiaPack) DefaultRules() policy.ResidencyRule {
	return policy.ResidencyRule{
		// ID primary; SG accepted as comparable (equivalence).
		AllowedJurisdictions: []policy.Region{"ID", "SG"},
		AllowedModelFamilies: []string{"openai", "azure-openai", "anthropic", "sovereign_id", "open_weights"},
		DataResidency:        policy.Region("ID"),
		CrossBorderAllowed:   true, // requires equivalence (UU PDP §56)
		BlacklistedCountries: nil,
	}
}

// Evaluate applies the UU PDP rules.
func (p *IndonesiaPack) Evaluate(_ context.Context, in policy.EvalContext, override *policy.ResidencyRule) policy.Decision {
	rules := p.DefaultRules()
	if override != nil {
		rules = *override
	}
	d := policy.Decision{Region: p.Region(), PackID: p.ID()}

	if !regionAllowed(in.ModelRegion, rules.AllowedJurisdictions) {
		d.Allowed = false
		d.Reason = "model upstream region not in UU PDP allowed jurisdictions"
		d.Violations = append(d.Violations, "jurisdiction:"+string(in.ModelRegion))
		return d
	}
	if !familyAllowed(in.UpstreamFamily, rules.AllowedModelFamilies) {
		d.Allowed = false
		d.Reason = "model family not whitelisted for ID pack"
		d.Violations = append(d.Violations, "family:"+in.UpstreamFamily)
		return d
	}
	d.Allowed = true
	return d
}
