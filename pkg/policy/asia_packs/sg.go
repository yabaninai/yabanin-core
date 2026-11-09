package asiapacks

import (
	"context"

	"github.com/reireirei/yabanin/pkg/policy"
)

// SingaporePack implements the PDPA (Personal Data Protection Act 2012, rev.
// 2020) + MAS (Notice 655 / TRM Guidelines) residency policy for Singapore.
//
// Regulatory grounding:
//   - PDPA: personal-data cross-border transfer is allowed when the destination
//     provides "comparable protection".
//   - MAS TRM / Outsourcing Guidelines: regulated BFSI workloads expect data
//     localisation in SG; third-party risk must be assessed.
type SingaporePack struct{}

// NewSingaporePack returns a ready-to-register Singapore pack.
func NewSingaporePack() *SingaporePack { return &SingaporePack{} }

// ID returns the stable pack identifier.
func (p *SingaporePack) ID() string { return "sg_pdpa_mas" }

// Region returns the governed jurisdiction.
func (p *SingaporePack) Region() policy.Region { return policy.Region("SG") }

// DefaultRules returns the built-in PDPA/MAS rule set.
func (p *SingaporePack) DefaultRules() policy.ResidencyRule {
	return policy.ResidencyRule{
		// Inference preferred in SG; EU accepted as comparable protection.
		AllowedJurisdictions: []policy.Region{"SG", "EU"},
		AllowedModelFamilies: []string{"openai", "azure-openai", "anthropic", "sovereign_sg", "open_weights"},
		DataResidency:        policy.Region("SG"),
		CrossBorderAllowed:   true, // PDPA: comparable protection
		BlacklistedCountries: nil,  // no government blacklist
	}
}

// Evaluate applies the rules. override (from the DB, PA.6) replaces the
// defaults when non-nil.
func (p *SingaporePack) Evaluate(_ context.Context, in policy.EvalContext, override *policy.ResidencyRule) policy.Decision {
	rules := p.DefaultRules()
	if override != nil {
		rules = *override
	}
	d := policy.Decision{Region: p.Region(), PackID: p.ID()}

	// Jurisdiction check.
	if !regionAllowed(in.ModelRegion, rules.AllowedJurisdictions) {
		d.Allowed = false
		d.Reason = "model upstream region not in PDPA/MAS allowed jurisdictions"
		d.Violations = append(d.Violations, "jurisdiction:"+string(in.ModelRegion))
		return d
	}
	// Family whitelist check.
	if !familyAllowed(in.UpstreamFamily, rules.AllowedModelFamilies) {
		d.Allowed = false
		d.Reason = "model family not whitelisted for SG pack"
		d.Violations = append(d.Violations, "family:"+in.UpstreamFamily)
		return d
	}
	d.Allowed = true
	return d
}
