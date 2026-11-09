package asiapacks

import (
	"context"

	"github.com/reireirei/yabanin/pkg/policy"
)

// JapanPack implements the APPI (Act on the Protection of Personal
// Information, amended 2022) residency policy for Japan.
//
// Regulatory grounding (verify with counsel before customer contracts):
//   - APPI Art. 28: cross-border transfer of personal data requires either
//     the destination country having APPI-equivalent standards, or the data
//     subject's consent, plus ongoing supervision of the recipient.
//   - Japanese regulated buyers commonly operate an approved-model list that
//     only admits models with in-country data storage (国内データ保管). The
//     fail-closed enforcer is the product primitive for such a list: only
//     models REGISTERED with region JP pass (an Azure OpenAI Japan East
//     resource, a Bedrock ap-northeast-1 model, a domestic provider, or
//     self-hosted open weights).
type JapanPack struct{}

// NewJapanPack returns a ready-to-register Japan pack.
func NewJapanPack() *JapanPack { return &JapanPack{} }

// ID returns the stable pack identifier.
func (p *JapanPack) ID() string { return "jp_appi" }

// Region returns the governed jurisdiction.
func (p *JapanPack) Region() policy.Region { return policy.Region("JP") }

// DefaultRules returns the built-in APPI rule set: strictest posture — JP
// only. Cross-border (EU/US defaults) requires an explicit per-org override
// plus the customer's own APPI transfer assessment.
func (p *JapanPack) DefaultRules() policy.ResidencyRule {
	return policy.ResidencyRule{
		AllowedJurisdictions: []policy.Region{"JP"},
		AllowedModelFamilies: []string{"openai", "azure-openai", "anthropic", "sovereign_jp", "open_weights"},
		DataResidency:        policy.Region("JP"),
		CrossBorderAllowed:   false, // APPI: consent or equivalent standards required
		BlacklistedCountries: nil,   // no statutory blacklist; add via per-org override
	}
}

// Evaluate applies the rules. override (from the DB, PA.6) replaces the
// defaults when non-nil.
func (p *JapanPack) Evaluate(_ context.Context, in policy.EvalContext, override *policy.ResidencyRule) policy.Decision {
	rules := p.DefaultRules()
	if override != nil {
		rules = *override
	}
	d := policy.Decision{Region: p.Region(), PackID: p.ID()}

	// Jurisdiction check.
	if !regionAllowed(in.ModelRegion, rules.AllowedJurisdictions) {
		d.Allowed = false
		d.Reason = "model upstream region not in APPI allowed jurisdictions"
		d.Violations = append(d.Violations, "jurisdiction:"+string(in.ModelRegion))
		return d
	}
	// Family whitelist check.
	if !familyAllowed(in.UpstreamFamily, rules.AllowedModelFamilies) {
		d.Allowed = false
		d.Reason = "model family not whitelisted for JP pack"
		d.Violations = append(d.Violations, "family:"+in.UpstreamFamily)
		return d
	}
	d.Allowed = true
	return d
}
