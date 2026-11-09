// Package policy defines residency policy-packs: pluggable rules that pin
// inference and data residency to a jurisdiction (SG/IN/ID/...).
//
// A Pack encapsulates which upstream jurisdictions and model families are
// allowed for an organisation, where request logs must be stored, and whether
// cross-border transfer is permitted. Packs are registered into a Registry
// keyed by Region; the gateway asks the Enforcer (PA.5) to evaluate each
// request against the org's pack.
package policy

import "context"

// Region is an ISO-3166 alpha-2 jurisdiction code (SG, IN, ID, EU, US, GLOBAL).
type Region string

const (
	// RegionGlobal means no residency pin (free-pass).
	RegionGlobal Region = "GLOBAL"
)

// ResidencyRule describes the constraints for one jurisdiction.
type ResidencyRule struct {
	// AllowedJurisdictions lists upstream regions inference may be sent to.
	AllowedJurisdictions []Region
	// AllowedModelFamilies whitelists provider families: "openai","anthropic",
	// "sovereign_sg","open_weights", ...
	AllowedModelFamilies []string
	// DataResidency is the region where request_logs / embeddings must reside.
	DataResidency Region
	// CrossBorderAllowed mirrors PDPA "comparable protection" semantics.
	CrossBorderAllowed bool
	// BlacklistedCountries is the DPDP §16 negative-list (hard-deny).
	BlacklistedCountries []Region
}

// EvalContext is the per-request input handed to a Pack for evaluation.
type EvalContext struct {
	OrgID          string
	ModelRequested string
	// ModelRegion is the jurisdiction of the selected upstream model
	// (from resolver.ModelInfo.Region).
	ModelRegion    Region
	UpstreamFamily string
	SessionID      string
	ClientIP       string
}

// Decision is the output of a residency evaluation.
type Decision struct {
	Allowed       bool
	Region        Region // residency region of the requesting org
	PackID        string
	RemappedModel string // non-empty when the model was swapped to an in-region one
	Reason        string // human-readable deny/remap reason
	Violations    []string
}

// Pack is the abstraction every residency policy-pack implements.
type Pack interface {
	// ID returns a stable pack identifier, e.g. "sg_pdpa_mas".
	ID() string
	// Region returns the jurisdiction this pack governs, e.g. "SG".
	Region() Region
	// DefaultRules returns the built-in (code-level) rule set.
	DefaultRules() ResidencyRule
	// Evaluate applies the rules to the context. overrideRules comes from the
	// DB (PA.6); nil means use DefaultRules.
	Evaluate(ctx context.Context, in EvalContext, overrideRules *ResidencyRule) Decision
}

// RegionIn reports whether r appears in list.
func RegionIn(r Region, list []Region) bool {
	for _, x := range list {
		if x == r {
			return true
		}
	}
	return false
}

// FamilyIn reports whether f appears in list.
func FamilyIn(f string, list []string) bool {
	for _, x := range list {
		if x == f {
			return true
		}
	}
	return false
}
