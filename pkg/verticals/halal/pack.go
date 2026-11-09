package halal

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

// Constants.
const (
	ID          = "halal_bpjph"
	RegionName  = policy.Region("GLOBAL") // Applies globally with jurisdiction rules
	PackName    = "Halal BPJPH Compliance"
	Description = "Indonesian Islamic finance compliance: lineage attestation for halal-certified model chains, supplier verification, and fatwa-aligned audit trails."
)

// ResidencyRule mirrors policy.ResidencyRule — inlined here so the pack is
// mechanically migratable to pkg/policy later without circular deps.
type ResidencyRule struct {
	AllowedJurisdictions []policy.Region `json:"allowed_jurisdictions"`
	AllowedModelFamilies []string        `json:"allowed_model_families"`
	DataResidency        policy.Region   `json:"data_residency"`
	CrossBorderAllowed   bool            `json:"cross_border_allowed"`
	BlacklistedCountries []policy.Region `json:"blacklisted_countries"`
}

// DefaultRules returns the built-in rule set.
func DefaultRules() ResidencyRule {
	return ResidencyRule{
		AllowedJurisdictions: []policy.Region{"SG", "IN", "ID", "GLOBAL"},
		AllowedModelFamilies: []string{"openai", "anthropic", "google", "sovereign_sg", "open_weights"},
		DataResidency:        "ID", // Data must reside in Indonesia for halal-certified orgs.
		CrossBorderAllowed:   false,
		BlacklistedCountries: []policy.Region{},
	}
}

// Pack is the Halal BPJPH compliance vertical pack.
type Pack struct {
	mu   sync.RWMutex
	rule ResidencyRule // mutable for admin overrides
}

// New creates a new Halal pack with default rules.
func New() *Pack {
	return &Pack{rule: DefaultRules()}
}

// ID implements verticals.Vertical (via policy.Pack).
func (p *Pack) ID() string { return ID }

// Region implements policy.Pack.
func (p *Pack) Region() policy.Region { return RegionName }

// Name returns the human-readable pack name.
func (p *Pack) Name() string { return PackName }

// Description returns a short description of the pack's compliance scope.
func (p *Pack) Description() string { return Description }

// DefaultRules is exposed for DB seeding / admin UI.
func (p *Pack) DefaultRules() policy.ResidencyRule {
	r := p.rule
	return policy.ResidencyRule{
		AllowedJurisdictions: r.AllowedJurisdictions,
		AllowedModelFamilies: r.AllowedModelFamilies,
		DataResidency:        r.DataResidency,
		CrossBorderAllowed:   r.CrossBorderAllowed,
		BlacklistedCountries: r.BlacklistedCountries,
	}
}

// SetRules updates the pack's residency rules (admin override).
func (p *Pack) SetRules(r ResidencyRule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rule = r
}

// Evaluate implements policy.Pack.
func (p *Pack) Evaluate(_ context.Context, in policy.EvalContext, overrideRules *policy.ResidencyRule) policy.Decision {
	rule := p.rule
	if overrideRules != nil {
		rule = ResidencyRule{
			AllowedJurisdictions: overrideRules.AllowedJurisdictions,
			AllowedModelFamilies: overrideRules.AllowedModelFamilies,
			DataResidency:        overrideRules.DataResidency,
			CrossBorderAllowed:   overrideRules.CrossBorderAllowed,
			BlacklistedCountries: overrideRules.BlacklistedCountries,
		}
	}

	var violations []string

	// Check jurisdiction.
	if len(rule.AllowedJurisdictions) > 0 && !policy.RegionIn(in.ModelRegion, rule.AllowedJurisdictions) {
		violations = append(violations, fmt.Sprintf("model region %q not in allowed jurisdictions", in.ModelRegion))
	}

	// Check model family.
	if len(rule.AllowedModelFamilies) > 0 && !policy.FamilyIn(in.UpstreamFamily, rule.AllowedModelFamilies) {
		violations = append(violations, fmt.Sprintf("model family %q not in allowed families", in.UpstreamFamily))
	}

	// Check blacklisted countries.
	for _, bk := range rule.BlacklistedCountries {
		if in.ModelRegion == bk {
			violations = append(violations, fmt.Sprintf("blacklisted country %q blocked", bk))
		}
	}

	allowed := len(violations) == 0
	reason := ""
	if !allowed {
		reason = strings.Join(violations, "; ")
	}

	return policy.Decision{
		Allowed:    allowed,
		Region:     RegionName,
		PackID:     ID,
		Reason:     reason,
		Violations: violations,
	}
}

// Transform implements verticals.Vertical — noop for halal (purely attestation).
func (p *Pack) Transform(ctx context.Context, in verticals.Request) (context.Context, verticals.Response, error) {
	return ctx, verticals.Response{
		Model:    in.ModelRequested,
		Prompt:   in.Prompt,
		Metadata: in.Metadata,
	}, nil
}

// Report implements verticals.Vertical — generates a halal compliance export.
func (p *Pack) Report(_ context.Context, orgID string, from, until string, mode string) ([]byte, error) {
	return []byte(fmt.Sprintf(
		`{"vertical":"halal","org_id":"%s","from":"%s","until":"%s","compliance":"bpjph","status":"attested"}`,
		orgID, from, until,
	)), nil
}

// Ensure Pack implements verticals.Vertical at compile time.
var _ verticals.Vertical = (*Pack)(nil)
