// Package defense provides the defense vertical pack for ITAR screening and
// sovereign-only model pool enforcement.
package defense

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
	ID          = "defense_itar"
	RegionName  = policy.Region("US")
	PackName    = "Defense ITAR Compliance"
	Description = "ITAR screening + sovereign-only pool: hard-deny non-sovereign models for defense orgs, screen prompts for controlled technical data."
)

// ResidencyRule mirrors policy.ResidencyRule.
type ResidencyRule struct {
	AllowedJurisdictions []policy.Region `json:"allowed_jurisdictions"`
	AllowedModelFamilies []string        `json:"allowed_model_families"`
	DataResidency        policy.Region   `json:"data_residency"`
	CrossBorderAllowed   bool            `json:"cross_border_allowed"`
	BlacklistedCountries []policy.Region `json:"blacklisted_countries"`
}

// DefaultRules returns the built-in rule set — defense is sovereign-only.
func DefaultRules() ResidencyRule {
	return ResidencyRule{
		AllowedJurisdictions: []policy.Region{"US"},
		AllowedModelFamilies: []string{"sovereign_us", "open_weights"}, // NO commodity cloud models
		DataResidency:        "US",
		CrossBorderAllowed:   false,
		BlacklistedCountries: []policy.Region{"CN", "RU", "IR", "KP"},
	}
}

// ScreeningError represents an ITAR screening violation.
type ScreeningError struct {
	Type    string `json:"type"` // "itar_controlled", "sanctioned_country", "unapproved_model"
	Message string `json:"message"`
	Code    int    `json:"code"` // 403-like error code for the caller
}

// Pack is the Defense vertical pack.
type Pack struct {
	mu   sync.RWMutex
	rule ResidencyRule
	// sovereignPool contains models explicitly approved for defense use.
	sovereignPool map[string]bool
	// screeningKeywords holds ITAR-related terms to screen.
	screeningTerms []string
}

// New creates a new Defense pack with default rules and ITAR screening terms.
func New() *Pack {
	p := &Pack{
		rule:          DefaultRules(),
		sovereignPool: make(map[string]bool),
		screeningTerms: []string{
			"itar", "controlled technical data", "defense article",
			"munitions", "fire control", "radar cross-section",
			"guided missile", "ballistic trajectory", "encryption export",
			"national defense", "military application",
		},
	}
	return p
}

// ID implements verticals.Vertical.
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

// SetRules updates the pack's residency rules.
func (p *Pack) SetRules(r ResidencyRule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rule = r
}

// AddToSovereignPool adds a model to the sovereign-only pool.
func (p *Pack) AddToSovereignPool(model string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sovereignPool[model] = true
}

// RemoveFromSovereignPool removes a model from the sovereign pool.
func (p *Pack) RemoveFromSovereignPool(model string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sovereignPool, model)
}

// IsInSovereignPool checks if a model is in the sovereign pool.
func (p *Pack) IsInSovereignPool(model string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.sovereignPool) == 0 {
		return true // empty pool = all allowed (nil maps have len 0)
	}
	_, exists := p.sovereignPool[model]
	return exists
}

// Evaluate implements policy.Pack — defense pack has hard residency gate.
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

	// Defense: model MUST be in a sovereign jurisdiction.
	if len(rule.AllowedJurisdictions) > 0 && !policy.RegionIn(in.ModelRegion, rule.AllowedJurisdictions) {
		violations = append(violations, fmt.Sprintf("model region %q not in sovereign pool", in.ModelRegion))
	}

	// Blacklisted countries are hard-deny.
	for _, bk := range rule.BlacklistedCountries {
		if in.ModelRegion == bk {
			violations = append(violations, fmt.Sprintf("sanctioned country %q hard-denied by ITAR", bk))
		}
	}

	return policy.Decision{
		Allowed:    len(violations) == 0,
		Region:     RegionName,
		PackID:     ID,
		Reason:     "",
		Violations: violations,
	}
}

// ScreenPrompt checks a prompt for ITAR-controlled technical data.
func (p *Pack) ScreenPrompt(prompt string) []ScreeningError {
	var errors []ScreeningError
	lower := strings.ToLower(prompt)
	for _, term := range p.screeningTerms {
		if strings.Contains(lower, term) {
			errors = append(errors, ScreeningError{
				Type:    "itar_controlled",
				Message: fmt.Sprintf("potential ITAR-controlled term detected: %q", term),
				Code:    403,
			})
		}
	}
	return errors
}

// Transform implements verticals.Vertical — hard-deny non-sovereign models and screen for ITAR terms.
func (p *Pack) Transform(ctx context.Context, in verticals.Request) (context.Context, verticals.Response, error) {
	// Check sovereign pool membership.
	if len(p.sovereignPool) > 0 && !p.IsInSovereignPool(in.ModelRequested) {
		return ctx, verticals.Response{
			Deny:   true,
			Model:  "",
			Prompt: "",
		}, fmt.Errorf("model %q not in sovereign pool — ITAR violation", in.ModelRequested)
	}

	// Screen for ITAR terms.
	screens := p.ScreenPrompt(in.Prompt)
	if len(screens) > 0 {
		if in.Metadata == nil {
			in.Metadata = make(map[string]string)
		}
		in.Metadata["itar_screened"] = "true"
		in.Metadata["flagged_terms"] = fmt.Sprintf("%d", len(screens))

		// In defense mode, flag for manual review rather than auto-deny.
		// The gateway can choose to hard-deny or route to human review.
	}

	resp := verticals.Response{
		Model:    in.ModelRequested,
		Prompt:   in.Prompt,
		Metadata: in.Metadata,
	}
	return ctx, resp, nil
}

// Report implements verticals.Vertical — generates ITAR compliance report.
func (p *Pack) Report(_ context.Context, orgID string, from, until string, mode string) ([]byte, error) {
	p.mu.RLock()
	poolSize := len(p.sovereignPool)
	p.mu.RUnlock()

	return []byte(fmt.Sprintf(
		`{"vertical":"defense","org_id":"%s","from":"%s","until":"%s","compliance":"itar","sovereign_pool_size":%d}`,
		orgID, from, until, poolSize,
	)), nil
}

// Ensure Pack implements verticals.Vertical at compile time.
var _ verticals.Vertical = (*Pack)(nil)
