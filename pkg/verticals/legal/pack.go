// Package legal provides the attorney-client privilege and legal AI ethics
// compliance vertical pack.
package legal

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
	ID          = "legal_privilege"
	RegionName  = policy.Region("GLOBAL")
	PackName    = "Legal Privilege & Ethics"
	Description = "Attorney-client privilege protection: detects privileged legal communications, prevents them from reaching upstream models, and enforces strict data residency."
)

// ResidencyRule mirrors policy.ResidencyRule.
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
		AllowedJurisdictions: []policy.Region{"US", "EU", "SG"},
		AllowedModelFamilies: []string{"sovereign_us", "sovereign_sg", "open_weights"},
		DataResidency:        "US",
		CrossBorderAllowed:   false,
		BlacklistedCountries: nil,
	}
}

// Pack is the Legal vertical pack.
type Pack struct {
	mu   sync.RWMutex
	rule ResidencyRule
}

// New creates a new Legal pack with default rules.
func New() *Pack {
	return &Pack{rule: DefaultRules()}
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
	if len(rule.AllowedJurisdictions) > 0 && !policy.RegionIn(in.ModelRegion, rule.AllowedJurisdictions) {
		violations = append(violations, fmt.Sprintf("model region %q not in allowed jurisdictions", in.ModelRegion))
	}

	return policy.Decision{
		Allowed:    len(violations) == 0,
		Region:     RegionName,
		PackID:     ID,
		Reason:     "",
		Violations: violations,
	}
}

// Transform implements verticals.Vertical — legal privilege detection.
func (p *Pack) Transform(ctx context.Context, in verticals.Request) (context.Context, verticals.Response, error) {
	lower := strings.ToLower(in.Prompt + " " + in.SystemPrompt)
	privilegedTerms := []string{"attorney-client", "privileged communication", "work product doctrine", "confidential legal advice"}

	for _, term := range privilegedTerms {
		if strings.Contains(lower, term) {
			if in.Metadata == nil {
				in.Metadata = make(map[string]string)
			}
			in.Metadata["legal_privilege_detected"] = "true"
			in.Metadata["privilege_term"] = term
			return ctx, verticals.Response{
				Deny:       true,
				DenyReason: fmt.Sprintf("attorney-client privilege detected — %q blocked", term),
				Metadata:   in.Metadata,
			}, fmt.Errorf("legal privilege violation: %s", term)
		}
	}

	resp := verticals.Response{
		Model:    in.ModelRequested,
		Prompt:   in.Prompt,
		Metadata: in.Metadata,
	}
	return ctx, resp, nil
}

// Report implements verticals.Vertical.
func (p *Pack) Report(_ context.Context, orgID string, from, until string, mode string) ([]byte, error) {
	return []byte(fmt.Sprintf(
		`{"vertical":"legal","org_id":"%s","from":"%s","until":"%s","compliance":"attorney_privilege"}`,
		orgID, from, until,
	)), nil
}

var _ verticals.Vertical = (*Pack)(nil)
