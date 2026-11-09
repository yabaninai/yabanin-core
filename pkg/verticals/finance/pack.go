// Package finance provides the finance vertical pack for RBI model allow-listing
// and human-in-the-loop regulatory approval.
package finance

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
	ID          = "finance_rbi"
	RegionName  = policy.Region("IN")
	PackName    = "Finance RBI Compliance"
	Description = "Indian financial services compliance: model allow-listing, human-in-the-loop regulatory approval for sensitive requests, and RBI audit trail generation."
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
		AllowedJurisdictions: []policy.Region{"IN", "GLOBAL"},
		AllowedModelFamilies: []string{"openai", "anthropic", "google", "sovereign_sg", "open_weights"},
		DataResidency:        "IN", // Financial data must reside in India (RBI DPDP).
		CrossBorderAllowed:   false,
		BlacklistedCountries: nil,
	}
}

// ApprovalRequest represents a human-in-the-loop approval pend.
type ApprovalRequest struct {
	RequestID string `json:"request_id"`
	OrgID     string `json:"org_id"`
	ModelUsed string `json:"model_used"`
	Reason    string `json:"reason"`
	Status    string `json:"status"` // "pending" | "approved" | "rejected"
	CreatedAt string `json:"created_at"`
}

// Pack is the Finance vertical pack.
type Pack struct {
	mu   sync.RWMutex
	rule ResidencyRule
	// allowList holds models explicitly approved for this org. Empty = all allowed.
	allowList map[string]bool
	// pendingApprovals tracks requests needing human sign-off.
	pendingApprovals map[string]string
}

// New creates a new Finance pack with default rules.
func New() *Pack {
	return &Pack{
		rule:             DefaultRules(),
		allowList:        make(map[string]bool),
		pendingApprovals: make(map[string]string),
	}
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

// AddToAllowList adds a model to the org's approved list.
func (p *Pack) AddToAllowList(model string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowList[model] = true
}

// RemoveFromAllowList removes a model from the allow-list.
func (p *Pack) RemoveFromAllowList(model string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.allowList, model)
}

// IsModelAllowed checks if a model is in the org's allow-list.
func (p *Pack) IsModelAllowed(model string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.allowList) == 0 {
		return true // empty allow-list = all allowed (nil maps have len 0)
	}
	_, exists := p.allowList[model]
	return exists
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

	if len(rule.AllowedModelFamilies) > 0 && !policy.FamilyIn(in.UpstreamFamily, rule.AllowedModelFamilies) {
		violations = append(violations, fmt.Sprintf("model family %q not in allowed families", in.UpstreamFamily))
	}

	// Check allow-list.
	p.mu.RLock()
	if len(p.allowList) > 0 && !p.allowList[in.ModelRequested] {
		violations = append(violations, fmt.Sprintf("model %q not in RBI allow-list", in.ModelRequested))
	}
	p.mu.RUnlock()

	return policy.Decision{
		Allowed:    len(violations) == 0,
		Region:     RegionName,
		PackID:     ID,
		Reason:     "",
		Violations: violations,
	}
}

// Transform implements verticals.Vertical — checks model allow-list and injects
// regulatory_decision flag for human-in-the-loop approval.
func (p *Pack) Transform(ctx context.Context, in verticals.Request) (context.Context, verticals.Response, error) {
	if !p.IsModelAllowed(in.ModelRequested) {
		return ctx, verticals.Response{
			Deny:     true,
			Model:    "",
			Prompt:   "",
			Metadata: nil,
		}, fmt.Errorf("model %q not in finance allow-list", in.ModelRequested)
	}

	if in.Metadata == nil {
		in.Metadata = make(map[string]string)
	}

	// Flag sensitive requests for human-in-the-loop.
	// In production this would check org config for regulatory_decision=true.
	if isSensitive(in.Prompt, in.SystemPrompt) {
		in.Metadata["regulatory_decision"] = "true"
		in.Metadata["requires_approval"] = "true"
		p.mu.Lock()
		reqID := fmt.Sprintf("req-%s", in.ModelRequested[:min(8, len(in.ModelRequested))])
		p.pendingApprovals[reqID] = "pending"
		p.mu.Unlock()
	}

	resp := verticals.Response{
		Model:    in.ModelRequested,
		Prompt:   in.Prompt,
		Metadata: in.Metadata,
	}
	return ctx, resp, nil
}

// isSensitive checks if a request looks like it needs regulatory approval.
func isSensitive(prompt, systemPrompt string) bool {
	lower := strings.ToLower(prompt + " " + systemPrompt)
	sensitiveWords := []string{
		"credit score", "loan approval", "risk assessment", "AML",
		"kyc", "fraud detection", "trading strategy", "portfolio",
		"margin call", "liquidity ratio", "basel",
	}
	for _, w := range sensitiveWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// Report implements verticals.Vertical — generates RBI audit trail.
func (p *Pack) Report(_ context.Context, orgID string, from, until string, mode string) ([]byte, error) {
	p.mu.RLock()
	pending := len(p.pendingApprovals)
	p.mu.RUnlock()

	return []byte(fmt.Sprintf(
		`{"vertical":"finance","org_id":"%s","from":"%s","until":"%s","compliance":"rbi","pending_approvals":%d}`,
		orgID, from, until, pending,
	)), nil
}

// Ensure Pack implements verticals.Vertical at compile time.
var _ verticals.Vertical = (*Pack)(nil)
