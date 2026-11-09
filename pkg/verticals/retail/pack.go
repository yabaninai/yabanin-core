// Package retail provides the PCI-DSS and consumer data protection compliance
// vertical pack for e-commerce and retail organizations.
package retail

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

// Constants.
const (
	ID          = "retail_pci"
	RegionName  = policy.Region("GLOBAL")
	PackName    = "Retail PCI-DSS & Consumer Data"
	Description = "PCI-DSS consumer data protection: detects and redacts credit card numbers, bank account details, and CVV codes from prompts before upstream inference."
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
		AllowedJurisdictions: []policy.Region{"US", "EU", "SG", "IN", "GLOBAL"},
		AllowedModelFamilies: []string{"openai", "anthropic", "google", "sovereign_sg", "open_weights"},
		DataResidency:        "GLOBAL",
		CrossBorderAllowed:   true,
		BlacklistedCountries: nil,
	}
}

// Pack is the Retail vertical pack.
type Pack struct {
	mu   sync.RWMutex
	rule ResidencyRule

	cardPatterns []*regexp.Regexp
}

// New creates a new Retail pack with PCI-DSS detection patterns.
func New() *Pack {
	p := &Pack{rule: DefaultRules()}
	p.cardPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`), // Credit card 16 digits
		regexp.MustCompile(`\b\d{4}[- ]?\d{6}[- ]?\d{5}\b`),           // Amex format
		regexp.MustCompile(`CVV[: ]*\d{3,4}`),                         // CVV codes
		regexp.MustCompile(`routing\s*#\s*\d{9}`),                     // Bank routing numbers
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

// DetectPCI scans text for PCI-DSS sensitive data patterns.
func (p *Pack) DetectPCI(text string) []string {
	var findings []string
	for _, pat := range p.cardPatterns {
		if matches := pat.FindString(text); matches != "" {
			findings = append(findings, matches)
		}
	}
	return findings
}

// Transform implements verticals.Vertical — PCI-DSS data redaction.
func (p *Pack) Transform(ctx context.Context, in verticals.Request) (context.Context, verticals.Response, error) {
	findings := p.DetectPCI(in.Prompt)

	if len(findings) > 0 {
		// Redact all sensitive patterns from the prompt.
		result := in.Prompt
		for _, pat := range p.cardPatterns {
			result = pat.ReplaceAllString(result, "[REDACTED]")
		}
		in.Prompt = result

		if in.Metadata == nil {
			in.Metadata = make(map[string]string)
		}
		in.Metadata["pci_detected"] = fmt.Sprintf("%d", len(findings))
		in.Metadata["pci_redacted"] = "true"
		in.Metadata["card_numbers_found"] = strings.Join(findings, ",")
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
		`{"vertical":"retail","org_id":"%s","from":"%s","until":"%s","compliance":"pci_dss"}`,
		orgID, from, until,
	)), nil
}

var _ verticals.Vertical = (*Pack)(nil)
