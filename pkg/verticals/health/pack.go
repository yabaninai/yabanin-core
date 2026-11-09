// Package health provides the healthcare vertical pack for PHI redaction
// and DPDP/PDPA/HIPAA compliance enforcement.
package health

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

const (
	// ID is the stable pack identifier.
	ID = "healthcare_phi"

	// RegionName is the jurisdiction region for this pack.
	RegionName = policy.Region("GLOBAL")

	// PackName is the human-readable pack name.
	PackName = "Healthcare PHI Redaction"

	// Description is a short description of the pack's compliance scope.
	Description = "PHI redaction for DPDP/PDPA/HIPAA compliance: detects and redacts health-related PII before upstream inference, returns structured violation counts."
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
		AllowedJurisdictions: []policy.Region{"SG", "IN", "US", "EU", "GLOBAL"},
		AllowedModelFamilies: []string{"openai", "anthropic", "google", "sovereign_sg", "open_weights"},
		DataResidency:        "US", // PHI must not leave data residency jurisdiction.
		CrossBorderAllowed:   false,
		BlacklistedCountries: nil,
	}
}

// PHIError represents a PHI detection violation.
type PHIError struct {
	Type         string `json:"type"`          // "ssn", "name_dob", "phone", "email", "medication", "diagnosis"
	Sanitized    bool   `json:"sanitized"`     // whether the value was redacted
	OriginalHint string `json:"original_hint"` // first 2 chars + "***" for audit trail
}

// Pack is the Healthcare vertical pack.
type Pack struct {
	mu   sync.RWMutex
	rule ResidencyRule

	// PHI detection patterns.
	patterns []*regexp.Regexp
	pTypes   []string
}

// New creates a new Healthcare pack with default rules and PHI detection patterns.
func New() *Pack {
	p := &Pack{rule: DefaultRules()}

	// Build PHI detection patterns.
	typePatterns := []struct {
		re  string
		typ string
	}{
		{`\b\d{3}-\d{2}-\d{4}\b`, "ssn"},                                 // SSN format
		{`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, "email"}, // email
		{`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`, "phone"},                       // phone
		{`\b(?:medical|health|diagnosis|prescription|treatment)\b.*\b(?:[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)\b`, "diagnosis"},
		{`\b(?: aspirin | ibuprofen | acetaminophen | morphine | fentanyl | oxycodone )\b`, "medication"},
	}
	for _, tp := range typePatterns {
		p.patterns = append(p.patterns, regexp.MustCompile(tp.re))
		p.pTypes = append(p.pTypes, tp.typ)
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

// DetectPHI scans text for PHI patterns and returns detected violations.
func (p *Pack) DetectPHI(text string) []PHIError {
	var errors []PHIError
	for i, pat := range p.patterns {
		matches := pat.FindAllString(text, -1)
		for _, match := range matches {
			errors = append(errors, PHIError{
				Type:         p.pTypes[i],
				Sanitized:    true,
				OriginalHint: hint(match),
			})
		}
	}
	return errors
}

// RedactPHI removes PHI from text using detected patterns.
func (p *Pack) RedactPHI(text string) (string, []PHIError) {
	errors := p.DetectPHI(text)
	result := text
	for i, pat := range p.patterns {
		result = pat.ReplaceAllString(result, "[REDACTED:"+p.pTypes[i]+"]")
	}
	return result, errors
}

// hint returns first 2 chars + "***" for audit trail.
func hint(s string) string {
	runes := []rune(s)
	if len(runes) <= 3 {
		return strings.Repeat("*", len(runes))
	}
	return string(runes[:2]) + "***"
}

// Transform implements verticals.Vertical — redacts PHI from prompts.
func (p *Pack) Transform(ctx context.Context, in verticals.Request) (context.Context, verticals.Response, error) {
	errors := p.DetectPHI(in.Prompt)

	if len(errors) > 0 {
		// Return response with metadata about violations — do NOT hard-deny,
		// let the caller decide. The prompt is redacted and passed through.
		// RedactPHI returns (redactedText, detectedErrors). We always use the redacted text.
		in.Prompt, _ = p.RedactPHI(in.Prompt)
		if in.Metadata == nil {
			in.Metadata = make(map[string]string)
		}
		in.Metadata["phi_detected"] = fmt.Sprintf("%d", len(errors))
		in.Metadata["phi_types"] = stringifyTypes(errors)
		in.Metadata["prompt_redacted"] = "true"
	}

	resp := verticals.Response{
		Model:    in.ModelRequested,
		Prompt:   in.Prompt,
		Metadata: in.Metadata,
	}
	return ctx, resp, nil
}

// stringifyTypes returns comma-separated error types.
func stringifyTypes(errors []PHIError) string {
	types := make(map[string]bool)
	for _, e := range errors {
		types[e.Type] = true
	}
	var result []string
	for t := range types {
		result = append(result, t)
	}
	return strings.Join(result, ",")
}

// Report implements verticals.Vertical — generates a healthcare compliance report.
func (p *Pack) Report(_ context.Context, orgID string, from, until string, mode string) ([]byte, error) {
	// In production this would query the audit log for PHI detection events.
	return []byte(fmt.Sprintf(
		`{"vertical":"healthcare","org_id":"%s","from":"%s","until":"%s","compliance":"hipaa_dpdp_pdpa","redactions":0,"violations":0}`,
		orgID, from, until,
	)), nil
}

// Ensure Pack implements verticals.Vertical at compile time.
var _ verticals.Vertical = (*Pack)(nil)
