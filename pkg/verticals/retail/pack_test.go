package retail

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

func TestRetailPack_IDAndRegion(t *testing.T) {
	p := New()
	if p.ID() != ID {
		t.Errorf("expected ID=%s, got %s", ID, p.ID())
	}
	if p.Region() != RegionName {
		t.Errorf("expected region=%s, got %s", RegionName, p.Region())
	}
	if p.Name() != PackName {
		t.Errorf("expected name=%s, got %s", PackName, p.Name())
	}
	if p.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestRetailPack_DefaultRules(t *testing.T) {
	p := New()
	rules := p.DefaultRules()
	if !policy.RegionIn("US", rules.AllowedJurisdictions) {
		t.Error("expected US in allowed jurisdictions")
	}
	if !policy.RegionIn("GLOBAL", rules.AllowedJurisdictions) {
		t.Error("expected GLOBAL in allowed jurisdictions")
	}
	if rules.DataResidency != "GLOBAL" {
		t.Errorf("expected data_residency=GLOBAL, got %s", rules.DataResidency)
	}
	if !rules.CrossBorderAllowed {
		t.Error("expected cross_border=true for retail")
	}
}

func TestRetailPack_Evaluate(t *testing.T) {
	p := New()
	ctx := context.Background()

	// Allowed: model in allowed jurisdiction.
	dec := p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "US",
		UpstreamFamily: "openai",
	}, nil)
	if !dec.Allowed {
		t.Errorf("expected allowed for US, got denied: %s", dec.Reason)
	}

	// Denied: model region not in allowed list.
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "CN",
		UpstreamFamily: "openai",
	}, nil)
	if dec.Allowed {
		t.Error("expected denied for CN region")
	}

	// Custom override.
	custom := &policy.ResidencyRule{
		AllowedJurisdictions: []policy.Region{"US"},
		AllowedModelFamilies: []string{"anthropic"},
		DataResidency:        "US",
		CrossBorderAllowed:   false,
	}
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "US",
		UpstreamFamily: "anthropic",
	}, custom)
	if !dec.Allowed {
		t.Error("expected allowed with custom override")
	}
}

func TestRetailPack_DetectPCI_CreditCard(t *testing.T) {
	p := New()

	tests := []struct {
		name     string
		input    string
		findings int
	}{
		{
			name:     "standard 16-digit card",
			input:    "Pay with 4111-1111-1111-1111",
			findings: 1,
		},
		{
			name:     "card without dashes",
			input:    "Card number is 4111111111111111",
			findings: 1,
		},
		{
			name:     "card with spaces",
			input:    "Use card 4111 1111 1111 1111",
			findings: 1,
		},
		{
			name:     "CVV code",
			input:    "CVV: 123 on the back",
			findings: 1,
		},
		{
			name:     "CVV with space",
			input:    "CVV 456 for payment",
			findings: 1,
		},
		{
			name:     "routing number",
			input:    "routing # 123456789",
			findings: 1,
		},
		{
			name:     "no PCI data",
			input:    "Please process the order for widgets",
			findings: 0,
		},
		{
			name:     "multiple findings",
			input:    "Pay with 4111-1111-1111-1111 CVV: 999 routing # 098765432",
			findings: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := p.DetectPCI(tt.input)
			if len(findings) != tt.findings {
				t.Errorf("expected %d findings, got %d: %v", tt.findings, len(findings), findings)
			}
		})
	}
}

func TestRetailPack_Transform_Redaction(t *testing.T) {
	p := New()
	ctx := context.Background()

	in := verticals.Request{
		OrgID:          "org-1",
		ModelRequested: "gpt-4o",
		Prompt:         "Charge card 4111-1111-1111-1111 CVV: 123",
		Metadata:       make(map[string]string),
	}

	_, resp, err := p.Transform(ctx, in)
	if err != nil {
		t.Fatalf("transform error: %v", err)
	}

	if resp.Deny {
		t.Error("retail transform should not deny, only redact")
	}

	// Card numbers and CVV should be replaced with [REDACTED].
	if strings.Contains(resp.Prompt, "4111") {
		t.Error("credit card number should be redacted from prompt")
	}
	if strings.Contains(resp.Prompt, "123") && !strings.Contains(resp.Prompt, "redact") {
		t.Error("CVV should be redacted from prompt")
	}

	// Metadata should indicate PCI detection.
	if resp.Metadata["pci_redacted"] != "true" {
		t.Error("expected pci_redacted=true in metadata")
	}
	if resp.Metadata["pci_detected"] != "2" {
		t.Errorf("expected pci_detected=2, got %s", resp.Metadata["pci_detected"])
	}
}

func TestRetailPack_Transform_NoPCI(t *testing.T) {
	p := New()
	ctx := context.Background()

	in := verticals.Request{
		OrgID:          "org-1",
		ModelRequested: "gpt-4o",
		Prompt:         "Process the order for 5 widgets",
		Metadata:       make(map[string]string),
	}

	_, resp, err := p.Transform(ctx, in)
	if err != nil {
		t.Fatalf("transform error: %v", err)
	}

	if resp.Deny {
		t.Error("did not expect deny for non-PCI prompt")
	}
	if resp.Prompt != in.Prompt {
		t.Error("prompt should be unchanged when no PCI data detected")
	}
}

func TestRetailPack_Report(t *testing.T) {
	p := New()
	report, err := p.Report(context.Background(), "org-1", "2024-01-01", "2024-12-31", "saas")
	if err != nil {
		t.Fatalf("report error: %v", err)
	}
	if !strings.Contains(string(report), `"vertical":"retail"`) {
		t.Error("expected vertical=retail in report")
	}
	if !strings.Contains(string(report), `"compliance":"pci_dss"`) {
		t.Error("expected compliance=pci_dss in report")
	}
}

func TestRetailPack_SetRules(t *testing.T) {
	p := New()
	custom := ResidencyRule{
		AllowedJurisdictions: []policy.Region{"US"},
		AllowedModelFamilies: []string{"openai"},
		DataResidency:        "US",
		CrossBorderAllowed:   false,
	}
	p.SetRules(custom)

	rules := p.DefaultRules()
	if rules.DataResidency != "US" {
		t.Errorf("expected data_residency=US after SetRules, got %s", rules.DataResidency)
	}
	if rules.CrossBorderAllowed {
		t.Error("expected cross_border=false after SetRules")
	}
}
