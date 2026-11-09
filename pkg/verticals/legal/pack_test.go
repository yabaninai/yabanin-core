package legal

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

func TestLegalPack_IDAndRegion(t *testing.T) {
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

func TestLegalPack_DefaultRules(t *testing.T) {
	p := New()
	rules := p.DefaultRules()
	if len(rules.AllowedJurisdictions) == 0 {
		t.Error("expected allowed jurisdictions")
	}
	if rules.DataResidency != "US" {
		t.Errorf("expected data_residency=US, got %s", rules.DataResidency)
	}
	if rules.CrossBorderAllowed {
		t.Error("expected cross_border=false for legal privilege pack")
	}
}

func TestLegalPack_Evaluate(t *testing.T) {
	p := New()
	ctx := context.Background()

	// Allowed: model in allowed jurisdiction.
	dec := p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "US",
		UpstreamFamily: "sovereign_us",
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

	// Denied: model region not in allowed list.
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "BR",
		UpstreamFamily: "openai",
	}, nil)
	if dec.Allowed {
		t.Error("expected denied for BR region")
	}

	// Custom override.
	custom := &policy.ResidencyRule{
		AllowedJurisdictions: []policy.Region{"US"},
		AllowedModelFamilies: []string{"openai"},
		DataResidency:        "US",
		CrossBorderAllowed:   true,
	}
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "US",
		UpstreamFamily: "openai",
	}, custom)
	if !dec.Allowed {
		t.Error("expected allowed with custom override")
	}
}

func TestLegalPack_Transform_PrivilegeDetection(t *testing.T) {
	p := New()
	ctx := context.Background()

	tests := []struct {
		name     string
		prompt   string
		system   string
		deny     bool
		privTerm string
	}{
		{
			name:     "attorney-client phrase",
			prompt:   "Prepare the attorney-client privileged communication for client meeting",
			deny:     true,
			privTerm: "attorney-client",
		},
		{
			name:     "privileged communication",
			prompt:   "This is a privileged communication between counsel and client",
			deny:     true,
			privTerm: "privileged communication",
		},
		{
			name:     "work product doctrine",
			prompt:   "Analyze under the work product doctrine standard",
			deny:     true,
			privTerm: "work product doctrine",
		},
		{
			name:     "confidential legal advice",
			prompt:   "Provide confidential legal advice on merger terms",
			deny:     true,
			privTerm: "confidential legal advice",
		},
		{
			name:   "generic question",
			prompt: "Explain contract law basics",
			system: "",
			deny:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := verticals.Request{
				OrgID:          "org-1",
				ModelRequested: "gpt-4o",
				Prompt:         tt.prompt,
				SystemPrompt:   tt.system,
				Metadata:       make(map[string]string),
			}

			_, resp, err := p.Transform(ctx, in)
			if !tt.deny && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.deny {
				if !resp.Deny {
					t.Error("expected deny for privileged content")
				}
				if resp.DenyReason == "" {
					t.Error("expected deny reason for blocked privilege term")
				}
				if resp.Metadata["legal_privilege_detected"] != "true" {
					t.Error("expected legal_privilege_detected=true in metadata")
				}
				if tt.privTerm != "" && !strings.Contains(resp.Metadata["privilege_term"], tt.privTerm) {
					t.Errorf("expected privilege_term=%q, got %q", tt.privTerm, resp.Metadata["privilege_term"])
				}
			} else {
				if resp.Deny {
					t.Error("did not expect deny for generic prompt")
				}
			}
		})
	}
}

func TestLegalPack_Report(t *testing.T) {
	p := New()
	report, err := p.Report(context.Background(), "org-1", "2024-01-01", "2024-12-31", "saas")
	if err != nil {
		t.Fatalf("report error: %v", err)
	}
	if !strings.Contains(string(report), `"vertical":"legal"`) {
		t.Error("expected vertical=legal in report")
	}
	if !strings.Contains(string(report), `"compliance":"attorney_privilege"`) {
		t.Error("expected compliance=attorney_privilege in report")
	}
}

func TestLegalPack_SetRules(t *testing.T) {
	p := New()
	custom := ResidencyRule{
		AllowedJurisdictions: []policy.Region{"EU"},
		AllowedModelFamilies: []string{"anthropic"},
		DataResidency:        "EU",
		CrossBorderAllowed:   true,
	}
	p.SetRules(custom)

	rules := p.DefaultRules()
	if rules.DataResidency != "EU" {
		t.Errorf("expected data_residency=EU after SetRules, got %s", rules.DataResidency)
	}
}
