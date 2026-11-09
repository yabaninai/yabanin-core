package education

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

func TestEducationPack_IDAndRegion(t *testing.T) {
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

func TestEducationPack_DefaultRules(t *testing.T) {
	p := New()
	rules := p.DefaultRules()
	if !policy.RegionIn("US", rules.AllowedJurisdictions) {
		t.Error("expected US in allowed jurisdictions")
	}
	if rules.DataResidency != "US" {
		t.Errorf("expected data_residency=US, got %s", rules.DataResidency)
	}
	if rules.CrossBorderAllowed {
		t.Error("expected cross_border=false for FERPA")
	}
}

func TestEducationPack_Evaluate(t *testing.T) {
	p := New()
	ctx := context.Background()

	// Allowed: model in US (allowed jurisdiction).
	dec := p.Evaluate(ctx, policy.EvalContext{
		OrgID:          "org-1",
		ModelRequested: "gpt-4o",
		ModelRegion:    "US",
		UpstreamFamily: "sovereign_us",
	}, nil)
	if !dec.Allowed {
		t.Errorf("expected allowed for US region, got denied: %s", dec.Reason)
	}

	// Denied: model region not in allowed list.
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "EU",
		UpstreamFamily: "openai",
	}, nil)
	if dec.Allowed {
		t.Error("expected denied for EU region (FERPA requires US)")
	}

	// Denied: foreign model family.
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "SG",
		UpstreamFamily: "forbidden_family",
	}, nil)
	if dec.Allowed {
		t.Error("expected denied for forbidden model family")
	}

	// Custom override: allow EU.
	custom := &policy.ResidencyRule{
		AllowedJurisdictions: []policy.Region{"EU"},
		AllowedModelFamilies: []string{"openai"},
		DataResidency:        "EU",
		CrossBorderAllowed:   false,
	}
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "EU",
		UpstreamFamily: "openai",
	}, custom)
	if !dec.Allowed {
		t.Error("expected allowed with custom EU override")
	}
}

func TestEducationPack_Transform_FERPADetection(t *testing.T) {
	p := New()
	ctx := context.Background()

	tests := []struct {
		name       string
		prompt     string
		flagged    bool
		mustDetect bool
	}{
		{"student record", "What is John's GPA?", true, true},
		{"grade inquiry", "Show me the grade for student ID 12345", true, true},
		{"gpa lookup", "Find average GPA by class", true, true},
		{"generic question", "Explain quantum mechanics", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := verticals.Request{
				OrgID:          "org-1",
				ModelRequested: "gpt-4o",
				Prompt:         tt.prompt,
				Metadata:       make(map[string]string),
			}

			_, resp, err := p.Transform(ctx, in)
			if err != nil {
				t.Fatalf("transform error: %v", err)
			}
			if resp.Deny {
				t.Error("education transform should not deny by default")
			}
			if tt.mustDetect && !strings.Contains(resp.Metadata["ferpa_flagged"], "true") {
				t.Error("expected ferpa_flagged=metadata for student/grade/gpa prompts")
			}
			if tt.mustDetect && !strings.Contains(resp.Metadata["education_data_detected"], "true") {
				t.Error("expected education_data_detected metadata")
			}
		})
	}
}

func TestEducationPack_Report(t *testing.T) {
	p := New()
	report, err := p.Report(context.Background(), "org-1", "2024-01-01", "2024-12-31", "saas")
	if err != nil {
		t.Fatalf("report error: %v", err)
	}
	if !strings.Contains(string(report), `"vertical":"education"`) {
		t.Error("expected vertical=education in report")
	}
	if !strings.Contains(string(report), `"compliance":"ferpa"`) {
		t.Error("expected compliance=ferpa in report")
	}
}

func TestEducationPack_SetRules(t *testing.T) {
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
	if !policy.RegionIn("EU", rules.AllowedJurisdictions) {
		t.Error("expected EU in allowed jurisdictions after SetRules")
	}
}
