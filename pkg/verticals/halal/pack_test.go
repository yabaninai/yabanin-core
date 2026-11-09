package halal

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

func TestHalalID(t *testing.T) {
	p := New()
	if p.ID() != ID {
		t.Errorf("expected %s, got %s", ID, p.ID())
	}
	if p.Region() != RegionName {
		t.Errorf("expected %s, got %s", RegionName, p.Region())
	}
}

func TestHalalDefaultRules(t *testing.T) {
	p := New()
	rules := p.DefaultRules()
	if len(rules.AllowedJurisdictions) == 0 {
		t.Error("expected allowed jurisdictions")
	}
	if rules.DataResidency != "ID" {
		t.Errorf("expected data_residency=ID, got %s", rules.DataResidency)
	}
	if rules.CrossBorderAllowed {
		t.Error("expected cross_border=false for halal")
	}
}

func TestHalalEvaluate(t *testing.T) {
	p := New()
	ctx := context.Background()

	// Allowed: model in allowed jurisdictions.
	dec := p.Evaluate(ctx, policy.EvalContext{
		OrgID:          "org-1",
		ModelRequested: "gpt-4o",
		ModelRegion:    "SG",
		UpstreamFamily: "openai",
	}, nil)
	if !dec.Allowed {
		t.Errorf("expected allowed, got denied: %s", dec.Reason)
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

	// Denied: model family not in allowed list.
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "SG",
		UpstreamFamily: "forbidden_family",
	}, nil)
	if dec.Allowed {
		t.Error("expected denied for forbidden family")
	}

	// Overridden rules: custom allowed jurisdictions.
	custom := &policy.ResidencyRule{
		AllowedJurisdictions: []policy.Region{"US"},
		AllowedModelFamilies: []string{"openai"},
		DataResidency:        "US",
		CrossBorderAllowed:   false,
	}
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "US",
		UpstreamFamily: "openai",
	}, custom)
	if !dec.Allowed {
		t.Error("expected allowed with custom rules")
	}
}

func TestHalalTransform(t *testing.T) {
	p := New()
	ctx := context.Background()
	in := verticals.Request{
		OrgID:          "org-1",
		ModelRequested: "gpt-4o",
		Prompt:         "test prompt",
		Metadata:       make(map[string]string),
	}

	_, resp, err := p.Transform(ctx, in)
	if err != nil {
		t.Fatalf("transform error: %v", err)
	}
	if resp.Deny {
		t.Error("halal transform should not deny by default")
	}
	if resp.Model != "gpt-4o" {
		t.Errorf("expected model=gpt-4o, got %s", resp.Model)
	}

	// Report should produce valid JSON.
	report, err := p.Report(ctx, "org-1", "2024-01-01", "2024-12-31", "saas")
	if err != nil {
		t.Fatalf("report error: %v", err)
	}
	if !strings.Contains(string(report), `"vertical":"halal"`) {
		t.Error("expected halal vertical in report")
	}
}

func TestHalalSetRules(t *testing.T) {
	p := New()
	custom := ResidencyRule{
		AllowedJurisdictions: []policy.Region{"US"},
		AllowedModelFamilies: []string{"anthropic"},
		DataResidency:        "US",
		CrossBorderAllowed:   true,
	}
	p.SetRules(custom)

	rules := p.DefaultRules()
	if rules.DataResidency != "US" {
		t.Errorf("expected data_residency=US after SetRules, got %s", rules.DataResidency)
	}
}
