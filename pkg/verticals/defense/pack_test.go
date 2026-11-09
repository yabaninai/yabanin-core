package defense

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

func TestDefenseID(t *testing.T) {
	p := New()
	if p.ID() != ID {
		t.Errorf("expected %s, got %s", ID, p.ID())
	}
	if p.Region() != RegionName {
		t.Errorf("expected %s, got %s", RegionName, p.Region())
	}
}

func TestDefenseDefaultRules(t *testing.T) {
	p := New()
	rules := p.DefaultRules()
	if rules.DataResidency != "US" {
		t.Errorf("expected data_residency=US, got %s", rules.DataResidency)
	}
	if !policy.RegionIn("CN", rules.BlacklistedCountries) {
		t.Error("CN should be in blacklisted countries")
	}
	if !policy.RegionIn("RU", rules.BlacklistedCountries) {
		t.Error("RU should be in blacklisted countries")
	}
	if rules.CrossBorderAllowed {
		t.Error("defense should not allow cross-border")
	}
}

func TestDefenseEvaluate(t *testing.T) {
	p := New()
	ctx := context.Background()

	// Allowed: US region, sovereign family.
	dec := p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "sovereign-model",
		ModelRegion:    "US",
		UpstreamFamily: "sovereign_us",
	}, nil)
	if !dec.Allowed {
		t.Errorf("expected allowed for US/sovereign, got denied: %s", dec.Reason)
	}

	// Denied: non-US region.
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "SG",
	}, nil)
	if dec.Allowed {
		t.Error("expected denied for non-US defense")
	}

	// Denied: sanctioned country.
	dec = p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "CN",
	}, nil)
	if dec.Allowed {
		t.Error("expected denied for CN — ITAR blacklisted")
	}
}

func TestDefenseSovereignPool(t *testing.T) {
	p := New()

	// Empty pool = all allowed by pool check.
	if !p.IsInSovereignPool("any-model") {
		t.Error("empty pool should allow any model")
	}

	// Add to sovereign pool.
	p.AddToSovereignPool("sovereign-a")
	if !p.IsInSovereignPool("sovereign-a") {
		t.Error("sovereign-a should be in pool")
	}
	if p.IsInSovereignPool("commodity-model") {
		t.Error("commodity-model should not be in sovereign pool")
	}

	// Add another model so pool isn't empty after removing sovereign-a.
	p.AddToSovereignPool("defense-model-ref")
	// Now remove sovereign-a — should be gone but ref remains.
	p.RemoveFromSovereignPool("sovereign-a")
	if p.IsInSovereignPool("sovereign-a") {
		t.Error("sovereign-a should be removed after removal")
	}
	if !p.IsInSovereignPool("defense-model-ref") {
		t.Error("defense-model-ref should still be in pool")
	}

	// Test with two models: add both, remove one.
	p.AddToSovereignPool("defense-model-x")
	p.AddToSovereignPool("defense-model-y")
	if !p.IsInSovereignPool("defense-model-x") {
		t.Error("defense-model-x should be in pool")
	}
	p.RemoveFromSovereignPool("defense-model-x")
	if p.IsInSovereignPool("defense-model-x") {
		t.Error("defense-model-x should be removed after removal")
	}
	if !p.IsInSovereignPool("defense-model-y") {
		t.Error("defense-model-y should still be in pool")
	}
}

func TestDefenseScreenPrompt(t *testing.T) {
	p := New()

	tests := []struct {
		name     string
		prompt   string
		expected int
	}{
		{"ITAR term", "This document contains controlled technical data per ITAR", 2}, // itar + controlled technical data
		{"Munitions", "Guided missile radar cross-section analysis", 2},               // munitions, radar cross-section
		{"Clean prompt", "Hello world this is a test", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := p.ScreenPrompt(tt.prompt)
			if len(errors) != tt.expected {
				t.Errorf("expected %d screening errors, got %d: %+v", tt.expected, len(errors), errors)
			}
			for _, e := range errors {
				if e.Type != "itar_controlled" {
					t.Errorf("expected type itar_controlled, got %s", e.Type)
				}
			}
		})
	}
}

func TestDefenseTransform(t *testing.T) {
	p := New()
	ctx := context.Background()

	// In sovereign pool — should pass.
	p.AddToSovereignPool("defense-model")
	in := verticals.Request{
		OrgID:          "org-1",
		ModelRequested: "defense-model",
		Prompt:         "analysis of ballistic trajectory data",
		Metadata:       make(map[string]string),
	}

	_, resp, err := p.Transform(ctx, in)
	if err != nil {
		t.Fatalf("transform error: %v", err)
	}
	if resp.Deny {
		t.Error("sovereign model should not deny")
	}
	if resp.Metadata["itar_screened"] != "true" {
		t.Error("expected itar_screened=true for ITAR-flagged prompt")
	}

	// Not in pool — should deny.
	in.ModelRequested = "commodity-model"
	_, resp, err = p.Transform(ctx, in)
	if err == nil {
		t.Error("expected error for non-sovereign model")
	}
	if !resp.Deny {
		t.Error("expected deny response for non-sovereign model")
	}

	// Report should produce valid JSON.
	report, err := p.Report(ctx, "org-1", "2024-01-01", "2024-12-31", "saas")
	if err != nil {
		t.Fatalf("report error: %v", err)
	}
	if !strings.Contains(string(report), `"vertical":"defense"`) {
		t.Error("expected defense vertical in report")
	}
}

func TestDefenseSetRules(t *testing.T) {
	p := New()
	custom := ResidencyRule{
		AllowedJurisdictions: []policy.Region{"US", "CA"},
		AllowedModelFamilies: []string{"sovereign_us"},
		DataResidency:        "US",
		CrossBorderAllowed:   false,
	}
	p.SetRules(custom)

	rules := p.DefaultRules()
	if !policy.RegionIn("CA", rules.AllowedJurisdictions) {
		t.Error("CA should be in allowed jurisdictions after SetRules")
	}
}
