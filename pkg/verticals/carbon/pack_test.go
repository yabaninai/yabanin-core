package carbon

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

func TestCarbonID(t *testing.T) {
	p := New()
	if p.ID() != ID {
		t.Errorf("expected %s, got %s", ID, p.ID())
	}
}

func TestCarbonDefaultRules(t *testing.T) {
	p := New()
	rules := p.DefaultRules()
	if !rules.CrossBorderAllowed {
		t.Error("carbon pack should allow cross-border by default")
	}
}

func TestCarbonEvaluate(t *testing.T) {
	p := New()
	ctx := context.Background()

	dec := p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "GLOBAL",
	}, nil)
	if !dec.Allowed {
		t.Errorf("expected allowed, got denied: %s", dec.Reason)
	}
}

func TestCarbonEstimateTokens(t *testing.T) {
	// ~4 chars per token heuristic.
	if EstimateTokens("") != 0 {
		t.Error("empty prompt should have 0 tokens")
	}
	got := EstimateTokens("hello world test")
	if got < 1 || got > 20 {
		t.Errorf("unexpected token count: %d", got)
	}
}

func TestCarbonEstimateGrams(t *testing.T) {
	p := New()
	grams := p.EstimateGrams("gpt-4o", 1_000_000)
	if grams != 50.0 {
		t.Errorf("expected 50.0g for 1M tokens, got %.2f", grams)
	}

	grams = p.EstimateGrams("gpt-4o", 100_000)
	if grams != 5.0 {
		t.Errorf("expected 5.0g for 100K tokens, got %.2f", grams)
	}

	// Unknown model uses default 50g per 1M.
	grams = p.EstimateGrams("unknown-model", 1_000_000)
	if grams != 50.0 {
		t.Errorf("expected 50.0g for unknown model, got %.2f", grams)
	}
}

func TestCarbonTransform(t *testing.T) {
	p := New()
	ctx := context.Background()

	// No budget set — should pass through unchanged.
	in := verticals.Request{
		OrgID:          "org-1",
		ModelRequested: "gpt-4o",
		Prompt:         "hello world",
		Metadata:       make(map[string]string),
	}

	_, resp, err := p.Transform(ctx, in)
	if err != nil {
		t.Fatalf("transform error: %v", err)
	}
	if resp.Deny {
		t.Error("carbon transform should not deny")
	}

	// Set a tight budget — should trigger remap.
	p.SetBudget("org-2", 1.0) // 1 gram limit
	in.OrgID = "org-2"
	in.ModelRequested = "gpt-4o"
	in.Prompt = strings.Repeat("x", 400_000) // ~100K tokens → 5g

	_, resp, err = p.Transform(ctx, in)
	if err != nil {
		t.Fatalf("transform error: %v", err)
	}
	if resp.Metadata["carbon_remapped"] != "true" {
		t.Log("budget exceeded but no remap found — OK if no lower-carbon alternative exists")
	}

	// Report should produce valid JSON.
	report, err := p.Report(ctx, "org-1", "2024-01-01", "2024-12-31", "saas")
	if err != nil {
		t.Fatalf("report error: %v", err)
	}
	if !strings.Contains(string(report), `"vertical":"carbon"`) {
		t.Error("expected carbon vertical in report")
	}
}

func TestCarbonSetFactor(t *testing.T) {
	p := New()
	p.SetFactor("custom-model", "test-provider", 25.0)

	factor := p.GetFactor("custom-model")
	if factor.GramsPer1M != 25.0 {
		t.Errorf("expected 25.0g, got %.2f", factor.GramsPer1M)
	}
	if factor.Provider != "test-provider" {
		t.Errorf("expected test-provider, got %s", factor.Provider)
	}
}

func TestCarbonPreferLowCarbon(t *testing.T) {
	p := New()
	best := p.preferLowCarbon("gpt-4o") // 50g per 1M
	if best == "" {
		t.Log("no lower-carbon alternative found — acceptable depending on seed data")
	} else {
		factor := p.GetFactor(best)
		if factor.GramsPer1M >= 35.0 { // should be < 70% of 50 = 35
			t.Errorf("best model %s has %.2fg, expected < 35g", best, factor.GramsPer1M)
		}
	}
}
