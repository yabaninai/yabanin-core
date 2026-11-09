package finance

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/verticals"
)

func TestFinanceID(t *testing.T) {
	p := New()
	if p.ID() != ID {
		t.Errorf("expected %s, got %s", ID, p.ID())
	}
	if p.Region() != RegionName {
		t.Errorf("expected %s, got %s", RegionName, p.Region())
	}
}

func TestFinanceDefaultRules(t *testing.T) {
	p := New()
	rules := p.DefaultRules()
	if rules.DataResidency != "IN" {
		t.Errorf("expected data_residency=IN, got %s", rules.DataResidency)
	}
	if rules.CrossBorderAllowed {
		t.Error("finance should not allow cross-border by default")
	}
}

func TestFinanceEvaluate(t *testing.T) {
	p := New()
	ctx := context.Background()

	// Allowed: IN region, allowed family.
	dec := p.Evaluate(ctx, policy.EvalContext{
		ModelRequested: "gpt-4o",
		ModelRegion:    "IN",
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
}

func TestFinanceAllowList(t *testing.T) {
	p := New()

	// Empty allow-list = all allowed.
	if !p.IsModelAllowed("any-model") {
		t.Error("empty allow-list should allow all models")
	}

	// Add to allow-list.
	p.AddToAllowList("gpt-4o")
	if !p.IsModelAllowed("gpt-4o") {
		t.Error("gpt-4o should be allowed after adding")
	}
	if p.IsModelAllowed("claude-sonnet") {
		t.Error("claude-sonnet should not be in allow-list")
	}

	// Remove only entry — empty allow-list means all allowed.
	p.RemoveFromAllowList("gpt-4o")
	if !p.IsModelAllowed("any-model") {
		t.Error("empty allow-list should allow all models after removal")
	}

	// Add two models, remove one — remaining should still be denied.
	p.AddToAllowList("model-a")
	p.AddToAllowList("model-b")
	if !p.IsModelAllowed("model-a") {
		t.Error("model-a should be allowed")
	}
	p.RemoveFromAllowList("model-a")
	if p.IsModelAllowed("model-a") {
		t.Error("model-a should be removed after removal")
	}
	if !p.IsModelAllowed("model-b") {
		t.Error("model-b should still be allowed")
	}
}

func TestFinanceTransform(t *testing.T) {
	p := New()
	ctx := context.Background()

	// Not in allow-list — should deny.
	p.AddToAllowList("approved-model")
	in := verticals.Request{
		OrgID:          "org-1",
		ModelRequested: "unapproved-model",
		Prompt:         "hello",
		Metadata:       make(map[string]string),
	}

	_, resp, err := p.Transform(ctx, in)
	if err == nil {
		t.Error("expected error for unapproved model")
	}
	if !resp.Deny {
		t.Error("expected deny response for unapproved model")
	}

	// In allow-list — should pass.
	in.ModelRequested = "approved-model"
	_, resp, err = p.Transform(ctx, in)
	if err != nil {
		t.Fatalf("transform error: %v", err)
	}
	if resp.Deny {
		t.Error("approved model should not deny")
	}

	// Sensitive request — should flag for approval.
	in.Prompt = "credit score calculation for loan application"
	_, resp, err = p.Transform(ctx, in)
	if err != nil {
		t.Fatalf("transform error: %v", err)
	}
	if resp.Metadata["regulatory_decision"] != "true" {
		t.Error("expected regulatory_decision=true for sensitive finance request")
	}

	// Report should produce valid JSON.
	report, err := p.Report(ctx, "org-1", "2024-01-01", "2024-12-31", "saas")
	if err != nil {
		t.Fatalf("report error: %v", err)
	}
	if !strings.Contains(string(report), `"vertical":"finance"`) {
		t.Error("expected finance vertical in report")
	}
}

func TestFinanceIsSensitive(t *testing.T) {
	tests := []struct {
		name     string
		prompt   string
		expected bool
	}{
		{"Credit score", "Calculate credit score for applicant", true},
		{"Loan approval", "Determine loan approval decision", true},
		{"General query", "What is the weather today?", false},
		{"Trading", "Analyze trading strategy for portfolio", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSensitive(tt.prompt, "")
			if got != tt.expected {
				t.Errorf("expected %v for %q, got %v", tt.expected, tt.prompt, got)
			}
		})
	}
}
