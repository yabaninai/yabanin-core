package asiapacks

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
)

func inCtx(region policy.Region, family string) policy.EvalContext {
	return policy.EvalContext{
		OrgID:          "org-in",
		ModelRequested: "gpt-4",
		ModelRegion:    region,
		UpstreamFamily: family,
	}
}

func TestIndiaPack_IDAndRegion(t *testing.T) {
	p := NewIndiaPack()
	if p.ID() != "in_dpdp_rbi" {
		t.Fatalf("expected id in_dpdp_rbi, got %s", p.ID())
	}
	if p.Region() != policy.Region("IN") {
		t.Fatalf("expected region IN, got %s", p.Region())
	}
}

func TestIndiaPack_DataResidencyAlwaysIN(t *testing.T) {
	p := NewIndiaPack()
	if p.DefaultRules().DataResidency != policy.Region("IN") {
		t.Fatal("RBI requires data residency IN")
	}
}

func TestIndiaPack_CNModel_BlacklistDenied(t *testing.T) {
	p := NewIndiaPack()
	d := p.Evaluate(context.Background(), inCtx("CN", "openai"), nil)
	if d.Allowed {
		t.Fatal("expected CN to be hard-denied via blacklist")
	}
	found := false
	for _, v := range d.Violations {
		if v == "blacklist:CN" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected blacklist:CN violation, got %v", d.Violations)
	}
}

func TestIndiaPack_INModel_Allowed(t *testing.T) {
	p := NewIndiaPack()
	d := p.Evaluate(context.Background(), inCtx("IN", "openai"), nil)
	if !d.Allowed {
		t.Fatalf("expected IN allowed, got: %s", d.Reason)
	}
}

func TestIndiaPack_SGModel_Allowed(t *testing.T) {
	p := NewIndiaPack()
	d := p.Evaluate(context.Background(), inCtx("SG", "anthropic"), nil)
	if !d.Allowed {
		t.Fatalf("expected SG (comparable) allowed, got: %s", d.Reason)
	}
}

func TestIndiaPack_USModel_Denied(t *testing.T) {
	p := NewIndiaPack()
	d := p.Evaluate(context.Background(), inCtx("US", "openai"), nil)
	if d.Allowed {
		t.Fatal("expected US (not allowed) to be denied")
	}
}
