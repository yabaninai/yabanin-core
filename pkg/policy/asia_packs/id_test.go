package asiapacks

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
)

func idCtx(region policy.Region, family string) policy.EvalContext {
	return policy.EvalContext{
		OrgID:          "org-id",
		ModelRequested: "gpt-4",
		ModelRegion:    region,
		UpstreamFamily: family,
	}
}

func TestIndonesiaPack_IDAndRegion(t *testing.T) {
	p := NewIndonesiaPack()
	if p.ID() != "id_pdp" {
		t.Fatalf("expected id id_pdp, got %s", p.ID())
	}
	if p.Region() != policy.Region("ID") {
		t.Fatalf("expected region ID, got %s", p.Region())
	}
	if p.DefaultRules().DataResidency != policy.Region("ID") {
		t.Fatal("expected data residency ID")
	}
}

func TestIndonesiaPack_IDModel_Allowed(t *testing.T) {
	p := NewIndonesiaPack()
	d := p.Evaluate(context.Background(), idCtx("ID", "openai"), nil)
	if !d.Allowed {
		t.Fatalf("expected ID allowed, got: %s", d.Reason)
	}
}

func TestIndonesiaPack_SGModel_Allowed(t *testing.T) {
	p := NewIndonesiaPack()
	d := p.Evaluate(context.Background(), idCtx("SG", "anthropic"), nil)
	if !d.Allowed {
		t.Fatalf("expected SG (comparable) allowed, got: %s", d.Reason)
	}
}

func TestIndonesiaPack_EUModel_Denied(t *testing.T) {
	p := NewIndonesiaPack()
	d := p.Evaluate(context.Background(), idCtx("EU", "openai"), nil)
	if d.Allowed {
		t.Fatal("expected EU (not allowed for ID) to be denied")
	}
}

func TestIndonesiaPack_USModel_Denied(t *testing.T) {
	p := NewIndonesiaPack()
	d := p.Evaluate(context.Background(), idCtx("US", "openai"), nil)
	if d.Allowed {
		t.Fatal("expected US to be denied for ID pack")
	}
}
