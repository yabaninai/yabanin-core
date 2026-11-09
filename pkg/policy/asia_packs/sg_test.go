package asiapacks

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
)

func sgCtx(region policy.Region, family string) policy.EvalContext {
	return policy.EvalContext{
		OrgID:          "org-sg",
		ModelRequested: "gpt-4",
		ModelRegion:    region,
		UpstreamFamily: family,
		SessionID:      "sess-1",
	}
}

func TestSingaporePack_IDAndRegion(t *testing.T) {
	p := NewSingaporePack()
	if p.ID() != "sg_pdpa_mas" {
		t.Fatalf("expected id sg_pdpa_mas, got %s", p.ID())
	}
	if p.Region() != policy.Region("SG") {
		t.Fatalf("expected region SG, got %s", p.Region())
	}
	if p.DefaultRules().DataResidency != policy.Region("SG") {
		t.Fatal("expected data residency SG")
	}
}

func TestSingaporePack_SGModel_Allowed(t *testing.T) {
	p := NewSingaporePack()
	d := p.Evaluate(context.Background(), sgCtx("SG", "openai"), nil)
	if !d.Allowed {
		t.Fatalf("expected allowed, got denied: %s (violations=%v)", d.Reason, d.Violations)
	}
}

func TestSingaporePack_EUModel_Allowed(t *testing.T) {
	p := NewSingaporePack()
	d := p.Evaluate(context.Background(), sgCtx("EU", "anthropic"), nil)
	if !d.Allowed {
		t.Fatalf("expected EU allowed via comparable protection, got: %s", d.Reason)
	}
}

func TestSingaporePack_USModel_Denied(t *testing.T) {
	p := NewSingaporePack()
	d := p.Evaluate(context.Background(), sgCtx("US", "openai"), nil)
	if d.Allowed {
		t.Fatal("expected US-only model to be denied")
	}
	found := false
	for _, v := range d.Violations {
		if v == "jurisdiction:US" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jurisdiction:US violation, got %v", d.Violations)
	}
}

func TestSingaporePack_BlacklistedFamily_Denied(t *testing.T) {
	p := NewSingaporePack()
	// SG region is allowed, but "cohere" family is not whitelisted.
	d := p.Evaluate(context.Background(), sgCtx("SG", "cohere"), nil)
	if d.Allowed {
		t.Fatal("expected non-whitelisted family to be denied")
	}
	if d.Reason == "" {
		t.Fatal("expected a deny reason")
	}
}

func TestSingaporePack_OverrideRelaxes_Allowed(t *testing.T) {
	p := NewSingaporePack()
	// DB override adds "US" to allowed jurisdictions.
	override := p.DefaultRules()
	override.AllowedJurisdictions = append(override.AllowedJurisdictions, policy.Region("US"))

	d := p.Evaluate(context.Background(), sgCtx("US", "openai"), &override)
	if !d.Allowed {
		t.Fatalf("expected override to allow US, got: %s", d.Reason)
	}
}
