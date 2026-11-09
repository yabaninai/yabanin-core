package asiapacks

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
)

func jpCtx(region policy.Region, family string) policy.EvalContext {
	return policy.EvalContext{
		OrgID:          "org-jp",
		ModelRequested: "azure-jp-gpt4o",
		ModelRegion:    region,
		UpstreamFamily: family,
		SessionID:      "sess-1",
	}
}

func TestJapanPack_IDAndRegion(t *testing.T) {
	p := NewJapanPack()
	if p.ID() != "jp_appi" {
		t.Fatalf("expected id jp_appi, got %s", p.ID())
	}
	if p.Region() != policy.Region("JP") {
		t.Fatalf("expected region JP, got %s", p.Region())
	}
	if p.DefaultRules().DataResidency != policy.Region("JP") {
		t.Fatal("expected data residency JP")
	}
	if p.DefaultRules().CrossBorderAllowed {
		t.Fatal("expected cross-border to be disallowed by default under APPI")
	}
}

func TestJapanPack_JPRegionOpenAI_Allowed(t *testing.T) {
	// Azure OpenAI Japan East resource registered with region JP.
	p := NewJapanPack()
	d := p.Evaluate(context.Background(), jpCtx("JP", "openai"), nil)
	if !d.Allowed {
		t.Fatalf("expected JP openai-family model allowed, got denied: %s (violations=%v)", d.Reason, d.Violations)
	}
}

func TestJapanPack_JPRegionSovereign_Allowed(t *testing.T) {
	p := NewJapanPack()
	d := p.Evaluate(context.Background(), jpCtx("JP", "sovereign_jp"), nil)
	if !d.Allowed {
		t.Fatalf("expected JP sovereign model allowed, got denied: %s", d.Reason)
	}
}

func TestJapanPack_USModel_Denied(t *testing.T) {
	// Global api.openai.com registered with region US must be denied.
	p := NewJapanPack()
	d := p.Evaluate(context.Background(), jpCtx("US", "openai"), nil)
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

func TestJapanPack_BlacklistedFamily_Denied(t *testing.T) {
	p := NewJapanPack()
	// JP region is allowed, but the family is not whitelisted.
	d := p.Evaluate(context.Background(), jpCtx("JP", "cohere"), nil)
	if d.Allowed {
		t.Fatal("expected non-whitelisted family to be denied")
	}
	if d.Reason == "" {
		t.Fatal("expected a deny reason")
	}
}

func TestJapanPack_OverrideRelaxes_Allowed(t *testing.T) {
	p := NewJapanPack()
	// DB override adds "US" to allowed jurisdictions (with the customer's own
	// APPI transfer assessment).
	override := p.DefaultRules()
	override.AllowedJurisdictions = append(override.AllowedJurisdictions, policy.Region("US"))

	d := p.Evaluate(context.Background(), jpCtx("US", "openai"), &override)
	if !d.Allowed {
		t.Fatalf("expected override to allow US, got: %s", d.Reason)
	}
}
