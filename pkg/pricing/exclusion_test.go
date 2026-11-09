package pricing

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// With removed drafts absent from the new pack, the old generic table fallback
// would silently activate five OpenAI rates. This assertion targets that path.
func TestPricingExclusionNoImplicitResurrection(t *testing.T) {
	auditPristineDefaults(t)
	for _, model := range []string{"gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"} {
		if _, ok := DefaultLookup("openai", model); ok {
			t.Errorf("excluded default rate reactivated: %s", model)
		}
		q, err := NewMarkupPricer(nil, StaticPricer(), nil).Quote(context.Background(), "fixture", "openai", model, 100, 50, 0, 0)
		if !errors.Is(err, ErrUnknownModel) || q != nil {
			t.Errorf("unknown rate produced quote: %s %+v %v", model, q, err)
		}
	}
	for _, model := range []string{"claude-3-5-sonnet-20241022", "claude-3-5-sonnet-latest", "claude-3-5-haiku-20241022", "claude-3-5-haiku-latest", "claude-3-opus-20240229"} {
		p, ok := DefaultLookup("anthropic", model)
		if !ok || p != Lookup("anthropic", model) {
			t.Errorf("independent historical price changed: %s", model)
		}
	}
	_, cat, err := LoadRefPack(BundledRefPackJSON())
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Models) != 5 {
		t.Fatalf("unexpected built-in inventory: %d", len(cat.Models))
	}
	if strings.Contains(strings.ToLower(string(BundledRefPackJSON())), "litellm") {
		t.Fatal("third-party corpus/provenance survives in shipped pack")
	}
}

func TestPricingExclusionExplicitUnitsStillWork(t *testing.T) {
	saved := DefaultUnitPricer()
	t.Cleanup(func() { SetDefaultUnitPricer(saved) })
	custom, err := NewUnitFilePricer(UnitFile{Source: "authored synthetic unit fixture", Date: "2026-11-09", Currency: "USD", Units: []UnitEntry{{Provider: "azure", Model: "fixture-speech", Unit: UnitPerCharacter, Rate: 0.0000321}}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	SetDefaultUnitPricer(custom)
	for _, provider := range []string{"azure", "azure-openai"} {
		p, ok := DefaultUnitPricer().LookupUnit(provider, "fixture-speech")
		if !ok || p.Rate != 0.0000321 {
			t.Errorf("operator unit override unavailable: %+v/%v", p, ok)
		}
	}
	if _, ok := DefaultUnitPricer().LookupUnit("azure", "absent"); ok {
		t.Fatal("missing unit became free")
	}
}
