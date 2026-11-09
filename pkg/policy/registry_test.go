package policy

import (
	"context"
	"reflect"
	"testing"
)

// stubPack is a minimal Pack used to exercise the registry and decisions.
type stubPack struct {
	id     string
	region Region
	rules  ResidencyRule
}

func (s *stubPack) ID() string                  { return s.id }
func (s *stubPack) Region() Region              { return s.region }
func (s *stubPack) DefaultRules() ResidencyRule { return s.rules }
func (s *stubPack) Evaluate(_ context.Context, _ EvalContext, _ *ResidencyRule) Decision {
	return Decision{Allowed: true, Region: s.region, PackID: s.id}
}

func TestRegionIn(t *testing.T) {
	if !RegionIn("SG", []Region{"SG", "EU"}) {
		t.Fatal("expected SG to be found")
	}
	if RegionIn("US", []Region{"SG", "EU"}) {
		t.Fatal("expected US to NOT be found")
	}
}

func TestFamilyIn(t *testing.T) {
	if !FamilyIn("openai", []string{"openai", "anthropic"}) {
		t.Fatal("expected openai to be found")
	}
	if FamilyIn("cohere", []string{"openai", "anthropic"}) {
		t.Fatal("expected cohere to NOT be found")
	}
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	p := &stubPack{id: "sg_pdpa_mas", region: "SG", rules: ResidencyRule{DataResidency: "SG"}}
	r.Register(p)

	got := r.Get("SG")
	if got == nil {
		t.Fatal("expected non-nil pack for SG")
	}
	if got.ID() != "sg_pdpa_mas" {
		t.Fatalf("expected id sg_pdpa_mas, got %s", got.ID())
	}
}

func TestRegistry_GetUnknownRegion_Nil(t *testing.T) {
	r := NewRegistry()
	if got := r.Get("ZZ"); got != nil {
		t.Fatalf("expected nil for unregistered region, got %v", got)
	}
}

func TestRegistry_List_ReturnsAll(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubPack{id: "a", region: "SG"})
	r.Register(&stubPack{id: "b", region: "IN"})

	list := r.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 packs, got %d", list)
	}

	ids := map[string]bool{}
	for _, p := range list {
		ids[p.ID()] = true
	}
	if !ids["a"] || !ids["b"] {
		t.Fatalf("expected packs a and b, got %v", ids)
	}
}

// TestDecision_DenyWhenModelRegionNotInAllowed is a pure helper-level check
// exercising RegionIn the way the real packs do.
func TestDecision_DenyWhenModelRegionNotInAllowed(t *testing.T) {
	allowed := []Region{"SG"}
	modelRegion := Region("US")

	d := Decision{Region: "SG", PackID: "sg_pdpa_mas"}
	if !RegionIn(modelRegion, allowed) {
		d.Allowed = false
		d.Reason = "model upstream region not in allowed jurisdictions"
		d.Violations = append(d.Violations, "jurisdiction:"+string(modelRegion))
	}
	if d.Allowed {
		t.Fatal("expected denied decision")
	}
	want := []string{"jurisdiction:US"}
	if !reflect.DeepEqual(d.Violations, want) {
		t.Fatalf("expected violations %v, got %v", want, d.Violations)
	}
}
