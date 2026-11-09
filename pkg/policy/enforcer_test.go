package policy

import (
	"context"
	"testing"
)

// denyAllPack denies every model not in SG (used to exercise remap).
type denyAllPack struct{}

func (denyAllPack) ID() string     { return "test_sg" }
func (denyAllPack) Region() Region { return Region("SG") }
func (denyAllPack) DefaultRules() ResidencyRule {
	return ResidencyRule{AllowedJurisdictions: []Region{"SG"}}
}
func (denyAllPack) Evaluate(_ context.Context, in EvalContext, _ *ResidencyRule) Decision {
	if in.ModelRegion == "SG" {
		return Decision{Allowed: true, Region: "SG", PackID: "test_sg"}
	}
	return Decision{Allowed: false, Region: "SG", PackID: "test_sg", Reason: "not in SG", Violations: []string{"jurisdiction:" + string(in.ModelRegion)}}
}

func TestEnforcer_GlobalOrg_FreePass(t *testing.T) {
	reg := NewRegistry()
	e := NewEnforcer(reg, func(_ context.Context, _ string) Region { return "" }, nil, nil)
	d := e.Enforce(context.Background(), "org", "gpt-4", "US", "openai")
	if !d.Allowed {
		t.Fatal("global org must be free-pass")
	}
	if d.Region != RegionGlobal {
		t.Fatalf("expected region GLOBAL, got %s", d.Region)
	}
}

func TestEnforcer_GlobalRegionConstant_FreePass(t *testing.T) {
	reg := NewRegistry()
	e := NewEnforcer(reg, func(_ context.Context, _ string) Region { return RegionGlobal }, nil, nil)
	d := e.Enforce(context.Background(), "org", "gpt-4", "US", "openai")
	if !d.Allowed {
		t.Fatal("GLOBAL region must be free-pass")
	}
}

func TestEnforcer_RegulatedNoPack_FailClosed(t *testing.T) {
	reg := NewRegistry() // empty: no pack for "XX"
	e := NewEnforcer(reg, func(_ context.Context, _ string) Region { return Region("XX") }, nil, nil)
	d := e.Enforce(context.Background(), "org", "gpt-4", "US", "openai")
	if d.Allowed {
		t.Fatal("regulated region without pack must fail-closed")
	}
	if d.PackID != "missing" {
		t.Fatalf("expected pack_id missing, got %s", d.PackID)
	}
}

func TestEnforcer_Deny_NoPool_StaysDenied(t *testing.T) {
	reg := NewRegistry()
	reg.Register(denyAllPack{})
	e := NewEnforcer(reg, func(_ context.Context, _ string) Region { return Region("SG") }, nil, nil)
	d := e.Enforce(context.Background(), "org", "gpt-4", "US", "openai")
	if d.Allowed {
		t.Fatal("expected deny without a remap pool")
	}
}

// stubPool returns a fixed candidate list.
type stubPool struct{ c []ModelCandidate }

func (s stubPool) ModelsForRegion(_ context.Context, _ Region) []ModelCandidate { return s.c }

func TestEnforcer_Deny_RemapsToInRegionModel(t *testing.T) {
	reg := NewRegistry()
	reg.Register(denyAllPack{})
	pool := stubPool{c: []ModelCandidate{{Name: "sea-lion-sg", Region: "SG", Family: "sovereign_sg"}}}
	e := NewEnforcer(reg, func(_ context.Context, _ string) Region { return Region("SG") }, pool, nil)

	d := e.Enforce(context.Background(), "org", "gpt-4", "US", "openai")
	if !d.Allowed {
		t.Fatal("expected remap to succeed")
	}
	if d.RemappedModel != "sea-lion-sg" {
		t.Fatalf("expected remap to sea-lion-sg, got %q", d.RemappedModel)
	}
	if d.Reason != "remapped to in-region model" {
		t.Fatalf("unexpected reason: %s", d.Reason)
	}
}

func TestEnforcer_Allowed_NoRemap(t *testing.T) {
	reg := NewRegistry()
	reg.Register(denyAllPack{})
	pool := stubPool{c: []ModelCandidate{{Name: "sea-lion-sg", Region: "SG", Family: "sovereign_sg"}}}
	e := NewEnforcer(reg, func(_ context.Context, _ string) Region { return Region("SG") }, pool, nil)

	d := e.Enforce(context.Background(), "org", "sg-model", "SG", "openai")
	if !d.Allowed {
		t.Fatal("expected allowed")
	}
	if d.RemappedModel != "" {
		t.Fatalf("expected no remap on allow, got %q", d.RemappedModel)
	}
}
