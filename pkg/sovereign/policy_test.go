package sovereign

import (
	"context"
	"testing"
)

func TestPolicy_Allows_FullSatisfiesRequiredFull(t *testing.T) {
	p := Policy{RequiredTier: TierFull}
	m := ModelMeta{Country: "JP", Tier: TierFull}
	if !p.Allows(m) {
		t.Fatal("full-tier model should satisfy required_tier=full")
	}
}

func TestPolicy_Rejects_CNWhenNotAllowed(t *testing.T) {
	p := Policy{RequiredTier: TierForeign}
	m := ModelMeta{Country: "CN", CNFlagged: true, Tier: TierForeign}
	if p.Allows(m) {
		t.Fatal("CN model must be rejected when cn_allowed=false")
	}
}

func TestPolicy_Allows_CNWhenExplicitlyOptIn(t *testing.T) {
	p := Policy{RequiredTier: TierForeign, CNAllowed: true}
	m := ModelMeta{Country: "CN", CNFlagged: true, Tier: TierForeign}
	if !p.Allows(m) {
		t.Fatal("CN model allowed when cn_allowed=true")
	}
}

func TestPolicy_Rejects_ExcludedCountry(t *testing.T) {
	p := Policy{RequiredTier: TierForeign, ExcludedCountries: []string{"US"}}
	m := ModelMeta{Country: "US", Tier: TierFull}
	if p.Allows(m) {
		t.Fatal("US model must be excluded")
	}
}

func TestPolicy_Rejects_ExcludedVendorHQ(t *testing.T) {
	p := Policy{RequiredTier: TierForeign, ExcludedCountries: []string{"US"}}
	m := ModelMeta{Country: "JP", VendorHQ: "US", Tier: TierFull}
	if p.Allows(m) {
		t.Fatal("model with US vendor HQ must be excluded")
	}
}

func TestPolicy_DefaultAllowsAllNonCN(t *testing.T) {
	p := DefaultPolicy()
	if !p.Allows(ModelMeta{Country: "JP", Tier: TierFull}) {
		t.Fatal("default policy allows non-CN")
	}
	if p.Allows(ModelMeta{Country: "CN", CNFlagged: true}) {
		t.Fatal("default policy still rejects CN (CNGuard-style)")
	}
}

func TestPolicyStore_NilStore_ReturnsDefault(t *testing.T) {
	var s *PolicyStore
	if got := s.Get(context.Background(), "o1"); got.RequiredTier != TierForeign {
		t.Fatalf("nil store should return default; got %s", got.RequiredTier)
	}
}
