//go:build cnoff

// Package sovereignty tests the CN-off safety gate end-to-end.
// These tests verify that when CNGuard is active, Chinese-flagged models are
// never served regardless of any org-level policy allowing them.
package sovereignty

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/classifier"
	sovereign "github.com/reireirei/yabanin/pkg/sovereign"
)

func TestCNOff_Default_NoCNModelServed(t *testing.T) {
	// With the default policy (TierForeign), models marked CNFlagged=true
	// should never appear in any tier pool.
	defPolicy := sovereign.DefaultPolicy()
	cnModel := sovereign.ModelMeta{
		Name:      "qwen-max",
		Country:   "CN",
		VendorHQ:  "CN",
		Tier:      sovereign.TierChinaOnshore,
		CNFlagged: true,
	}
	if defPolicy.Allows(cnModel) {
		t.Fatal("default policy should reject CN-flagged model")
	}

	foreignModel := sovereign.ModelMeta{
		Name:      "gpt-4o",
		Country:   "US",
		VendorHQ:  "US",
		Tier:      sovereign.TierForeign,
		CNFlagged: false,
	}
	if !defPolicy.Allows(foreignModel) {
		t.Fatal("default policy should allow foreign model")
	}
}

func TestCNOff_GuardBlocksRegardlessOfPolicyAllows(t *testing.T) {
	// Even a permissive policy (TierChinaOnshore + CNAllowed=true) must
	// still be subject to the CNGuard double-check. This tests the guard
	// logic directly.
	guard := sovereign.NewCNGuard(
		sovereign.CNGuardConfig{Enabled: true, StrictMode: true},
	)

	cnModel := sovereign.ModelMeta{
		Name:      "qwen-max",
		Country:   "CN",
		VendorHQ:  "CN",
		Tier:      sovereign.TierChinaOnshore,
		CNFlagged: true,
	}
	policy := sovereign.Policy{
		RequiredTier:      sovereign.TierChinaOnshore,
		BuyerJurisdiction: "IN",
		CNAllowed:         true, // explicitly allowed by org policy
	}

	// Policy says OK, but CNGuard should block.
	if guard.Check(cnModel, policy) != nil {
		t.Log("CNGuard correctly blocked CN-flagged model even with CNAllowed=true")
	} else {
		t.Error("CNGuard should have blocked CN-flagged model in strict mode")
	}

	foreignModel := sovereign.ModelMeta{
		Name:      "gpt-4o",
		Country:   "US",
		VendorHQ:  "US",
		Tier:      sovereign.TierForeign,
		CNFlagged: false,
	}
	if guard.Check(foreignModel, policy) != nil {
		t.Error("CNGuard should allow non-CN model")
	}
}

func TestCNOff_OptIn_AllowsCN(t *testing.T) {
	guard := sovereign.NewCNGuard(
		sovereign.CNGuardConfig{Enabled: true, StrictMode: false}, // lenient mode
	)

	cnModel := sovereign.ModelMeta{
		Name:      "qwen-max",
		Country:   "CN",
		VendorHQ:  "CN",
		Tier:      sovereign.TierChinaOnshore,
		CNFlagged: true,
	}
	policy := sovereign.Policy{
		RequiredTier:      sovereign.TierChinaOnshore,
		BuyerJurisdiction: "IN",
		CNAllowed:         true, // opt-in for this org
	}

	if guard.Check(cnModel, policy) != nil {
		t.Error("CNGuard in lenient mode with CNAllowed=true should allow CN model")
	}
}

func TestCNOff_DisabledGuard_AllowsCN(t *testing.T) {
	guard := sovereign.NewCNGuard(
		sovereign.CNGuardConfig{Enabled: false}, // guard disabled
	)

	cnModel := sovereign.ModelMeta{
		Name:      "qwen-max",
		Country:   "CN",
		VendorHQ:  "CN",
		Tier:      sovereign.TierChinaOnshore,
		CNFlagged: true,
	}
	policy := sovereign.Policy{
		RequiredTier:      sovereign.TierChinaOnshore,
		BuyerJurisdiction: "IN",
		CNAllowed:         true,
	}

	if guard.Check(cnModel, policy) != nil {
		t.Error("disabled CNGuard should not block any model")
	}
}

func TestCNOff_InvalidTierRejected(t *testing.T) {
	guard := sovereign.NewCNGuard(
		sovereign.CNGuardConfig{Enabled: true, StrictMode: true},
	)

	badModel := sovereign.ModelMeta{
		Name:      "unknown-model",
		Country:   "",
		VendorHQ:  "",
		Tier:      sovereign.Tier(""), // invalid tier
		CNFlagged: false,
	}
	policy := sovereign.Policy{RequiredTier: sovereign.TierForeign}

	if guard.Check(badModel, policy) == nil {
		t.Error("CNGuard should reject models with invalid tier")
	}
}

func TestCNOff_CNCountryExcluded(t *testing.T) {
	guard := sovereign.NewCNGuard(
		sovereign.CNGuardConfig{Enabled: true, StrictMode: true},
	)

	cnModel := sovereign.ModelMeta{
		Name:      "qwen-max",
		Country:   "CN",
		VendorHQ:  "CN",
		Tier:      sovereign.TierChinaOnshore,
		CNFlagged: true,
	}
	policy := sovereign.Policy{
		RequiredTier:      sovereign.TierForeign,
		ExcludedCountries: []string{"CN"},
		BuyerJurisdiction: "IN",
		CNAllowed:         false,
	}

	if guard.Check(cnModel, policy) == nil {
		t.Error("CNGuard should block CN model when country is excluded")
	}
}
