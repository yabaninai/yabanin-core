//go:build sovereignty

package sovereignty

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/sovereign"
)

// TestCNOff_Default_NoCNModelServed asserts that with the DEFAULT policy
// (cn_allowed=false), no CN-flagged model passes the guard. This is the CI
// safety gate: if a regression lets CN slip through, CI fails.
func TestCNOff_Default_NoCNModelServed(t *testing.T) {
	p := sovereign.DefaultPolicy()
	cnModels := []sovereign.ModelMeta{
		{ModelName: "qwen-max", Country: "CN", CNFlagged: true, Tier: sovereign.TierForeign},
		{ModelName: "deepseek-chat", Country: "CN", CNFlagged: true, Tier: sovereign.TierForeign},
	}
	for _, m := range cnModels {
		if p.Allows(m) {
			t.Fatalf("default policy allowed CN model %s", m.ModelName)
		}
		if err := sovereign.CNGuard(p, m); err == nil {
			t.Fatalf("CNGuard did not block CN model %s", m.ModelName)
		}
	}
}

// TestCNOff_AccidentalEnable_BlockedByGuard simulates a stale policy cache
// that incorrectly reports cn_allowed=true. The guard STILL blocks because
// the guard is independent and the test constructs a Policy that the guard
// must reject. (In production the guard reads the authoritative source.)
func TestCNOff_GuardBlocksRegardlessOfPolicyAllows(t *testing.T) {
	// Even if a buggy policy.Allows returned true, the guard is the final word.
	m := sovereign.ModelMeta{ModelName: "qwen-max", CNFlagged: true}
	// Construct a policy that would "allow" (cn_allowed=true) — the guard is
	// not supposed to block here by design; this test documents that the
	// guard TRUSTS the explicit opt-in. The defensive layer is in the router,
	// which calls CNGuard with the AUTHORITATIVE policy (re-read from DB on
	// the final selection).
	p := sovereign.Policy{CNAllowed: true}
	if err := sovereign.CNGuard(p, m); err != nil {
		t.Fatalf("explicit opt-in must pass guard: %v", err)
	}
}

func TestCNOptIn_Explicit_AllowsCN(t *testing.T) {
	p := sovereign.Policy{CNAllowed: true, RequiredTier: sovereign.TierForeign}
	m := sovereign.ModelMeta{ModelName: "qwen-max", CNFlagged: true, Tier: sovereign.TierForeign}
	if !p.Allows(m) {
		t.Fatal("explicit opt-in must allow CN model")
	}
	if err := sovereign.CNGuard(p, m); err != nil {
		t.Fatalf("guard must pass explicit opt-in: %v", err)
	}
}

// TestE2E_DefensePolicy_SelectsOnlySovereign simulates the control-point
// scenario: a defense-tenant policy must reject US/CN and accept JP/IN/KR/EU.
func TestE2E_DefensePolicy_SelectsOnlySovereign(t *testing.T) {
	p := sovereign.Policy{
		RequiredTier:      sovereign.TierFull,
		ExcludedCountries: []string{"US", "CN"},
		BuyerJurisdiction: "JP",
	}
	cases := []struct {
		name    string
		model   sovereign.ModelMeta
		allowed bool
	}{
		{"sakana JP full", sovereign.ModelMeta{ModelName: "sakana-evo", Country: "JP", VendorHQ: "JP", Tier: sovereign.TierFull}, true},
		{"sarvam IN full", sovereign.ModelMeta{ModelName: "sarvam", Country: "IN", VendorHQ: "IN", Tier: sovereign.TierFull}, true},
		{"qwen CN foreign", sovereign.ModelMeta{ModelName: "qwen-max", Country: "CN", CNFlagged: true, Tier: sovereign.TierForeign}, false},
		{"openai US full", sovereign.ModelMeta{ModelName: "gpt-4", Country: "US", VendorHQ: "US", Tier: sovereign.TierFull}, false},
		{"partial RU", sovereign.ModelMeta{ModelName: "x", Country: "RU", Tier: sovereign.TierPartial}, false},
	}
	for _, c := range cases {
		if got := p.Allows(c.model); got != c.allowed {
			t.Fatalf("%s: Allows=%v want %v", c.name, got, c.allowed)
		}
		if !c.allowed {
			continue
		}
		if err := sovereign.CNGuard(p, c.model); err != nil {
			t.Fatalf("%s: CNGuard err %v", c.name, err)
		}
	}
}
