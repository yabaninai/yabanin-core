package sovereign

import (
	"strings"
	"testing"
)

// TestAllowsExplainParityWithAllows: AllowsExplain must return EXACTLY the
// same boolean as the historical Allows contract over the whole decision
// matrix (single source of truth — Allows delegates). The reason label is
// asserted per denial class.
func TestAllowsExplainParityWithAllows(t *testing.T) {
	mk := func(name, provider, country, vendor string, tier Tier, cn bool) ModelMeta {
		return ModelMeta{
			ModelName: name, Provider: provider,
			Country: country, VendorHQ: vendor, Tier: tier, CNFlagged: cn,
		}
	}
	models := []ModelMeta{
		mk("m-openai", "openai", "US", "US", TierFull, false),
		mk("m-cn", "sakana", "CN", "CN", TierForeign, true),
		mk("m-cn-allowed-tier-ok", "sakana", "CN", "CN", TierFull, true),
		mk("m-country-hit", "openai", "RU", "US", TierFull, false),
		mk("m-vendor-hit", "openai", "US", "RU", TierFull, false),
		mk("m-tier-low", "openai", "US", "US", TierForeign, false),
		mk("m-tier-unknown", "openai", "US", "US", Tier("nonsense"), false),
		mk("m-empty", "", "", "", "", false),
	}
	policies := map[string]Policy{
		"default":         DefaultPolicy(),
		"cn-off-explicit": {RequiredTier: TierForeign, CNAllowed: false, ExcludedCountries: []string{"RU"}},
		"cn-on":           {RequiredTier: TierForeign, CNAllowed: true, ExcludedCountries: []string{"RU"}},
		"tier-partial":    {RequiredTier: TierPartial},
		"tier-full":       {RequiredTier: TierFull},
	}

	for pname, pol := range policies {
		for _, m := range models {
			want := pol.Allows(m)
			got, denial := pol.AllowsExplain(m)
			if got != want {
				t.Fatalf("%s/%s: AllowsExplain=%v != Allows=%v (denial=%+v)", pname, m.ModelName, got, want, denial)
			}
			// Identity fields are always populated from the evaluated meta.
			if denial.ModelName != m.ModelName || denial.Provider != m.Provider ||
				denial.Country != m.Country || denial.VendorHQ != m.VendorHQ {
				t.Fatalf("%s/%s: identity fields not carried: %+v", pname, m.ModelName, denial)
			}
			if want && denial.Reason != "" {
				t.Fatalf("%s/%s: allow must carry empty reason, got %q", pname, m.ModelName, denial.Reason)
			}
			if want {
				continue
			}
			// Expected denial class for this matrix point.
			var wantReason ProviderDenialReason
			switch {
			case !pol.CNAllowed && m.CNFlagged:
				wantReason = DenialProviderCNFlagged
			case containsString(pol.ExcludedCountries, m.Country):
				wantReason = DenialProviderCountryExcluded
			case containsString(pol.ExcludedCountries, m.VendorHQ):
				wantReason = DenialProviderVendorExcluded
			case !tierKnown(m.Tier):
				wantReason = DenialProviderTierUnknown
			default:
				wantReason = DenialProviderTierBelowRequired
			}
			if denial.Reason != wantReason {
				t.Fatalf("%s/%s: reason=%q, want %q (denial=%+v)", pname, m.ModelName, denial.Reason, wantReason, denial)
			}
		}
	}
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// TestAllowsExplainHistoricalEdgeCases pins the historical Allows semantics
// that the explanation layer must not change.
func TestAllowsExplainHistoricalEdgeCases(t *testing.T) {
	// Unknown tier with a FOREIGN floor: Rank(unknown)=0 >= Rank(foreign)=0
	// → allowed historically; the unknown-tier reason may only appear when
	// the floor is actually higher.
	pol := DefaultPolicy()
	ok, denial := pol.AllowsExplain(ModelMeta{ModelName: "m", Tier: Tier("nonsense")})
	if !ok || denial.Reason != "" {
		t.Fatalf("unknown tier must pass a foreign floor, got ok=%v reason=%q", ok, denial.Reason)
	}

	// Unknown tier with a PARTIAL floor: denied as tier_unknown (readable
	// posture, not merely weak).
	pol = Policy{RequiredTier: TierPartial}
	ok, denial = pol.AllowsExplain(ModelMeta{ModelName: "m", Tier: Tier("nonsense")})
	if ok || denial.Reason != DenialProviderTierUnknown || denial.RequiredTier != TierPartial {
		t.Fatalf("unknown tier vs partial floor: ok=%v reason=%q required=%q", ok, denial.Reason, denial.RequiredTier)
	}

	// Recognized but low tier: tier_below_required, floor echoed.
	ok, denial = pol.AllowsExplain(ModelMeta{ModelName: "m", Tier: TierForeign})
	if ok || denial.Reason != DenialProviderTierBelowRequired || denial.RequiredTier != TierPartial {
		t.Fatalf("foreign tier vs partial floor: ok=%v reason=%q required=%q", ok, denial.Reason, denial.RequiredTier)
	}

	// Per-entry scan order decides the label when both match on DIFFERENT
	// entries: the first list entry that hits wins (same entry parity with
	// the historical Allows boolean, which denies at the first hit).
	pol = Policy{ExcludedCountries: []string{"IR", "RU"}}
	_, denial = pol.AllowsExplain(ModelMeta{ModelName: "m", Country: "IR", VendorHQ: "RU"})
	if denial.Reason != DenialProviderCountryExcluded {
		t.Fatalf("first list entry (IR) hits the country: want country_excluded, got %q", denial.Reason)
	}
	pol = Policy{ExcludedCountries: []string{"RU", "IR"}}
	_, denial = pol.AllowsExplain(ModelMeta{ModelName: "m", Country: "IR", VendorHQ: "RU"})
	if denial.Reason != DenialProviderVendorExcluded {
		t.Fatalf("first list entry (RU) hits the vendor: want vendor_excluded, got %q", denial.Reason)
	}
	// Same entry matching both: country explanation wins.
	pol = Policy{ExcludedCountries: []string{"RU"}}
	_, denial = pol.AllowsExplain(ModelMeta{ModelName: "m", Country: "RU", VendorHQ: "RU"})
	if denial.Reason != DenialProviderCountryExcluded {
		t.Fatalf("same-entry hit must report country_excluded, got %q", denial.Reason)
	}
	// Vendor-only hit.
	_, denial = pol.AllowsExplain(ModelMeta{ModelName: "m", Country: "US", VendorHQ: "RU"})
	if denial.Reason != DenialProviderVendorExcluded {
		t.Fatalf("vendor-only hit must report vendor_excluded, got %q", denial.Reason)
	}
}

// TestFilterMeta: split preserves input order on both sides and carries the
// per-provider denial records.
func TestFilterMeta(t *testing.T) {
	pol := Policy{ExcludedCountries: []string{"RU"}, RequiredTier: TierPartial}
	pool := []ModelMeta{
		{ModelName: "a", Provider: "openai", Country: "US", Tier: TierFull},
		{ModelName: "b", Provider: "ru-vendor", Country: "US", VendorHQ: "RU", Tier: TierFull},
		{ModelName: "c", Provider: "openai", Country: "RU", Tier: TierFull},
		{ModelName: "d", Provider: "openai", Country: "DE", Tier: TierForeign},
	}
	kept, denied := FilterMeta(pol, pool)
	if len(kept) != 1 || kept[0].ModelName != "a" {
		t.Fatalf("kept=%v, want only [a]", kept)
	}
	if len(denied) != 3 {
		t.Fatalf("denied=%d, want 3", len(denied))
	}
	wantOrder := []struct {
		model  string
		reason ProviderDenialReason
	}{
		{"b", DenialProviderVendorExcluded},
		{"c", DenialProviderCountryExcluded},
		{"d", DenialProviderTierBelowRequired},
	}
	for i, w := range wantOrder {
		if denied[i].ModelName != w.model || denied[i].Reason != w.reason {
			t.Fatalf("denied[%d]=%s/%s, want %s/%s", i, denied[i].ModelName, denied[i].Reason, w.model, w.reason)
		}
	}
	// Deterministic across repeated runs (no map iteration anywhere).
	for range 5 {
		k2, d2 := FilterMeta(pol, pool)
		if len(k2) != len(kept) || len(d2) != len(denied) {
			t.Fatal("FilterMeta is not deterministic in lengths")
		}
		for i := range kept {
			if k2[i].ModelName != kept[i].ModelName || d2[i].ModelName != denied[i].ModelName {
				t.Fatal("FilterMeta is not deterministic in order")
			}
		}
	}
}

// TestErrProvidersExcluded: the refusal carries one reason record per
// provider and the mandatory disclosure (negative criterion).
func TestErrProvidersExcluded(t *testing.T) {
	err := &ErrProvidersExcluded{
		OrgID: "org-1",
		Excluded: []ProviderDenial{
			{ModelName: "b", Provider: "ru-vendor", Country: "US", VendorHQ: "RU", Reason: DenialProviderVendorExcluded},
			{ModelName: "c", Provider: "openai", Country: "RU", Reason: DenialProviderCountryExcluded},
		},
	}
	msg := err.Error()
	for _, want := range []string{
		"org=org-1",
		"b=ru-vendor/US/RU/vendor_excluded",
		"c=openai/RU//country_excluded",
		ResidencyDisclosure,
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must contain %q", msg, want)
		}
	}
	// Defensive empty rendering.
	empty := (&ErrProvidersExcluded{OrgID: "org-2"}).Error()
	if !strings.Contains(empty, "denied=[none]") {
		t.Fatalf("empty exclusion set must render [none], got %q", empty)
	}
}
