package sovereign

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEgressKindValid(t *testing.T) {
	for _, k := range EgressKinds {
		if !k.Valid() {
			t.Errorf("EgressKind(%q).Valid() = false, want true", k)
		}
	}
	for _, k := range []EgressKind{"", "bogus", "Inference"} {
		if k.Valid() {
			t.Errorf("EgressKind(%q).Valid() = true, want false", k)
		}
	}
	if len(EgressKinds) != 5 {
		t.Fatalf("expected 5 egress kinds, got %d", len(EgressKinds))
	}
}

// TestCheckEgress_PerKindProfile: per-kind rules win over org-wide rules.
func TestCheckEgress_PerKindProfile(t *testing.T) {
	p := Policy{
		ExcludedCountries: []string{"CN"},
		Egress: map[EgressKind]EgressProfile{
			EgressLogs: {
				AllowedCountries:  []string{"SG"},
				ExcludedCountries: []string{"CN", "RU"},
			},
		},
	}
	cases := []struct {
		kind    EgressKind
		country string
		want    bool
		reason  DenialReason
	}{
		{EgressLogs, "SG", true, ""},
		{EgressLogs, "EU", false, DenialKindNotAllowed},
		{EgressLogs, "CN", false, DenialKindExcluded}, // excluded wins over org-wide
		{EgressLogs, "RU", false, DenialKindExcluded},
		{EgressExport, "US", true, ""},                 // no export profile → org-wide only
		{EgressExport, "CN", false, DenialOrgExcluded}, // org-wide still applies
		{EgressInference, "CN", false, DenialOrgExcluded},
		{EgressEmbeddings, "IN", true, ""},
		{EgressTools, "AE", true, ""},
	}
	for _, c := range cases {
		ok, reason := p.CheckEgress(c.kind, c.country)
		if ok != c.want || (c.want == false && reason != c.reason) {
			t.Errorf("CheckEgress(%s, %s) = (%v, %q), want (%v, %q)",
				c.kind, c.country, ok, reason, c.want, c.reason)
		}
		if ok != p.AllowsEgress(c.kind, c.country) {
			t.Errorf("AllowsEgress(%s, %s) disagrees with CheckEgress", c.kind, c.country)
		}
	}
}

func TestCheckEgress_AllowlistWinsOverOrgWideExclusion(t *testing.T) {
	p := Policy{
		ExcludedCountries: []string{"SG"},
		Egress: map[EgressKind]EgressProfile{
			EgressExport: {AllowedCountries: []string{"SG"}}, // contradictory config
		},
	}
	// The per-kind exclusion list is empty, and the allowlist permits SG —
	// org-wide exclusion still applies on top: SG must stay denied.
	ok, reason := p.CheckEgress(EgressExport, "SG")
	if ok || reason != DenialOrgExcluded {
		t.Errorf("org-wide exclusion must apply on top of kind allowlist, got (%v,%q)", ok, reason)
	}
}

func TestCheckEgress_Normalization(t *testing.T) {
	p := Policy{
		Egress: map[EgressKind]EgressProfile{
			EgressLogs: {AllowedCountries: []string{"sg", " in "}},
		},
	}
	if ok, _ := p.CheckEgress(EgressLogs, " SG "); !ok {
		t.Error("case/whitespace-insensitive match expected for SG")
	}
	if ok, _ := p.CheckEgress(EgressLogs, "in"); !ok {
		t.Error("list entry with whitespace must normalize to IN")
	}
	if ok, reason := p.CheckEgress(EgressLogs, "us"); ok || reason != DenialKindNotAllowed {
		t.Errorf("US not on allowlist: got (%v,%q)", ok, reason)
	}
}

// TestCheckEgress_EmptyCountryFailClosed: an unknown/empty country never
// satisfies a non-empty allowlist.
func TestCheckEgress_EmptyCountryFailClosed(t *testing.T) {
	p := Policy{
		Egress: map[EgressKind]EgressProfile{
			EgressExport: {AllowedCountries: []string{"SG"}},
		},
	}
	if ok, reason := p.CheckEgress(EgressExport, ""); ok || reason != DenialKindNotAllowed {
		t.Errorf("empty country vs allowlist must deny kind_not_allowed, got (%v,%q)", ok, reason)
	}
	// Without an allowlist an empty country passes org-wide rules (nothing
	// matches) — documented behavior; region callers always pass a country
	// from the region map.
	if ok, _ := p.CheckEgress(EgressInference, ""); !ok {
		t.Error("no rules at all must allow")
	}
}

func TestCheckEgress_UnknownKindFallsBackToOrgWide(t *testing.T) {
	p := Policy{
		ExcludedCountries: []string{"CN"},
		Egress: map[EgressKind]EgressProfile{
			EgressLogs: {ExcludedCountries: []string{"RU"}},
		},
	}
	// A kind with no profile gets org-wide rules only (RU allowed at
	// org-wide level, so allowed here too).
	if ok, _ := p.CheckEgress("bogus", "RU"); !ok {
		t.Error("unknown kind must resolve against org-wide rules")
	}
	if ok, reason := p.CheckEgress("bogus", "CN"); ok || reason != DenialOrgExcluded {
		t.Errorf("unknown kind must still respect org-wide exclusions, got (%v,%q)", ok, reason)
	}
}

func TestCheckEgress_ZeroPolicyAllows(t *testing.T) {
	var p Policy
	for _, k := range EgressKinds {
		if ok, reason := p.CheckEgress(k, "CN"); !ok || reason != "" {
			t.Errorf("zero policy must allow %s, got (%v,%q)", k, ok, reason)
		}
	}
}

// TestPolicyJSONRoundTrip proves the PolicyStore Redis cache format stays
// compatible in both directions (rollout and rollback).
func TestPolicyJSONRoundTrip(t *testing.T) {
	p := Policy{
		RequiredTier:      TierFull,
		ExcludedCountries: []string{"CN"},
		BuyerJurisdiction: "SG",
		Egress: map[EgressKind]EgressProfile{
			EgressInference: {AllowedCountries: []string{"SG", "IN"}},
			EgressLogs:      {ExcludedCountries: []string{"us"}},
		},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Policy
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Egress) != 2 {
		t.Fatalf("expected 2 egress profiles after round trip, got %d", len(back.Egress))
	}
	if ok, _ := back.CheckEgress(EgressLogs, "US"); ok {
		t.Error("round-tripped policy must keep per-kind exclusions")
	}
	if ok, _ := back.CheckEgress(EgressInference, "SG"); !ok {
		t.Error("round-tripped policy must keep per-kind allowlists")
	}

	// Legacy cache entry (written before the field existed): decodes with
	// Egress=nil and keeps enforcing org-wide rules.
	legacy := `{"RequiredTier":"full","ExcludedCountries":["CN"],"BuyerJurisdiction":"SG"}`
	var old Policy
	if err := json.Unmarshal([]byte(legacy), &old); err != nil {
		t.Fatalf("legacy unmarshal: %v", err)
	}
	if old.Egress != nil {
		t.Fatalf("legacy entry must decode with Egress=nil, got %v", old.Egress)
	}
	if ok, reason := old.CheckEgress(EgressExport, "CN"); ok || reason != DenialOrgExcluded {
		t.Errorf("legacy policy must keep org-wide enforcement, got (%v,%q)", ok, reason)
	}
}

func TestErrEgressDeniedMessage(t *testing.T) {
	e := ErrEgressDenied{OrgID: "org-1", Kind: EgressLogs, Country: "CN", Rule: DenialKindExcluded}
	want := "egress denied for org org-1: kind=logs country=CN rule=kind_excluded"
	if e.Error() != want {
		t.Errorf("message = %q, want %q", e.Error(), want)
	}
}

// TestFailoverAcceptance_SovereignExclusionNotWeakened guards the packet
// acceptance at the policy layer: a country on the org-wide exclusion list
// is denied for EVERY egress kind, including the inference fallback path.
func TestFailoverAcceptance_SovereignExclusionNotWeakened(t *testing.T) {
	p := DefaultPolicy()
	p.ExcludedCountries = []string{"CN", " RU "}
	for _, k := range EgressKinds {
		for _, c := range []string{"CN", "ru", " Ru "} {
			if ok, reason := p.CheckEgress(k, c); ok || reason != DenialOrgExcluded {
				t.Errorf("denied country %q must be refused for kind %s, got (%v,%q)", c, k, ok, reason)
			}
		}
	}
	if !strings.Contains(ErrEgressDenied{Kind: EgressInference, Rule: DenialOrgExcluded}.Error(), "rule=org_excluded") {
		t.Error("denial error must carry the machine-readable rule")
	}
}
