package sovereign

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// N09-P05-T05 negative-scenario battery (packet kind=negative): the packet
// negative criterion «Country endpoint не выдаётся за юридическую гарантию
// residency» must hold with an observable result and a verifiable process
// control, and the refusal must not be hidden. This file pins the sovereign
// side: the canonical non-claim wording, and the observable
// exclusion-scenario that produces explained, disclosed, structured
// refusals. The router and regionrouter batteries compose the same control
// across the whole routing surface set.

// disclosureCanonical is the exact canonical sentence every routing surface
// must carry when it names a country-bound endpoint or a country-scoped
// exclusion. Pinning it here (and again via the regionrouter alias) is the
// process control: a wording edit that drops the negation, softens the
// non-claim or moves the sentence out from the surfaces fails loudly.
const disclosureCanonical = "country endpoint binding is a technical routing control, not a legal residency guarantee"

// assertNoAffirmativeGuaranteeClaim is the shared negative property: every
// occurrence of the word "guarantee" on a produced surface must sit inside
// the exact non-claim sentence — an unqualified guarantee mention would be
// an affirmative residency claim leaking onto the surface.
func assertNoAffirmativeGuaranteeClaim(t *testing.T, name, s string) {
	t.Helper()
	if s == "" {
		t.Fatalf("%s: empty surface", name)
	}
	if strings.Contains(s, "legal residency guarantee") && !strings.Contains(s, "not a legal residency guarantee") {
		t.Errorf("%s claims a legal residency guarantee: %q", name, s)
	}
	if got, want := strings.Count(s, "guarantee"), strings.Count(s, disclosureCanonical); got != want {
		t.Errorf("%s has %d guarantee mentions but %d non-claim sentences (unqualified claim?): %q",
			name, got, want, s)
	}
}

// TestN09P5T05_DisclosureCanonicalWordingPinned pins the canonical non-claim
// sentence byte-for-byte. The negation ("not a") is the load-bearing word:
// losing it turns every disclosure-carrying surface into an affirmative
// residency claim.
func TestN09P5T05_DisclosureCanonicalWordingPinned(t *testing.T) {
	if ResidencyDisclosure != disclosureCanonical {
		t.Fatalf("ResidencyDisclosure drifted:\n got %q\nwant %q", ResidencyDisclosure, disclosureCanonical)
	}
	for _, must := range []string{
		"technical routing control",
		"not a legal residency guarantee",
	} {
		if !strings.Contains(ResidencyDisclosure, must) {
			t.Errorf("canonical disclosure must contain %q, got %q", must, ResidencyDisclosure)
		}
	}
	assertNoAffirmativeGuaranteeClaim(t, "disclosure", ResidencyDisclosure)
}

// TestN09P5T05_CountryExcludedPool_ObservableResult is the observable
// negative scenario on the sovereign surface: a provider pool where a
// country-excluded, a CN-flagged, a vendor-excluded and an unknown-tier
// model meet a restrictive policy. Every denied provider must come out of
// FilterMeta with its structured reason, the typed refusal must carry all
// of them, and the rendered message must name each provider and country
// together with the non-claim disclosure — the exclusion is explainable and
// never phrased as a residency guarantee.
func TestN09P5T05_CountryExcludedPool_ObservableResult(t *testing.T) {
	pol := Policy{
		CNAllowed:         false,
		ExcludedCountries: []string{"RU"},
		RequiredTier:      TierPartial,
	}
	pool := []ModelMeta{
		{ModelName: "m-ok", Provider: "prov-a", Country: "DE", VendorHQ: "DE", Tier: TierFull},
		{ModelName: "m-cn", Provider: "prov-b", Country: "CN", VendorHQ: "CN", Tier: TierForeign, CNFlagged: true},
		{ModelName: "m-ru", Provider: "prov-c", Country: "RU", VendorHQ: "RU", Tier: TierFull},
		{ModelName: "m-ru-vendor", Provider: "prov-d", Country: "US", VendorHQ: "RU", Tier: TierFull},
		{ModelName: "m-unknown-tier", Provider: "prov-e", Country: "US", VendorHQ: "US", Tier: Tier("nonstandard")},
	}

	kept, denied := FilterMeta(pol, pool)
	if len(kept) != 1 || kept[0].ModelName != "m-ok" {
		t.Fatalf("kept = %+v, want only m-ok", kept)
	}
	wantReasons := map[string]ProviderDenialReason{
		"m-cn":           DenialProviderCNFlagged,
		"m-ru":           DenialProviderCountryExcluded,
		"m-ru-vendor":    DenialProviderVendorExcluded,
		"m-unknown-tier": DenialProviderTierUnknown,
	}
	if len(denied) != len(wantReasons) {
		t.Fatalf("denied = %+v, want %d records", denied, len(wantReasons))
	}
	seen := map[string]ProviderDenial{}
	for _, d := range denied {
		if _, dup := seen[d.ModelName]; dup {
			t.Errorf("model %s excluded twice", d.ModelName)
		}
		seen[d.ModelName] = d
		want, ok := wantReasons[d.ModelName]
		if !ok {
			t.Errorf("unexpected exclusion %+v", d)
			continue
		}
		if d.Reason != want {
			t.Errorf("%s reason = %q, want %q", d.ModelName, d.Reason, want)
		}
	}

	err := &ErrProvidersExcluded{OrgID: "org-n09p5", Excluded: denied}
	var typed *ErrProvidersExcluded
	// %w wrap: the structured refusal must survive the boundary intact —
	// an error that loses its type or records downstream is a hidden error.
	if !errors.As(fmt.Errorf("gateway: %w", err), &typed) {
		t.Fatal("ErrProvidersExcluded not recoverable through %w wrap (error hidden)")
	}
	if len(typed.Excluded) != len(denied) || typed.OrgID != "org-n09p5" {
		t.Fatalf("typed refusal fields lost: org=%q excluded=%d", typed.OrgID, len(typed.Excluded))
	}

	msg := err.Error()
	for _, d := range denied {
		want := fmt.Sprintf("%s=%s/%s/%s/%s", d.ModelName, d.Provider, d.Country, d.VendorHQ, d.Reason)
		if !strings.Contains(msg, want) {
			t.Errorf("refusal must name %q, got %q", want, msg)
		}
	}
	if !strings.Contains(msg, "org-n09p5") {
		t.Errorf("refusal must name the org, got %q", msg)
	}
	if !strings.Contains(msg, disclosureCanonical) {
		t.Errorf("country-scoped exclusion surface must carry the non-claim disclosure, got %q", msg)
	}
	assertNoAffirmativeGuaranteeClaim(t, "sovereign-refusal", msg)
}
