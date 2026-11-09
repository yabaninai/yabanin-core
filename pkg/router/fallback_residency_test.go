package router

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/sovereign"
)

// metaModels builds the tier-pool registry slice used by TierMetaLookup in
// these tests.
func metaModels() []ModelInfo {
	return []ModelInfo{
		{Name: "m-us-full", Country: "US", VendorHQ: "US", SovereigntyTier: string(sovereign.TierFull)},
		{Name: "m-eu-full", Country: "DE", VendorHQ: "DE", SovereigntyTier: string(sovereign.TierFull)},
		{Name: "m-cn", Country: "CN", VendorHQ: "CN", SovereigntyTier: string(sovereign.TierForeign), CNFlagged: true},
		{Name: "m-ru", Country: "RU", VendorHQ: "RU", SovereigntyTier: string(sovereign.TierFull)},
		{Name: "m-ru-vendor", Country: "US", VendorHQ: "RU", SovereigntyTier: string(sovereign.TierFull)},
		{Name: "m-tier-low", Country: "US", VendorHQ: "US", SovereigntyTier: string(sovereign.TierForeign)},
	}
}

// chainInfo builds a resolver-level chain candidate.
func chainInfo(name, provider, region, url string) resolver.ModelInfo {
	return resolver.ModelInfo{ModelName: name, Provider: provider, Region: region, UpstreamURL: url}
}

// restrictiveExclusionPolicy mirrors an org-wide exclusion posture that can
// deny candidates on every dimension.
func restrictiveExclusionPolicy() sovereign.Policy {
	return sovereign.Policy{
		CNAllowed:         false,
		ExcludedCountries: []string{"RU"},
		RequiredTier:      sovereign.TierPartial,
	}
}

// TestFilterChainByPolicy_ExcludesDeniedCandidates: every denial reason of
// the closed set is produced with the right label, order is preserved on
// both sides, and repeated runs are deterministic.
func TestFilterChainByPolicy_ExcludesDeniedCandidates(t *testing.T) {
	pol := restrictiveExclusionPolicy()
	lookup := TierMetaLookup(metaModels())
	chain := []resolver.ModelInfo{
		chainInfo("m-us-full", "openai", "US", "https://us.example"),
		chainInfo("m-cn", "sakana", "GLOBAL", "https://cn.example"),
		chainInfo("m-ru", "ru-model", "EU", "https://ru.example"),
		chainInfo("m-ru-vendor", "openai-ru", "EU", "https://ru-vendor.example"),
		chainInfo("m-tier-low", "openai", "US", "https://low.example"),
		chainInfo("m-eu-full", "openai", "EU", "https://eu.example"),
	}

	got := FilterChainByPolicy(pol, chain, lookup)

	if len(got.Chain) != 2 || got.Chain[0].ModelName != "m-us-full" || got.Chain[1].ModelName != "m-eu-full" {
		t.Fatalf("chain=%v, want [m-us-full m-eu-full] (order preserved)", got.Chain)
	}
	if len(got.MetaUnknown) != 0 {
		t.Fatalf("MetaUnknown=%v, want empty for fully-known metas", got.MetaUnknown)
	}
	wantReasons := map[string]sovereign.ProviderDenialReason{
		"m-cn":        sovereign.DenialProviderCNFlagged,
		"m-ru":        sovereign.DenialProviderCountryExcluded,
		"m-ru-vendor": sovereign.DenialProviderVendorExcluded,
		"m-tier-low":  sovereign.DenialProviderTierBelowRequired,
	}
	if len(got.Excluded) != len(wantReasons) {
		t.Fatalf("excluded=%d, want %d (%+v)", len(got.Excluded), len(wantReasons), got.Excluded)
	}
	prev := -1
	for _, x := range got.Excluded {
		want, ok := wantReasons[x.Denial.ModelName]
		if !ok {
			t.Fatalf("unexpected exclusion %+v", x)
		}
		if x.Denial.Reason != want {
			t.Fatalf("%s: reason=%q, want %q", x.Denial.ModelName, x.Denial.Reason, want)
		}
		if x.Region == "" {
			t.Fatalf("%s: chain candidate region not carried", x.Denial.ModelName)
		}
		// Input order preservation.
		idx := indexOfModel(chain, x.Denial.ModelName)
		if idx <= prev {
			t.Fatalf("exclusion order broken: %s at %d after %d", x.Denial.ModelName, idx, prev)
		}
		prev = idx
	}
	// Deterministic across repeated runs.
	for range 5 {
		again := FilterChainByPolicy(pol, chain, lookup)
		if fmt.Sprint(again.Excluded) != fmt.Sprint(got.Excluded) ||
			fmt.Sprint(again.Chain) != fmt.Sprint(got.Chain) {
			t.Fatal("FilterChainByPolicy is not deterministic")
		}
	}
}

func indexOfModel(chain []resolver.ModelInfo, name string) int {
	for i, c := range chain {
		if c.ModelName == name {
			return i
		}
	}
	return -1
}

// TestFilterChainByPolicy_FailClosedOnUnknownMeta: under a restrictive
// policy a candidate with unreadable metadata is EXCLUDED (reason
// meta_unknown), never speculatively dialed.
func TestFilterChainByPolicy_FailClosedOnUnknownMeta(t *testing.T) {
	pol := restrictiveExclusionPolicy()
	lookup := TierMetaLookup(metaModels())
	chain := []resolver.ModelInfo{
		chainInfo("m-us-full", "openai", "US", "https://us.example"),
		chainInfo("m-unlisted", "openai", "EU", "https://unlisted.example"),
		chainInfo("m-eu-full", "openai", "EU", "https://eu.example"),
	}

	got := FilterChainByPolicy(pol, chain, lookup)

	kept := map[string]bool{}
	for _, c := range got.Chain {
		kept[c.ModelName] = true
	}
	if kept["m-unlisted"] {
		t.Fatal("unknown-meta candidate must not be kept under a restrictive policy")
	}
	found := false
	for _, x := range got.Excluded {
		if x.Denial.ModelName == "m-unlisted" {
			found = true
			if x.Denial.Reason != sovereign.DenialProviderMetaUnknown {
				t.Fatalf("m-unlisted reason=%q, want meta_unknown", x.Denial.Reason)
			}
		}
	}
	if !found {
		t.Fatalf("m-unlisted must appear in Excluded with meta_unknown, got %+v", got.Excluded)
	}
	if len(got.Chain) != 2 || got.Chain[0].ModelName != "m-us-full" || got.Chain[1].ModelName != "m-eu-full" {
		t.Fatalf("permitted candidates lost: %v", got.Chain)
	}
}

// TestFilterChainByPolicy_PermissiveKeepsUnknownMeta: a fully permissive
// policy (CN allowed, no exclusions, foreign floor) denies nothing — an
// unknown-meta candidate is kept but MARKED in MetaUnknown (kept-and-marked,
// not silently promoted to a verdict).
func TestFilterChainByPolicy_PermissiveKeepsUnknownMeta(t *testing.T) {
	permissive := sovereign.Policy{RequiredTier: sovereign.TierForeign, CNAllowed: true}
	lookup := TierMetaLookup(metaModels())
	chain := []resolver.ModelInfo{
		chainInfo("m-us-full", "openai", "US", "https://us.example"),
		chainInfo("m-unlisted", "openai", "EU", "https://unlisted.example"),
	}

	got := FilterChainByPolicy(permissive, chain, lookup)

	if len(got.Chain) != 2 {
		t.Fatalf("permissive policy must keep both candidates, got %v", got.Chain)
	}
	if len(got.MetaUnknown) != 1 || got.MetaUnknown[0] != "m-unlisted" {
		t.Fatalf("MetaUnknown=%v, want [m-unlisted]", got.MetaUnknown)
	}
	if len(got.Excluded) != 0 {
		t.Fatalf("permissive policy must not exclude, got %+v", got.Excluded)
	}
}

// TestFilterChainByPolicy_DefaultPolicyFailsClosedOnUnknownMeta: DefaultPolicy
// is CN-off (the default posture). CN-off cannot confirm an unknown candidate
// is not CN-flagged, so unknown metadata must fail closed — never
// speculatively dialed.
func TestFilterChainByPolicy_DefaultPolicyFailsClosedOnUnknownMeta(t *testing.T) {
	lookup := TierMetaLookup(metaModels())
	chain := []resolver.ModelInfo{
		chainInfo("m-us-full", "openai", "US", "https://us.example"),
		chainInfo("m-unlisted", "openai", "EU", "https://unlisted.example"),
	}

	got := FilterChainByPolicy(sovereign.DefaultPolicy(), chain, lookup)

	if len(got.Chain) != 1 || got.Chain[0].ModelName != "m-us-full" {
		t.Fatalf("DefaultPolicy must fail closed on unknown meta, got chain %v", got.Chain)
	}
	if len(got.Excluded) != 1 || got.Excluded[0].Denial.Reason != sovereign.DenialProviderMetaUnknown {
		t.Fatalf("excluded=%+v, want m-unlisted with meta_unknown", got.Excluded)
	}
}

// TestFilterChainByPolicy_NilMetaReturnsChainUnchanged: a nil metadata
// lookup cannot evaluate the policy — the chain passes through unchanged
// with nothing excluded and nothing marked (enforcement stays at the
// caller's per-attempt gate).
func TestFilterChainByPolicy_NilMetaReturnsChainUnchanged(t *testing.T) {
	pol := restrictiveExclusionPolicy()
	chain := []resolver.ModelInfo{
		chainInfo("m-ru", "ru-model", "EU", "https://ru.example"),
		chainInfo("m-us-full", "openai", "US", "https://us.example"),
	}

	got := FilterChainByPolicy(pol, chain, nil)

	if len(got.Chain) != 2 || len(got.Excluded) != 0 || len(got.MetaUnknown) != 0 {
		t.Fatalf("nil meta must pass the chain through, got %+v", got)
	}
}

// TestTierMetaLookup: registry metadata resolves by model name; unlisted
// names resolve as not-found (the filter's unknown-meta branch).
func TestTierMetaLookup(t *testing.T) {
	lookup := TierMetaLookup(metaModels())

	mm, ok := lookup(resolver.ModelInfo{ModelName: "m-cn"})
	if !ok || !mm.CNFlagged || mm.Country != "CN" || mm.Tier != sovereign.TierForeign {
		t.Fatalf("m-cn meta=(%+v, %v)", mm, ok)
	}
	if _, ok := lookup(resolver.ModelInfo{ModelName: "m-nope"}); ok {
		t.Fatal("unlisted model must resolve as not-found")
	}
}

// TestFilteredChainErr: Err yields *ErrNoPermittedProvider exactly when the
// filter emptied the chain through exclusions; the message lists one
// reason record per candidate and carries the disclosure.
func TestFilteredChainErr(t *testing.T) {
	pol := restrictiveExclusionPolicy()
	lookup := TierMetaLookup(metaModels())

	// All candidates excluded → typed refusal.
	allDenied := FilterChainByPolicy(pol, []resolver.ModelInfo{
		chainInfo("m-ru", "ru-model", "EU", "https://ru.example"),
	}, lookup)
	err := allDenied.Err()
	var denied *ErrNoPermittedProvider
	if !errors.As(err, &denied) {
		t.Fatalf("Err()=%v, want *ErrNoPermittedProvider", err)
	}
	msg := denied.Error()
	for _, want := range []string{
		"m-ru=ru-model/EU/country_excluded",
		sovereign.ResidencyDisclosure,
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must contain %q", msg, want)
		}
	}

	// Mixed outcome → no error (candidates remain).
	mixed := FilterChainByPolicy(pol, []resolver.ModelInfo{
		chainInfo("m-us-full", "openai", "US", "https://us.example"),
		chainInfo("m-ru", "ru-model", "EU", "https://ru.example"),
	}, lookup)
	if err := mixed.Err(); err != nil {
		t.Fatalf("mixed chain must not error, got %v", err)
	}

	// Empty input chain → no policy refusal (caller's shape).
	empty := FilterChainByPolicy(pol, nil, lookup)
	if err := empty.Err(); err != nil {
		t.Fatalf("empty input chain must not error, got %v", err)
	}
}

// TestFilteredChain_DeniedProviderNeverAttemptedDuringOutage is the packet
// acceptance tooth for the provider-exclusion path: a policy-excluded
// fallback candidate is NEVER dialed — not as the primary and not as a
// failover hop — even when EVERY permitted candidate is down (outage). The
// excluded provider's endpoint must not appear in the attempt trace.
func TestFilteredChain_DeniedProviderNeverAttemptedDuringOutage(t *testing.T) {
	// Real HTTP endpoints so the executor's attempts are observable; every
	// permitted upstream answers 500 — a full outage of the permitted chain.
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer fail.Close()

	pol := restrictiveExclusionPolicy()
	lookup := TierMetaLookup(metaModels())
	resolved := []resolver.ModelInfo{
		chainInfo("m-us-full", "openai", "US", fail.URL+"/us"),
		chainInfo("m-ru", "ru-model", "EU", fail.URL+"/ru-denied"),
		chainInfo("m-eu-full", "openai", "EU", fail.URL+"/eu"),
	}

	filtered := FilterChainByPolicy(pol, resolved, lookup)
	if len(filtered.Chain) != 2 || filtered.Chain[0].ModelName != "m-us-full" || filtered.Chain[1].ModelName != "m-eu-full" {
		t.Fatalf("filtered chain=%v, want [m-us-full m-eu-full]", filtered.Chain)
	}
	if len(filtered.Excluded) != 1 || filtered.Excluded[0].Denial.ModelName != "m-ru" {
		t.Fatalf("excluded=%+v, want only m-ru", filtered.Excluded)
	}

	// Wire the FILTERED chain into the executor the way the gateway would:
	// primary = first permitted candidate, failovers = the rest.
	primary := filtered.Chain[0]
	byName := map[string]resolver.ModelInfo{}
	for _, c := range filtered.Chain {
		byName[c.ModelName] = c
	}
	for _, c := range filtered.Chain[1:] {
		primary.FailoverModels = append(primary.FailoverModels, c.ModelName)
	}
	exec := NewFallbackExecutor(&stubResolver{byName: byName}, 0, nil)

	var dials []string
	_, _, attempts, err := exec.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			dials = append(dials, info.UpstreamURL)
			return http.StatusInternalServerError, fmt.Errorf("upstream down")
		})
	if err == nil {
		t.Fatal("expected chain exhaustion error: every permitted upstream is down")
	}

	// The denied provider's endpoint was never dialed — before, during or
	// after the outage of the permitted candidates.
	for _, u := range dials {
		if strings.Contains(u, "ru-denied") {
			t.Fatalf("denied provider endpoint %q was dialed (dials=%v)", u, dials)
		}
	}
	if len(dials) != 2 || !strings.Contains(dials[0], "/us") || !strings.Contains(dials[1], "/eu") {
		t.Fatalf("dials=%v, want exactly [us eu] in filtered order", dials)
	}
	if len(attempts) != 2 {
		t.Fatalf("attempts=%d, want 2", len(attempts))
	}
}

// stubResolver resolves model names from a fixed map (router.ModelResolver).
type stubResolver struct {
	byName map[string]resolver.ModelInfo
}

func (s *stubResolver) Resolve(_ context.Context, name string) resolver.ModelInfo {
	return s.byName[name]
}
