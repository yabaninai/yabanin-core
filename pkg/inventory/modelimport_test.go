package inventory

// E02-P01 W03-C01 tests: model/provider asset construction from the three
// upstream planes. The catalog fixture is a real *provider.ModelCatalog
// (strict NewModelCatalog validation) so alias attribution and status
// classification run against production semantics; the pricing fixture is
// an in-memory pack (the bundled production pack is exercised at the
// provenance level in modelprovenance_test.go).

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// modelFixtureAt is the import instant every fixture is expressed against.
var modelFixtureAt = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func fixtureCatalog(t *testing.T) *provider.ModelCatalog {
	t.Helper()
	at := modelFixtureAt
	cat, err := provider.NewModelCatalog(provider.ModelCatalogSpec{
		Version:       "cat-v1",
		SchemaVersion: 1,
		Source:        "test-snapshot",
		AsOf:          at,
		Entries: []provider.ModelCatalogEntry{
			{
				Provider: "openai", Model: "gpt-x", Aliases: []string{"gpt-x-alias"},
				EffectiveFrom: at.Add(-24 * time.Hour), // active
			},
			{
				Provider: "openai", Model: "gpt-old",
				EffectiveFrom: at.Add(-48 * time.Hour), DeprecatedAt: at.Add(-12 * time.Hour), // deprecated, window open
			},
			{
				Provider: "openai", Model: "gpt-dead",
				EffectiveFrom: at.Add(-48 * time.Hour), EffectiveTo: at.Add(-1 * time.Hour), // window closed → withdrawn
			},
			{
				Provider: "openai", Model: "gpt-future",
				EffectiveFrom: at.Add(24 * time.Hour), // pending
			},
			{
				Provider: "anthropic", Model: "claude-x", // active, but provider withdrawn below
				EffectiveFrom: at.Add(-24 * time.Hour),
			},
			{
				Provider: "refonly", Model: "ref-model", // known to the reference side only
				EffectiveFrom: at.Add(-24 * time.Hour),
			},
		},
		Withdrawals: []provider.Withdrawal{
			{Provider: "anthropic", WithdrawnAt: at.Add(-2 * time.Hour)},
			{Provider: "gore", WithdrawnAt: at.Add(-1 * time.Hour)}, // withdrawal-only provider
		},
	})
	if err != nil {
		t.Fatalf("fixture catalog: %v", err)
	}
	return cat
}

type fakePricingPack struct {
	meta   PricingMeta
	models []pricing.RefModel
}

func (p fakePricingPack) Meta() PricingMeta          { return p.meta }
func (p fakePricingPack) Models() []pricing.RefModel { return p.models }

func fixturePricing() PricingPack {
	return fakePricingPack{
		meta: PricingMeta{Version: "pack-v7", GeneratedAt: "2026-11-06T00:00:00Z",
			Digest: "sha256:abc123", AsOfTime: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)},
		models: []pricing.RefModel{
			{Provider: "openai", Model: "gpt-x", Status: pricing.RefStatusActive, Region: "us", Tier: "standard"},
			{Provider: "openai", Model: "gpt-x", Status: pricing.RefStatusActive, Region: "eu", Tier: "premium"},
			{Provider: "openai", Model: "gpt-old", Status: pricing.RefStatusRetired, Aliases: []string{"gpt-old-legacy"}},
			{Provider: "priceonly", Model: "price-model", Status: pricing.RefStatusActive}, // pricing-only pair
		},
	}
}

func modelPayloadOf(t *testing.T, a Asset) ModelPayload {
	t.Helper()
	var p ModelPayload
	if err := json.Unmarshal(a.Payload, &p); err != nil {
		t.Fatalf("unmarshal model payload %s: %v", a.AssetKey, err)
	}
	return p
}

func providerPayloadOf(t *testing.T, a Asset) ProviderPayload {
	t.Helper()
	var p ProviderPayload
	if err := json.Unmarshal(a.Payload, &p); err != nil {
		t.Fatalf("unmarshal provider payload %s: %v", a.AssetKey, err)
	}
	return p
}

func findAsset(assets []Asset, key string) (Asset, bool) {
	for _, a := range assets {
		if a.AssetKey == key {
			return a, true
		}
	}
	return Asset{}, false
}

// TestModelImportThreePlanes covers the full adapter: registry + catalog +
// pricing converge on canonical keys, every lifecycle status persists,
// discrepancies are flagged per side, providers roll up, and a
// withdrawal-only provider is still an asset.
func TestModelImportThreePlanes(t *testing.T) {
	at := Timestamps{FirstSeen: modelFixtureAt, LastSeen: modelFixtureAt}
	reg := []RegistryModel{
		{ModelName: "gpt-x-alias", Provider: "openai", Tier: "premium", Enabled: true}, // alias row → canonical pair
		{ModelName: "gpt-x", Provider: "openai", Tier: "standard", Enabled: true, UpstreamURL: "https://api.openai.com/v1"},
		{ModelName: "gpt-local", Provider: "openai", Tier: "standard", Enabled: true}, // registry-only pair
	}
	prov := &ReferenceProvenance{CatalogVersion: "cat-v1", CatalogSource: "test-snapshot",
		PricingVersion: "pack-v7", PricingAsOf: "2026-11-06T00:00:00Z", PricingDigest: "sha256:abc123"}

	assets, skips := BuildModelAssets(at, "org-1", reg, ProviderCatalog{Cat: fixtureCatalog(t)}, fixturePricing(), prov)
	if len(skips) != 0 {
		t.Fatalf("unexpected skips: %+v", skips)
	}

	// Canonical convergence: the alias-named registry row and the canonical
	// row land on ONE model:openai/gpt-x asset.
	gptX, ok := findAsset(assets, ModelKey("openai", "gpt-x"))
	if !ok {
		t.Fatalf("model:openai/gpt-x asset missing; got keys: %v", assetKeys(assets))
	}
	if gptX.Kind != KindModel || gptX.Source != SourceModelsRegistry || gptX.Confidence != ConfidenceHigh {
		t.Fatalf("gpt-x asset header wrong: %+v", gptX)
	}
	p := modelPayloadOf(t, gptX)
	if p.Status != "active" {
		t.Fatalf("gpt-x status = %q, want active", p.Status)
	}
	if len(p.Registry) != 2 {
		t.Fatalf("gpt-x registry observations = %d, want 2 (alias row + canonical row): %+v", len(p.Registry), p.Registry)
	}
	if p.Registry[0].ModelName != "gpt-x" || p.Registry[1].ModelName != "gpt-x-alias" {
		t.Fatalf("gpt-x registry observations not sorted verbatim: %+v", p.Registry)
	}
	if p.Registry[1].Tier != "premium" || p.Registry[0].UpstreamURL != "https://api.openai.com/v1" {
		t.Fatalf("gpt-x registry observations lost verbatim fields: %+v", p.Registry)
	}
	if p.Catalog == nil || p.Pricing == nil {
		t.Fatalf("gpt-x must carry both reference sections: %+v", p)
	}
	if p.Discrepancy != "" {
		t.Fatalf("gpt-x known to both sides must not be flagged, got %q", p.Discrepancy)
	}
	if !reflect.DeepEqual(p.Aliases, []string{"gpt-x-alias"}) {
		t.Fatalf("gpt-x aliases = %v, want [gpt-x-alias]", p.Aliases)
	}
	if reflect.DeepEqual(p.Provenance, prov) != true {
		t.Fatalf("gpt-x provenance not fixed: %+v", p.Provenance)
	}
	if p.Pricing.Regions[0] != "eu" || p.Pricing.Regions[1] != "us" || p.Pricing.Tiers[0] != "premium" {
		t.Fatalf("gpt-x pricing scoping not deduped/sorted: %+v", p.Pricing)
	}

	// Lifecycle statuses persist as assets (never dropped on delist).
	for key, want := range map[string]string{
		ModelKey("openai", "gpt-old"):    "deprecated",
		ModelKey("openai", "gpt-dead"):   "withdrawn",
		ModelKey("openai", "gpt-future"): "pending",
	} {
		a, ok := findAsset(assets, key)
		if !ok {
			t.Fatalf("%s asset missing (lifecycle persists as asset)", key)
		}
		if got := modelPayloadOf(t, a).Status; got != want {
			t.Fatalf("%s status = %q, want %q", key, got, want)
		}
	}
	old := modelPayloadOf(t, mustAsset(t, assets, ModelKey("openai", "gpt-old")))
	wantDeprecated := modelFixtureAt.Add(-12 * time.Hour)
	if old.DeprecatedAt == nil || !old.DeprecatedAt.Equal(wantDeprecated) {
		t.Fatalf("gpt-old deprecated_at = %v, want %v", old.DeprecatedAt, wantDeprecated)
	}

	// Provider withdrawal overrides model lifecycle and is recorded on both
	// the model and the provider.
	claude := modelPayloadOf(t, mustAsset(t, assets, ModelKey("anthropic", "claude-x")))
	if claude.Status != "withdrawn" || claude.WithdrawnAt == nil {
		t.Fatalf("claude-x under withdrawn provider: %+v", claude)
	}
	anth, ok := findAsset(assets, ProviderKey("anthropic"))
	if !ok || providerPayloadOf(t, anth).Status != "withdrawn" {
		t.Fatalf("anthropic provider must be withdrawn: %+v", anth)
	}
	if got := providerPayloadOf(t, anth).RegistryModels; got != 0 {
		t.Fatalf("anthropic registry models = %d, want 0", got)
	}

	// Withdrawal-only provider: still an asset, zero models anywhere.
	gore, ok := findAsset(assets, ProviderKey("gore"))
	if !ok {
		t.Fatalf("withdrawal-only provider asset missing")
	}
	gp := providerPayloadOf(t, gore)
	if gp.Status != "withdrawn" || gp.RegistryModels+gp.CatalogModels+gp.PricingModels != 0 || gp.WithdrawnAt == nil {
		t.Fatalf("gore provider payload wrong: %+v", gp)
	}

	// Registry-only pair: deployment knows it, reference does not.
	local := modelPayloadOf(t, mustAsset(t, assets, ModelKey("openai", "gpt-local")))
	if local.Discrepancy != "registry_only" || local.Catalog != nil || local.Pricing != nil {
		t.Fatalf("registry-only pair payload wrong: %+v", local)
	}

	// Reference-only pairs (catalog, pricing): materialize with the flag,
	// source = model_catalog, status from the plane that knows them.
	refOnly := modelPayloadOf(t, mustAsset(t, assets, ModelKey("refonly", "ref-model")))
	if refOnly.Discrepancy != "reference_only" || len(refOnly.Registry) != 0 || refOnly.Status != "active" {
		t.Fatalf("catalog-only pair payload wrong: %+v", refOnly)
	}
	if a := mustAsset(t, assets, ModelKey("refonly", "ref-model")); a.Source != SourceModelCatalog {
		t.Fatalf("catalog-only pair source = %q, want %q", a.Source, SourceModelCatalog)
	}
	priceOnly := modelPayloadOf(t, mustAsset(t, assets, ModelKey("priceonly", "price-model")))
	if priceOnly.Discrepancy != "reference_only" || priceOnly.Status != "unknown" || priceOnly.Catalog != nil {
		t.Fatalf("pricing-only pair payload wrong: %+v", priceOnly)
	}

	// Provider rollups carry per-side counts.
	oa := providerPayloadOf(t, mustAsset(t, assets, ProviderKey("openai")))
	if oa.RegistryModels != 3 || oa.CatalogModels != 4 || oa.PricingModels != 2 || oa.Status != "active" {
		t.Fatalf("openai provider rollup wrong: %+v", oa)
	}
	if mustAsset(t, assets, ProviderKey("openai")).Source != SourceModelsRegistry {
		t.Fatalf("openai provider source must be models_registry")
	}
	if pp := providerPayloadOf(t, mustAsset(t, assets, ProviderKey("priceonly"))); pp.Discrepancy != "reference_only" {
		t.Fatalf("priceonly provider discrepancy = %q, want reference_only", pp.Discrepancy)
	}

	// Every constructed asset passes the model contract, deterministically.
	second, _ := BuildModelAssets(at, "org-1", reg, ProviderCatalog{Cat: fixtureCatalog(t)}, fixturePricing(), prov)
	if !reflect.DeepEqual(assets, second) {
		t.Fatalf("BuildModelAssets is not deterministic")
	}
}

// TestModelImportEmptyUpstream: empty/absent planes yield zero assets and
// no error — absence of observations is not absence of assets, and an empty
// registry is not a wipe (the runner owns wipes).
func TestModelImportEmptyUpstream(t *testing.T) {
	at := Timestamps{FirstSeen: time.Unix(0, 0).UTC(), LastSeen: time.Unix(0, 0).UTC()}

	assets, skips := BuildModelAssets(at, "org-1", nil, nil, nil, nil)
	if len(assets) != 0 || len(skips) != 0 {
		t.Fatalf("all-empty upstream: got %d assets, %d skips", len(assets), len(skips))
	}

	// Registry rows alone (no catalog, no pack) import fine.
	assets, skips = BuildModelAssets(at, "org-1",
		[]RegistryModel{{ModelName: "m1", Provider: "p1", Enabled: true}}, nil, nil, nil)
	if len(skips) != 0 {
		t.Fatalf("registry-only skips: %+v", skips)
	}
	if len(assets) != 2 { // model:p1/m1 + provider:p1
		t.Fatalf("registry-only assets = %d, want 2", len(assets))
	}
	m := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", "m1")))
	if m.Status != "unknown" || m.Discrepancy != "registry_only" || len(m.Registry) != 1 {
		t.Fatalf("registry-only payload wrong: %+v", m)
	}

	// A catalog with zero entries and a pack with zero models behave the
	// same as absent planes for the pair union.
	emptyCat, err := provider.NewModelCatalog(provider.ModelCatalogSpec{
		Version: "empty", SchemaVersion: 1, Source: "test", AsOf: at.LastSeen})
	if err != nil {
		t.Fatalf("empty catalog: %v", err)
	}
	assets, skips = BuildModelAssets(at, "org-1", nil, ProviderCatalog{Cat: emptyCat}, fakePricingPack{}, nil)
	if len(assets) != 0 || len(skips) != 0 {
		t.Fatalf("empty reference planes: got %d assets, %d skips", len(assets), len(skips))
	}
}

// TestModelImportSkipsBrokenRegistryRows: identity-defective registry rows
// are skipped and counted, never fatal for the healthy siblings.
func TestModelImportSkipsBrokenRegistryRows(t *testing.T) {
	at := Timestamps{FirstSeen: time.Unix(0, 0).UTC(), LastSeen: time.Unix(0, 0).UTC()}
	reg := []RegistryModel{
		{ModelName: "good", Provider: "p1", Enabled: true},
		{ModelName: "", Provider: "p1"},          // empty model_name
		{ModelName: "bad name", Provider: "p1"},  // whitespace fails key rules
		{ModelName: "no-provider", Provider: ""}, // empty provider
	}
	assets, skips := BuildModelAssets(at, "org-1", reg, nil, nil, nil)
	if len(skips) != 3 {
		t.Fatalf("skips = %d (%+v), want 3", len(skips), skips)
	}
	if _, ok := findAsset(assets, ModelKey("p1", "good")); !ok {
		t.Fatalf("healthy sibling must import: %v", assetKeys(assets))
	}
	for _, a := range assets {
		if err := a.Validate(); err != nil {
			t.Fatalf("asset %s invalid: %v", a.AssetKey, err)
		}
	}
}

// TestModelImportDBRegistrySource: the SQL seam reads the GLOBAL
// models_registry through the production migrations (chk_provider
// vocabulary enforced there), in model_name order, and never selects
// upstream_api_key.
func TestModelImportDBRegistrySource(t *testing.T) {
	store := newTestStore(t)
	ctx := t.Context()
	if _, err := store.db.Exec(ctx, `
		INSERT INTO models_registry (model_name, display_name, provider, tier, upstream_url, enabled)
		VALUES
		  ('db-model-b', 'DB Model B', 'openai', 'premium', 'https://api.openai.com/v1', true),
		  ('db-model-a', 'DB Model A', 'anthropic', 'standard', '', false)`); err != nil {
		t.Fatalf("seed models_registry: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.Exec(ctx, `DELETE FROM models_registry WHERE model_name IN ('db-model-a','db-model-b')`)
	})

	src := NewDBModelRegistrySource(store.db)
	rows, err := src.ListRegistryModels(ctx)
	if err != nil {
		t.Fatalf("ListRegistryModels: %v", err)
	}
	// migrations seed the global models_registry (~31 rows); narrow to ours.
	var mine []RegistryModel
	for _, r := range rows {
		if len(r.ModelName) >= 8 && r.ModelName[:8] == "db-model" {
			mine = append(mine, r)
		}
	}
	if len(mine) != 2 || mine[0].ModelName != "db-model-a" || mine[1].ModelName != "db-model-b" {
		t.Fatalf("seeded rows not found or misordered: %+v", mine)
	}
	if mine[1].Provider != "openai" || mine[1].Tier != "premium" || !mine[1].Enabled || mine[1].UpstreamURL == "" {
		t.Fatalf("registry row fields wrong: %+v", mine[1])
	}
	if mine[0].Enabled || mine[0].UpstreamURL != "" {
		t.Fatalf("registry row defaults wrong: %+v", mine[0])
	}

	assets, skips := BuildModelAssets(Timestamps{FirstSeen: time.Unix(0, 0).UTC(), LastSeen: time.Unix(0, 0).UTC()},
		"org-1", mine, nil, nil, nil)
	if len(skips) != 0 || len(assets) != 4 {
		t.Fatalf("db registry import: %d assets, %d skips", len(assets), len(skips))
	}
}

func mustAsset(t *testing.T, assets []Asset, key string) Asset {
	t.Helper()
	a, ok := findAsset(assets, key)
	if !ok {
		t.Fatalf("asset %s missing; have %v", key, assetKeys(assets))
	}
	return a
}

func assetKeys(assets []Asset) []string {
	out := make([]string, 0, len(assets))
	for _, a := range assets {
		out = append(out, a.AssetKey)
	}
	return out
}
