package inventory

// E02-P01 W03-C02 tests: provenance fixing, discrepancy surfacing, the
// org-scoped model import runner (stability of re-imports, empty-org
// refusal, per-org materialization) and the bundled pricing pack loader.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/provider"
)

// staticRegistry is a ModelRegistrySource fixture.
type staticRegistry struct {
	rows []RegistryModel
	err  error
}

func (s staticRegistry) ListRegistryModels(context.Context) ([]RegistryModel, error) {
	return s.rows, s.err
}

func provenanceFixtureCatalog(t *testing.T, version string) *provider.ModelCatalog {
	t.Helper()
	cat, err := provider.NewModelCatalog(provider.ModelCatalogSpec{
		Version:       version,
		SchemaVersion: 1,
		Source:        "test-snapshot",
		AsOf:          modelFixtureAt,
		Entries: []provider.ModelCatalogEntry{
			{Provider: "openai", Model: "gpt-x", Aliases: []string{"gpt-x-alias"}, EffectiveFrom: modelFixtureAt.Add(-24 * time.Hour)},
			{Provider: "refonly", Model: "ref-model", EffectiveFrom: modelFixtureAt.Add(-24 * time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("fixture catalog: %v", err)
	}
	return cat
}

func newModelRunner(t *testing.T, orgREG []RegistryModel, catalog *provider.ModelCatalog, pack PricingPack) (*ModelImportRunner, *Store) {
	t.Helper()
	store := newTestStore(t)
	runner, err := NewModelImportRunner(store, staticRegistry{rows: orgREG},
		ProviderCatalog{Cat: catalog}, pack)
	if err != nil {
		t.Fatalf("NewModelImportRunner: %v", err)
	}
	runner.now = func() time.Time { return modelFixtureAt } // fixed clock
	return runner, store
}

// TestModelImportDiscrepancy: the two observations land as disjoint
// sections on one asset; a pair known to one side only is flagged, counted
// in the report, and never an error.
func TestModelImportDiscrepancy(t *testing.T) {
	ctx := t.Context()
	reg := []RegistryModel{
		{ModelName: "gpt-x-alias", Provider: "openai", Tier: "premium", Enabled: true}, // alias row → canonical pair, both sides
		{ModelName: "gpt-local", Provider: "openai", Tier: "standard", Enabled: true},  // registry-only
	}
	runner, store := newModelRunner(t, reg, provenanceFixtureCatalog(t, "cat-v1"), fixturePricing())

	rep, err := runner.Run(ctx, "org-mp1")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Both-sides pair: no flag, both reference sections, provenance fixed.
	both, ok, err := store.GetAsset(ctx, "org-mp1", KindModel, ModelKey("openai", "gpt-x"))
	if err != nil || !ok {
		t.Fatalf("canonical pair missing (err=%v)", err)
	}
	var mp ModelPayload
	unmarshalT(t, both.Payload, &mp)
	if mp.Discrepancy != "" || mp.Catalog == nil || mp.Pricing == nil || len(mp.Registry) != 1 {
		t.Fatalf("both-sides payload wrong: %+v", mp)
	}
	if mp.Provenance == nil || mp.Provenance.CatalogVersion != "cat-v1" || mp.Provenance.PricingVersion != "pack-v7" ||
		mp.Provenance.PricingDigest != "sha256:abc123" || mp.Provenance.PricingAsOf != "2026-11-06T00:00:00Z" {
		t.Fatalf("provenance block wrong: %+v", mp.Provenance)
	}
	if both.Source != SourceModelsRegistry {
		t.Fatalf("both-sides source = %q", both.Source)
	}

	// One-side pairs carry the flag.
	local := modelPayloadOfT(t, store, ctx, "org-mp1", ModelKey("openai", "gpt-local"))
	if local.Discrepancy != "registry_only" || local.Catalog != nil {
		t.Fatalf("registry-only flag wrong: %+v", local)
	}
	ref := modelPayloadOfT(t, store, ctx, "org-mp1", ModelKey("refonly", "ref-model"))
	if ref.Discrepancy != "reference_only" || len(ref.Registry) != 0 {
		t.Fatalf("reference-only flag wrong: %+v", ref)
	}
	price := modelPayloadOfT(t, store, ctx, "org-mp1", ModelKey("priceonly", "price-model"))
	if price.Discrepancy != "reference_only" {
		t.Fatalf("pricing-only flag wrong: %+v", price)
	}

	// Report journal: versions + discrepancy count (models only).
	if rep.CatalogVersion != "cat-v1" || rep.PricingVersion != "pack-v7" || rep.PricingDigest != "sha256:abc123" {
		t.Fatalf("report versions journal wrong: %+v", rep)
	}
	// Flagged models: gpt-local (registry_only); refonly/ref-model,
	// priceonly/price-model, openai/gpt-old (pricing-only in this fixture) —
	// all reference_only.
	if rep.Discrepancies != 4 {
		t.Fatalf("report discrepancies = %d, want 4", rep.Discrepancies)
	}
	if rep.Counts.Created != 8 { // 5 models + 3 providers (openai, refonly, priceonly)
		t.Fatalf("created = %d, want 8", rep.Counts.Created)
	}
}

// TestModelImportReimportStable: same snapshot + fixed clock ⇒ unchanged;
// a catalog version bump rewrites payloads ⇒ updated; the report journal
// records the version that ran.
func TestModelImportReimportStable(t *testing.T) {
	ctx := t.Context()
	reg := []RegistryModel{{ModelName: "gpt-x", Provider: "openai", Enabled: true}}
	runner, _ := newModelRunner(t, reg, provenanceFixtureCatalog(t, "cat-v1"), fixturePricing())

	first, err := runner.Run(ctx, "org-mp2")
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	second, err := runner.Run(ctx, "org-mp2")
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second.Counts.Created != 0 || second.Counts.Updated != 0 || second.Counts.Unchanged != first.Counts.Created {
		t.Fatalf("re-import must be a no-op: first=%+v second=%+v", first.Counts, second.Counts)
	}
	if second.CatalogVersion != "cat-v1" || second.PricingDigest != "sha256:abc123" {
		t.Fatalf("second run journal wrong: %+v", second)
	}

	// Version bump: same pairs, new provenance ⇒ payloads change ⇒ updated.
	runner.catalog = ProviderCatalog{Cat: provenanceFixtureCatalog(t, "cat-v2")}
	third, err := runner.Run(ctx, "org-mp2")
	if err != nil {
		t.Fatalf("third run: %v", err)
	}
	if third.CatalogVersion != "cat-v2" {
		t.Fatalf("third run journal wrong: %+v", third)
	}
	if third.Counts.Updated == 0 || third.Counts.Created != 0 {
		t.Fatalf("version bump must rewrite rows: %+v", third.Counts)
	}
}

// TestModelImportRunnerRefusesEmptyOrg: obligation ② — the seam refuses an
// empty org before touching the store or the upstream.
func TestModelImportRunnerRefusesEmptyOrg(t *testing.T) {
	runner, store := newModelRunner(t, []RegistryModel{{ModelName: "m", Provider: "p", Enabled: true}}, nil, nil)
	if _, err := runner.Run(t.Context(), ""); err == nil {
		t.Fatalf("empty org must be refused")
	} else if err != ErrOrgRequired {
		t.Fatalf("empty org error = %v, want ErrOrgRequired", err)
	}
	rows, _, err := store.ListAssets(t.Context(), "org-x", ListParams{})
	if err != nil || len(rows) != 0 {
		t.Fatalf("refused run must not write anything: %v %+v", err, rows)
	}
}

// TestModelImportPerOrgMaterialization: the GLOBAL registry read lands
// per-org; org-1's rows never leak into org-2.
func TestModelImportPerOrgMaterialization(t *testing.T) {
	ctx := t.Context()
	reg := []RegistryModel{{ModelName: "gpt-x", Provider: "openai", Enabled: true}}
	runner, store := newModelRunner(t, reg, provenanceFixtureCatalog(t, "cat-v1"), nil)

	for _, org := range []string{"org-mp4a", "org-mp4b"} {
		if _, err := runner.Run(ctx, org); err != nil {
			t.Fatalf("run for %s: %v", org, err)
		}
	}
	for _, org := range []string{"org-mp4a", "org-mp4b"} {
		if _, ok, err := store.GetAsset(ctx, org, KindModel, ModelKey("openai", "gpt-x")); err != nil || !ok {
			t.Fatalf("%s missing its materialized copy (err=%v)", org, err)
		}
	}
	rows, _, err := store.ListAssets(ctx, "org-mp4c", ListParams{})
	if err != nil || len(rows) != 0 {
		t.Fatalf("org-3 must stay empty: %v %+v", err, rows)
	}
}

// TestModelImportEmptyRegistryNoWipe: an empty registry snapshot is a
// no-op pass — assets only shrink through tombstones, never through an
// import observing nothing.
func TestModelImportEmptyRegistryNoWipe(t *testing.T) {
	ctx := t.Context()
	runner, store := newModelRunner(t,
		[]RegistryModel{{ModelName: "gpt-x", Provider: "openai", Enabled: true}},
		provenanceFixtureCatalog(t, "cat-v1"), nil)
	if _, err := runner.Run(ctx, "org-mp6"); err != nil {
		t.Fatalf("seed run: %v", err)
	}

	// Every plane now reports nothing — a true empty upstream.
	runner.registry = staticRegistry{}
	runner.catalog = nil
	runner.pack = nil
	rep, err := runner.Run(ctx, "org-mp6")
	if err != nil {
		t.Fatalf("empty run: %v", err)
	}
	if rep.Counts.Created != 0 || rep.Counts.Updated != 0 || rep.Counts.Unchanged != 0 {
		t.Fatalf("empty upstream must be a no-op: %+v", rep.Counts)
	}
	if _, ok, gerr := store.GetAsset(ctx, "org-mp6", KindModel, ModelKey("openai", "gpt-x")); gerr != nil || !ok {
		t.Fatalf("empty pass must not wipe existing assets (err=%v)", gerr)
	}
}

// TestBundledPricingPack: the embedded bundle loads exactly once, with a
// recomputed digest and a non-empty model set (the production pricing
// plane the runner wires by default).
func TestBundledPricingPack(t *testing.T) {
	pack, err := BundledPricingPack()
	if err != nil {
		t.Fatalf("BundledPricingPack: %v", err)
	}
	meta := pack.Meta()
	if meta.Version == "" || meta.Digest == "" {
		t.Fatalf("pack meta incomplete: %+v", meta)
	}
	if n := len(pack.Models()); n == 0 {
		t.Fatalf("bundled pack carries no models")
	}
	again, err := BundledPricingPack()
	if err != nil || again != pack {
		t.Fatalf("BundledPricingPack must be load-once stable")
	}
}

// TestNewModelImportRunnerWiring: nil store / nil registry source are
// wiring defects, refused at construction.
func TestNewModelImportRunnerWiring(t *testing.T) {
	if _, err := NewModelImportRunner(nil, staticRegistry{}, nil, nil); err != ErrNilStore {
		t.Fatalf("nil store: %v", err)
	}
	store := newTestStore(t)
	if _, err := NewModelImportRunner(store, nil, nil, nil); err != ErrNilRegistrySource {
		t.Fatalf("nil registry: %v", err)
	}
}

func unmarshalT(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func modelPayloadOfT(t *testing.T, store *Store, ctx context.Context, org, key string) ModelPayload {
	t.Helper()
	row, ok, err := store.GetAsset(ctx, org, KindModel, key)
	if err != nil || !ok {
		t.Fatalf("asset %s/%s missing (err=%v)", org, key, err)
	}
	var p ModelPayload
	unmarshalT(t, row.Payload, &p)
	return p
}
