package inventory

// Independent semantic pinning of the model-asset build pipeline (ordering,
// header propagation, alias-resolution guard, lifecycle boundaries,
// withdrawal timing, pricing merge, verbatim skip records). Derived from the
// observable contract, not from internal structure; must hold before and
// after any behavior-preserving refactor of BuildModelAssets.

import (
	"reflect"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

var semanticAt = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

func semanticTS() Timestamps { return Timestamps{FirstSeen: semanticAt, LastSeen: semanticAt} }

// semanticCatalog is a direct ModelCatalogSource fixture: entry and
// withdrawal rows are fed verbatim (no constructor validation) and alias
// resolution is injectable per case.
type semanticCatalog struct {
	entries     []provider.ModelCatalogEntry
	withdrawals []provider.Withdrawal
	resolve     func(providerName, alias string, at time.Time) (string, provider.ModelStatus)
}

func (c *semanticCatalog) Meta() CatalogMeta                     { return CatalogMeta{} }
func (c *semanticCatalog) Entries() []provider.ModelCatalogEntry { return c.entries }
func (c *semanticCatalog) Withdrawals() []provider.Withdrawal    { return c.withdrawals }

func (c *semanticCatalog) ResolveAlias(providerName, alias string, at time.Time) (string, provider.ModelStatus) {
	if c.resolve != nil {
		return c.resolve(providerName, alias, at)
	}
	return "", provider.StatusUnknown
}

func wantStrings(t *testing.T, got, want []string, what string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

// TestBuildModelAssetsOutputOrder pins the deterministic asset sequence:
// model assets sorted by (provider, model) first, provider assets sorted by
// name after them.
func TestBuildModelAssetsOutputOrder(t *testing.T) {
	cat := &semanticCatalog{entries: []provider.ModelCatalogEntry{
		{Provider: "pb", Model: "m2", EffectiveFrom: semanticAt.Add(-time.Hour)},
		{Provider: "pa", Model: "m0", EffectiveFrom: semanticAt.Add(-time.Hour)},
	}}
	reg := []RegistryModel{
		{ModelName: "m1", Provider: "pb", Enabled: true},
		{ModelName: "m1", Provider: "pa", Enabled: true},
	}
	pack := fakePricingPack{models: []pricing.RefModel{
		{Provider: "pc", Model: "m1", Status: pricing.RefStatusActive},
		{Provider: "pa", Model: "m2", Status: pricing.RefStatusActive},
	}}
	assets, _ := BuildModelAssets(semanticTS(), "org-s", reg, cat, pack, nil)
	want := []string{
		ModelKey("pa", "m0"), ModelKey("pa", "m1"), ModelKey("pa", "m2"),
		ModelKey("pb", "m1"), ModelKey("pb", "m2"),
		ModelKey("pc", "m1"),
		ProviderKey("pa"), ProviderKey("pb"), ProviderKey("pc"),
	}
	wantStrings(t, assetKeys(assets), want, "asset order")
}

// TestBuildModelAssetsHeaderFields pins OrgID, kind, source choice,
// confidence and verbatim first/last-seen propagation on every asset kind.
func TestBuildModelAssetsHeaderFields(t *testing.T) {
	firstSeen := semanticAt.Add(-90 * time.Minute)
	at := Timestamps{FirstSeen: firstSeen, LastSeen: semanticAt}
	cat := &semanticCatalog{
		entries: []provider.ModelCatalogEntry{
			{Provider: "pc", Model: "m2", EffectiveFrom: semanticAt.Add(-time.Hour)},
		},
		withdrawals: []provider.Withdrawal{{Provider: "pw", WithdrawnAt: semanticAt.Add(-time.Minute)}},
	}
	reg := []RegistryModel{{ModelName: "m1", Provider: "pr", Enabled: true}}
	pack := fakePricingPack{models: []pricing.RefModel{
		{Provider: "pp", Model: "m3", Status: pricing.RefStatusActive},
	}}
	assets, skips := BuildModelAssets(at, "org-42", reg, cat, pack, nil)
	if len(skips) != 0 {
		t.Fatalf("skips: %+v", skips)
	}
	wantSource := map[string]Source{
		ModelKey("pr", "m1"):    SourceModelsRegistry,
		ModelKey("pc", "m2"):    SourceModelCatalog,
		ModelKey("pp", "m3"):    SourceModelCatalog,
		ProviderKey("pr"):       SourceModelsRegistry,
		ProviderKey("pc"):       SourceModelCatalog,
		ProviderKey("pp"):       SourceModelCatalog,
		ProviderKey("pw"):       SourceModelCatalog,
	}
	if len(assets) != len(wantSource) {
		t.Fatalf("assets = %v, want exactly %v", assetKeys(assets), wantSource)
	}
	for _, a := range assets {
		want, ok := wantSource[a.AssetKey]
		if !ok {
			t.Fatalf("unexpected asset %s", a.AssetKey)
		}
		if a.OrgID != "org-42" || a.Confidence != ConfidenceHigh || a.Source != want {
			t.Fatalf("%s header wrong: %+v (want source %s)", a.AssetKey, a, want)
		}
		if !a.FirstSeen.Equal(firstSeen) || !a.LastSeen.Equal(semanticAt) {
			t.Fatalf("%s seen window not propagated: %+v", a.AssetKey, a)
		}
		if err := a.Validate(); err != nil {
			t.Fatalf("asset %s invalid: %v", a.AssetKey, err)
		}
	}
	if k := mustAsset(t, assets, ModelKey("pr", "m1")); k.Kind != KindModel {
		t.Fatalf("model asset kind = %q", k.Kind)
	}
	if k := mustAsset(t, assets, ProviderKey("pw")); k.Kind != KindProvider {
		t.Fatalf("provider asset kind = %q", k.Kind)
	}
}

// TestBuildModelAssetsRegistryAliasGuard pins when a registry row is
// re-attributed to a canonical pair: only a non-empty canonical name with a
// non-unknown status redirects the observation; everything else keeps the
// row's own pair.
func TestBuildModelAssetsRegistryAliasGuard(t *testing.T) {
	cases := []struct {
		name     string
		catalog  ModelCatalogSource
		wantPair string
	}{
		{"nil catalog keeps own pair", nil, "beta"},
		{"unknown alias keeps own pair", &semanticCatalog{}, "beta"},
		{"canonical with unknown status keeps own pair", &semanticCatalog{
			resolve: func(_, _ string, _ time.Time) (string, provider.ModelStatus) {
				return "alpha", provider.StatusUnknown
			},
		}, "beta"},
		{"active canonical attributes", &semanticCatalog{
			resolve: func(_, _ string, _ time.Time) (string, provider.ModelStatus) {
				return "alpha", provider.StatusActive
			},
		}, "alpha"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := []RegistryModel{{ModelName: "beta", Provider: "p1", Enabled: true}}
			assets, skips := BuildModelAssets(semanticTS(), "org-s", reg, tc.catalog, nil, nil)
			if len(skips) != 0 {
				t.Fatalf("skips: %+v", skips)
			}
			p := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", tc.wantPair)))
			if len(p.Registry) != 1 || p.Registry[0].ModelName != "beta" {
				t.Fatalf("observation not on pair %q: %+v", tc.wantPair, p.Registry)
			}
		})
	}
}

// TestBuildModelAssetsStatusBoundaries pins the lifecycle classification at
// the exact window edges: the import instant counts as inside the sell
// window at EffectiveFrom and outside it at EffectiveTo/DeprecatedAt.
func TestBuildModelAssetsStatusBoundaries(t *testing.T) {
	now := semanticAt
	cat := &semanticCatalog{entries: []provider.ModelCatalogEntry{
		{Provider: "p1", Model: "at-open", EffectiveFrom: now},
		{Provider: "p1", Model: "pre-open", EffectiveFrom: now.Add(time.Nanosecond)},
		{Provider: "p1", Model: "at-close", EffectiveFrom: now.Add(-time.Hour), EffectiveTo: now},
		{Provider: "p1", Model: "at-dep", EffectiveFrom: now.Add(-time.Hour), DeprecatedAt: now},
		{Provider: "p1", Model: "plain"},
	}}
	assets, skips := BuildModelAssets(semanticTS(), "org-s", nil, cat, nil, nil)
	if len(skips) != 0 {
		t.Fatalf("skips: %+v", skips)
	}
	for model, want := range map[string]string{
		"at-open": "active", "pre-open": "pending", "at-close": "withdrawn",
		"at-dep": "deprecated", "plain": "active",
	} {
		if got := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", model))).Status; got != want {
			t.Fatalf("%s status = %q, want %q", model, got, want)
		}
	}
}

// TestBuildModelAssetsFutureWithdrawalIgnored pins that a withdrawal after
// the import instant changes nothing yet: models keep their lifecycle
// status, provider stays active, no WithdrawnAt anywhere.
func TestBuildModelAssetsFutureWithdrawalIgnored(t *testing.T) {
	now := semanticAt
	cat := &semanticCatalog{
		entries: []provider.ModelCatalogEntry{
			{Provider: "p1", Model: "depd", EffectiveFrom: now.Add(-2 * time.Hour), DeprecatedAt: now.Add(-time.Hour)},
			{Provider: "p1", Model: "live", EffectiveFrom: now.Add(-2 * time.Hour)},
		},
		withdrawals: []provider.Withdrawal{{Provider: "p1", WithdrawnAt: now.Add(2 * time.Hour)}},
	}
	assets, skips := BuildModelAssets(semanticTS(), "org-s", nil, cat, nil, nil)
	if len(skips) != 0 {
		t.Fatalf("skips: %+v", skips)
	}
	pp := providerPayloadOf(t, mustAsset(t, assets, ProviderKey("p1")))
	if pp.Status != "active" || pp.WithdrawnAt != nil {
		t.Fatalf("future withdrawal reached the provider: %+v", pp)
	}
	for model, want := range map[string]string{"live": "active", "depd": "deprecated"} {
		p := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", model)))
		if p.Status != want || p.WithdrawnAt != nil {
			t.Fatalf("%s under future withdrawal: %+v (want %q)", model, p, want)
		}
	}
}

// TestBuildModelAssetsWithdrawalOverrideCarriesDeprecatedAt pins that an
// in-effect withdrawal overrides the status on models and provider while the
// in-effect deprecation instant still rides along on the model payload.
func TestBuildModelAssetsWithdrawalOverrideCarriesDeprecatedAt(t *testing.T) {
	now := semanticAt
	dep := now.Add(-time.Hour)
	wd := now.Add(-30 * time.Minute)
	cat := &semanticCatalog{
		entries: []provider.ModelCatalogEntry{
			{Provider: "p1", Model: "depd", EffectiveFrom: now.Add(-2 * time.Hour), DeprecatedAt: dep},
			{Provider: "p1", Model: "live", EffectiveFrom: now.Add(-2 * time.Hour)},
		},
		withdrawals: []provider.Withdrawal{{Provider: "p1", WithdrawnAt: wd}},
	}
	assets, skips := BuildModelAssets(semanticTS(), "org-s", nil, cat, nil, nil)
	if len(skips) != 0 {
		t.Fatalf("skips: %+v", skips)
	}
	m := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", "depd")))
	if m.Status != "withdrawn" || m.WithdrawnAt == nil || !m.WithdrawnAt.Equal(wd.UTC()) {
		t.Fatalf("withdrawal override missing: %+v", m)
	}
	if m.DeprecatedAt == nil || !m.DeprecatedAt.Equal(dep.UTC()) {
		t.Fatalf("deprecation instant must survive the withdrawal override: %+v", m)
	}
	if p := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", "live"))); p.Status != "withdrawn" {
		t.Fatalf("live model under withdrawal: %+v", p)
	}
	pp := providerPayloadOf(t, mustAsset(t, assets, ProviderKey("p1")))
	if pp.Status != "withdrawn" || pp.WithdrawnAt == nil || !pp.WithdrawnAt.Equal(wd.UTC()) {
		t.Fatalf("provider withdrawal missing: %+v", pp)
	}
}

// TestBuildModelAssetsPricingObservationMerge pins the many-rows-to-one-pair
// merge: values deduped and sorted, empty strings dropped, and the provider
// rollup counts pairs, not rows.
func TestBuildModelAssetsPricingObservationMerge(t *testing.T) {
	pack := fakePricingPack{models: []pricing.RefModel{
		{Provider: "p1", Model: "m", Status: pricing.RefStatusActive, Region: "us", Tier: "t1", Aliases: []string{"b", "a"}},
		{Provider: "p1", Model: "m", Status: pricing.RefStatusActive, Region: "us", Tier: "", Aliases: []string{"a", "c"}},
		{Provider: "p1", Model: "m", Status: pricing.RefStatusRetired, Region: "eu", Tier: "t1", Aliases: []string{""}},
		{Provider: "p1", Model: "m", Status: "", Region: "", Tier: "t0"},
	}}
	assets, skips := BuildModelAssets(semanticTS(), "org-s", nil, nil, pack, nil)
	if len(skips) != 0 {
		t.Fatalf("skips: %+v", skips)
	}
	p := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", "m")))
	if p.Pricing == nil {
		t.Fatalf("pricing section missing: %+v", p)
	}
	wantStrings(t, p.Pricing.Statuses, []string{"active", "retired"}, "pricing statuses")
	wantStrings(t, p.Pricing.Regions, []string{"eu", "us"}, "pricing regions")
	wantStrings(t, p.Pricing.Tiers, []string{"t0", "t1"}, "pricing tiers")
	wantStrings(t, p.Pricing.Aliases, []string{"a", "b", "c"}, "pricing aliases")
	if p.Status != "unknown" || p.Discrepancy != "reference_only" {
		t.Fatalf("pricing-only pair classification wrong: %+v", p)
	}
	pp := providerPayloadOf(t, mustAsset(t, assets, ProviderKey("p1")))
	if pp.PricingModels != 1 {
		t.Fatalf("provider counts rows not pairs: %+v", pp)
	}
}

// TestBuildModelAssetsAliasUnionAcrossPlanes pins that the model payload's
// alias list is the deduped, sorted union of the catalog and pricing alias
// sets, while each section keeps its own (sorted) copy.
func TestBuildModelAssetsAliasUnionAcrossPlanes(t *testing.T) {
	cat := &semanticCatalog{entries: []provider.ModelCatalogEntry{
		{Provider: "p1", Model: "m", Aliases: []string{"zeta", "alpha"}, EffectiveFrom: semanticAt.Add(-time.Hour)},
	}}
	pack := fakePricingPack{models: []pricing.RefModel{
		{Provider: "p1", Model: "m", Status: pricing.RefStatusActive, Aliases: []string{"alpha", "mid"}},
	}}
	assets, skips := BuildModelAssets(semanticTS(), "org-s", nil, cat, pack, nil)
	if len(skips) != 0 {
		t.Fatalf("skips: %+v", skips)
	}
	p := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", "m")))
	wantStrings(t, p.Aliases, []string{"alpha", "mid", "zeta"}, "payload alias union")
	wantStrings(t, p.Catalog.Aliases, []string{"alpha", "zeta"}, "catalog aliases")
	wantStrings(t, p.Pricing.Aliases, []string{"alpha", "mid"}, "pricing aliases")
}

// TestBuildModelAssetsSkipRecords pins the verbatim skip records (plane, ref
// and reason strings, in plane order) and that a defective-only input yields
// zero assets — skipped rows never count toward a provider.
func TestBuildModelAssetsSkipRecords(t *testing.T) {
	cat := &semanticCatalog{entries: []provider.ModelCatalogEntry{{Provider: "qc", Model: ""}}}
	reg := []RegistryModel{
		{ModelName: "", Provider: "qr"},
		{ModelName: "m", Provider: ""},
	}
	pack := fakePricingPack{models: []pricing.RefModel{{Provider: "", Model: "m"}}}
	assets, skips := BuildModelAssets(semanticTS(), "org-s", reg, cat, pack, nil)
	want := []ModelImportSkip{
		{Plane: "registry", Ref: "qr/", Reason: "empty provider or model_name"},
		{Plane: "registry", Ref: "/m", Reason: "empty provider or model_name"},
		{Plane: "catalog", Ref: "qc/", Reason: "empty provider or model"},
		{Plane: "pricing", Ref: "/m", Reason: "empty provider or model"},
	}
	if !reflect.DeepEqual(skips, want) {
		t.Fatalf("skips = %+v, want %+v", skips, want)
	}
	if len(assets) != 0 {
		t.Fatalf("defective-only input must yield zero assets: %v", assetKeys(assets))
	}
}
