package inventory

// E02-P01 W03-C03: adversarial battery for the model import adapter.
//
// The fixture source below implements ModelCatalogSource DIRECTLY (not via
// provider.NewModelCatalog): its job is to feed snapshots the strict
// catalog constructor would refuse — broken entries, duplicate pairs,
// malformed withdrawals, alias cycles and shadowing — and prove the builder
// skips-and-counts instead of aborting, attributes deterministically, and
// never lets an alias resurrect a withdrawn target. Post-conditions:
// every produced asset passes Validate, and identical input produces
// identical output.

import (
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// adversarialCatalog is a ModelCatalogSource that bypasses
// NewModelCatalog validation on purpose (broken rows are the payload).
type adversarialCatalog struct {
	meta       CatalogMeta
	entries    []provider.ModelCatalogEntry
	withdrawal []provider.Withdrawal
	aliases    map[string]string               // "provider:alias" -> canonical model
	status     map[string]provider.ModelStatus // "provider:model" -> status override
}

func (c *adversarialCatalog) Meta() CatalogMeta                     { return c.meta }
func (c *adversarialCatalog) Entries() []provider.ModelCatalogEntry { return c.entries }
func (c *adversarialCatalog) Withdrawals() []provider.Withdrawal    { return c.withdrawal }

func (c *adversarialCatalog) ResolveAlias(providerName, alias string, at time.Time) (string, provider.ModelStatus) {
	if m, ok := c.aliases[providerName+":"+alias]; ok {
		st := provider.StatusActive
		if s, ok := c.status[providerName+":"+m]; ok {
			st = s
		}
		return m, st
	}
	return "", provider.StatusUnknown
}

var adversarialAt = Timestamps{
	FirstSeen: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC),
	LastSeen:  time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC),
}

// TestModelImportAdversarialBrokenCatalogEntries: identity defects and
// inverted deprecation windows are skipped with counted reasons; healthy
// siblings still import; duplicates for one pair keep the first entry.
func TestModelImportAdversarialBrokenCatalogEntries(t *testing.T) {
	cat := &adversarialCatalog{entries: []provider.ModelCatalogEntry{
		{Provider: "", Model: "orphan"},     // empty provider
		{Provider: "p1", Model: ""},         // empty model
		{Provider: "p1", Model: "bad name"}, // key-rule failure
		{Provider: "p1", Model: "pre-window", EffectiveFrom: adversarialAt.LastSeen.Add(24 * time.Hour),
			DeprecatedAt: adversarialAt.LastSeen.Add(12 * time.Hour)}, // deprecation before window opens
		{Provider: "p1", Model: "post-window", EffectiveFrom: adversarialAt.LastSeen.Add(-48 * time.Hour),
			EffectiveTo: adversarialAt.LastSeen.Add(-24 * time.Hour), DeprecatedAt: adversarialAt.LastSeen}, // deprecation at/after window close
		{Provider: "p1", Model: "healthy", EffectiveFrom: adversarialAt.LastSeen.Add(-24 * time.Hour)},
		{Provider: "p1", Model: "healthy", EffectiveFrom: adversarialAt.LastSeen.Add(-12 * time.Hour)}, // duplicate pair
	}}
	assets, skips := BuildModelAssets(adversarialAt, "org-adv", nil, cat, nil, nil)

	wantReasons := map[string]bool{
		"empty provider or model":                                   false,
		"model name fails key rules":                                false,
		"deprecation instant precedes the sell window opening":      false,
		"deprecation instant is not before the sell window closing": false,
		"duplicate entry for pair":                                  false,
	}
	emptyCount := 0
	for _, s := range skips {
		if s.Reason == "empty provider or model" {
			emptyCount++
			continue
		}
		if _, ok := wantReasons[s.Reason]; !ok {
			t.Fatalf("unexpected skip reason %q (ref %s)", s.Reason, s.Ref)
		}
		wantReasons[s.Reason] = true
	}
	if emptyCount != 2 { // empty provider + empty model
		t.Fatalf("empty-identity skips = %d, want 2", emptyCount)
	}
	for reason, seen := range wantReasons {
		if reason != "empty provider or model" && !seen {
			t.Fatalf("expected skip reason %q never fired; skips=%+v", reason, skips)
		}
	}

	// The healthy pair imported exactly once (first entry wins on duplicates).
	healthy, ok := findAsset(assets, ModelKey("p1", "healthy"))
	if !ok {
		t.Fatalf("healthy sibling must import: %v", assetKeys(assets))
	}
	hp := modelPayloadOf(t, healthy)
	if hp.Status != "active" || hp.Catalog == nil || !hp.Catalog.EffectiveFrom.Equal(adversarialAt.LastSeen.Add(-24*time.Hour)) {
		t.Fatalf("duplicate pair must keep the FIRST entry: %+v", hp.Catalog)
	}
	// No asset ever materializes for a defective entry name.
	for _, bad := range []string{"orphan", "bad name", "pre-window", "post-window", ""} {
		if bad == "" {
			continue
		}
		if _, ok := findAsset(assets, ModelKey("p1", bad)); ok {
			t.Fatalf("defective entry %q must not become an asset", bad)
		}
	}
	for _, a := range assets {
		if err := a.Validate(); err != nil {
			t.Fatalf("asset %s invalid: %v", a.AssetKey, err)
		}
	}
}

// TestModelImportAdversarialAliasShadow: an alias-named registry row
// attributes to its canonical target even when the alias string is ALSO a
// catalog entry of its own — the ResolveAlias contract wins, both pairs
// stay distinct identities, and the outcome is deterministic.
func TestModelImportAdversarialAliasShadow(t *testing.T) {
	cat := &adversarialCatalog{
		entries: []provider.ModelCatalogEntry{
			{Provider: "p1", Model: "alpha", EffectiveFrom: adversarialAt.LastSeen.Add(-24 * time.Hour)},
			{Provider: "p1", Model: "beta", EffectiveFrom: adversarialAt.LastSeen.Add(-24 * time.Hour)},
		},
		aliases: map[string]string{"p1:beta": "alpha"}, // beta is an alias of alpha…
	}
	reg := []RegistryModel{
		{ModelName: "beta", Provider: "p1", Enabled: true}, // …so this row belongs to alpha
		{ModelName: "gamma", Provider: "p1", Enabled: true},
	}
	assets, skips := BuildModelAssets(adversarialAt, "org-adv", reg, cat, nil, nil)
	if len(skips) != 0 {
		t.Fatalf("skips: %+v", skips)
	}
	alpha := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", "alpha")))
	if len(alpha.Registry) != 1 || alpha.Registry[0].ModelName != "beta" {
		t.Fatalf("alias-named row must land on the canonical pair: %+v", alpha.Registry)
	}
	beta := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", "beta")))
	if len(beta.Registry) != 0 {
		t.Fatalf("the beta ENTRY is its own identity but no registry row landed there: %+v", beta.Registry)
	}
	// Deterministic replay.
	again, _ := BuildModelAssets(adversarialAt, "org-adv", reg, cat, nil, nil)
	if len(again) != len(assets) {
		t.Fatalf("replay diverged: %d vs %d assets", len(again), len(assets))
	}
}

// TestModelImportAdversarialAliasCycle: a ResolveAlias cycle (a→b, b→a)
// cannot loop the builder — each registry row resolves exactly once and
// lands deterministically.
func TestModelImportAdversarialAliasCycle(t *testing.T) {
	cat := &adversarialCatalog{
		aliases: map[string]string{"p1:a": "b", "p1:b": "a"},
	}
	reg := []RegistryModel{
		{ModelName: "a", Provider: "p1", Enabled: true},
		{ModelName: "b", Provider: "p1", Enabled: true},
	}
	done := make(chan struct{})
	go func() {
		assets, skips := BuildModelAssets(adversarialAt, "org-adv", reg, cat, nil, nil)
		if len(skips) != 0 {
			t.Errorf("skips: %+v", skips)
		}
		// Row "a" → pair b; row "b" → pair a: two distinct pairs, one row each.
		pa := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", "a")))
		pb := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", "b")))
		if len(pa.Registry) != 1 || pa.Registry[0].ModelName != "b" {
			t.Errorf("pair a payload wrong: %+v", pa.Registry)
		}
		if len(pb.Registry) != 1 || pb.Registry[0].ModelName != "a" {
			t.Errorf("pair b payload wrong: %+v", pb.Registry)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("alias cycle looped the builder")
	}
}

// TestModelImportAdversarialMalformedWithdrawals: empty provider or zero
// instant are noise (no withdrawal signal, no asset spam); a healthy
// withdrawal still applies; duplicate withdrawals keep the earliest.
func TestModelImportAdversarialMalformedWithdrawals(t *testing.T) {
	wd := adversarialAt.LastSeen.Add(-1 * time.Hour)
	cat := &adversarialCatalog{
		entries: []provider.ModelCatalogEntry{
			{Provider: "p1", Model: "m", EffectiveFrom: adversarialAt.LastSeen.Add(-24 * time.Hour)},
		},
		withdrawal: []provider.Withdrawal{
			{Provider: "", WithdrawnAt: wd},                                              // no provider
			{Provider: "p2", WithdrawnAt: time.Time{}},                                   // no instant
			{Provider: "p1", WithdrawnAt: adversarialAt.LastSeen.Add(-30 * time.Minute)}, // later duplicate…
			{Provider: "p1", WithdrawnAt: wd},                                            // …earliest wins
		},
	}
	assets, skips := BuildModelAssets(adversarialAt, "org-adv", nil, cat, nil, nil)
	if len(skips) != 0 {
		t.Fatalf("malformed withdrawals are noise, not skips: %+v", skips)
	}
	m := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", "m")))
	if m.Status != "withdrawn" || m.WithdrawnAt == nil || !m.WithdrawnAt.Equal(wd) {
		t.Fatalf("earliest healthy withdrawal must apply: %+v", m)
	}
	// p2's zero-instant withdrawal must NOT produce a provider asset.
	if _, ok := findAsset(assets, ProviderKey("p2")); ok {
		t.Fatalf("zero-instant withdrawal must not materialize a provider")
	}
}

// TestModelImportAdversarialRetiredAliasTarget: an alias cannot resurrect a
// withdrawn target — the registry row still attributes to the canonical
// pair and the pair reports the target's closed window.
func TestModelImportAdversarialRetiredAliasTarget(t *testing.T) {
	cat := &adversarialCatalog{
		entries: []provider.ModelCatalogEntry{
			{Provider: "p1", Model: "dead", EffectiveFrom: adversarialAt.LastSeen.Add(-48 * time.Hour),
				EffectiveTo: adversarialAt.LastSeen.Add(-1 * time.Hour)},
		},
		aliases: map[string]string{"p1:legacy-name": "dead"},
		status:  map[string]provider.ModelStatus{"p1:dead": provider.StatusRetired},
	}
	reg := []RegistryModel{{ModelName: "legacy-name", Provider: "p1", Enabled: true}}
	assets, skips := BuildModelAssets(adversarialAt, "org-adv", reg, cat, nil, nil)
	if len(skips) != 0 {
		t.Fatalf("skips: %+v", skips)
	}
	p := modelPayloadOf(t, mustAsset(t, assets, ModelKey("p1", "dead")))
	if p.Status != "withdrawn" {
		t.Fatalf("alias must not resurrect: status = %q", p.Status)
	}
	if len(p.Registry) != 1 || p.Registry[0].ModelName != "legacy-name" {
		t.Fatalf("registry observation lost: %+v", p.Registry)
	}
	if p.Discrepancy != "" {
		t.Fatalf("both sides know the pair (through the alias): %+v", p)
	}
}

// TestModelImportAdversarialBrokenPricingRows: identity-defective pricing
// entries are skipped and counted; healthy siblings import.
func TestModelImportAdversarialBrokenPricingRows(t *testing.T) {
	pack := fakePricingPack{models: []pricing.RefModel{
		{Provider: "", Model: "orphan"},
		{Provider: "p1", Model: ""},
		{Provider: "p1", Model: "bad name"},
		{Provider: "p1", Model: "good"},
	}}
	assets, skips := BuildModelAssets(adversarialAt, "org-adv", nil, nil, pack, nil)
	if len(skips) != 3 {
		t.Fatalf("skips = %d, want 3: %+v", len(skips), skips)
	}
	if _, ok := findAsset(assets, ModelKey("p1", "good")); !ok {
		t.Fatalf("healthy pricing sibling must import: %v", assetKeys(assets))
	}
	for _, a := range assets {
		if err := a.Validate(); err != nil {
			t.Fatalf("asset %s invalid: %v", a.AssetKey, err)
		}
	}
}
