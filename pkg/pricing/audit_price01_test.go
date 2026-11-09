package pricing

// Pricing defaults must not resurrect removed draft rates through the legacy
// table. Explicit operator prices still win; only the independently maintained
// historical primary allowlist remains an automatic fallback.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// auditRetiredName mirrors the catalog's retired nebius-token-factory
	// entry (reference-pack-v1.json: status "retired"), so the retired
	// refusal is driven on a legacy-table row this test owns — the shipped
	// table has no retired names of its own yet.
	auditRetiredName = "deepseek-ai/DeepSeek-V4-Flash"
	// auditActiveName is its active sibling (-0731): same family, serveable,
	// proving the refusal is status-scoped and not family-scoped.
	auditActiveName = "deepseek-ai/DeepSeek-V4-Flash-0731"
)

// auditCatalog returns the embedded reference catalog for in-package tests.
func auditCatalog(t *testing.T) Catalog {
	t.Helper()
	_, cat, err := LoadRefPack(bundledRefPackBytes)
	require.NoError(t, err)
	return cat
}

// auditPristineDefaults pins BOTH process defaults to their shipped state —
// the Pricer default to the staticPricer{} baseline and the file-backed
// default to a pristine re-initialization — so the fallback assertions below
// are deterministic under `go test -shuffle`. Restores both on cleanup.
func auditPristineDefaults(t *testing.T) {
	t.Helper()
	defaultFilePricerMu.Lock()
	savedFile := defaultFilePricer
	defaultFilePricerMu.Unlock()
	var savedPricer Pricer
	if h, ok := defaultPricer.Load().(pricerHolder); ok {
		savedPricer = h.p
	}
	SetDefaultPricer(staticPricer{})
	SetDefaultFilePricer(nil)
	resetFilePricerOnce()
	t.Cleanup(func() {
		SetDefaultFilePricer(savedFile)
		if savedPricer != nil {
			SetDefaultPricer(savedPricer)
		} else {
			SetDefaultPricer(staticPricer{})
		}
	})
}

// TestAuditPRICE01_RefusalSet: the refusal set carries exactly the catalog's
// draft and retired identities — canonical names and their provider-alias
// variants — and nothing else.
func TestAuditPRICE01_RefusalSet(t *testing.T) {
	assert.True(t, catalogRefused("nebius-token-factory", auditRetiredName), "retired identity remains refused")
	assert.False(t, catalogRefused("nebius-token-factory", auditActiveName), "active identity is not refused")
	assert.False(t, catalogRefused("openai", "gpt-4o"), "removed data must not survive as a hidden refusal corpus")
}

// TestAuditPRICE01_StaticFallbackRefusesDraftRetired drives the refusal on
// the legacy-table rung of both global-default consumers. The draft rows are
// shipped table entries; the retired row and the canonical-provider row are
// injected so the exact rung this audit targets is exercised on table rows
// the test owns.
func TestAuditPRICE01_StaticFallbackRefusesDraftRetired(t *testing.T) {
	auditPristineDefaults(t)

	// Fixture sanity: the draft names really are legacy-table rows today —
	// without this guard the assertions below could pass vacuously after a
	// fixture cleanup.
	draftNames := []string{
		"openai:gpt-4o", "openai:gpt-4o-mini", "openai:gpt-4-turbo",
		"openai:gpt-4", "openai:gpt-3.5-turbo",
	}
	for _, key := range draftNames {
		require.Contains(t, table, key, "fixture drift: expected legacy-table row %s", key)
	}

	// Inject (a) the retired catalog name and (b) the canonical azure draft
	// name into the legacy table, restoring both afterwards.
	table["nebius-token-factory:"+auditRetiredName] = Price{InputPerM: 1, OutputPerM: 2}
	table["azure:gpt-4o"] = Price{InputPerM: 3, OutputPerM: 4}
	t.Cleanup(func() {
		delete(table, "nebius-token-factory:"+auditRetiredName)
		delete(table, "azure:gpt-4o")
	})

	rows := []struct {
		provider, model, why string
	}{
		{"openai", "gpt-4o", "catalog draft"},
		{"openai", "gpt-4o-mini", "catalog draft"},
		{"openai", "gpt-4-turbo", "catalog draft"},
		{"openai", "gpt-4", "catalog draft"},
		{"openai", "gpt-3.5-turbo", "catalog draft"},
		{"nebius-token-factory", auditRetiredName, "catalog retired"},
		{"azure-openai", "gpt-4o", "catalog draft under the canonical azure provider"},
	}
	for _, row := range rows {
		_, okStatic := staticPricer{}.Lookup(row.provider, row.model)
		assert.False(t, okStatic, "staticPricer served %s/%s (%s) through the legacy table fallback",
			row.provider, row.model, row.why)
		_, okDefault := DefaultLookup(row.provider, row.model)
		assert.False(t, okDefault, "DefaultLookup served %s/%s (%s) through the legacy table fallback",
			row.provider, row.model, row.why)
	}

	// An arbitrary historical-table entry must not expand the fallback policy.
	table["fixture:catalog-unknown-model"] = Price{InputPerM: 7, OutputPerM: 9}
	t.Cleanup(func() { delete(table, "fixture:catalog-unknown-model") })
	p, ok := staticPricer{}.Lookup("fixture", "catalog-unknown-model")
	assert.False(t, ok, "unknown names must never reactivate the historical table")
	assert.Equal(t, Price{}, p, "an unknown rate is not a priced zero")
	_, okDefault := DefaultLookup("fixture", "catalog-unknown-model")
	assert.False(t, okDefault, "DefaultLookup must keep unknown prices unknown")
}

// TestAuditPRICE01_ConstructorPathsEnforceCatalog: table over every
// construction path of the serving chain, including the compatibility loader.
func TestAuditPRICE01_ConstructorPathsEnforceCatalog(t *testing.T) {
	cat := auditCatalog(t)

	t.Run("LoadBundledRefServe_projection", func(t *testing.T) {
		// Same fixed now as refserve_test.go, via the production seam: this
		// subtest pins the shipped catalog's projection membership and
		// provenance citation, which must not depend on the machine clock.
		p, err := loadBundledRefServeAt(audit02Time)
		require.NoError(t, err)
		_, ok := p.Lookup("openai", "gpt-4o")
		assert.False(t, ok, "draft openai/gpt-4o must not serve from the catalog projection")
		_, ok = p.Lookup("nebius-token-factory", auditRetiredName)
		assert.False(t, ok, "retired entry must not serve from the catalog projection")
		info, okProv := p.CatalogProvenance()
		require.True(t, okProv, "the catalog-backed pricer must cite its catalog")
		assert.Equal(t, refGenesisDigest, info.Digest)
		assert.Equal(t, "0.1.0", info.Version)
	})

	t.Run("DefaultFilePricer_pristine", func(t *testing.T) {
		defaultFilePricerMu.Lock()
		saved := defaultFilePricer
		defaultFilePricerMu.Unlock()
		SetDefaultFilePricer(nil)
		resetFilePricerOnce()
		t.Cleanup(func() {
			if saved == nil {
				defaultFilePricerMu.Lock()
				defaultFilePricer = nil
				defaultFilePricerMu.Unlock()
				resetFilePricerOnce()
				return
			}
			SetDefaultFilePricer(saved)
		})
		p := DefaultFilePricer()
		require.NotNil(t, p)
		_, ok := p.Lookup("openai", "gpt-4o")
		assert.False(t, ok, "the default file pricer must not serve catalog-draft names")
		_, ok = p.Lookup("nebius-token-factory", auditRetiredName)
		assert.False(t, ok, "the default file pricer must not serve catalog-retired names")
	})

	t.Run("projectServeable_NewFilePricer", func(t *testing.T) {
		// Same fixed now as refserve_test.go: keeps the projection
		// membership stable regardless of the test machine's clock.
		now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
		pf, err := projectServeable(cat, now)
		require.NoError(t, err)
		names := map[string]bool{}
		for _, m := range pf.Models {
			names[m.Provider+":"+m.Model] = true
		}
		assert.NotContains(t, names, "openai:gpt-4o", "draft entries never project")
		assert.NotContains(t, names, "nebius-token-factory:"+auditRetiredName,
			"retired entries never project")
		assert.Contains(t, names, "nebius-token-factory:"+auditActiveName,
			"the active sibling of the retired entry stays serveable")
		// projectServeable is label-free by design (refserve.go); the caller
		// fills Source/Date, exactly as LoadBundledRefServe does.
		pf.Source = "audit-fixture"
		pf.Date = "2026-11-02"
		p, err := NewFilePricer(pf, "test")
		require.NoError(t, err)
		pr, ok := p.Lookup("nebius-token-factory", auditActiveName)
		require.True(t, ok)
		assert.InDelta(t, 0.14, pr.InputPerM, 1e-9)
		assert.InDelta(t, 0.28, pr.OutputPerM, 1e-9)
	})

	t.Run("ExternalLoader_offline_delegation", func(t *testing.T) {
		// ExternalSource.Offline must route through LoadBundledRefServe —
		// pinned by behavioral equivalence so the leg stays green across
		// the shipped catalog's real 2026-12-07 expiry: pre-expiry both
		// calls serve the same projection, post-expiry both fail closed
		// identically (filepricer.go delegates offline 1:1). The
		// fixed-instant projection membership is pinned by the
		// seam-routed LoadBundledRefServe_projection subtest above.
		p, errLoad := (&ExternalLoader{}).Load(ExternalSource{Offline: true})
		pRef, errRef := LoadBundledRefServe()
		if (errLoad == nil) != (errRef == nil) {
			t.Fatalf("offline external load must track LoadBundledRefServe: err=%v, ref err=%v", errLoad, errRef)
		}
		if errRef != nil {
			return
		}
		require.NotNil(t, p)
		_, ok := p.Lookup("openai", "gpt-4o")
		assert.False(t, ok, "offline external mode routes through the catalog projection")
		assert.Equal(t, pRef.Provenance(), p.Provenance(),
			"offline external load must cite the same catalog provenance as LoadBundledRefServe")
	})

	t.Run("LoadBundled_cannot_resurrect_corpus", func(t *testing.T) {
		// The compatibility loader follows the primary-only catalog.
		p, err := LoadBundled()
		_, refErr := LoadBundledRefServe()
		require.Equal(t, err == nil, refErr == nil, "compatibility loader must preserve freshness refusal")
		if err != nil {
			return
		}
		_, ok := p.Lookup("openai", "gpt-4o")
		assert.False(t, ok, "compatibility loader must not resurrect excluded rates")
	})
}
