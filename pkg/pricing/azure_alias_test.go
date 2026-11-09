package pricing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// "azure-openai" resolves onto the litellm catalog namespace "azure"
// (ratified D5 2026-10-16 — prices come from the existing pricing
// mechanism; no new vendor sync).
func TestCanonicalProvider_AzureOpenAI(t *testing.T) {
	assert.Equal(t, "azure", CanonicalProvider("azure-openai"))
	// Unknown names pass through unchanged.
	assert.Equal(t, "openai", CanonicalProvider("openai"))
	assert.Equal(t, "bedrock", CanonicalProvider("bedrock"))
	assert.Empty(t, CanonicalProvider(""))
}

// aliasFixture installs a deterministic file pricer carrying an "azure"
// model as the process default and returns a restore func. Since CORE-REF-04
// the shipped default serves the reference catalog (no azure entries), so
// the alias mechanism is pinned against a fixture instead of snapshot
// content.
func aliasFixture(t *testing.T) func() {
	t.Helper()
	p, err := NewFilePricer(PriceFile{
		Source: "alias-fixture", Date: "2026-11-02", Currency: "USD", Units: "per_1m_tokens",
		Models: []PriceFileModel{{Provider: "azure", Model: "alias-probe", Input: 3.25, Output: 9.75}},
	}, "sha256:alias-fixture")
	if err != nil {
		t.Fatalf("alias fixture: %v", err)
	}
	defaultFilePricerMu.Lock()
	saved := defaultFilePricer
	defaultFilePricerMu.Unlock()
	SetDefaultFilePricer(p)
	return func() {
		if saved == nil {
			defaultFilePricerMu.Lock()
			defaultFilePricer = nil
			defaultFilePricerMu.Unlock()
			resetFilePricerOnce()
			return
		}
		SetDefaultFilePricer(saved)
	}
}

// TestDefaultLookup_AzureOpenAI_AliasFallsBackToCatalog: a catalog storing
// Azure models under provider "azure" is reachable under "azure-openai" via
// the alias (exact name wins first, alias is fallback only).
func TestDefaultLookup_AzureOpenAI_AliasFallsBackToCatalog(t *testing.T) {
	restore := aliasFixture(t)
	defer restore()

	p, known := DefaultLookup("azure-openai", "alias-probe")
	assert.True(t, known, "azure-openai:alias-probe must resolve via the azure catalog alias")
	assert.InDelta(t, 3.25, p.InputPerM, 0.0001)
	assert.InDelta(t, 9.75, p.OutputPerM, 0.0001)

	// The direct catalog name keeps working unchanged.
	p2, known2 := DefaultLookup("azure", "alias-probe")
	assert.True(t, known2)
	assert.Equal(t, p, p2)
}

// TestDefaultLookup_AzureOpenAI_UnknownDeployment_StaysUnknown: an unmapped
// deployment name must NOT resolve — unknown-price stays distinct from free
// (PriceKnown=false → gateway cost_status unknown_price, never a silent $0).
func TestDefaultLookup_AzureOpenAI_UnknownDeployment_StaysUnknown(t *testing.T) {
	_, known := DefaultLookup("azure-openai", "my-private-custom-deploy-42")
	assert.False(t, known, "unknown deployment must not resolve through the alias")
}

// TestStaticPricer_AzureOpenAI_Alias: the static/file pricer (the default
// pricer) applies the same alias fallback as DefaultLookup.
func TestStaticPricer_AzureOpenAI_Alias(t *testing.T) {
	restore := aliasFixture(t)
	defer restore()

	p, known := staticPricer{}.Lookup("azure-openai", "alias-probe")
	assert.True(t, known)
	assert.InDelta(t, 3.25, p.InputPerM, 0.0001)

	_, known = staticPricer{}.Lookup("azure-openai", "no-such-deployment")
	assert.False(t, known)
}

// TestCanonicalProvider_ExactNameWins: an operator-entered row under the
// registry name must beat the catalog alias (fallback ordering).
func TestCanonicalProvider_ExactNameWins(t *testing.T) {
	saved := loadDefaultPricer()
	t.Cleanup(func() { SetDefaultPricer(saved) })
	file, err := NewFilePricer(PriceFile{Source: "synthetic exact/alias test", Date: "2026-11-09", Currency: "USD", Units: "per_1m_tokens", Models: []PriceFileModel{
		{Provider: "azure-openai", Model: "custom-deploy", Input: 1, Output: 2},
		{Provider: "azure", Model: "custom-deploy", Input: 7, Output: 9},
	}}, "test")
	require.NoError(t, err)
	SetDefaultPricer(file)

	p, known := DefaultLookup("azure-openai", "custom-deploy")
	assert.True(t, known)
	assert.InDelta(t, 1.0, p.InputPerM, 0.0001)
}
