package pricing

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImportLiteLLM_Sample(t *testing.T) {
	pf, stats := importSample(t)

	assert.Equal(t, 16, stats.Total)
	assert.Equal(t, 8, stats.Imported)
	assert.Equal(t, 4, stats.SkippedMode)
	assert.Equal(t, 1, stats.SkippedNoPrice)
	assert.Equal(t, 2, stats.SkippedInvalid)
	assert.Equal(t, 1, stats.Duplicates)
	assert.Equal(t, 1, stats.TieredIgnored)

	priced := findModel(t, pf, "openai", "priced")
	assert.InDelta(t, 3.0, priced.Input, 1e-9)
	assert.InDelta(t, 15.0, priced.Output, 1e-9)
	assert.InDelta(t, 3.75, priced.CacheW, 1e-9)
	assert.InDelta(t, 0.3, priced.CacheR, 1e-9)

	embed := findModel(t, pf, "openai", "embed-small")
	assert.InDelta(t, 0.1, embed.Input, 1e-9)
	assert.InDelta(t, 0.0, embed.Output, 1e-9)

	claude := findModel(t, pf, "anthropic", "claude-x")
	assert.Equal(t, "claude-x", claude.Model)

	dup := findModel(t, pf, "openai", "gpt-dup")
	assert.InDelta(t, 1.0, dup.Input, 1e-9, "the first sorted key wins")

	assert.Equal(t, "openai", findModel(t, pf, "openai", "legacy").Provider)
	assert.Equal(t, "together", findModel(t, pf, "together", "llama").Provider)
	assert.Equal(t, "fireworks", findModel(t, pf, "fireworks", "mixtral").Provider)
	assert.Equal(t, "vertex", findModel(t, pf, "vertex", "gemini").Provider)
}

func TestImportLiteLLM_ValidatesOutput(t *testing.T) {
	pf, _ := importSample(t)
	require.NoError(t, ValidatePriceFile(pf))

	again, _ := importSample(t)
	first, err := json.Marshal(pf)
	require.NoError(t, err)
	second, err := json.Marshal(again)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(first, second))
}

func TestStaticPricer_UsesBundledFile(t *testing.T) {
	prev := DefaultFilePricer()
	pf := PriceFile{
		Source:   "test",
		Date:     "2026-09-30",
		Currency: "USD",
		Units:    "per_1m_tokens",
		Models: []PriceFileModel{
			{Provider: "openai", Model: "gpt-4o", Input: 9, Output: 9},
			{Provider: "fixture", Model: "only-file", Input: 4.2, Output: 1},
		},
	}
	file, err := NewFilePricer(pf, "test")
	require.NoError(t, err)
	SetDefaultFilePricer(file)
	t.Cleanup(func() { SetDefaultFilePricer(prev) })

	fromFile, ok := StaticPricer().Lookup("openai", "gpt-4o")
	require.True(t, ok)
	assert.InDelta(t, 9.0, fromFile.InputPerM, 1e-9, "the price file wins over the legacy table")

	onlyFile, ok := StaticPricer().Lookup("fixture", "only-file")
	require.True(t, ok)
	assert.InDelta(t, 4.2, onlyFile.InputPerM, 1e-9)

	// The fallback keeps serving catalog-UNKNOWN legacy-table rows
	// (AUD-PRICE-01); catalog-draft openai names refuse instead.
	fromTable, ok := StaticPricer().Lookup("anthropic", "claude-3-opus-20240229")
	require.True(t, ok)
	assert.InDelta(t, 15.0, fromTable.InputPerM, 1e-9)
}

func importSample(t *testing.T) (PriceFile, LiteLLMImportStats) {
	t.Helper()
	raw, err := os.ReadFile("testdata/litellm_sample.json")
	require.NoError(t, err)
	pf, stats, err := ImportLiteLLM(bytes.NewReader(raw), "fixture", "2026-09-30")
	require.NoError(t, err)
	return pf, stats
}

func findModel(t *testing.T, pf PriceFile, provider, model string) PriceFileModel {
	t.Helper()
	for _, m := range pf.Models {
		if m.Provider == provider && m.Model == model {
			return m
		}
	}
	t.Fatalf("missing %s/%s", provider, model)
	return PriceFileModel{}
}
