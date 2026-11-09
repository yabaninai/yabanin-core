package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/pricing"
)

func TestComputeCost_OpenAIGpt4o(t *testing.T) {
	gpt4oPriceFixture(t) // AUD-PRICE-01: classic rates as an explicit fixture
	// 10k prompt + 2k completion, no cache. Expected:
	//   input:  10000 / 1e6 * 2.50  = $0.025
	//   output: 2000  / 1e6 * 10.00 = $0.020
	//   total = $0.045
	u := Usage{PromptTokens: 10000, CompletionTokens: 2000, TotalTokens: 12000}
	ext := ComputeCost(u, "openai", "gpt-4o")

	assert.InDelta(t, 0.045, ext.EstimatedCostUSD, 0.0001)
	assert.Equal(t, "openai", ext.ProviderName)
	assert.Equal(t, "gpt-4o", ext.ModelName)
}

func TestComputeCost_AnthropicWithCache(t *testing.T) {
	body := []byte(`{"usage":{"input_tokens":100,"cache_read_input_tokens":50000,"cache_creation_input_tokens":2000,"output_tokens":500}}`)
	u := (Anthropic{}).ParseUsage(body)
	want := Usage{
		PromptTokens:        52100,
		CompletionTokens:    500,
		TotalTokens:         52600,
		CacheReadTokens:     50000,
		CacheCreationTokens: 2000,
		Source:              UsageSourceProvider,
	}
	assert.Equal(t, want, u)

	ext := ComputeCost(u, "anthropic", "claude-3-5-sonnet-20241022")
	assert.InDelta(t, canonicalTokenCost(t, u, "anthropic", "claude-3-5-sonnet-20241022"), ext.EstimatedCostUSD, 1e-9)

	zeroInput := u
	zeroInput.PromptTokens = u.CacheReadTokens + u.CacheCreationTokens
	zeroInput.TotalTokens = zeroInput.PromptTokens + zeroInput.CompletionTokens
	cheaper := ComputeCost(zeroInput, "anthropic", "claude-3-5-sonnet-20241022")
	assert.Greater(t, ext.EstimatedCostUSD, cheaper.EstimatedCostUSD,
		"the 100 uncached input tokens must be billed")
}

func TestComputeCost_OpenAICached(t *testing.T) {
	gpt4oPriceFixture(t) // AUD-PRICE-01: classic rates as an explicit fixture
	u := Usage{PromptTokens: 10000, CompletionTokens: 100, CacheReadTokens: 8000}
	ext := ComputeCost(u, "openai", "gpt-4o")
	assert.InDelta(t, canonicalTokenCost(t, u, "openai", "gpt-4o"), ext.EstimatedCostUSD, 1e-9)
}

func canonicalTokenCost(t *testing.T, u Usage, providerName, model string) float64 {
	t.Helper()
	p, ok := pricing.DefaultLookup(providerName, model)
	require.True(t, ok, "model %s/%s missing from bundled prices", providerName, model)
	nonCache := u.PromptTokens - u.CacheReadTokens - u.CacheCreationTokens
	if nonCache < 0 {
		nonCache = 0
	}
	return (float64(nonCache)*p.InputPerM +
		float64(u.CompletionTokens)*p.OutputPerM +
		float64(u.CacheReadTokens)*p.CacheReadPerM +
		float64(u.CacheCreationTokens)*p.CacheWritePerM) / 1_000_000
}

func TestComputeCost_UnknownModel_ZeroCost(t *testing.T) {
	u := Usage{PromptTokens: 1_000_000, CompletionTokens: 1_000_000}
	ext := ComputeCost(u, "grok", "grok-4")

	assert.InDelta(t, 0.0, ext.EstimatedCostUSD, 1e-9)
	// Token counts are preserved even when cost is unknown.
	assert.Equal(t, int64(1_000_000), ext.PromptTokens)
	assert.Equal(t, int64(1_000_000), ext.CompletionTokens)
}

func TestComputeCost_CacheCheaperThanInput(t *testing.T) {
	// Sanity check: a request that uses prompt caching should cost strictly
	// less than the same request without caching.
	withCache := Usage{
		PromptTokens:     5000,
		CacheReadTokens:  4000, // 80% cache hit
		CompletionTokens: 500,
	}
	withoutCache := Usage{
		PromptTokens:     5000,
		CompletionTokens: 500,
	}
	extWith := ComputeCost(withCache, "anthropic", "claude-3-5-haiku-20241022")
	extWithout := ComputeCost(withoutCache, "anthropic", "claude-3-5-haiku-20241022")

	assert.Less(t, extWith.EstimatedCostUSD, extWithout.EstimatedCostUSD,
		"cache-read should produce a cheaper cost than non-cached input")
}

func TestComputeCost_ClampsNegativeInput(t *testing.T) {
	// Defensive: a misreporting provider claims more cache-read tokens than
	// prompt tokens. Should not produce negative cost.
	u := Usage{
		PromptTokens:    100,
		CacheReadTokens: 500, // impossible but defensive
	}
	ext := ComputeCost(u, "openai", "gpt-4o")
	assert.GreaterOrEqual(t, ext.EstimatedCostUSD, 0.0)
}
