package pricing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookup_KnownModel_ReturnsPrice(t *testing.T) {
	p := Lookup("openai", "gpt-4o")
	assert.InDelta(t, 2.5, p.InputPerM, 0.0001)
	assert.InDelta(t, 10.0, p.OutputPerM, 0.0001)
	// Cache rates populated.
	assert.Greater(t, p.CacheWritePerM, 0.0)
	assert.Greater(t, p.CacheReadPerM, 0.0)
}

func TestLookup_AnthropicModel_HasCachePricing(t *testing.T) {
	p := Lookup("anthropic", "claude-3-5-sonnet-20241022")
	assert.InDelta(t, 3.0, p.InputPerM, 0.0001)
	assert.InDelta(t, 15.0, p.OutputPerM, 0.0001)
	// Cache read is the prompt-caching discount — should be cheaper than input.
	assert.Less(t, p.CacheReadPerM, p.InputPerM)
	// Cache write is the upfront cost — Anthropic charges 1.25x input.
	assert.InDelta(t, 3.75, p.CacheWritePerM, 0.0001)
}

func TestLookup_UnknownModel_ReturnsZero(t *testing.T) {
	p := Lookup("grok", "grok-4")
	assert.Equal(t, Price{}, p)
}

func TestIsKnown(t *testing.T) {
	// AUD-PRICE-01: the catalog marks openai/gpt-4o draft, so the
	// default-chain fallback (IsKnown → DefaultLookup) reports it unknown.
	assert.False(t, IsKnown("openai", "gpt-4o"))
	assert.True(t, IsKnown("anthropic", "claude-3-5-sonnet-20241022"))
	assert.False(t, IsKnown("", ""))
	assert.False(t, IsKnown("openai", "gpt-99"))
}

// TestTable_AllRatesPositive ensures we didn't accidentally leave a zero or
// negative rate in the seed table (a $0 input rate would make every cost
// computation look "free" and hide billing bugs). Cache rates may be zero
// for providers that don't support caching (e.g. gpt-4 base).
func TestTable_AllRatesPositive(t *testing.T) {
	for key, p := range table {
		assert.Greater(t, p.InputPerM, 0.0, "input rate for %s must be positive", key)
		assert.Greater(t, p.OutputPerM, 0.0, "output rate for %s must be positive", key)
		// CacheRead < Input is the caching value proposition; if a provider
		// supports caching the discount must be real.
		if p.CacheReadPerM > 0 {
			assert.Less(t, p.CacheReadPerM, p.InputPerM,
				"cache-read for %s must be cheaper than input", key)
		}
	}
}
