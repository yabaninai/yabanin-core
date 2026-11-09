package provider

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// TestSpendAccuracy_GPT4o verifies that ComputeCost produces exact expected values
// for a known model with specific token counts. This is the baseline for billing accuracy.
func TestSpendAccuracy_GPT4o(t *testing.T) {
	gpt4oPriceFixture(t) // AUD-PRICE-01: classic rates as an explicit fixture
	// gpt-4o: $2.50/1M input, $10/1M output
	u := Usage{
		PromptTokens:     1000,
		CompletionTokens: 500,
	}

	ext := ComputeCost(u, "openai", "gpt-4o")

	expectedInput := float64(1000) / 1_000_000 * 2.5
	expectedOutput := float64(500) / 1_000_000 * 10.0
	expectedTotal := expectedInput + expectedOutput

	if ext.EstimatedCostUSD < expectedTotal*0.999 || ext.EstimatedCostUSD > expectedTotal*1.001 {
		t.Errorf("expected cost ~%.8f, got %.8f (error: %.8f)", expectedTotal, ext.EstimatedCostUSD, ext.EstimatedCostUSD-expectedTotal)
	}

	if ext.ProviderName != "openai" {
		t.Errorf("expected provider=openai, got %s", ext.ProviderName)
	}
	if ext.ModelName != "gpt-4o" {
		t.Errorf("expected model=gpt-4o, got %s", ext.ModelName)
	}
}

// TestSpendAccuracy_CacheTokens verifies cache token accounting.
func TestSpendAccuracy_CacheTokens(t *testing.T) {
	gpt4oPriceFixture(t) // AUD-PRICE-01: classic rates as an explicit fixture
	// gpt-4o: input $2.50, cache-read $1.25 per 1M
	u := Usage{
		PromptTokens:    10000,
		CacheReadTokens: 5000, // half of prompt is cached
	}

	ext := ComputeCost(u, "openai", "gpt-4o")

	// Non-cache input: (10000 - 5000) * $2.50/1M = 5000 * 2.5 / 1M = $0.0125
	// Cache read: 5000 * $1.25/1M = 5000 * 1.25 / 1M = $0.00625
	expected := float64(5000)/1_000_000*2.5 + float64(5000)/1_000_000*1.25

	if ext.EstimatedCostUSD < expected*0.999 || ext.EstimatedCostUSD > expected*1.001 {
		t.Errorf("expected cost ~%.8f, got %.8f", expected, ext.EstimatedCostUSD)
	}
}

// TestSpendAccuracy_AnthropicClaude verifies Anthropic pricing with cache.
func TestSpendAccuracy_AnthropicClaude(t *testing.T) {
	// claude-3-5-sonnet: input $3.00, output $15.00, cache-write $3.75, cache-read $0.30
	u := Usage{
		PromptTokens:        2000,
		CompletionTokens:    1000,
		CacheCreationTokens: 1500, // new cache entries
	}

	ext := ComputeCost(u, "anthropic", "claude-3-5-sonnet-20241022")

	// PromptTokens includes cache creation; only the remainder is billed at input rate.
	expectedInput := float64(2000-1500) / 1_000_000 * 3.0
	expectedOutput := float64(1000) / 1_000_000 * 15.0
	expectedCacheWrite := float64(1500) / 1_000_000 * 3.75
	expectedTotal := expectedInput + expectedOutput + expectedCacheWrite

	if ext.EstimatedCostUSD < expectedTotal*0.999 || ext.EstimatedCostUSD > expectedTotal*1.001 {
		t.Errorf("expected cost ~%.8f, got %.8f", expectedTotal, ext.EstimatedCostUSD)
	}
}

// TestSpendAccuracy_ZeroForUnknownModel verifies unknown models produce zero cost.
func TestSpendAccuracy_ZeroForUnknownModel(t *testing.T) {
	u := Usage{
		PromptTokens:     100000,
		CompletionTokens: 50000,
	}

	ext := ComputeCost(u, "unknown-provider", "unknown-model")

	if ext.EstimatedCostUSD != 0 {
		t.Errorf("expected zero cost for unknown model, got %.8f", ext.EstimatedCostUSD)
	}
}

// TestSpendAccuracy_MarkupIntegration verifies that MarkupPricer applies markup correctly.
func TestSpendAccuracy_MarkupIntegration(t *testing.T) {
	gpt4oPriceFixture(t) // AUD-PRICE-01: classic rates as an explicit fixture
	mp := pricing.NewMarkupPricer(nil, pricing.StaticPricer(), nil)

	quote, err := mp.Quote(context.TODO(), "org-1", "openai", "gpt-4o",
		1000, 500, 0, 0,
	)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}

	// Total cost should match ComputeCost.
	cost := ComputeCost(Usage{PromptTokens: 1000, CompletionTokens: 500}, "openai", "gpt-4o")
	if quote.TotalCostUSD < cost.EstimatedCostUSD*0.999 || quote.TotalCostUSD > cost.EstimatedCostUSD*1.001 {
		t.Errorf("reseller total cost should match base cost: expected ~%.8f, got %.8f",
			cost.EstimatedCostUSD, quote.TotalCostUSD)
	}

	// Resale should be 15% higher than cost (default markup).
	expectedResale := cost.EstimatedCostUSD * 1.15
	if quote.TotalResaleUSD < expectedResale*0.99 || quote.TotalResaleUSD > expectedResale*1.01 {
		t.Errorf("expected resale ~%.8f, got %.8f", expectedResale, quote.TotalResaleUSD)
	}

	// Margin should be positive.
	if quote.MarginPct <= 0 {
		t.Errorf("expected positive margin, got %.2f%%", quote.MarginPct)
	}
}
