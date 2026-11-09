package pricing

import (
	"context"
	"errors"
	"testing"
)

func TestMarkupPricer_Quote_KnownModel(t *testing.T) {
	mp := NewMarkupPricer(nil, staticPricer{}, nil)

	// AUD-PRICE-01: catalog-draft openai names refuse through the fallback;
	// the fixture uses a catalog-UNKNOWN legacy-table row instead
	// (anthropic:claude-3-5-sonnet-20241022, input 3.0 / output 15.0).
	quote, err := mp.Quote(context.Background(), "org-1", "anthropic", "claude-3-5-sonnet-20241022",
		1000, 500, 0, 0, // 1K input, 500 output tokens
	)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}

	// Base price for claude-3-5-sonnet-20241022: $3/1M input, $15/1M output.
	// 1K input = 0.001 * 3.0 = $0.003
	// 500 output = 0.0005 * 15 = $0.0075
	// With 15% default markup:
	// Input resale = 0.003 * 1.15 = $0.00345
	// Output resale = 0.0075 * 1.15 = $0.008625
	expectedInput := float64(1000) / 1_000_000 * 3.0
	expectedOutput := float64(500) / 1_000_000 * 15.0

	if quote.InputCostUSD != expectedInput {
		t.Errorf("input cost: expected %.8f, got %.8f", expectedInput, quote.InputCostUSD)
	}
	if quote.OutputCostUSD != expectedOutput {
		t.Errorf("output cost: expected %.8f, got %.8f", expectedOutput, quote.OutputCostUSD)
	}

	// Check markup applied.
	expectedResaleInput := expectedInput * 1.15
	if quote.InputResaleUSD < expectedResaleInput*0.99 || quote.InputResaleUSD > expectedResaleInput*1.01 {
		t.Errorf("input resale: expected ~%.8f, got %.8f", expectedResaleInput, quote.InputResaleUSD)
	}

	if quote.TotalCostUSD < 0 {
		t.Errorf("total cost should be non-negative, got %f", quote.TotalCostUSD)
	}
}

func TestMarkupPricer_Quote_UnknownModel(t *testing.T) {
	mp := NewMarkupPricer(nil, staticPricer{}, nil)

	quote, err := mp.Quote(context.Background(), "org-1", "unknown", "some-model",
		1000, 500, 0, 0,
	)
	if !errors.Is(err, ErrUnknownModel) {
		t.Fatalf("expected ErrUnknownModel, got: %v", err)
	}
	if quote != nil {
		t.Errorf("expected nil quote for unknown model, got %+v", quote)
	}
}

func TestMarkupPricer_ComputeResaleAmount(t *testing.T) {
	mp := NewMarkupPricer(nil, staticPricer{}, nil)

	// Catalog-UNKNOWN row (AUD-PRICE-01): anthropic:claude-3-5-haiku-20241022,
	// input 0.8 / output 4.0 per 1M.
	amount, err := mp.ComputeResaleAmount(context.Background(), "org-1", "anthropic", "claude-3-5-haiku-20241022",
		5000, 2000, 0, 0, // 5K input, 2K output
	)
	if err != nil {
		t.Fatalf("ComputeResaleAmount: %v", err)
	}

	// Base: 5K * $0.80/1M = $0.004; 2K * $4/1M = $0.008 → $0.012
	// Markup 15%: $0.012 * 1.15 = $0.0138
	expected := float64(5000)/1_000_000*0.8 + float64(2000)/1_000_000*4.0
	expectedResale := expected * 1.15

	if amount < expectedResale*0.99 || amount > expectedResale*1.01 {
		t.Errorf("expected resale ~%.8f, got %.8f", expectedResale, amount)
	}
}

func TestComputeResaleAmount_CacheArgsOrder(t *testing.T) {
	mp := NewMarkupPricer(nil, staticPricer{}, nil)
	p, ok := DefaultLookup("anthropic", "claude-3-5-sonnet-20241022")
	if !ok {
		t.Fatal("bundled price missing")
	}
	const cacheRead int64 = 50000
	// Gateway call order after the fix: input, output, cache write, cache read.
	// A usage that is only a cache read must be billed at CacheReadPerM, not CacheWritePerM.
	amount, err := mp.ComputeResaleAmount(context.Background(), "org-1", "anthropic", "claude-3-5-sonnet-20241022",
		0, 0, 0, cacheRead,
	)
	if err != nil {
		t.Fatalf("ComputeResaleAmount: %v", err)
	}
	want := float64(cacheRead) / 1_000_000 * p.CacheReadPerM * 1.15
	writePrice := float64(cacheRead) / 1_000_000 * p.CacheWritePerM * 1.15
	if amount < want*0.999 || amount > want*1.001 {
		t.Fatalf("cache read billed at wrong rate: got %.8f, want read %.8f (write would be %.8f)", amount, want, writePrice)
	}
	if amount > writePrice*0.5 {
		t.Fatalf("cache read was billed near the write price: got %.8f, write %.8f", amount, writePrice)
	}
}

func TestMarkupPricer_CacheWithNilPool(t *testing.T) {
	// When pool is nil, should fall back to default 15% markup.
	mp := NewMarkupPricer(nil, staticPricer{}, nil)

	quote1, _ := mp.Quote(context.Background(), "org-a", "anthropic", "claude-3-5-sonnet-20241022", 1000, 0, 0, 0)
	quote2, _ := mp.Quote(context.Background(), "org-b", "anthropic", "claude-3-5-sonnet-20241022", 1000, 0, 0, 0)

	// Both should have same margin (default 15%).
	if quote1.MarginPct != quote2.MarginPct {
		t.Errorf("expected same default margin for nil pool, got %f vs %f", quote1.MarginPct, quote2.MarginPct)
	}
}
