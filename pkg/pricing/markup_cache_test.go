package pricing

import (
	"context"
	"math"
	"testing"
	"time"
)

// N03-P06-T03: cache read/write tokens carry their own per-M prices on the
// resale/wallet surface, mirroring provider.ComputeCost on the base-cost
// side. Quote receives the CANONICAL input count (provider.Usage.PromptTokens,
// which includes the cache subsets) and must bill the cache portions exactly
// once — at CacheReadPerM / CacheWritePerM — never also at InputPerM.

// quoteExpectation computes the exact expected totals for canonical
// (inclusive) input semantics.
func quoteExpectation(p Price, nonCacheInput, output, cacheWrite, cacheRead int64) float64 {
	return float64(nonCacheInput)/1_000_000*p.InputPerM +
		float64(output)/1_000_000*p.OutputPerM +
		float64(cacheWrite)/1_000_000*p.CacheWritePerM +
		float64(cacheRead)/1_000_000*p.CacheReadPerM
}

func TestQuote_CacheSubsetsNotDoubleCounted(t *testing.T) {
	mp := NewMarkupPricer(nil, staticPricer{}, nil)

	// AUD-PRICE-01: catalog-draft openai names refuse through the fallback,
	// so the cache-rate fixture uses a catalog-UNKNOWN legacy-table row
	// (anthropic:claude-3-5-haiku-20241022, input 0.8 / write 1.0 / read 0.08).
	p, ok := staticPricer{}.Lookup("anthropic", "claude-3-5-haiku-20241022")
	if !ok {
		t.Fatal("bundled price missing for anthropic:claude-3-5-haiku-20241022")
	}
	if p.CacheReadPerM <= 0 || p.CacheReadPerM >= p.InputPerM {
		t.Fatalf("fixture expects a real cache-read discount: read %v vs input %v", p.CacheReadPerM, p.InputPerM)
	}

	// Canonical usage shape: prompt includes the cache subsets.
	const (
		prompt int64 = 10_000
		read   int64 = 4_000
		write  int64 = 2_000
		out    int64 = 1_000
	)
	q, err := mp.Quote(context.Background(), "org-1", "anthropic", "claude-3-5-haiku-20241022", prompt, out, write, read)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}

	wantCost := quoteExpectation(p, prompt-read-write, out, write, read)
	if math.Abs(q.TotalCostUSD-wantCost) > 1e-12 {
		t.Fatalf("total cost %.12f, want %.12f (cache subsets billed once)", q.TotalCostUSD, wantCost)
	}
	if math.Abs(q.TotalResaleUSD-wantCost*1.15) > 1e-12 {
		t.Fatalf("total resale %.12f, want %.12f (15%% default markup)", q.TotalResaleUSD, wantCost*1.15)
	}

	// The pre-fix behavior billed the full prompt at InputPerM on top of the
	// cache terms: pin that the total is strictly below it.
	doubleCounted := float64(prompt)/1_000_000*p.InputPerM +
		float64(out)/1_000_000*p.OutputPerM +
		float64(write)/1_000_000*p.CacheWritePerM +
		float64(read)/1_000_000*p.CacheReadPerM
	if q.TotalCostUSD >= doubleCounted {
		t.Fatalf("cache subsets double-counted: got %.12f, double-counted %.12f", q.TotalCostUSD, doubleCounted)
	}

	// Line items carry the cache split separately from the input term.
	if math.Abs(q.CacheReadCost-float64(read)/1_000_000*p.CacheReadPerM) > 1e-12 {
		t.Fatalf("cache read line %.12f, want %.12f", q.CacheReadCost, float64(read)/1_000_000*p.CacheReadPerM)
	}
	if math.Abs(q.CacheWriteCost-float64(write)/1_000_000*p.CacheWritePerM) > 1e-12 {
		t.Fatalf("cache write line %.12f, want %.12f", q.CacheWriteCost, float64(write)/1_000_000*p.CacheWritePerM)
	}
	if math.Abs(q.InputCostUSD-float64(prompt-read-write)/1_000_000*p.InputPerM) > 1e-12 {
		t.Fatalf("input line %.12f, want non-cache %.12f", q.InputCostUSD, float64(prompt-read-write)/1_000_000*p.InputPerM)
	}
}

func TestQuote_CacheReadAndWriteDistinctPrices(t *testing.T) {
	mp := NewMarkupPricer(nil, staticPricer{}, nil)

	// Anthropic rows carry three distinct per-M rates: input 3.0,
	// cache write 3.75 (1.25x input premium), cache read 0.3.
	p, ok := staticPricer{}.Lookup("anthropic", "claude-3-5-sonnet-20241022")
	if !ok {
		t.Fatal("bundled price missing for anthropic:claude-3-5-sonnet-20241022")
	}
	if !(p.CacheWritePerM > p.InputPerM && p.InputPerM > p.CacheReadPerM) {
		t.Fatalf("fixture expects distinct input/write/read rates, got %+v", p)
	}

	const (
		prompt int64 = 9_000 // 3_000 non-cache + 4_000 read + 2_000 write
		read   int64 = 4_000
		write  int64 = 2_000
		out    int64 = 0
	)
	q, err := mp.Quote(context.Background(), "org-1", "anthropic", "claude-3-5-sonnet-20241022", prompt, out, write, read)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}

	wantCost := quoteExpectation(p, prompt-read-write, out, write, read)
	if math.Abs(q.TotalCostUSD-wantCost) > 1e-12 {
		t.Fatalf("total cost %.12f, want %.12f with per-rate split (write premium, read discount)", q.TotalCostUSD, wantCost)
	}
	// The write premium and the read discount must not blur into one rate:
	// read-only vs write-only quotes differ exactly by the rate ratio.
	readOnly, err := mp.Quote(context.Background(), "org-1", "anthropic", "claude-3-5-sonnet-20241022", read, 0, 0, read)
	if err != nil {
		t.Fatalf("Quote read-only: %v", err)
	}
	writeOnly, err := mp.Quote(context.Background(), "org-1", "anthropic", "claude-3-5-sonnet-20241022", write, 0, write, 0)
	if err != nil {
		t.Fatalf("Quote write-only: %v", err)
	}
	if math.Abs(readOnly.TotalCostUSD-float64(read)/1_000_000*p.CacheReadPerM) > 1e-12 {
		t.Fatalf("read-only quote %.12f, want %.12f at CacheReadPerM", readOnly.TotalCostUSD, float64(read)/1_000_000*p.CacheReadPerM)
	}
	if math.Abs(writeOnly.TotalCostUSD-float64(write)/1_000_000*p.CacheWritePerM) > 1e-12 {
		t.Fatalf("write-only quote %.12f, want %.12f at CacheWritePerM", writeOnly.TotalCostUSD, float64(write)/1_000_000*p.CacheWritePerM)
	}
}

func TestQuote_CacheSubsetsExceedInputClampToZero(t *testing.T) {
	mp := NewMarkupPricer(nil, staticPricer{}, nil)

	p, ok := staticPricer{}.Lookup("anthropic", "claude-3-5-haiku-20241022")
	if !ok {
		t.Fatal("bundled price missing")
	}

	// Misreporting source: cache subsets exceed the prompt count. The input
	// term clamps to zero instead of going negative (mirrors ComputeCost);
	// the cache terms still bill at their own rates.
	q, err := mp.Quote(context.Background(), "org-1", "anthropic", "claude-3-5-haiku-20241022", 1_000, 500, 2_000, 4_000)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	want := quoteExpectation(p, 0, 500, 2_000, 4_000)
	if math.Abs(q.TotalCostUSD-want) > 1e-12 {
		t.Fatalf("total cost %.12f, want %.12f (clamped input, cache still billed)", q.TotalCostUSD, want)
	}
	if q.TotalCostUSD <= 0 {
		t.Fatalf("clamped input must not zero out the whole quote, got %.12f", q.TotalCostUSD)
	}
	if q.InputCostUSD != 0 {
		t.Fatalf("input line must clamp to 0, got %.12f", q.InputCostUSD)
	}
}

func TestQuote_ZeroCacheUnchanged(t *testing.T) {
	mp := NewMarkupPricer(nil, staticPricer{}, nil)

	p, ok := staticPricer{}.Lookup("anthropic", "claude-3-5-haiku-20241022")
	if !ok {
		t.Fatal("bundled price missing")
	}

	// Without cache subsets the whole prompt bills at InputPerM — the
	// long-standing behavior is untouched by the subset subtraction.
	q, err := mp.Quote(context.Background(), "org-1", "anthropic", "claude-3-5-haiku-20241022", 5_000, 2_000, 0, 0)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	want := quoteExpectation(p, 5_000, 2_000, 0, 0)
	if math.Abs(q.TotalCostUSD-want) > 1e-12 {
		t.Fatalf("total cost %.12f, want %.12f", q.TotalCostUSD, want)
	}
}

func TestQuote_FixedPriceOverride_CacheSubsetsNotDoubleCounted(t *testing.T) {
	mp := NewMarkupPricer(nil, staticPricer{}, nil)

	p, ok := staticPricer{}.Lookup("anthropic", "claude-3-5-haiku-20241022")
	if !ok {
		t.Fatal("bundled price missing")
	}

	// Fixed-price override (org+model): the input resale rate is the fixed
	// price; cache subsets still ride their own base rates and must be
	// excluded from the fixed-input term too.
	fixedIn := 4.0
	fixedOut := 20.0
	mp.cacheMu.Lock()
	mp.cache["org-fixed:claude-3-5-haiku-20241022"] = pricingOverride{
		fixedInputPerM:  &fixedIn,
		fixedOutputPerM: &fixedOut,
		loadedAt:        time.Now(),
	}
	mp.cacheMu.Unlock()

	const (
		prompt int64 = 10_000
		read   int64 = 4_000
		write  int64 = 2_000
		out    int64 = 1_000
	)
	q, err := mp.Quote(context.Background(), "org-fixed", "anthropic", "claude-3-5-haiku-20241022", prompt, out, write, read)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}

	want := float64(prompt-read-write)/1_000_000*fixedIn +
		float64(out)/1_000_000*fixedOut +
		float64(write)/1_000_000*p.CacheWritePerM +
		float64(read)/1_000_000*p.CacheReadPerM
	if math.Abs(q.TotalResaleUSD-want) > 1e-12 {
		t.Fatalf("fixed-price total %.12f, want %.12f (fixed input on non-cache only)", q.TotalResaleUSD, want)
	}
	if q.MarginPct != 0 {
		t.Fatalf("fixed-price quote must report zero margin, got %v", q.MarginPct)
	}
}

func TestComputeResaleAmount_InclusiveInputMatchesQuote(t *testing.T) {
	mp := NewMarkupPricer(nil, staticPricer{}, nil)

	p, ok := staticPricer{}.Lookup("anthropic", "claude-3-5-haiku-20241022")
	if !ok {
		t.Fatal("bundled price missing")
	}

	// The gateway passes provider.Usage verbatim; the concise helper must
	// agree with Quote on the inclusive-input contract.
	amount, err := mp.ComputeResaleAmount(context.Background(), "org-1", "anthropic", "claude-3-5-haiku-20241022",
		6_000, 700, 1_500, 2_500)
	if err != nil {
		t.Fatalf("ComputeResaleAmount: %v", err)
	}
	want := quoteExpectation(p, 6_000-1_500-2_500, 700, 1_500, 2_500) * 1.15
	if math.Abs(amount-want) > 1e-12 {
		t.Fatalf("resale amount %.12f, want %.12f", amount, want)
	}
}
