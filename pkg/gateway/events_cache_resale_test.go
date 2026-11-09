package cli

import (
	"context"
	"math"
	"testing"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// N03-P06-T03: the wallet/resale surface must follow the real provider usage
// — cache read/write subsets of the canonical PromptTokens bill at their own
// per-M prices exactly once, never also at the full input rate. The gateway
// forwards provider.Usage verbatim to the markup pricer (events.go
// resaleCostUSD), so the end-to-end wallet quote must carry the discount.
func TestResaleCostUSD_CacheSubsetsNotDoubleCounted(t *testing.T) {
	gw := &gateway{markupPricer: pricing.NewMarkupPricer(nil, pricing.StaticPricer(), nil)}

	p, ok := pricing.StaticPricer().Lookup("openai", "gpt-4o")
	if !ok {
		t.Fatal("bundled price missing for openai:gpt-4o")
	}
	if p.CacheReadPerM <= 0 || p.CacheReadPerM >= p.InputPerM {
		t.Fatalf("fixture expects a real cache-read discount: read %v vs input %v", p.CacheReadPerM, p.InputPerM)
	}

	// Canonical usage: PromptTokens includes the cache subsets (see
	// provider.Usage docs). Shape mirrors an OpenAI cached response.
	usage := provider.Usage{
		PromptTokens:        10_000,
		CompletionTokens:    1_000,
		CacheReadTokens:     4_000,
		CacheCreationTokens: 2_000,
		Source:              provider.UsageSourceProvider,
	}

	got := gw.resaleCostUSD(context.Background(), "org-1", "openai", "gpt-4o", usage)
	if got <= 0 {
		t.Fatalf("resale quote must be positive, got %v", got)
	}

	nonCache := usage.PromptTokens - usage.CacheReadTokens - usage.CacheCreationTokens
	want := 1.15 * (float64(nonCache)/1_000_000*p.InputPerM +
		float64(usage.CompletionTokens)/1_000_000*p.OutputPerM +
		float64(usage.CacheCreationTokens)/1_000_000*p.CacheWritePerM +
		float64(usage.CacheReadTokens)/1_000_000*p.CacheReadPerM)
	if math.Abs(got-want) > 1e-12 {
		t.Fatalf("resale %.12f, want %.12f (cache subsets billed once at their own rates)", got, want)
	}

	// The pre-fix quote billed the whole prompt at InputPerM in addition to
	// the cache rates; the discount must actually show up on the wallet bill.
	doubleCounted := 1.15 * (float64(usage.PromptTokens)/1_000_000*p.InputPerM +
		float64(usage.CompletionTokens)/1_000_000*p.OutputPerM +
		float64(usage.CacheCreationTokens)/1_000_000*p.CacheWritePerM +
		float64(usage.CacheReadTokens)/1_000_000*p.CacheReadPerM)
	if got >= doubleCounted {
		t.Fatalf("wallet bill still double-counts cache subsets: got %.12f, double-counted %.12f", got, doubleCounted)
	}
}

func TestResaleCostUSD_NoCacheUnchanged(t *testing.T) {
	gw := &gateway{markupPricer: pricing.NewMarkupPricer(nil, pricing.StaticPricer(), nil)}

	p, ok := pricing.StaticPricer().Lookup("openai", "gpt-4o-mini")
	if !ok {
		t.Fatal("bundled price missing")
	}

	usage := provider.Usage{PromptTokens: 5_000, CompletionTokens: 2_000, Source: provider.UsageSourceProvider}
	got := gw.resaleCostUSD(context.Background(), "org-1", "openai", "gpt-4o-mini", usage)
	want := 1.15 * (float64(usage.PromptTokens)/1_000_000*p.InputPerM +
		float64(usage.CompletionTokens)/1_000_000*p.OutputPerM)
	if math.Abs(got-want) > 1e-12 {
		t.Fatalf("resale %.12f, want %.12f (no cache subsets — full input at InputPerM)", got, want)
	}
}

func TestResaleCostUSD_UnknownModelStaysZero(t *testing.T) {
	// Fail-closed pricing surfaces an unpriced quote as zero resale (the
	// wallet then falls back to the base-cost quote per reservationActuals);
	// an unknown model must never invent a bill.
	gw := &gateway{markupPricer: pricing.NewMarkupPricer(nil, pricing.StaticPricer(), nil)}
	usage := provider.Usage{PromptTokens: 1_000, CompletionTokens: 1_000}
	if got := gw.resaleCostUSD(context.Background(), "org-1", "nosuchprovider", "nosuchmodel", usage); got != 0 {
		t.Fatalf("unknown model must quote zero resale, got %v", got)
	}
}
