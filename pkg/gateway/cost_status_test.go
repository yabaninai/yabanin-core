package cli

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/provider"
)

func TestCostStatus_CacheHit(t *testing.T) {
	if got := costStatus(true, "provider", true); got != "cache_hit" {
		t.Fatalf("got %s", got)
	}
}

func TestCostStatus_NoUsage(t *testing.T) {
	if got := costStatus(false, "none", false); got != "no_usage" {
		t.Fatalf("got %s", got)
	}
	if got := costStatus(false, "", true); got != "no_usage" {
		t.Fatalf("empty source got %s", got)
	}
}

func TestCostStatus_UnknownPrice(t *testing.T) {
	if got := costStatus(false, "provider", false); got != "unknown_price" {
		t.Fatalf("got %s", got)
	}
	if got := costStatus(false, "estimated", false); got != "unknown_price" {
		t.Fatalf("estimated got %s", got)
	}
}

func TestCostStatus_Priced(t *testing.T) {
	if got := costStatus(false, "provider", true); got != "priced" {
		t.Fatalf("got %s", got)
	}
}

// N03-P06-T03: a provider prompt-cache hit still bills real money (the cache
// read at CacheReadPerM), so it must surface as "priced" with cost fields —
// "cache_hit" is reserved for gateway semantic-cache rows that carry no
// upstream usage. The hourly rollup sums cost_in_usd only from
// priced/cache_hit/legacy rows; collapsing provider cache reads into
// cache_hit would corrupt the dashboard cost rollups.
func TestCostStatus_ProviderCacheReadStaysPriced(t *testing.T) {
	if got := costStatus(false, provider.UsageSourceProvider, true); got != "priced" {
		t.Fatalf("provider cache read got %s, want priced", got)
	}
	// The semantic-cache hit classification is untouched.
	if got := costStatus(true, "none", false); got != "cache_hit" {
		t.Fatalf("semantic cache hit got %s, want cache_hit", got)
	}
}
