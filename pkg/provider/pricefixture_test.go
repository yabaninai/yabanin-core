package provider

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// AUD-PRICE-01 (pkg/pricing audit): the reference catalog marks the classic
// openai names (gpt-4o family) draft, so the global-default legacy fallback
// no longer serves them. Spend-accuracy tests that pin the billing math on
// those exact rates install this explicit price-file fixture instead of
// leaning on the fallback — same numbers, declared source, restored
// afterwards so shuffle-order siblings stay green (same pattern as the
// azure fixture defaults).
func gpt4oPriceFixture(t *testing.T) {
	t.Helper()
	prevFile := pricing.DefaultFilePricer()
	pf := pricing.PriceFile{
		Source: "audit-price01-fixture", Date: "2026-11-02", Currency: "USD", Units: "per_1m_tokens",
		Models: []pricing.PriceFileModel{
			{Provider: "openai", Model: "gpt-4o", Input: 2.5, Output: 10.0, CacheW: 3.125, CacheR: 1.25},
			{Provider: "openai", Model: "gpt-4o-mini", Input: 0.15, Output: 0.6, CacheW: 0.1875, CacheR: 0.075},
		},
	}
	// The sha256: prefix keeps the provenance contract shape (reports cite
	// a fingerprint); the value is a fixture label, not a real digest.
	p, err := pricing.NewFilePricer(pf, "sha256:audit-price01-fixture")
	if err != nil {
		t.Fatalf("gpt-4o price fixture: %v", err)
	}
	pricing.SetDefaultPricer(pricing.StaticPricer())
	pricing.SetDefaultFilePricer(p)
	t.Cleanup(func() {
		pricing.SetDefaultFilePricer(prevFile)
		pricing.SetDefaultPricer(pricing.StaticPricer())
	})
}
