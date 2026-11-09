package cli

import (
	"fmt"
	"os"
	"testing"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// TestMain installs the classic openai rates as an explicit price-file
// fixture for this test binary. AUD-PRICE-01 (pkg/pricing audit): the
// reference catalog marks the gpt-4o family draft, so the global-default
// legacy fallback no longer serves those names. Gateway tests pin billing
// math on those exact rates — golden event costs, resale quotes, budget
// judge settlements, counterfactual pricing — so the package declares the
// pricing explicitly instead of leaning on the fallback. This is
// shuffle-safe here: no gateway test uninstalls the file-backed default,
// and the SetDefaultPricer dances restore to the staticPricer{} baseline,
// whose chain re-reads this fixture. No gateway test asserts catalog
// provenance on the default pricer, so the fixture's provenance breaks no
// pin. Golden files stay byte-identical because the rates are unchanged.
func TestMain(m *testing.M) {
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
		fmt.Fprintf(os.Stderr, "gateway price fixture: %v\n", err)
		os.Exit(1)
	}
	pricing.SetDefaultPricer(pricing.StaticPricer())
	pricing.SetDefaultFilePricer(p)
	os.Exit(m.Run())
}
