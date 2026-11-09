package cli

// Regression pin for the w21-06 remediation (FIX-setdefaultpricer-leak,
// wave-20 record artifacts/internal-delivery-program/N03-P06/T06-record-20261026.md §2):
// the buildGateway composition root used to install its pooled DBPricer as
// the process-global default (pricing.SetDefaultPricer) and never restored
// it. Any test booting a gateway over wireTestDeps' dead-pool pgxpool
// therefore poisoned the global for every later test in the binary:
// DefaultLookup degraded to the hardcoded fallback table, where
// bundled.json-only models (anthropic:claude-sonnet-4-5) do not exist —
// they priced as unknown_price with zero cost, order-dependent under
// -shuffle (reproduced on seed 1792997880083202000).
//
// The composition root must not mutate process state: only the server boot
// path (RunGatewayServerWithJWT) installs the DBPricer as the global
// default. This test pins that constructing a pooled gateway leaves the
// global pricer — and bundled pricing through provider.ComputeCost —
// bit-for-bit unaffected.

import (
	"context"
	"log/slog"
	"math"
	"testing"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// defaultPricerWiringCanary is a fixture-only model (see
// n03p6t06PricedDefault): carried by the deterministic fixture snapshot the
// pristine baseline installs, but absent from the hardcoded fallback table
// in pkg/pricing. It is the canary that detects a dead-pool DBPricer
// installed as the global default — a dead pool misses every lookup, and
// DefaultLookup's fallback table does not know this model.
const defaultPricerWiringCanaryProvider = "anthropic"
const defaultPricerWiringCanaryModel = "claude-sonnet-4-5"

// assertBundledCanaryPriced pins the pristine-default behavior for the
// canary model: DefaultLookup resolves it from the installed fixture
// snapshot and provider.ComputeCost prices 1000 input / 200 output tokens at
// exactly the pinned rates (known=true, non-zero cost).
func assertBundledCanaryPriced(t *testing.T) {
	t.Helper()

	p, known := pricing.DefaultLookup(defaultPricerWiringCanaryProvider, defaultPricerWiringCanaryModel)
	if !known {
		t.Fatalf("DefaultLookup(%s, %s) = unknown: fixture-only model must price from the pristine default (input 3, output 15, cache_w 3.75, cache_r 0.3 $/M)",
			defaultPricerWiringCanaryProvider, defaultPricerWiringCanaryModel)
	}
	// Literal fixture rates: exact float64 round-trip for 3, 15, 3.75;
	// 0.3 compares equal to the Go literal because both are the nearest
	// float64 to 0.3 (JSON parse uses the same strconv conversion).
	if p.InputPerM != 3 || p.OutputPerM != 15 || p.CacheWritePerM != 3.75 || p.CacheReadPerM != 0.3 {
		t.Fatalf("DefaultLookup(%s, %s) = %+v, want the pinned fixture rates 3/15/3.75/0.3",
			defaultPricerWiringCanaryProvider, defaultPricerWiringCanaryModel, p)
	}

	u := provider.ComputeCost(provider.Usage{PromptTokens: 1000, CompletionTokens: 200},
		defaultPricerWiringCanaryProvider, defaultPricerWiringCanaryModel)
	if !u.PriceKnown {
		t.Fatal("ComputeCost reports unknown_price for the fixture-only canary — the global default pricer is not the pinned static snapshot")
	}
	// (3*1000 + 15*200) / 1e6 = 0.006; epsilon compares the rate-formula
	// float64 against the decimal oracle without copying its arithmetic.
	if want := 0.006; math.Abs(u.EstimatedCostUSD-want) > 1e-9 {
		t.Fatalf("ComputeCost = %v, want %v (1000 in + 200 out at pinned rates)", u.EstimatedCostUSD, want)
	}
}

// TestDefaultPricerWiring_PooledGatewayLeavesGlobalPristine is the
// deterministic reproduction of the w21-06 defect: boot a real gateway
// through the composition root over wireTestDeps' pooled (dead) wiring,
// then assert the process-global default pricer still resolves bundled-only
// pricing. Before the fix the DBPricer install leaked out of buildGateway
// and this exact sequence turned the canary into unknown_price.
func TestDefaultPricerWiring_PooledGatewayLeavesGlobalPristine(t *testing.T) {
	// Establish the pristine init() baseline regardless of shuffled neighbors
	// (pre-fix binaries may run a leaky buildGateway test first), and restore
	// Establish the pristine fixture baseline regardless of shuffled neighbors
	// (pre-fix binaries may run a leaky buildGateway test first), and restore
	// it on cleanup so this test leaves no residue of its own.
	pricing.SetDefaultPricer(n03p6t06PricedDefault(t))
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })

	assertBundledCanaryPriced(t)

	// The leak scenario: the real composition root over a pooled wiring whose
	// pool points at a dead address — the wireTestDeps setup from the wave-20
	// record (model_pack_wire_test.go, pgxpool on 127.0.0.1:1).
	t.Setenv("YABANIN_ML_PACK_DIR", "")
	t.Setenv("YABANIN_EMBEDDER_ENABLED", "")
	t.Setenv("YABANIN_EMBEDDER_MODEL", "")
	t.Setenv("YABANIN_CLASSIFIER_SERVICE_URL", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := packCompositionConfig(false)
	w, _, _ := wireTestDeps(t, ctx, cfg)
	gw, err := buildGateway(cfg, w.rdb, w.pool, slog.New(slog.DiscardHandler), ctx, JWTWiring{}, CircuitScopeWiring{})
	if err != nil {
		t.Fatalf("buildGateway over the pooled wiring must boot: %v", err)
	}
	if gw == nil {
		t.Fatal("buildGateway returned a nil gateway without an error")
	}

	// The pin: constructing the gateway did not touch the global default.
	// No reset in between — a leaked DBPricer would surface right here.
	assertBundledCanaryPriced(t)
}
