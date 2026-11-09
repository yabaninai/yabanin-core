package adminstore

// The GET /api/units/spend rollup
// builder under the mockDB. These tests pin the design contract at the
// store boundary:
//
//	unknown ≠ 0        — unmeasurable windows/units serialize null, never 0;
//	estimate ≠ exact   — coverage metadata, legacy rows and usage_source mix
//	                     degrade the fidelity marks;
//	never sum across   — each line is one measured quantity in one unit;
//	fixed line order   — [usd actual, usd counterfactual, credits, tokens,
//	                     gCO2e] so the UI can render a stable grid.
//
// Query routing keys on stable SQL markers (the same seams the analytics
// mocks use), not call order.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spendFixtures carries the raw aggregates each routed query returns.
type spendFixtures struct {
	totalUSD   float64 // cost analytics total
	totalCF    float64 // cost analytics counterfactual
	requests   int64   // window request count
	unpriced   int64   // coverage: unpriced requests (routed via models_pricing)
	exactTok   int64
	estTok     int64
	unknownTok int64 // rows with usage_source none
	legacy     int64 // rows with cost_status legacy
	grams      float64
	gramsUnv   float64
	unmodeled  int64 // usage rows without carbon factor
	unverified int64 // usage rows with unverified factor
	usageRows  int64 // usage-bearing rows seen by the carbon query
	spentCents int64
	usageCount int64
	hasWallet  bool
	balance    int64
}

// newSpendStore builds a mock-backed store whose QueryRow hook routes by
// stable SQL markers.
func newSpendStore(t *testing.T, fx spendFixtures) *Store {
	t.Helper()
	rowFor := func(sql string) pgx.Row {
		switch {
		case strings.Contains(sql, "credit_transactions"):
			return &mockPGXRow{data: [][]interface{}{{fx.spentCents, fx.usageCount}}}
		case strings.Contains(sql, "org_credits"):
			if !fx.hasWallet {
				return &mockPGXRow{err: pgx.ErrNoRows}
			}
			return &mockPGXRow{data: [][]interface{}{{fx.balance, time.Now().UTC()}}}
		case strings.Contains(sql, "carbon_factors"):
			return &mockPGXRow{data: [][]interface{}{{fx.grams, fx.gramsUnv, fx.unmodeled, fx.unverified, fx.usageRows}}}
		case strings.Contains(sql, "usage_source"):
			return &mockPGXRow{data: [][]interface{}{{fx.exactTok, fx.estTok, fx.unknownTok, fx.legacy, fx.requests}}}
		case strings.Contains(sql, "counterfactual_cost_usd"):
			return &mockPGXRow{data: [][]interface{}{{fx.totalUSD, fx.totalCF, fx.requests}}}
		case strings.Contains(sql, "models_pricing"):
			return &mockPGXRow{data: [][]interface{}{{fx.unpriced}}}
		default:
			return &mockPGXRow{err: errors.New("spend test: unexpected QueryRow: " + sql)}
		}
	}
	return newForTest(&mockDB{
		queryRowFn: func(_ context.Context, sql string, _ ...interface{}) pgx.Row {
			return rowFor(sql)
		},
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			switch {
			case strings.Contains(sql, "GROUP BY model_used"),
				strings.Contains(sql, "GROUP BY DATE(created_at)"),
				strings.Contains(sql, "LIMIT 5"):
				return &mockPGXRows{}, nil
			default:
				return nil, errors.New("spend test: unexpected Query: " + sql)
			}
		},
	}, newTestLogger(), nil)
}

func runSpendRollup(t *testing.T, fx spendFixtures) *UnitSpendRollup {
	t.Helper()
	store := newSpendStore(t, fx)
	from := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 11, 30, 23, 59, 59, 0, time.UTC)
	rollup, err := store.GetUnitSpendRollup(context.Background(), "org-1", from, to)
	require.NoError(t, err)
	require.Len(t, rollup.Lines, 5, "fixed line set: usd, usd-cf, credits, tokens, gco2e")
	// Fixed order tooth — the UI grid depends on it.
	require.Equal(t, UnitUSD, rollup.Lines[0].Unit)
	require.Equal(t, UnitUSD, rollup.Lines[1].Unit)
	require.Equal(t, UnitCredits, rollup.Lines[2].Unit)
	require.Equal(t, UnitTokens, rollup.Lines[3].Unit)
	require.Equal(t, UnitGCO2e, rollup.Lines[4].Unit)
	for i, line := range rollup.Lines {
		require.NoErrorf(t, line.Validate(), "line %d must satisfy the measure vocabulary", i)
	}
	require.Equal(t, "org-1", rollup.OrgID)
	require.Equal(t, WalletUnitScale, rollup.CreditsScale)
	return rollup
}

func requireAmount(t *testing.T, m Measure, want float64, msgAndArgs ...interface{}) {
	t.Helper()
	require.NotNil(t, m.Amount, "expected a measured amount, got unknown")
	require.InDelta(t, want, *m.Amount, 1e-9, msgAndArgs...)
}

// TestUnitSpendRollup_ExactWindow — the fully-measured window: every mark is
// exact except the counterfactual (always simulated), and provenance cites
// the served price catalog.
func TestUnitSpendRollup_ExactWindow(t *testing.T) {
	rollup := runSpendRollup(t, spendFixtures{
		totalUSD: 12.5, totalCF: 18.0, requests: 10, unpriced: 0,
		exactTok: 5000, usageRows: 10, grams: 4.2,
		spentCents: 1000, usageCount: 5, hasWallet: true, balance: 5000,
	})
	assert.Equal(t, int64(10), rollup.Requests)
	assert.Equal(t, int64(0), rollup.UnknownUsageRows)
	assert.Equal(t, int64(0), rollup.UnmodeledCarbonRows)
	assert.Equal(t, int64(0), rollup.LegacyCostRows)

	usd := rollup.Lines[0]
	requireAmount(t, usd.Measure, 12.5)
	assert.Equal(t, FidelityExact, usd.Fidelity)
	assert.Equal(t, UnitFamilyMoney, usd.Family)
	assert.True(t, strings.HasPrefix(usd.Provenance, "catalog:"), "provenance must cite the served price catalog, got %q", usd.Provenance)

	cf := rollup.Lines[1]
	requireAmount(t, cf.Measure, 18.0)
	assert.Equal(t, FidelitySimulated, cf.Fidelity, "counterfactual is a projection, never exact")

	credits := rollup.Lines[2]
	requireAmount(t, credits.Measure, 1000, "credits spend is wallet cents")
	assert.Equal(t, FidelityExact, credits.Fidelity)
	assert.Equal(t, ProvenanceCreditsLedger, credits.Provenance)

	tokens := rollup.Lines[3]
	requireAmount(t, tokens.Measure, 5000)
	assert.Equal(t, FidelityExact, tokens.Fidelity)

	carbon := rollup.Lines[4]
	requireAmount(t, carbon.Measure, 4.2)
	assert.Equal(t, FidelityExact, carbon.Fidelity)
	assert.Equal(t, ProvenanceCarbonFactors, carbon.Provenance)
	assert.Equal(t, UnitFamilyImpact, carbon.Family)
}

// TestUnitSpendRollup_UnknownCoverageIsNotNullZero — a fully-unpriced window
// serializes null amounts on the USD lines. "We don't know" is never "0".
func TestUnitSpendRollup_UnknownCoverageIsNotNullZero(t *testing.T) {
	rollup := runSpendRollup(t, spendFixtures{
		totalUSD: 12.5, totalCF: 18.0, requests: 5, unpriced: 5, // 100% unpriced → unknown
		exactTok: 800, usageRows: 5, grams: 2.5,
		spentCents: 1000, usageCount: 2, hasWallet: true, balance: 4000,
	})
	for _, idx := range []int{0, 1} {
		line := rollup.Lines[idx]
		assert.Nil(t, line.Amount, "unknown USD line must not carry an amount")
		assert.Equal(t, FidelityUnknown, line.Fidelity)
		assert.NotEmpty(t, line.Note, "unknown lines explain why")
	}
	// Wire shape tooth: JSON carries null, never a collapsed 0.
	raw, err := json.Marshal(rollup)
	require.NoError(t, err)
	assert.Equal(t, 2, strings.Count(string(raw), `"amount":null`),
		"both USD lines must serialize amount:null, got %s", raw)
	assert.NotContains(t, string(raw), `"amount":0,`, "no collapsed zero may appear in this fixture")
	// The measured lines stay intact.
	requireAmount(t, rollup.Lines[3].Measure, 800)
	requireAmount(t, rollup.Lines[4].Measure, 2.5)
}

// TestUnitSpendRollup_EmptyWindowIsExactZero — the ONLY state where zeros
// appear: a measured empty window. Empty ≠ unknown.
func TestUnitSpendRollup_EmptyWindowIsExactZero(t *testing.T) {
	rollup := runSpendRollup(t, spendFixtures{
		requests: 0, unpriced: 0, usageRows: 0, hasWallet: true, balance: 0,
	})
	for i, line := range rollup.Lines {
		requireAmount(t, line.Measure, 0, "line %d: empty window is exact zero", i)
		assert.Equal(t, FidelityExact, line.Fidelity, "line %d", i)
		assert.Equal(t, CoverageEmpty, rollup.Pricing.CoverageStatus)
	}
}

// TestUnitSpendRollup_PartialCoverageEstimated — partial price coverage
// degrades USD to estimated without touching the amount.
func TestUnitSpendRollup_PartialCoverageEstimated(t *testing.T) {
	rollup := runSpendRollup(t, spendFixtures{
		totalUSD: 12.5, totalCF: 18.0, requests: 10, unpriced: 3,
		exactTok: 5000, usageRows: 10, grams: 4.2,
		spentCents: 1000, usageCount: 5, hasWallet: true, balance: 5000,
	})
	assert.Equal(t, CoveragePartial, rollup.Pricing.CoverageStatus)
	requireAmount(t, rollup.Lines[0].Measure, 12.5)
	assert.Equal(t, FidelityEstimated, rollup.Lines[0].Fidelity)
	assert.Equal(t, FidelitySimulated, rollup.Lines[1].Fidelity)
}

// TestUnitSpendRollup_LegacyRowsEstimated — complete coverage over a window
// that contains legacy estimator rows is still an estimate.
func TestUnitSpendRollup_LegacyRowsEstimated(t *testing.T) {
	rollup := runSpendRollup(t, spendFixtures{
		totalUSD: 12.5, totalCF: 18.0, requests: 10, unpriced: 0, legacy: 4,
		exactTok: 5000, usageRows: 10, grams: 4.2,
		spentCents: 1000, usageCount: 5, hasWallet: true, balance: 5000,
	})
	assert.Equal(t, CoverageComplete, rollup.Pricing.CoverageStatus)
	assert.Equal(t, int64(4), rollup.LegacyCostRows)
	requireAmount(t, rollup.Lines[0].Measure, 12.5)
	assert.Equal(t, FidelityEstimated, rollup.Lines[0].Fidelity,
		"legacy estimator rows must degrade exact to estimated")
}

// TestUnitSpendRollup_TokensMatrix — usage_source mix drives the tokens line.
func TestUnitSpendRollup_TokensMatrix(t *testing.T) {
	t.Run("mixed unknown rows degrade to estimated", func(t *testing.T) {
		rollup := runSpendRollup(t, spendFixtures{
			totalUSD: 12.5, totalCF: 18.0, requests: 12, unpriced: 0,
			exactTok: 1000, unknownTok: 2, usageRows: 10, grams: 4.2,
			spentCents: 1000, usageCount: 5, hasWallet: true, balance: 5000,
		})
		assert.Equal(t, int64(2), rollup.UnknownUsageRows)
		tok := rollup.Lines[3]
		requireAmount(t, tok.Measure, 1000, "only measured tokens are summed")
		assert.Equal(t, FidelityEstimated, tok.Fidelity)
		assert.Contains(t, tok.Note, "without recorded usage")
	})
	t.Run("all rows unknown is an unknown, not zero", func(t *testing.T) {
		rollup := runSpendRollup(t, spendFixtures{
			totalUSD: 12.5, totalCF: 18.0, requests: 3, unpriced: 0,
			unknownTok: 3, usageRows: 0, grams: 0,
			spentCents: 1000, usageCount: 5, hasWallet: true, balance: 5000,
		})
		tok := rollup.Lines[3]
		assert.Nil(t, tok.Amount, "tokens with no usage recorded anywhere must be unknown")
		assert.Equal(t, FidelityUnknown, tok.Fidelity)
		assert.NotEmpty(t, tok.Note)
	})
	t.Run("estimated-source tokens degrade the mark", func(t *testing.T) {
		rollup := runSpendRollup(t, spendFixtures{
			totalUSD: 12.5, totalCF: 18.0, requests: 10, unpriced: 0,
			estTok: 700, usageRows: 10, grams: 4.2,
			spentCents: 1000, usageCount: 5, hasWallet: true, balance: 5000,
		})
		tok := rollup.Lines[3]
		requireAmount(t, tok.Measure, 700)
		assert.Equal(t, FidelityEstimated, tok.Fidelity)
	})
}

// TestUnitSpendRollup_CarbonMatrix — carbon factor coverage drives gCO2e.
func TestUnitSpendRollup_CarbonMatrix(t *testing.T) {
	base := spendFixtures{
		totalUSD: 12.5, totalCF: 18.0, requests: 10, unpriced: 0,
		exactTok:   5000,
		spentCents: 1000, usageCount: 5, hasWallet: true, balance: 5000,
	}
	t.Run("no factors at all is unknown, not zero", func(t *testing.T) {
		fx := base
		fx.usageRows, fx.unmodeled, fx.grams = 10, 10, 0
		rollup := runSpendRollup(t, fx)
		assert.Equal(t, int64(10), rollup.UnmodeledCarbonRows)
		carbon := rollup.Lines[4]
		assert.Nil(t, carbon.Amount, "an unmodeled fleet is not a zero-emission fleet")
		assert.Equal(t, FidelityUnknown, carbon.Fidelity)
		assert.NotEmpty(t, carbon.Note)
	})
	t.Run("unmodeled rows degrade to estimated", func(t *testing.T) {
		fx := base
		fx.usageRows, fx.unmodeled, fx.grams = 10, 2, 3.0
		rollup := runSpendRollup(t, fx)
		assert.Equal(t, int64(2), rollup.UnmodeledCarbonRows)
		requireAmount(t, rollup.Lines[4].Measure, 3.0, "only modeled rows are summed")
		assert.Equal(t, FidelityEstimated, rollup.Lines[4].Fidelity)
		assert.Contains(t, rollup.Lines[4].Note, "without a carbon factor")
	})
	t.Run("unverified factors degrade to estimated", func(t *testing.T) {
		fx := base
		fx.usageRows, fx.unverified, fx.grams, fx.gramsUnv = 10, 5, 4.2, 1.5
		rollup := runSpendRollup(t, fx)
		requireAmount(t, rollup.Lines[4].Measure, 4.2)
		assert.Equal(t, FidelityEstimated, rollup.Lines[4].Fidelity)
		assert.Contains(t, rollup.Lines[4].Note, "unverified")
	})
}

// TestUnitSpendRollup_NoWalletIsUnknown — credits without a wallet are
// unknown, never zero.
func TestUnitSpendRollup_NoWalletIsUnknown(t *testing.T) {
	rollup := runSpendRollup(t, spendFixtures{
		totalUSD: 12.5, totalCF: 18.0, requests: 10, unpriced: 0,
		exactTok: 5000, usageRows: 10, grams: 4.2,
		spentCents: 0, usageCount: 0, hasWallet: false,
	})
	credits := rollup.Lines[2]
	assert.Nil(t, credits.Amount)
	assert.Equal(t, FidelityUnknown, credits.Fidelity)
	assert.Contains(t, credits.Note, "no wallet")
}

// TestUnitSpendRollup_Guards — nil DB and empty org refuse to build.
func TestUnitSpendRollup_Guards(t *testing.T) {
	nilStore := newForTest(nil, newTestLogger(), nil)
	from := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 0, 30)
	_, err := nilStore.GetUnitSpendRollup(context.Background(), "org-1", from, to)
	require.Error(t, err)
	_, err = newSpendStore(t, spendFixtures{}).GetUnitSpendRollup(context.Background(), "", from, to)
	require.Error(t, err)
}
