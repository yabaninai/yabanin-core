package adminstore

// AF-14: behavior contract of GetSavingsReport after the SQL optimization
// (typed UUID predicate, single FILTER aggregate, uncorrelated pricing
// coverage predicate). Real Postgres — the sums, denominators, shadow
// exclusion, provider scope and AF-07 coverage contract must be byte-for-byte
// the report semantics that existed before the refactor.

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W-VER isolation: per-run random org ids (uuid v4 shape). The fixed
// constants raced other test binaries' cleanups on the shared testcontainer
// stand (a concurrent `DELETE FROM organizations` nuked this test's rows
// mid-run → report came back empty → 7-vs-0 flake).
var (
	af14IntOrgA = af14RandomOrgID()
	af14IntOrgB = af14RandomOrgID()
)

func af14RandomOrgID() string {
	var b [16]byte
	_, err := crand.Read(b[:])
	if err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

type af14LogRow struct {
	model           string
	cost, cf        string // numeric literals, exact in numeric(12,6)
	cacheHit, tier  string
	classifierClass string
	abGroup         string
}

func af14InsertLog(t *testing.T, pool *pgxpool.Pool, org string, r af14LogRow) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO request_logs (
			org_id, model_requested, model_used, status_code, duration_ms,
			tokens_in, tokens_out, method, home_region,
			cost_in_usd, counterfactual_cost_usd,
			cache_hit_type, tier_used, classifier_class, ab_group
		) VALUES ($1, $2, $2, 200, 10, 5, 5, 'POST', 'sg',
			  $3::numeric, $4::numeric, $5, $6, $7, $8)`,
		org, r.model, r.cost, r.cf, argOrNull(r.cacheHit), argOrNull(r.tier),
		argOrNull(r.classifierClass), argOrNull(r.abGroup))
	require.NoError(t, err)
}

func argOrNull(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// TestStore_SavingsReport_Integration pins the full report semantics on the
// optimized SQL path: per-bucket FILTER counts, shadow exclusion, org scope,
// provider scope, AF-07 coverage metadata and the legacy empty/non-UUID
// report behavior.
func TestStore_SavingsReport_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	// Registry + pricing: the plain models and the provider-scope model are
	// priced; the mystery model stays absent from both → unpriced.
	// W-VER isolation: per-run model names — two concurrent copies of this
	// binary on the shared stand used to race over the fixed names (setup
	// DELETEs vs another run's report window).
	suffix := af14IntOrgA[0:8]
	m1, m2, m3 := "af14-int-m1-"+suffix, "af14-int-m2-"+suffix, "af14-int-m3-"+suffix
	anthModel := "af14-int-anth-model-" + suffix
	mystery := "af14-int-mystery-" + suffix
	_, err := pool.Exec(ctx, `DELETE FROM models_pricing WHERE model IN ($1, $2, $3, $4, $5)`,
		m1, m2, m3, anthModel, mystery)
	require.NoError(t, err)
	for _, m := range []string{m1, m2, m3} {
		_, err := pool.Exec(ctx,
			`INSERT INTO models_registry (model_name, display_name) VALUES ($1, $1)`, m)
		require.NoError(t, err)
		_, err = pool.Exec(ctx,
			`INSERT INTO models_pricing (provider, model, input_per_m, output_per_m) VALUES ('openai-compat', $1, 1.0, 2.0)`, m)
		require.NoError(t, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO models_registry (model_name, display_name, provider) VALUES ($1, $1, 'anthropic')`, anthModel)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO models_pricing (provider, model, input_per_m, output_per_m) VALUES ('anthropic', $1, 1.0, 2.0)`, anthModel)
	require.NoError(t, err)

	for i, org := range []string{af14IntOrgA, af14IntOrgB} {
		_, err := pool.Exec(ctx, `
			INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)
			ON CONFLICT (id) DO NOTHING`, org, "AF14 Int Org", fmt.Sprintf("af14-int-org-%d", i+1))
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `DELETE FROM request_logs WHERE org_id = $1`, org)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM request_logs WHERE org_id IN ($1, $2)`, af14IntOrgA, af14IntOrgB)
		_, _ = pool.Exec(bg, `DELETE FROM models_registry WHERE model_name IN ($1, $2, $3, $4)`,
			m1, m2, m3, anthModel)
		_, _ = pool.Exec(bg, `DELETE FROM models_pricing WHERE model IN ($1, $2, $3, $4, $5)`,
			m1, m2, m3, anthModel, mystery)
		_, _ = pool.Exec(bg, `DELETE FROM organizations WHERE id IN ($1, $2)`, af14IntOrgA, af14IntOrgB)
	})

	// Org A: 2 cache hits, 1 routed, 2 plain, 1 unpriced (mystery), 1 scoped
	// to the anthropic model, plus 1 shadow row that must vanish from every
	// client-visible aggregate.
	orgA := []af14LogRow{
		{model: m1, cost: "0.10", cf: "0.40", cacheHit: "exact"},
		{model: m1, cost: "0.20", cf: "0.40", cacheHit: "exact"},
		{model: m2, cost: "0.10", cf: "0.60", tier: "smart", classifierClass: "code"},
		{model: m2, cost: "0.10", cf: "0.20"},
		{model: m3, cost: "0.10", cf: "0.20"},
		{model: mystery, cost: "0", cf: "0.50"},
		{model: anthModel, cost: "0.30", cf: "0.60"},
		{model: m3, cost: "9.99", cf: "9.99", abGroup: "shadow"},
	}
	for _, r := range orgA {
		af14InsertLog(t, pool, af14IntOrgA, r)
	}
	// Org B: must never leak into org A's report.
	af14InsertLog(t, pool, af14IntOrgB, af14LogRow{model: m1, cost: "5.00", cf: "5.00"})

	// W-VER flake fix: the report window is [now-1d, host now], while
	// created_at comes from the DB clock. Under load the Docker-Desktop VM
	// clock can run AHEAD of the host, pushing freshly inserted rows outside
	// the window (the historic 7-vs-0/4/6 flake family). Wait (bounded)
	// until the host clock has caught up with the DB clock.
	for i := 0; i < 100; i++ {
		var dbNow time.Time
		require.NoError(t, pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&dbNow))
		if !dbNow.After(time.Now()) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	rep, err := store.GetSavingsReport(ctx, af14IntOrgA, 1, "")
	require.NoError(t, err)

	// Totals: 7 client-visible rows (shadow excluded, org B excluded).
	assert.Equal(t, 7, rep.TotalRequests)
	assert.InDelta(t, 0.90, rep.ActualCostUSD, 1e-9)
	assert.InDelta(t, 2.90, rep.CounterfactualCost, 1e-9)
	assert.InDelta(t, (2.90-0.90)/2.90*100, rep.CombinedSavingsPct, 1e-9)
	assert.True(t, rep.KillCriterionMet, "68.97% combined savings >= the 45% kill criterion")
	assert.Equal(t, "last_1_days", rep.Period)

	// Cache bucket: exactly the two cache_hit rows → 62.5% cache savings.
	assert.Equal(t, 2, rep.CacheHits)
	assert.InDelta(t, (0.80-0.30)/0.80*100, rep.CacheSavingsPct, 1e-9)

	// Routing bucket: exactly the tier+classifier row.
	assert.Equal(t, 1, rep.RoutedRequests)
	assert.InDelta(t, (0.60-0.10)/0.60*100, rep.RoutingSavingsPct, 1e-9)

	// AF-07 coverage: 1 of 7 unpriced → explicit partial, mystery listed.
	p := rep.Pricing
	require.Equal(t, CoveragePartial, p.CoverageStatus)
	require.NotNil(t, p.UnpricedShare)
	assert.InDelta(t, 1.0/7.0, *p.UnpricedShare, 1e-9)
	assert.Contains(t, p.UnpricedModels, mystery)
	assert.Empty(t, p.CoverageError)

	// Provider scope: only the anthropic-registry model remains.
	scoped, err := store.GetSavingsReport(ctx, af14IntOrgA, 1, "anthropic")
	require.NoError(t, err)
	assert.Equal(t, 1, scoped.TotalRequests)
	assert.InDelta(t, 0.30, scoped.ActualCostUSD, 1e-9)
	assert.InDelta(t, 0.60, scoped.CounterfactualCost, 1e-9)
	assert.Equal(t, 0, scoped.CacheHits)
	assert.Equal(t, 0, scoped.RoutedRequests)
	assert.Equal(t, CoverageComplete, scoped.Pricing.CoverageStatus, "scoped model is priced → complete")

	// Global report (org "") spans both orgs, still shadow-free. The dev
	// stand is shared, so the expectation is recomputed the same way the
	// store computes it (window + shadow exclusion) — but at minimum our
	// two orgs' 8 visible rows must be in.
	var wantGlobal int
	var wantGlobalCost float64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(SUM(cost_in_usd), 0)
		FROM request_logs
		WHERE created_at BETWEEN now() - interval '1 day' AND now()
		  AND COALESCE(ab_group, '') <> 'shadow'`).Scan(&wantGlobal, &wantGlobalCost))
	global, err := store.GetSavingsReport(ctx, "", 1, "")
	require.NoError(t, err)
	require.GreaterOrEqual(t, wantGlobal, 8)
	assert.Equal(t, wantGlobal, global.TotalRequests)
	assert.InDelta(t, wantGlobalCost, global.ActualCostUSD, 1e-6)

	// Legacy behavior: a non-UUID org filter never matched any row — the
	// typed predicate keeps that as an explicit empty report, not an error.
	bad, err := store.GetSavingsReport(ctx, "not-a-uuid", 7, "")
	require.NoError(t, err)
	require.NotNil(t, bad)
	assert.Equal(t, 0, bad.TotalRequests)
	assert.InDelta(t, 0, bad.ActualCostUSD, 0)
	assert.Equal(t, CoverageEmpty, bad.Pricing.CoverageStatus, "empty report keeps the AF-07 empty-window state")
	assert.Empty(t, bad.TopModelsByCost)
	assert.Empty(t, bad.DailyBreakdown)
	assert.Empty(t, bad.ClassifierDist)
}
