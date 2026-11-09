package adminstore

// aggregate SQL (percentiles, FILTER aggregates, registry join) runs against
// the disposable migrated stand; org scoping and honest empty results are
// asserted. Grouping rules live in routing_map_test.go.

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type providerHealthFixture struct {
	Token          string
	OrgA, OrgB     string
	ModelA, ModelB string
}

// seedProviderHealthFixture seeds models and an org-scoped request_logs mix:
// org A gets 4 rows for ModelA (3×200 at 100/200/300 ms, 1×500 with error),
// 2 rows for ModelB (both 200) and one 200 row for a model absent from the
// registry (the "unknown" provider bucket); org B gets its own row that must
// never leak into org A's aggregates.
func seedProviderHealthFixture(t *testing.T, pool *pgxpool.Pool) *providerHealthFixture {
	t.Helper()
	ctx := context.Background()
	token := fmt.Sprintf("ph47a%x", time.Now().UnixNano())
	fx := &providerHealthFixture{
		Token:  token,
		ModelA: token + "-m-a",
		ModelB: token + "-m-b",
	}

	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-a", token+"-org-a").Scan(&fx.OrgA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-b", token+"-org-b").Scan(&fx.OrgB))

	for _, m := range []struct {
		name     string
		provider string
	}{
		// Real providers (chk_provider constraint): two distinct ones so the
		// multi-provider grouping is exercised against real data.
		{fx.ModelA, "anthropic"},
		{fx.ModelB, "openai"},
	} {
		_, err := pool.Exec(ctx, `
			INSERT INTO models_registry (model_name, display_name, tier, provider, failover_models, tier_pool)
			VALUES ($1, $1, 'smart', $2, '{}'::text[], '{}'::text[])`,
			m.name, m.provider)
		require.NoError(t, err, "seed model %s", m.name)
	}

	logRows := []struct {
		org, model string
		status     int
		durationMs int
		errText    string
		ageMin     int
	}{
		{fx.OrgA, fx.ModelA, 200, 100, "", 240},
		{fx.OrgA, fx.ModelA, 200, 200, "", 180},
		{fx.OrgA, fx.ModelA, 200, 300, "", 120},
		{fx.OrgA, fx.ModelA, 500, 400, "upstream exploded", 60},
		{fx.OrgA, fx.ModelB, 200, 50, "", 30},
		{fx.OrgA, fx.ModelB, 200, 70, "", 20},
		// Unknown model: absent from models_registry on purpose.
		{fx.OrgA, token + "-m-unregistered", 200, 10, "", 10},
		// Another org's traffic — must stay out of org A's aggregates.
		{fx.OrgB, fx.ModelA, 500, 999, "other org failure", 15},
	}
	for i, r := range logRows {
		_, err := pool.Exec(ctx, `
			INSERT INTO request_logs (org_id, model_requested, model_used, status_code, duration_ms, tokens_in, tokens_out, error, created_at, home_region)
			VALUES ($1::uuid, $2, $2, $3, $4, 10, 5, NULLIF($5, ''), $6, 'GLOBAL')`,
			r.org, r.model, r.status, r.durationMs, r.errText,
			time.Now().Add(-time.Duration(r.ageMin)*time.Minute).Add(time.Duration(i)*time.Millisecond))
		require.NoError(t, err, "seed request_logs row %d", i)
	}

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("provider health fixture cleanup: %v", err)
			}
		}
		orgs := []string{fx.OrgA, fx.OrgB}
		cleanup(`DELETE FROM request_logs WHERE org_id::text = ANY($1)`, orgs)
		cleanup(`DELETE FROM models_registry WHERE model_name LIKE $1`, token+"%")
		cleanup(`DELETE FROM organizations WHERE id::text = ANY($1)`, orgs)
	})

	return fx
}

func TestStore_GetProviderHealth_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedProviderHealthFixture(t, pool)

	from := time.Now().Add(-24 * time.Hour)
	to := time.Now().Add(time.Hour)
	health, err := store.GetProviderHealth(context.Background(), fx.OrgA, from, to)
	require.NoError(t, err)

	require.Len(t, health, 3, "org A traffic spans two providers plus the unknown bucket")

	// Ordered by request volume: provider of ModelA (4 rows), provider of
	// ModelB (2), unknown (1).
	prov := health[0]
	require.Equal(t, "anthropic", prov.Provider)
	assert.Equal(t, int64(4), prov.Requests)
	assert.Equal(t, int64(1), prov.Errors)
	assert.InDelta(t, 0.25, prov.ErrorRate, 1e-9)

	byModel := map[string]ProviderHealthModel{}
	for _, m := range prov.Models {
		byModel[m.Model] = m
	}
	ma, ok := byModel[fx.ModelA]
	require.True(t, ok, "model A must be aggregated")
	assert.Equal(t, int64(4), ma.Requests)
	assert.Equal(t, int64(1), ma.Errors)
	// PERCENTILE_CONT interpolates over [100,200,300,400]:
	// p50 at index 1.5 → 250; p95 at index 2.85 → 385.
	assert.InDelta(t, 250.0, ma.P50Ms, 0.001)
	assert.InDelta(t, 385.0, ma.P95Ms, 0.001)
	require.NotNil(t, ma.LastErrorA)
	assert.Equal(t, "upstream exploded", ma.LastError)
	assert.WithinDuration(t, time.Now().Add(-60*time.Minute), *ma.LastErrorA, 10*time.Minute)

	if _, ok := byModel[fx.ModelB]; ok {
		t.Errorf("model B belongs to another provider bucket, not %q", health[0].Provider)
	}
	assert.Equal(t, "openai", health[1].Provider)
	assert.Equal(t, int64(2), health[1].Requests)
	assert.Nil(t, health[1].Models[0].LastErrorA, "a model without errors must not carry a last-error timestamp")
	assert.Empty(t, health[1].Models[0].LastError)

	// The unregistered model lands in the unknown bucket — traffic the org
	// served is never silently dropped.
	assert.Equal(t, "unknown", health[2].Provider)
	assert.Equal(t, int64(1), health[2].Requests)

	// Org scoping: org B sees only its own row, never org A's aggregates.
	healthB, err := store.GetProviderHealth(context.Background(), fx.OrgB, from, to)
	require.NoError(t, err)
	require.Len(t, healthB, 1)
	assert.Equal(t, int64(1), healthB[0].Requests)
	assert.Equal(t, "other org failure", healthB[0].Models[0].LastError)
}

func TestStore_GetProviderHealth_Integration_EmptyWindow(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedProviderHealthFixture(t, pool)

	// A window before any seeded traffic: the honest empty result.
	health, err := store.GetProviderHealth(context.Background(), fx.OrgA,
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.NotNil(t, health)
	assert.Empty(t, health, "no traffic in the window must yield an empty provider list, not null")
}
