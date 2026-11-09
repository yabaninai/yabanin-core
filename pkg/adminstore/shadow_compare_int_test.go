package adminstore

// D-01 regression: GetShadowComparison numbered the org-filter placeholder
// from len(args) BEFORE appending the org argument, so the filter compared
// p.org_id::text with $2 (the window bound) and every org-scoped request died
// in Postgres (500). Real-Postgres contract: two orgs, each with primary and
// shadow rows sharing a request_id — an org-scoped call returns only that
// org's overlap, the global call sees both, and no SQL error escapes.

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

const (
	shadowIntOrgA = "99933333-3333-4333-8333-333333333301"
	shadowIntOrgB = "99944444-4444-4444-8444-444444444402"

	shadowIntPrimaryModel = "imp01-int-primary"
	shadowIntShadowModel  = "imp01-int-shadow"
	shadowIntTaskClass    = "imp01/task"
)

func shadowIntInsertLog(t *testing.T, pool *pgxpool.Pool, org, requestID, taskID, model, abGroup, cost string, ms int) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO request_logs (
			org_id, model_requested, model_used, status_code, duration_ms,
			tokens_in, tokens_out, method, home_region,
			request_id, task_id, cost_in_usd, ab_group, created_at
		) VALUES ($1, $2, $3, 200, $4, 5, 5, 'POST', 'sg', $5, NULLIF($6, ''), $7::numeric, NULLIF($8, ''), $9)`,
		// Anchor fixtures inside the host-clock report window instead of at its
		// upper edge: the Docker VM database clock may be ahead of the host.
		org, shadowIntPrimaryModel, model, ms, requestID, taskID, cost, abGroup, time.Now().Add(-time.Hour))
	require.NoError(t, err)
}

// shadowIntInsertPair writes one primary row and its shadow mirror on the
// same request_id. taskID "" leaves the pair untagged.
func shadowIntInsertPair(t *testing.T, pool *pgxpool.Pool, org, requestID, taskID, primaryCost, shadowCost string) {
	t.Helper()
	shadowIntInsertLog(t, pool, org, requestID, taskID, shadowIntPrimaryModel, "", primaryCost, 100)
	shadowIntInsertLog(t, pool, org, requestID, taskID, shadowIntShadowModel, "shadow", shadowCost, 900)
}

func TestStore_ShadowComparison_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	for i, org := range []string{shadowIntOrgA, shadowIntOrgB} {
		_, err := pool.Exec(ctx, `
			INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)
			ON CONFLICT (id) DO NOTHING`,
			org, "IMP01 Int Org", fmt.Sprintf("imp01-int-org-%d", i+1))
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `DELETE FROM request_logs WHERE org_id = $1`, org)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM request_logs WHERE org_id IN ($1, $2)`, shadowIntOrgA, shadowIntOrgB)
		_, _ = pool.Exec(bg, `DELETE FROM organizations WHERE id IN ($1, $2)`, shadowIntOrgA, shadowIntOrgB)
	})

	// Org A: two overlap pairs (one tagged, one untagged), shadow 4x pricier.
	shadowIntInsertPair(t, pool, shadowIntOrgA, "imp01-a-1", shadowIntTaskClass, "0.10", "0.40")
	shadowIntInsertPair(t, pool, shadowIntOrgA, "imp01-a-2", "", "0.20", "0.80")
	// Org B: two overlap pairs on its own request_ids, shadow cheaper.
	shadowIntInsertPair(t, pool, shadowIntOrgB, "imp01-b-1", shadowIntTaskClass, "0.50", "0.25")
	shadowIntInsertPair(t, pool, shadowIntOrgB, "imp01-b-2", "", "0.30", "0.15")

	// Org-scoped: only org A's overlap, no SQL error (the D-01 defect made
	// this call fail with a placeholder/type error before the fix).
	repA, err := store.GetShadowComparison(ctx, shadowIntOrgA, 30)
	require.NoError(t, err)
	require.NotNil(t, repA)
	require.Len(t, repA.ByModel, 1, "only the (primary, shadow) pair of org A must match")
	assert.Equal(t, shadowIntPrimaryModel, repA.ByModel[0].PrimaryModel)
	assert.Equal(t, shadowIntShadowModel, repA.ByModel[0].ShadowModel)
	assert.Equal(t, 2, repA.Overlap, "org A overlap must exclude org B's pairs")
	assert.InDelta(t, 0.15, repA.ByModel[0].PrimaryAvgUSD, 1e-9)
	assert.InDelta(t, 0.60, repA.ByModel[0].ShadowAvgUSD, 1e-9)
	require.Len(t, repA.ByTaskClass, 2)
	byTaskA := map[string]int{}
	for _, g := range repA.ByTaskClass {
		byTaskA[g.TaskClass] = g.Overlap
	}
	assert.Equal(t, map[string]int{shadowIntTaskClass: 1, "(untagged)": 1}, byTaskA)

	// The symmetric org B call is also error-free and isolated.
	repB, err := store.GetShadowComparison(ctx, shadowIntOrgB, 30)
	require.NoError(t, err)
	assert.Equal(t, 2, repB.Overlap)
	assert.InDelta(t, 0.20, repB.ByModel[0].ShadowAvgUSD, 1e-9, "org B's shadow is cheaper")

	// Global: both orgs' pairs merge into the same (primary, shadow) group.
	repAll, err := store.GetShadowComparison(ctx, "", 30)
	require.NoError(t, err)
	require.Len(t, repAll.ByModel, 1)
	assert.Equal(t, 4, repAll.ByModel[0].Overlap, "global overlap must span both orgs")

	// Small samples stay honest: 2 overlaps < shadowInsufficientOverlap.
	assert.Equal(t, "insufficient_data", repA.Verdict)
}
