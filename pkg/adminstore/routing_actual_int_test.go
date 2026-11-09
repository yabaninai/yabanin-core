package adminstore

// aggregate SQL (requested×used grouping, shadow exclusion, window bounds)
// runs against the disposable migrated stand; org scoping, override-shaped
// edges and honest empty results are asserted. Grouping/share rules live
// in routing_actual_test.go.

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

type routingActualFixture struct {
	Token          string
	OrgA, OrgB     string
	ModelA, ModelB string
}

// seedRoutingActualFixture seeds an org-scoped request_logs mix exercising
// every aggregate rule: org A gets 3× A→A2 (rule-override shape), 1× A→A1
// (failover shape), 2× B→B2, one row with an empty requested model (the
// unattributed bucket) and one shadow row that must stay out; org B gets
// its own A→A2 row that must never leak into org A's aggregate.
func seedRoutingActualFixture(t *testing.T, pool *pgxpool.Pool) *routingActualFixture {
	t.Helper()
	ctx := context.Background()
	token := fmt.Sprintf("ra47a%x", time.Now().UnixNano())
	fx := &routingActualFixture{
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

	logRows := []struct {
		org     string
		request string
		used    string
		abGroup string
		ageMin  int
	}{
		{fx.OrgA, fx.ModelA, fx.ModelA + "-override", "", 120},
		{fx.OrgA, fx.ModelA, fx.ModelA + "-override", "", 90},
		{fx.OrgA, fx.ModelA, fx.ModelA + "-override", "", 60},
		{fx.OrgA, fx.ModelA, fx.ModelA + "-failover", "", 45},
		{fx.OrgA, fx.ModelB, fx.ModelB + "-override", "", 30},
		{fx.OrgA, fx.ModelB, fx.ModelB + "-override", "", 20},
		// No requested model on the row (unattributed bucket).
		{fx.OrgA, "", token + "-m-c", "", 10},
		// Shadow traffic: excluded by the shared convention.
		{fx.OrgA, fx.ModelB, fx.ModelB + "-override", "shadow", 5},
		// Another org's traffic — must stay out of org A's aggregate.
		{fx.OrgB, fx.ModelA, fx.ModelA + "-override", "", 15},
	}
	for i, r := range logRows {
		_, err := pool.Exec(ctx, `
			INSERT INTO request_logs (org_id, model_requested, model_used, status_code, duration_ms, tokens_in, tokens_out, created_at, home_region, ab_group)
			VALUES ($1::uuid, $2, $3, 200, 100, 10, 5, $4, 'GLOBAL', $5)`,
			r.org, r.request, r.used,
			time.Now().Add(-time.Duration(r.ageMin)*time.Minute).Add(time.Duration(i)*time.Millisecond),
			r.abGroup)
		require.NoError(t, err, "seed request_logs row %d", i)
	}

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("routing actual fixture cleanup: %v", err)
			}
		}
		orgs := []string{fx.OrgA, fx.OrgB}
		cleanup(`DELETE FROM request_logs WHERE org_id::text = ANY($1)`, orgs)
		cleanup(`DELETE FROM organizations WHERE id::text = ANY($1)`, orgs)
	})

	return fx
}

func TestStore_GetRoutingActual_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedRoutingActualFixture(t, pool)

	from := time.Now().Add(-24 * time.Hour)
	to := time.Now().Add(time.Hour)
	actual, err := store.GetActualRouting(context.Background(), fx.OrgA, from, to)
	require.NoError(t, err)

	// Ordered by volume: A→override (3), B→override (2), A→failover (1).
	require.Len(t, actual.Edges, 3, "shadow and unattributed rows must not create edges")
	assert.Equal(t, fx.ModelA, actual.Edges[0].From)
	assert.Equal(t, fx.ModelA+"-override", actual.Edges[0].To)
	assert.Equal(t, int64(3), actual.Edges[0].Requests)
	assert.InDelta(t, 0.5, actual.Edges[0].Share, 1e-9)

	assert.Equal(t, fx.ModelB, actual.Edges[1].From)
	assert.Equal(t, fx.ModelB+"-override", actual.Edges[1].To)
	assert.Equal(t, int64(2), actual.Edges[1].Requests)
	assert.InDelta(t, 1.0/3.0, actual.Edges[1].Share, 1e-9)

	assert.Equal(t, fx.ModelA, actual.Edges[2].From)
	assert.Equal(t, fx.ModelA+"-failover", actual.Edges[2].To)
	assert.Equal(t, int64(1), actual.Edges[2].Requests)
	assert.InDelta(t, 1.0/6.0, actual.Edges[2].Share, 1e-9)

	// 7 non-shadow rows in the window; 6 attributed, 1 without a requested
	// model; the shadow row is excluded everywhere.
	assert.Equal(t, RoutingActualCoverage{
		TotalRequests:        7,
		AttributedRequests:   6,
		UnattributedRequests: 1,
		Share:                6.0 / 7.0,
	}, actual.Coverage)

	// Org scoping: org B sees only its own row, never org A's edges.
	actualB, err := store.GetActualRouting(context.Background(), fx.OrgB, from, to)
	require.NoError(t, err)
	require.Len(t, actualB.Edges, 1)
	assert.Equal(t, fx.ModelA, actualB.Edges[0].From)
	assert.Equal(t, fx.ModelA+"-override", actualB.Edges[0].To)
	assert.Equal(t, int64(1), actualB.Edges[0].Requests)
	assert.InDelta(t, 1.0, actualB.Edges[0].Share, 1e-9)
	assert.Equal(t, RoutingActualCoverage{
		TotalRequests:      1,
		AttributedRequests: 1,
		Share:              1,
	}, actualB.Coverage)
}

func TestStore_GetRoutingActual_Integration_EmptyWindow(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedRoutingActualFixture(t, pool)

	// A window before any seeded traffic: the honest empty result.
	actual, err := store.GetActualRouting(context.Background(), fx.OrgA,
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	require.NoError(t, err)
	require.NotNil(t, actual)
	assert.NotNil(t, actual.Edges)
	assert.Empty(t, actual.Edges, "no traffic in the window must yield empty edges, not null")
	assert.Equal(t, RoutingActualCoverage{}, actual.Coverage)
}
