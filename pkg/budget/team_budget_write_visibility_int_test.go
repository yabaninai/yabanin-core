//go:build integration

// The first-budget visibility controls on one real, fully migrated Postgres
// stand (testdb.Postgres): the budget write goes through the admin consumer
// entry (adminstore.Store — the store behind PUT /api/teams/{id}/budget) and
// the enforcement through the gateway consumer entry (Enforcer.CheckBudget —
// the check admission.go runs). Every immediate-visibility claim is backed
// by an independent read of the persisted row, and the stale/outage shapes
// (changed limit, deleted row, store down) must deny or re-read — never
// serve a remembered limit.
package budget

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// visibilitySeedTeam inserts a fresh team under a fresh org and returns the
// team id. Cleanup cascades from the org.
func visibilitySeedTeam(t *testing.T, pool *pgxpool.Pool, label string) string {
	t.Helper()
	ctx := context.Background()
	orgID := uuid.New()
	_, err := pool.Exec(ctx,
		`INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`,
		orgID, label, label)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM organizations WHERE id = $1`, orgID)
	})
	teamID := uuid.New()
	_, err = pool.Exec(ctx,
		`INSERT INTO organizations_teams (id, org_id, name, slug) VALUES ($1, $2, $3, $3)`,
		teamID, orgID, label)
	require.NoError(t, err)
	return teamID.String()
}

// persistedLimit independently reads the committed team_budgets row.
func persistedLimit(t *testing.T, pool *pgxpool.Pool, teamID string) (float64, bool, bool) {
	t.Helper()
	var limit float64
	var hard bool
	err := pool.QueryRow(context.Background(),
		`SELECT monthly_limit_usd, hard_limit FROM team_budgets WHERE team_id = $1`,
		teamID).Scan(&limit, &hard)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, false
	}
	require.NoError(t, err)
	return limit, hard, true
}

// TestIntegration_FirstBudgetWriteVisibleToNextCheck: the frozen original
// sequence end to end — the team is denied while unconfigured, the
// authorized write commits through the admin store (the method the handler
// calls after validation), and the IMMEDIATELY following gateway check
// evaluates the persisted budget. The row's existence is verified
// independently of the enforcer.
func TestIntegration_FirstBudgetWriteVisibleToNextCheck(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	team := visibilitySeedTeam(t, pool, "vis-first-"+uuid.NewString()[:8])

	adminStore := adminstore.New(pool, slog.Default(), nil)
	e := NewEnforcer(pool, slog.Default())

	// Original immediate denial: fail-closed without a budget row.
	err := e.CheckBudget(ctx, team)
	require.ErrorIs(t, err, ErrNoBudget)

	// The authorized write: the store method behind PUT /api/teams/{id}/budget.
	require.NoError(t, adminStore.UpsertTeamBudget(ctx, team, 100.0, true))

	// Independent proof the row is committed.
	limit, hard, ok := persistedLimit(t, pool, team)
	require.True(t, ok, "team_budgets row persisted")
	assert.InDelta(t, 100.0, limit, 1e-9)
	assert.True(t, hard)

	// The very next check evaluates the persisted budget — no TTL wait.
	require.NoError(t, e.CheckBudget(ctx, team),
		"a committed first budget must be visible to the immediately following request")
}

// TestIntegration_TwoTeams_WriteScopedPerTeam: configuring team B never
// authorizes team A; A's own later write changes nothing for B; deleting B's
// budget denies only B.
func TestIntegration_TwoTeams_WriteScopedPerTeam(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	teamA := visibilitySeedTeam(t, pool, "vis-iso-a-"+uuid.NewString()[:8])
	teamB := visibilitySeedTeam(t, pool, "vis-iso-b-"+uuid.NewString()[:8])

	adminStore := adminstore.New(pool, slog.Default(), nil)
	e := NewEnforcer(pool, slog.Default())

	require.NoError(t, adminStore.UpsertTeamBudget(ctx, teamB, 50.0, true))
	require.NoError(t, e.CheckBudget(ctx, teamB))
	require.ErrorIs(t, e.CheckBudget(ctx, teamA), ErrNoBudget,
		"team B's budget row never authorizes team A")

	require.NoError(t, adminStore.UpsertTeamBudget(ctx, teamA, 25.0, true))
	require.NoError(t, e.CheckBudget(ctx, teamA))
	require.NoError(t, e.CheckBudget(ctx, teamB), "team A's write leaves team B's allowance intact")

	require.NoError(t, adminStore.DeleteTeamBudget(ctx, teamB))
	require.ErrorIs(t, e.CheckBudget(ctx, teamB), ErrNoBudget, "no stale allow after the committed delete")
	require.NoError(t, e.CheckBudget(ctx, teamA))
}

// TestIntegration_ChangedAndDeletedBudgetBindNextCheck: a lowered limit
// binds the next request (real exact spend recorded through the production
// writer), and a delete restores the fail-closed denial immediately.
func TestIntegration_ChangedAndDeletedBudgetBindNextCheck(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	team := visibilitySeedTeam(t, pool, "vis-change-"+uuid.NewString()[:8])

	adminStore := adminstore.New(pool, slog.Default(), nil)
	e := NewEnforcer(pool, slog.Default())

	require.NoError(t, adminStore.UpsertTeamBudget(ctx, team, 100.0, true))
	require.NoError(t, e.CheckBudget(ctx, team))

	// $50 of real spend through the production exact writer.
	period := time.Now().UTC().Format("2006-01")
	require.NoError(t, RecordTeamSpendExact(ctx, pool, team, period, 50_000_000))
	require.NoError(t, e.CheckBudget(ctx, team), "$50 under the $100 cap")

	// The operator lowers the cap under the recorded spend.
	require.NoError(t, adminStore.UpsertTeamBudget(ctx, team, 0.50, true))
	require.ErrorIs(t, e.CheckBudget(ctx, team), ErrBudgetExceeded,
		"the lowered limit binds the next request; no remembered $100 allowance")

	// The delete restores the fail-closed denial on the very next check.
	require.NoError(t, adminStore.DeleteTeamBudget(ctx, team))
	require.ErrorIs(t, e.CheckBudget(ctx, team), ErrNoBudget)
}

// TestIntegration_StoreOutage_DeniesNeverServesLastKnownLimit: with the pool
// closed mid-flight (a real store outage), the check denies with
// ErrBudgetUnavailable — the last-known limit is never served as proof of
// the current cap.
func TestIntegration_StoreOutage_DeniesNeverServesLastKnownLimit(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	team := visibilitySeedTeam(t, pool, "vis-outage-"+uuid.NewString()[:8])

	adminStore := adminstore.New(pool, slog.Default(), nil)
	outagePool := testdb.PostgresPool(t, func(c *pgxpool.Config) { c.MaxConns = 1 })
	e := NewEnforcer(outagePool, slog.Default())

	require.NoError(t, adminStore.UpsertTeamBudget(ctx, team, 100.0, true))
	require.NoError(t, e.CheckBudget(ctx, team), "preconditions: allowed under the live limit")

	outagePool.Close() // only this enforcer loses its database connections

	err := e.CheckBudget(ctx, team)
	require.ErrorIs(t, err, ErrBudgetUnavailable,
		"an unreadable store is a denial, not a last-known allowance")
}
