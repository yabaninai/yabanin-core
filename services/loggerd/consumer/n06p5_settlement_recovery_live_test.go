//go:build integration

// N06-P05-T05 negative-clause evidence at the consumer boundary (disposable
// PG+Redis, ADR-0001 §10): crash recovery and the settlement worker are
// independent money writers over the same reserves. When recovery closes an
// abandoned replica's reservations BEFORE the worker settles, the settle
// must degrade to ledger-only (no reserve decrement, no reconcile key);
// when they race, returned + settled must equal the granted escrow exactly
// once per scope. Complements the pkg/budget T05 file (the verdict side)
// with the consumer side of the same contract.
package consumer

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Both tests share the fixture's built-in enforce-mode org
// (n18dOrgEnf): seedNext18dWorld only creates the three n18d orgs and
// resets that org's whole world on every call, and these tests are
// sequential (no t.Parallel), so reuse is collision-free.

// n06p5ForceCrashShape backdates every allowance lease of the org 3 hours
// into the past — past the §14 ReservationSafetyWindow (2h), the canonical
// "replica died before the worker ever ticked" shape.
func n06p5ForceCrashShape(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) {
	t.Helper()
	tag, err := pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - interval '3 hours' WHERE org_id = $1`, org)
	require.NoError(t, err)
	require.Equal(t, int64(4), tag.RowsAffected(), "org %s must hold four allowances", org)
}

// n06p5KindDecrement sums the settled reconcile keys per charge kind
// (the µUSD that left each scope reserve via the settlement worker).
func n06p5KindDecrement(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) map[string]int64 {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT charge_kind, COALESCE(SUM((payload->>'`+budget.ReconcileSettleKey+`')::bigint), 0)
		FROM settlement_jobs
		WHERE org_id = $1 AND status = 'settled'
		GROUP BY charge_kind`, org)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var kind string
		var dec int64
		require.NoError(t, rows.Scan(&kind, &dec))
		out[kind] = dec
	}
	require.NoError(t, rows.Err())
	return out
}

// n06p5AllowanceScope reads (granted, returned, status) of one scope's
// allowance row for the org's replica.
func n06p5AllowanceScope(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org, scope string) (granted, returned int64, status string) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT granted_micro_usd, returned_micro_usd, status
		FROM budget_allowances WHERE org_id = $1 AND scope_kind = $2`,
		org, scope).Scan(&granted, &returned, &status))
	return granted, returned, status
}

// TestN06P05LiveConsumer_RecoveryThenSettleIsLedgerOnly: a replica crashed
// after the delivery committed its four settlement intents but before the
// worker ticked. Recovery (CloseAbandonedReplica) returns every reserve;
// the late settle must then degrade to ledger-only — jobs settle with the
// exact charge, but no reserve decrement and no reconcile key ever lands,
// the ledger carries exactly one usage row, and a second tick is a no-op.
func TestN06P05LiveConsumer_RecoveryThenSettleIsLedgerOnly(t *testing.T) {
	// Sequential by design: seedNext18dWorld resets the shared team/agent/
	// session spend rows, so consumer live tests must not overlap.
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgEnf, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p5-recovery", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("n06p5-rec-1", "req-n06p5-recovery", n18dOrgEnf, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrgEnf), "one intent per reserve scope")

	// The replica dies before the worker ever sees the intents.
	n06p5ForceCrashShape(ctx, t, pool, n18dOrgEnf)

	store := budget.NewReservationStore(pool, silentLogger())
	sum, err := store.CloseAbandonedReplica(ctx, "replica-"+n18dOrgEnf, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4), sum.Closed, "recovery closes every scope row")
	require.Equal(t, int64(48_000), sum.ReturnedMicroUSD, "4 × 12_000 µUSD return exactly once")

	// The reserves are back to zero; the allowances are released.
	walletRes, teamRes, teamSpend, agentRes, agentCost, sessRes, sessSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, walletRes)
	assert.Zero(t, teamRes)
	assert.Zero(t, agentRes)
	assert.Zero(t, sessRes)
	assert.Zero(t, teamSpend, "recovery never records spend")
	assert.Zero(t, agentCost)
	assert.Zero(t, sessSpent)
	require.Zero(t, ledgerRows, "recovery never charges the ledger")

	// The late settle: ledger-only for every scope.
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	var settled, withKey int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'settled'),
		       count(*) FILTER (WHERE payload ? $2)
		FROM settlement_jobs WHERE org_id = $1`, n18dOrgEnf, budget.ReconcileSettleKey).Scan(&settled, &withKey))
	assert.Equal(t, int64(4), settled, "every intent settles despite the released allowances")
	assert.Zero(t, withKey, "a post-recovery settle leaves NO reconcile key — ledger-only")

	walletRes, teamRes, teamSpend, agentRes, agentCost, sessRes, sessSpent, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, walletRes, "no reserve moves after recovery")
	assert.Zero(t, teamRes)
	assert.Zero(t, agentRes)
	assert.Zero(t, sessRes)
	assert.Equal(t, int64(fx.bound), teamSpend, "exact spend still recorded")
	assert.Equal(t, int64(fx.bound), agentCost)
	assert.Equal(t, int64(fx.bound), sessSpent)
	assert.Equal(t, int64(1), ledgerRows, "exactly one wallet usage row")
	assert.Equal(t, -int64(fx.bound), ledgerMicro, "the exact charge lands once")

	for _, scope := range []string{"wallet", "team_month", "agent_day", "session"} {
		granted, returned, status := n06p5AllowanceScope(ctx, t, pool, n18dOrgEnf, scope)
		assert.Equal(t, "released", status, "scope %s", scope)
		assert.Equal(t, granted, returned, "scope %s: recovery returned the full escrow once", scope)
	}

	// Idempotent tail: the settled queue never re-bills.
	w.tick(ctx)
	_, _, teamSpend2, _, agentCost2, _, sessSpent2, ledgerRows2, ledgerMicro2 := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, teamSpend, teamSpend2)
	assert.Equal(t, agentCost, agentCost2)
	assert.Equal(t, sessSpent, sessSpent2)
	assert.Equal(t, ledgerRows, ledgerRows2)
	assert.Equal(t, ledgerMicro, ledgerMicro2)
}

// TestN06P05LiveConsumer_RecoverySettleRaceExactOnce: recovery and the
// settlement worker race over the same crashed replica's reserves — the
// union of both money writers must equal the granted escrow exactly once
// per scope, whichever wins each row. The reserves end at zero, the ledger
// charges exactly once, and a trailing tick is a no-op.
func TestN06P05LiveConsumer_RecoverySettleRaceExactOnce(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgEnf, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p5-race", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("n06p5-race-1", "req-n06p5-race", n18dOrgEnf, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrgEnf))

	n06p5ForceCrashShape(ctx, t, pool, n18dOrgEnf)

	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	store := budget.NewReservationStore(pool, silentLogger())

	var (
		wg     sync.WaitGroup
		sum    budget.AbandonedReplicaSummary
		errRec error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		sum, errRec = store.CloseAbandonedReplica(ctx, "replica-"+n18dOrgEnf, 0)
	}()
	// The worker ticks while recovery runs — rows are won interleaved.
	for i := 0; i < 100; i++ {
		w.tick(ctx)
		var left int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM settlement_jobs
			 WHERE org_id = $1 AND status IN ('pending','retry','processing')`, n18dOrgEnf).Scan(&left))
		if left == 0 {
			break
		}
	}
	wg.Wait()
	require.NoError(t, errRec)
	require.Equal(t, int64(4), sum.Closed+sum.AlreadyReleased,
		"recovery visited every row: each was closed by recovery or already released")

	// Per-scope union: recovery's return + the settle's decrement equals
	// the granted escrow exactly once, whatever the interleaving.
	decs := n06p5KindDecrement(ctx, t, pool, n18dOrgEnf)
	for _, pair := range []struct{ scope, kind string }{
		{"wallet", ChargeKindResaleDeduction},
		{"team_month", ChargeKindTeamSpend},
		{"agent_day", ChargeKindAgentSpend},
		{"session", ChargeKindSessionSpend},
	} {
		granted, returned, status := n06p5AllowanceScope(ctx, t, pool, n18dOrgEnf, pair.scope)
		assert.Equal(t, "released", status, "scope %s must be released by exactly one side", pair.scope)
		assert.Equal(t, granted, returned+decs[pair.kind],
			"scope %s: returned (%d) + settled decrement (%d) == granted (%d)",
			pair.scope, returned, decs[pair.kind], granted)
	}

	walletRes, teamRes, teamSpend, agentRes, agentCost, sessRes, sessSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, walletRes, "no reserve left after both writers")
	assert.Zero(t, teamRes)
	assert.Zero(t, agentRes)
	assert.Zero(t, sessRes)
	assert.Equal(t, int64(fx.bound), teamSpend)
	assert.Equal(t, int64(fx.bound), agentCost)
	assert.Equal(t, int64(fx.bound), sessSpent)
	assert.Equal(t, int64(1), ledgerRows, "exactly one wallet usage row across both writers")
	assert.Equal(t, -int64(fx.bound), ledgerMicro)

	var settled int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM settlement_jobs WHERE org_id = $1 AND status = 'settled'`, n18dOrgEnf).Scan(&settled))
	assert.Equal(t, int64(4), settled)

	// Idempotent tail: a trailing tick moves nothing.
	w.tick(ctx)
	_, _, teamSpend2, _, agentCost2, _, sessSpent2, ledgerRows2, ledgerMicro2 := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, teamSpend, teamSpend2)
	assert.Equal(t, agentCost, agentCost2)
	assert.Equal(t, sessSpent, sessSpent2)
	assert.Equal(t, ledgerRows, ledgerRows2)
	assert.Equal(t, ledgerMicro, ledgerMicro2)
}
