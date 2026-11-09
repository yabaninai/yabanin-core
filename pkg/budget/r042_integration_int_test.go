//go:build integration

// D1–D3): the full crash→restart→sweep→reclaim→idempotent-second-pass
// cycle on a disposable live Postgres, driven through the ACTUAL entry
// points from the contract — a fresh Admission controller booting on
// the crashed host (the gateway's one-call startup seam) and the full
// ReconcileWorker.Tick machinery (release + invariants + lag +
// retention). Package criterion: «повтор reconciliation не меняет уже
// согласованный баланс» — the second full pass over the
// already-reconciled state leaves every money row byte-identical.
package budget

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// r042MoneySnapshot captures every money row of the world: the wallet
// (org_credits) plus the status ledger of its allowance rows.
type r042MoneySnapshot struct {
	balanceCents   int64
	remainderMicro int64
	reservedMicro  int64
	allowances     map[string]string // replica -> status
}

func r042Snapshot(t *testing.T, pool *pgxpool.Pool, org string) r042MoneySnapshot {
	t.Helper()
	var s r042MoneySnapshot
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT balance_cents, remainder_micro_usd, reserved_micro_usd FROM org_credits WHERE org_id = $1`, org).
		Scan(&s.balanceCents, &s.remainderMicro, &s.reservedMicro))
	rows, err := pool.Query(context.Background(),
		`SELECT replica_id, status FROM budget_allowances WHERE org_id = $1 ORDER BY replica_id`, org)
	require.NoError(t, err)
	defer rows.Close()
	s.allowances = map[string]string{}
	for rows.Next() {
		var replica, status string
		require.NoError(t, rows.Scan(&replica, &status))
		s.allowances[replica] = status
	}
	require.NoError(t, rows.Err())
	return s
}

func TestR042Integration_CrashRestartSweepReclaimIdempotentSecondPass(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-r042i-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 1_000_000, nil) // $10 000
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	grant := func(replica string, bound int64, backdate string) {
		g, err := store.Grant(ctx, replica, org, []GrantRequest{
			{Scope: ScopeWallet, Key: org, Bound: money.MicroUSD(bound)},
		})
		require.NoError(t, err)
		if backdate != "" {
			_, err = pool.Exec(ctx,
				`UPDATE budget_allowances SET lease_until = now() - $2::interval WHERE id = $1`,
				g[0].AllowanceID, backdate)
			require.NoError(t, err)
		}
	}
	crashed := "gwbox-4242-1699999999999999999"
	sibling := "gwbox-7777-1700000000000000000"
	foreign := "otherbox-111-1699999999999999999"
	grant(crashed, 600_000, "15 minutes") // the crashed predecessor (D1: killed -9)
	grant(sibling, 200_000, "")           // live sibling renewing on the same host
	grant(foreign, 300_000, "15 minutes") // crashed incarnation of a foreign host

	// Crash state: 1.1Mµ frozen.
	require.Equal(t, int64(1_100_000), walletState(t, pool, org))
	reaper := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())

	// --- Restart: a FRESH incarnation boots on gwbox and sweeps its own
	// crashed predecessors through the one-call startup seam (D1/D2).
	restart := func(tag string) int64 {
		a := NewAdmission(store, ScopedRateSource{}, newBudgetTestLogger(),
			"gwbox-"+tag+"-1700000000000000001", ModeEnforce, nil, DefaultAdmissionConfig())
		t.Cleanup(a.Stop)
		n, err := a.ReapCrashedPredecessors(ctx)
		require.NoError(t, err)
		return n
	}
	require.Equal(t, int64(1), restart("9001"), "the replacement reaps exactly its crashed predecessor")
	assert.Equal(t, AllowanceDraining, r042Status(t, pool, org, crashed))
	assert.Equal(t, AllowanceActive, r042Status(t, pool, org, sibling))
	assert.Equal(t, AllowanceActive, r042Status(t, pool, org, foreign))

	// Full reconcile tick INSIDE the safety window: the drained row holds
	// a remainder, so nothing releases (D3) — the sweep accelerated the
	// status transition, never the money.
	reaper.Tick(ctx)
	require.Equal(t, int64(1_100_000), walletState(t, pool, org), "escrow still frozen inside the window (D3)")

	// --- Reclaim: the safety window elapses; the SAME machinery returns
	// the crashed incarnation's escrow exactly once.
	_, err := pool.Exec(ctx, `UPDATE budget_allowances SET lease_until = now() - interval '2 hours 15 minutes'
		WHERE replica_id = $1`, crashed)
	require.NoError(t, err)
	summary, err := reaper.ReleasePass(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), summary.Released)
	require.Equal(t, int64(600_000), summary.ReturnedMicroUSD, "the frozen remainder returned exactly once")
	require.Equal(t, int64(500_000), walletState(t, pool, org), "sibling + foreign escrow untouched")
	assert.Equal(t, AllowanceReleased, r042Status(t, pool, org, crashed))

	// --- Idempotent second pass (package criterion): a SECOND restart
	// sweeps nothing, a SECOND full reconcile tick (release + invariants
	// + lag + retention) changes nothing — every money row byte-identical.
	before := r042Snapshot(t, pool, org)
	require.Zero(t, restart("9002"), "second restart reaps nothing")
	reaper.Tick(ctx)
	summary, err = reaper.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, summary.Released, "second release pass releases nothing")
	assert.Zero(t, summary.ReturnedMicroUSD)
	after := r042Snapshot(t, pool, org)
	assert.Equal(t, before, after, "повтор reconciliation не меняет уже согласованный баланс")
	assert.Equal(t, int64(500_000), walletState(t, pool, org))
	assert.Equal(t, AllowanceActive, r042Status(t, pool, org, sibling), "the live sibling keeps serving")
	assert.Equal(t, AllowanceActive, r042Status(t, pool, org, foreign), "the foreign host stays foreign (D2)")
}
