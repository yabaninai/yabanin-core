//go:build integration

// 2026-10-18: D1 automatic reconciliation at replica startup, D2 sweep own
// replica only, D3 the 2h safety window stays): the startup self-reap
// sweep flips a crashed previous incarnation's lapsed-lease allowances to
// draining, never touches live siblings or foreign hosts, keeps the safety
// window for frozen escrow, and a second restart (or a second full
// reconcile pass) is a verified no-op.
package budget

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// r042World seeds one crash scenario: a dead incarnation on the swept host
// (lapsed lease, still active), a live sibling on the same host (fresh
// lease) and a dead incarnation on a foreign host (lapsed lease). Every
// row holds its full grant in the wallet reserve.
type r042World struct {
	org          string
	pool         *pgxpool.Pool
	crashedID    string
	siblingID    string
	foreignID    string
	crashedGrant int64
}

func seedR042World(t *testing.T, lapsedLease string) r042World {
	t.Helper()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-r042-" + uuid.NewString()[:8]
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

	grant("gwbox-4242-1699999999999999999", 600_000, lapsedLease)
	grant("gwbox-7777-1700000000000000000", 200_000, "")
	grant("otherbox-111-1699999999999999999", 300_000, lapsedLease)
	return r042World{
		org:          org,
		pool:         pool,
		crashedID:    "gwbox-4242-1699999999999999999",
		siblingID:    "gwbox-7777-1700000000000000000",
		foreignID:    "otherbox-111-1699999999999999999",
		crashedGrant: 600_000,
	}
}

func r042Status(t *testing.T, pool *pgxpool.Pool, org, replica string) string {
	t.Helper()
	_, _, _, status, _ := allowanceRow(t, pool, replica, ScopeWallet, org, "")
	return status
}

// The main scenario: crash → restart sweep → escrow reclaimed through the
// safety window → second restart is a no-op, and a second full reconcile
// criterion).
func TestR042SelfReap_CrashRestartReclaimsEscrowSecondRestartNoop(t *testing.T) {
	w := seedR042World(t, "15 minutes")
	pool, org := w.pool, w.org
	store := newReservationStore(pool)
	ctx := context.Background()
	reaper := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())

	// Crash state: 1.1M frozen (600k dead own-host + 200k live sibling +
	// 300k dead foreign host).
	require.Equal(t, int64(1_100_000), walletState(t, pool, org))

	// --- Restart 1: the sweep flips ONLY the own-host crashed incarnation.
	n, err := store.SelfReapCrashedIncarnations(ctx, "gwbox")
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "exactly the crashed own-host incarnation is reaped")
	assert.Equal(t, AllowanceDraining, r042Status(t, pool, org, w.crashedID))
	assert.Equal(t, AllowanceActive, r042Status(t, pool, org, w.siblingID), "live sibling untouched")
	assert.Equal(t, AllowanceActive, r042Status(t, pool, org, w.foreignID), "foreign host untouched (D2)")

	// D3: the safety window still governs — the drained row holds a
	// remainder and its lease lapsed only 15 min ago, so a reconcile pass
	// releases nothing yet.
	summary, err := reaper.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, summary.Released, "no release inside the safety window (D3)")
	require.Equal(t, int64(1_100_000), walletState(t, pool, org), "escrow still frozen")

	// The safety window elapses (lease lapsed past 2h): the SAME reconcile
	// machinery returns the crashed incarnation's remainder exactly once.
	_, err = pool.Exec(ctx, `UPDATE budget_allowances SET lease_until = now() - interval '2 hours 15 minutes'
		WHERE replica_id = $1`, w.crashedID)
	require.NoError(t, err)
	summary, err = reaper.ReleasePass(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), summary.Released, "the crashed escrow is reclaimed")
	require.Equal(t, int64(w.crashedGrant), summary.ReturnedMicroUSD, "the full frozen remainder returned")
	require.Equal(t, int64(500_000), walletState(t, pool, org), "only the sibling + foreign escrow stay frozen")
	assert.Equal(t, AllowanceReleased, r042Status(t, pool, org, w.crashedID))

	// --- Restart 2: the sweep is a no-op (nothing active with a lapsed
	// lease on the own host), and a second full reconcile pass changes
	// nothing — the package criterion «повтор reconciliation не меняет
	// уже согласованный баланс».
	reapedBefore := testutil.ToFloat64(metrics.BudgetSelfReapedAllowances)
	n, err = store.SelfReapCrashedIncarnations(ctx, "gwbox")
	require.NoError(t, err)
	assert.Zero(t, n, "second restart reaps nothing")
	assert.InDelta(t, reapedBefore, testutil.ToFloat64(metrics.BudgetSelfReapedAllowances), 0.001)

	summary, err = reaper.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, summary.Released, "second release pass releases nothing")
	assert.Zero(t, summary.ReturnedMicroUSD)
	require.Equal(t, int64(500_000), walletState(t, pool, org), "already-reconciled balance unchanged")
	assert.Equal(t, AllowanceActive, r042Status(t, pool, org, w.siblingID))
	assert.Equal(t, AllowanceActive, r042Status(t, pool, org, w.foreignID))
}

// The immediate win of the sweep: a crashed incarnation whose in-flight
// cost fully settled (zero remainder left) releases on the FIRST reconcile
// tick after the sweep instead of waiting out the safety window (§7.1.2).
func TestR042SelfReap_ZeroRemainderReleasesOnNextTick(t *testing.T) {
	w := seedR042World(t, "15 minutes")
	pool, org := w.pool, w.org
	store := newReservationStore(pool)
	ctx := context.Background()

	// The crashed incarnation's request settled everything it had frozen:
	// a settled job carries the §5.3 settle-decrement and the wallet
	// reserve already dropped by the same amount.
	id, _, _, _, _ := allowanceRow(t, pool, w.crashedID, ScopeWallet, org, "")
	_, err := pool.Exec(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, allowance_id, payload, status)
		VALUES ($1, $2, 'wallet', $3, $4::jsonb, 'settled')`,
		org, "req-r042-zero-"+uuid.NewString(), id,
		`{"settle_decrement_micro_usd": 600000}`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`UPDATE org_credits SET reserved_micro_usd = reserved_micro_usd - 600000 WHERE org_id = $1`, org)
	require.NoError(t, err)

	n, err := store.SelfReapCrashedIncarnations(ctx, "gwbox")
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	reaper := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	summary, err := reaper.ReleasePass(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), summary.Released, "zero-remainder drained row releases immediately")
	require.Equal(t, int64(1), summary.ZeroRemainderReleased)
	require.Zero(t, summary.ReturnedMicroUSD, "nothing left to return")
	assert.Equal(t, AllowanceReleased, r042Status(t, pool, org, w.crashedID))
	// 1.1M − 600k settled = 500k still frozen for the sibling + foreign row.
	require.Equal(t, int64(500_000), walletState(t, pool, org))
}

// The Admission seam (the gateway's one-call wiring point): the startup
// sweep derives the host family from the controller's own replica id, so
// the replacement process reaps exactly its crashed predecessor.
func TestR042Admission_ReapCrashedPredecessors(t *testing.T) {
	w := seedR042World(t, "15 minutes")
	pool, org := w.pool, w.org
	ctx := context.Background()

	a := NewAdmission(newReservationStore(pool), ScopedRateSource{}, newBudgetTestLogger(),
		"gwbox-9999-1700000000000000001", ModeEnforce, nil, DefaultAdmissionConfig())
	t.Cleanup(a.Stop)

	n, err := a.ReapCrashedPredecessors(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "the predecessor on the same host is reaped")
	assert.Equal(t, AllowanceDraining, r042Status(t, pool, org, w.crashedID))
	assert.Equal(t, AllowanceActive, r042Status(t, pool, org, w.siblingID), "the live sibling untouched")
	assert.Equal(t, AllowanceActive, r042Status(t, pool, org, w.foreignID))

	// Idempotent: a second call on the same process reaps nothing.
	n, err = a.ReapCrashedPredecessors(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
}
