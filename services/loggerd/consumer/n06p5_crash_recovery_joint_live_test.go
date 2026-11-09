//go:build integration

// N06-P05-T06 joint crash-recovery scenario at the consumer boundary
// (disposable PG+Redis, ADR-0001 §10): a REAL settlement worker run loop
// claims the intents of one completed request and dies mid-batch (the
// process-kill analogue), the restarted instance recovers the expired
// claims through the production lease-recovery pass and settles exactly
// once, and the reconcile pass closes the loop to terminal 'released' —
// "восстановление сходится к одному ledger без вечных reservations".
//
// Real production paths under test: processMessage, SettlementWorker.Run/
// tick, recoverExpiredLeases, the §5.5 org batch (SettleOrgBatch), the
// §7.1.1/§7.1.2 reconcile release pass, and the fenced abandoned-replica
// verdict (N06-P05). Test-forced states are limited to:
//   - the per-org advisory gate (a production money-writer lock used for
//     scheduling only — it parks the batch executor mid-flight deterministically),
//   - context cancellation (the executor death),
//   - allowance-lease backdating (the wall-clock force past the §14 safety
//     window, same technique as T05; money columns are never touched).
//
// Complements T05 (hand-shaped crash worlds, verdict races) with the one
// shape no other test produces: settlement_jobs claimed by a real worker
// that then dies, and the full restart → settle → reconcile convergence.
package consumer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n06p5JointConsumer builds a consumer wired exactly like production: real
// Redis ops, real DB ops, the real agent spender and the real credit store.
func n06p5JointConsumer(rdb *redis.Client, pool *pgxpool.Pool, stream string) *StreamConsumer {
	c := New(NewRedisOps(rdb), NewDBOps(pool), stream, silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	return c
}

// n06p5JointHoldOrgGate takes the per-org advisory lock every settlement
// money writer serializes on (§5.3: the same key as DeductMicro, Grant,
// SettleDecrement and SettleOrgBatch) on a dedicated pooled connection.
// pg_advisory_lock returns VOID, so the result is not scanned — and the
// returned release is idempotent and registered as cleanup: a failed test
// must never leave a locked pooled connection behind (the pool is shared
// across the binary's tests, and a leaked session lock would deadlock the
// next gate holder on the same org).
func n06p5JointHoldOrgGate(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) func() {
	t.Helper()
	gate, err := pool.Acquire(ctx)
	require.NoError(t, err)
	var once sync.Once
	release := func() {
		once.Do(func() {
			// Best-effort unlock on a live background context: the session
			// must not carry the lock back into the pool.
			_, _ = gate.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext($1)::bigint)`, org)
			gate.Release()
		})
	}
	t.Cleanup(release)
	_, err = gate.Exec(ctx, `SELECT pg_advisory_lock(hashtext($1)::bigint)`, org)
	require.NoError(t, err)
	return release
}

// n06p5JointCrashMidClaim drives the REAL Run loop against the held gate:
// the worker claims every intent (jobs → 'processing', claim leases live),
// then blocks inside SettleOrgBatch on the per-org lock — the deterministic
// mid-batch position — and is cancelled (the process-kill analogue). The
// in-flight batch transaction aborts; the per-job fallback cannot commit on
// a dead context, so no money ever moves. Returns with the crashed shape in
// place and the gate released.
func n06p5JointCrashMidClaim(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string, w *SettlementWorker) {
	t.Helper()
	releaseGate := n06p5JointHoldOrgGate(ctx, t, pool, org)

	runCtx, crash := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.Run(runCtx) // Run returns nil on cancellation
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		var processing int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM settlement_jobs WHERE org_id = $1 AND status = 'processing'`, org).
			Scan(&processing))
		if processing == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the worker did not claim the four intents in time")
		}
		time.Sleep(10 * time.Millisecond)
	}

	crash()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the crashed worker did not stop")
	}
	releaseGate()
}

// n06p5JointAwaitExpiredLeases waits until `want` claimed jobs of the org
// hold lapsed claim leases — the exact state the production
// recoverExpiredLeases pass recovers (§5: a dead executor's leases expire).
func n06p5JointAwaitExpiredLeases(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string, want int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var expired int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM settlement_jobs
			 WHERE org_id = $1 AND status = 'processing' AND lease_until < now()`, org).
			Scan(&expired))
		if expired == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("claim leases did not lapse in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestN06P05JointLive_CrashMidFlightRestartConvergesOneLedger: the replica
// dies mid-batch (real Run loop, claims held, batch parked on the org lock).
// Recovery refuses to touch the live world while the claims are young (the
// fail-closed guard against a REAL mid-flight state, not a hand-shaped one);
// once the claim leases lapse, a fresh worker instance recovers them through
// the production lease-recovery pass and settles exactly once (attempts 2,
// one ledger row, reserves released by the settle keys); the reconcile pass
// then releases the fully-settled allowances as zero-remainder rows — no
// eternal reservations — and every trailing pass is a no-op.
func TestN06P05JointLive_CrashMidFlightRestartConvergesOneLedger(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgEnf, 1000)

	// Phase 1 — real ingest: the completed event reserves and intends.
	c := n06p5JointConsumer(rdb, pool, "events:n06p5-joint-crash")
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("n06p5-jc-1", "req-n06p5-joint-crash", n18dOrgEnf, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrgEnf), "one intent per reserve scope")

	walletRes, teamRes, teamSpend, agentRes, agentCost, sessRes, sessSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, int64(fx.bound)*4, walletRes+teamRes+agentRes+sessRes, "4 scopes × 12_000 µUSD reserved")
	assert.Zero(t, teamSpend)
	assert.Zero(t, agentCost)
	assert.Zero(t, sessSpent)
	assert.Zero(t, ledgerRows)
	assert.Zero(t, ledgerMicro)

	// Phase 2 — the real worker dies mid-batch.
	wA := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	n06p5JointCrashMidClaim(ctx, t, pool, n18dOrgEnf, wA)

	// Phase 3 — the crashed shape: all four claimed with live claim leases,
	// nothing settled, no reconcile key, no money moved.
	var processing, liveLease, firstAttempt, settled, withKey int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'processing'),
		       count(*) FILTER (WHERE status = 'processing' AND lease_until > now()),
		       count(*) FILTER (WHERE status = 'processing' AND attempts = 1),
		       count(*) FILTER (WHERE status = 'settled'),
		       count(*) FILTER (WHERE payload ? $2)
		FROM settlement_jobs WHERE org_id = $1`, n18dOrgEnf, budget.ReconcileSettleKey).
		Scan(&processing, &liveLease, &firstAttempt, &settled, &withKey))
	assert.Equal(t, int64(4), processing, "every intent is claimed")
	assert.Equal(t, int64(4), liveLease, "every claim lease is still live")
	assert.Equal(t, int64(4), firstAttempt, "exactly one claim per job")
	assert.Zero(t, settled, "the crashed batch settled nothing")
	assert.Zero(t, withKey)

	walletRes, teamRes, teamSpend, agentRes, agentCost, sessRes, sessSpent, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, int64(fx.bound)*4, walletRes+teamRes+agentRes+sessRes, "reserves intact through the crash")
	assert.Zero(t, teamSpend)
	assert.Zero(t, agentCost)
	assert.Zero(t, sessSpent)
	assert.Zero(t, ledgerRows, "the ledger carries nothing yet")

	// Phase 3b — recovery refuses the LIVE world (fail-closed on a real
	// mid-flight state): the claims are young, so neither the unfenced
	// verdict (window floored to the §14 default) nor the fenced variant
	// with the 30-minute override may release anything.
	store := budget.NewReservationStore(pool, silentLogger())
	sum, err := store.CloseAbandonedReplica(ctx, "replica-"+n18dOrgEnf, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(4), sum.SkippedLive, "every row is guarded as live")
	assert.Zero(t, sum.Closed)
	assert.Zero(t, sum.ReturnedMicroUSD)
	assert.Zero(t, sum.AlreadyReleased)

	fence := budget.NewRecoveryFence(pool, silentLogger())
	lease, err := fence.Acquire(ctx, "replica-"+n18dOrgEnf, "joint-operator", 5*time.Minute)
	require.NoError(t, err)
	fsum, err := store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(4), fsum.SkippedLive, "the fenced override cannot touch young live leases either")
	assert.Zero(t, fsum.Closed)
	assert.Zero(t, fsum.ReturnedMicroUSD)
	require.NoError(t, lease.Release(ctx))

	// Phase 4 — the claims lapse (LeaseTTL is the worker's own config), a
	// fresh worker instance recovers and settles exactly once.
	n06p5JointAwaitExpiredLeases(ctx, t, pool, n18dOrgEnf, 4)
	wB := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	wB.tick(ctx) // recoverExpiredLeases → retry(next=now) → claim → §5.5 batch settle

	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'settled'),
		       count(*) FILTER (WHERE status = 'settled' AND attempts = 2),
		       count(*) FILTER (WHERE status = 'settled' AND payload ? $2),
		       count(*) FILTER (WHERE status IN ('pending','retry','processing'))
		FROM settlement_jobs WHERE org_id = $1`, n18dOrgEnf, budget.ReconcileSettleKey).
		Scan(&settled, &firstAttempt, &withKey, &processing))
	assert.Equal(t, int64(4), settled, "the restart settles every recovered intent")
	assert.Equal(t, int64(4), firstAttempt, "attempt 2 = recovered claim + settled claim")
	assert.Equal(t, int64(4), withKey, "every reserve-linked settle carries its reconcile key")
	assert.Zero(t, processing, "the queue is empty")

	walletRes, teamRes, teamSpend, agentRes, agentCost, sessRes, sessSpent, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, walletRes+teamRes+agentRes+sessRes, "the settle released every reserve exactly once")
	assert.Equal(t, int64(fx.bound), teamSpend)
	assert.Equal(t, int64(fx.bound), agentCost)
	assert.Equal(t, int64(fx.bound), sessSpent)
	assert.Equal(t, int64(1), ledgerRows, "one ledger row for the crashed-and-recovered request")
	assert.Equal(t, -int64(fx.bound), ledgerMicro)

	// Per-scope union after the restart: returned(0) + settled(key) must
	// equal the granted escrow exactly once per allowance.
	rows, err := pool.Query(ctx, `
		SELECT a.scope_kind, a.granted_micro_usd, a.returned_micro_usd,
		       COALESCE((j.payload->>$2)::bigint, 0)
		FROM budget_allowances a
		LEFT JOIN settlement_jobs j ON j.allowance_id = a.id AND j.status = 'settled'
		WHERE a.org_id = $1`, n18dOrgEnf, budget.ReconcileSettleKey)
	require.NoError(t, err)
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var scope string
		var granted, returned, dec int64
		require.NoError(t, rows.Scan(&scope, &granted, &returned, &dec))
		assert.Equal(t, int64(fx.bound), granted, "scope %s", scope)
		assert.Equal(t, granted, returned+dec, "scope %s: returned + settled == granted exactly once", scope)
		seen++
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, 4, seen, "all four allowances audited")

	// Phase 5 — convergence: past the §14 safety window the reconcile pass
	// releases the fully-settled allowances as zero-remainder rows (the
	// settle already moved their money; nothing is left to return) — no
	// eternal reservations.
	tag, err := pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - interval '3 hours' WHERE org_id = $1`, n18dOrgEnf)
	require.NoError(t, err)
	require.Equal(t, int64(4), tag.RowsAffected(), "org %s must hold four allowances", n18dOrgEnf)

	reconciler := budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig())
	relSum, err := reconciler.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(4), relSum.Released)
	assert.Zero(t, relSum.ReturnedMicroUSD, "nothing left to return — the settle already released it")
	assert.Equal(t, int64(4), relSum.ZeroRemainderReleased)
	assert.Zero(t, relSum.ExpiredSafetyReleased)

	var released, liveRemainder, lapsedNonReleased int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM budget_allowances WHERE org_id = $1 AND status = 'released'`, n18dOrgEnf).
		Scan(&released))
	assert.Equal(t, int64(4), released, "every allowance reached the terminal state")
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(GREATEST(a.granted_micro_usd - a.returned_micro_usd - COALESCE(s.settled, 0), 0)), 0)
		FROM budget_allowances a
		LEFT JOIN LATERAL (
			SELECT COALESCE(SUM((j.payload->>$2)::bigint), 0) AS settled
			FROM settlement_jobs j
			WHERE j.allowance_id = a.id AND j.status = 'settled'
		) s ON TRUE
		WHERE a.org_id = $1 AND a.status <> 'released'`, n18dOrgEnf, budget.ReconcileSettleKey).
		Scan(&liveRemainder))
	assert.Zero(t, liveRemainder, "no stranded remainder outside the released rows")
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM budget_allowances
		WHERE org_id = $1 AND status <> 'released' AND lease_until < now()`, n18dOrgEnf).
		Scan(&lapsedNonReleased))
	assert.Zero(t, lapsedNonReleased, "no eternal reservations: nothing non-released stays past due")

	// The full production reconcile pass (release + invariants + lag) is a
	// no-op on the converged world.
	reconciler.Tick(ctx)
	relSum2, err := reconciler.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, relSum2.Released)
	assert.Zero(t, relSum2.ReturnedMicroUSD)
	assert.Zero(t, relSum2.ZeroRemainderReleased)
	assert.Zero(t, relSum2.ExpiredSafetyReleased)

	// Idempotent tails: extra worker and reconcile passes move nothing.
	wB.tick(ctx)
	reconciler.Tick(ctx)
	_, _, teamSpend2, _, agentCost2, _, sessSpent2, ledgerRows2, ledgerMicro2 := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, teamSpend, teamSpend2)
	assert.Equal(t, agentCost, agentCost2)
	assert.Equal(t, sessSpent, sessSpent2)
	assert.Equal(t, ledgerRows, ledgerRows2, "the ledger keeps exactly one row")
	assert.Equal(t, ledgerMicro, ledgerMicro2)
}

// TestN06P05JointLive_FencedTakeoverAfterRealCrashLedgerOnlyLateSettle: the
// packet's joint example on a REAL crashed world — a replica dies mid-batch
// and is declared permanently lost, the fenced takeover returns its escrow
// exactly once, a stale (released) lease is rejected at the consumer seam,
// and the late restart settle degrades to ledger-only (money already
// returned): one ledger row, no reserve decrement, no reconcile keys, no
// second return.
func TestN06P05JointLive_FencedTakeoverAfterRealCrashLedgerOnlyLateSettle(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgEnf, 1000)

	c := n06p5JointConsumer(rdb, pool, "events:n06p5-joint-fence")
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("n06p5-jf-1", "req-n06p5-joint-fence", n18dOrgEnf, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrgEnf))

	// The real crash: claims held, batch parked, executor dead.
	wA := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	n06p5JointCrashMidClaim(ctx, t, pool, n18dOrgEnf, wA)

	var processing, settled int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'processing'),
		       count(*) FILTER (WHERE status = 'settled')
		FROM settlement_jobs WHERE org_id = $1`, n18dOrgEnf).Scan(&processing, &settled))
	assert.Equal(t, int64(4), processing)
	assert.Zero(t, settled, "the crash committed nothing")

	// The replica is declared permanently lost: force its allowance leases
	// past the §14 window (wall-clock force; money columns untouched).
	tag, err := pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - interval '3 hours' WHERE org_id = $1`, n18dOrgEnf)
	require.NoError(t, err)
	require.Equal(t, int64(4), tag.RowsAffected())

	// Fenced takeover (packet example 1): the operator's fenced verdict
	// returns the lapsed escrow exactly once.
	store := budget.NewReservationStore(pool, silentLogger())
	fence := budget.NewRecoveryFence(pool, silentLogger())
	lease, err := fence.Acquire(ctx, "replica-"+n18dOrgEnf, "operator-B", 5*time.Minute)
	require.NoError(t, err)
	fsum, err := store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(4), fsum.Closed, "the takeover closes every scope row")
	assert.Equal(t, int64(48_000), fsum.ReturnedMicroUSD, "4 × 12_000 µUSD returned exactly once")
	assert.Zero(t, fsum.SkippedLive)
	assert.Zero(t, fsum.AlreadyReleased)

	_, _, teamSpend, _, agentCost, _, sessSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, teamSpend)
	assert.Zero(t, agentCost)
	assert.Zero(t, sessSpent)
	assert.Zero(t, ledgerRows, "recovery never charges the ledger")
	assert.Zero(t, ledgerMicro)
	for _, scope := range []string{"wallet", "team_month", "agent_day", "session"} {
		granted, returned, status := n06p5AllowanceScope(ctx, t, pool, n18dOrgEnf, scope)
		assert.Equal(t, "released", status, "scope %s", scope)
		assert.Equal(t, granted, returned, "scope %s: the full escrow returned once", scope)
	}

	// Stale-lease rejection (packet example 2, consumer seam): a released
	// lease may present no verdict, and no money moves on the attempt.
	require.NoError(t, lease.Release(ctx))
	_, err = store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.ErrorIs(t, err, budget.ErrStaleRecoveryFence)
	_, _, teamSpend2, _, agentCost2, _, sessSpent2, ledgerRows2, ledgerMicro2 := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, teamSpend2)
	assert.Zero(t, agentCost2)
	assert.Zero(t, sessSpent2)
	assert.Zero(t, ledgerRows2)
	assert.Zero(t, ledgerMicro2)

	// The late restart: the expired claims recover and settle LEDGER-ONLY —
	// the allowances are already released, so the settle records the exact
	// charges but never touches the reserves and writes no reconcile key.
	n06p5JointAwaitExpiredLeases(ctx, t, pool, n18dOrgEnf, 4)
	wB := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	wB.tick(ctx)

	var settledNow, withKey, processingLeft int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'settled'),
		       count(*) FILTER (WHERE status = 'settled' AND payload ? $2),
		       count(*) FILTER (WHERE status IN ('pending','retry','processing'))
		FROM settlement_jobs WHERE org_id = $1`, n18dOrgEnf, budget.ReconcileSettleKey).
		Scan(&settledNow, &withKey, &processingLeft))
	assert.Equal(t, int64(4), settledNow, "every recovered intent settles despite the released allowances")
	assert.Zero(t, withKey, "a post-recovery settle leaves NO reconcile key — ledger-only")
	assert.Zero(t, processingLeft)

	walletRes, teamRes, teamSpend3, agentRes, agentCost3, sessRes, sessSpent3, ledgerRows3, ledgerMicro3 := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, walletRes+teamRes+agentRes+sessRes, "reserves stay at zero after recovery")
	assert.Equal(t, int64(fx.bound), teamSpend3, "exact spend still recorded")
	assert.Equal(t, int64(fx.bound), agentCost3)
	assert.Equal(t, int64(fx.bound), sessSpent3)
	assert.Equal(t, int64(1), ledgerRows3, "exactly one wallet usage row")
	assert.Equal(t, -int64(fx.bound), ledgerMicro3, "the exact charge lands once")

	// The reconcile pass finds nothing to release and nothing past due: the
	// verdict already reached the terminal state.
	reconciler := budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig())
	relSum, err := reconciler.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, relSum.Released)
	assert.Zero(t, relSum.ReturnedMicroUSD)

	// Idempotent tails: extra passes move nothing.
	wB.tick(ctx)
	reconciler.Tick(ctx)
	_, _, teamSpend4, _, agentCost4, _, sessSpent4, ledgerRows4, ledgerMicro4 := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, teamSpend3, teamSpend4)
	assert.Equal(t, agentCost3, agentCost4)
	assert.Equal(t, sessSpent3, sessSpent4)
	assert.Equal(t, ledgerRows3, ledgerRows4)
	assert.Equal(t, ledgerMicro3, ledgerMicro4)
}
