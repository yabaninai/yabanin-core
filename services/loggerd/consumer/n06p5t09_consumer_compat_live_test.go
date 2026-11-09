//go:build integration

// N06-P05-T09 consumer compatibility at the crash-recovery seam (disposable
// PG+Redis, ADR-0001 §10): three properties no other N06-P05 file pins.
//
//  1. Config parity: an identical real crashed world (real ingest, a real
//     worker killed mid-batch) recovers through the OLD configuration only
//     (the production §7.1 ReconcileWorker release pass at the full §14
//     safety window) and through the NEW configuration only (the fenced
//     verdict with the 30-minute override) to the IDENTICAL terminal durable
//     state — per scope, in the reserves, the spends, the ledger and the job
//     queue. In the young band (1h lapsed) the old config refuses both doors
//     (the floored unfenced window and the not-yet-due release pass) where
//     the new config acts lawfully — timing differs, terminal truth does not.
//  2. Explicit unsupported refusals at the consumer seam never move money
//     and never poison the world: the unfenced acceleration attempt is
//     floored (SkippedLive summary), a nil lease, a second fence while one
//     is held, and an expired fence lease are rejected with typed errors;
//     after the whole battery the supported consumer still converges
//     exactly once and the late settle degrades to ledger-only.
//  3. Old and new recovery authorities interoperate under a real race:
//     fenced verdict × release pass × live settlement worker over one
//     crashed world — returned + settled == granted exactly once per scope,
//     the ledger charges exactly once, and every trailing pass is a no-op.
//
// Real production paths under test: processMessage, SettlementWorker.Run/
// tick, recoverExpiredLeases, the §5.5 org batch (SettleOrgBatch),
// ReconcileWorker.ReleasePass/Tick, the §7.1.1/§7.1.2 orphan verdicts
// (CloseAbandonedReplica and CloseAbandonedReplicaFenced), and the fencing
// lease (N06-P05-T04). Test-forced states are limited to: the per-org
// advisory gate (a production money-writer lock used for scheduling only),
// context cancellation (the executor death), and allowance-lease backdating
// (the wall-clock force; money columns are never touched) — the same
// discipline as T05–T08. Distinct from T05 (hand-shaped worlds, two-way
// verdict×settle race), T06 (joint restart convergence + fenced takeover),
// T07 (boundary corpus) and T08 (pkg/budget crash cycles): this file owns
// the configuration-compatibility axis and the live unsupported-lease
// refusal battery at the consumer seam.
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

// n06p5T09Worker builds a settlement worker with the live config over the
// given credit store.
func n06p5T09Worker(pool *pgxpool.Pool, creditStore *credits.Store) *SettlementWorker {
	return NewSettlementWorker(pool, creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).
		WithConfig(liveSettlementConfig())
}

// n06p5T09CrashedWorld seeds the enforce-mode org, drives one real
// completed request through the production consumer, and kills a real
// worker mid-batch: four claimed intents with live claim leases, nothing
// settled, no money moved. Returns the credit store for worker rebuilds
// and the per-scope escrow bound.
func n06p5T09CrashedWorld(ctx context.Context, t *testing.T, pool *pgxpool.Pool, rdb *redis.Client, stream, entry, request string) (*credits.Store, int64) {
	t.Helper()
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgEnf, 1000)
	bound := int64(fx.bound)
	c := n06p5JointConsumer(rdb, pool, stream)
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg(entry, request, n18dOrgEnf, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrgEnf), "one intent per reserve scope")
	w := n06p5T09Worker(pool, c.creditStore)
	n06p5JointCrashMidClaim(ctx, t, pool, n18dOrgEnf, w)
	return c.creditStore, bound
}

// n06p5T09Backdate forces the org's allowance leases `hours` into the past
// (the wall-clock force past the §14 safety window; money columns are
// never touched — same technique as T05–T08).
func n06p5T09Backdate(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string, hours int) {
	t.Helper()
	tag, err := pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - ($2::int * interval '1 hour') WHERE org_id = $1`,
		org, hours)
	require.NoError(t, err)
	require.Equal(t, int64(4), tag.RowsAffected(), "org %s must hold four allowances", org)
}

// n06p5T09ScopeSnap is one scope's terminal allowance state plus the µUSD
// the settle worker already removed from its reserve.
type n06p5T09ScopeSnap struct {
	Granted    int64
	Returned   int64
	Status     string
	SettledDec int64
}

// n06p5T09WorldSnap is the full durable matrix of one crashed world:
// reserves, spends, ledger, allowance scopes and the job queue.
type n06p5T09WorldSnap struct {
	ReserveTotal    int64
	TeamSpend       int64
	AgentCost       int64
	SessionSpend    int64
	LedgerRows      int64
	LedgerMicro     int64
	JobsSettled     int64
	JobsWithKey     int64
	JobsNonTerminal int64
	Scopes          map[string]n06p5T09ScopeSnap
}

// n06p5T09Snapshot reads the org's full durable matrix (the parity and
// terminal-comparison unit).
func n06p5T09Snapshot(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) n06p5T09WorldSnap {
	t.Helper()
	walletRes, teamRes, teamSpend, agentRes, agentCost, sessRes, sessSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, org)
	snap := n06p5T09WorldSnap{
		ReserveTotal: walletRes + teamRes + agentRes + sessRes,
		TeamSpend:    teamSpend,
		AgentCost:    agentCost,
		SessionSpend: sessSpent,
		LedgerRows:   ledgerRows,
		LedgerMicro:  ledgerMicro,
		Scopes:       map[string]n06p5T09ScopeSnap{},
	}
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'settled'),
		       count(*) FILTER (WHERE status = 'settled' AND payload ? $2),
		       count(*) FILTER (WHERE status IN ('pending','retry','processing'))
		FROM settlement_jobs WHERE org_id = $1`, org, budget.ReconcileSettleKey).
		Scan(&snap.JobsSettled, &snap.JobsWithKey, &snap.JobsNonTerminal))

	rows, err := pool.Query(ctx, `
		SELECT a.scope_kind, a.granted_micro_usd, a.returned_micro_usd, a.status,
		       COALESCE(SUM((j.payload->>$2)::bigint), 0)
		FROM budget_allowances a
		LEFT JOIN settlement_jobs j ON j.allowance_id = a.id AND j.status = 'settled'
		WHERE a.org_id = $1
		GROUP BY a.scope_kind, a.granted_micro_usd, a.returned_micro_usd, a.status`, org, budget.ReconcileSettleKey)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var scope, status string
		var granted, returned, dec int64
		require.NoError(t, rows.Scan(&scope, &granted, &returned, &status, &dec))
		snap.Scopes[scope] = n06p5T09ScopeSnap{Granted: granted, Returned: returned, Status: status, SettledDec: dec}
	}
	require.NoError(t, rows.Err())
	require.Len(t, snap.Scopes, 4, "the org must hold exactly the four reserve scopes")
	return snap
}

// n06p5T09AssertFrozen pins the fully-frozen crashed world: the whole
// escrow still reserved, nothing settled, no ledger row, every allowance
// active, every job non-terminal — the state after any refused recovery.
func n06p5T09AssertFrozen(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string, bound int64) {
	t.Helper()
	snap := n06p5T09Snapshot(ctx, t, pool, org)
	assert.Equal(t, bound*4, snap.ReserveTotal, "the whole escrow stays reserved through the refusal")
	assert.Zero(t, snap.TeamSpend)
	assert.Zero(t, snap.AgentCost)
	assert.Zero(t, snap.SessionSpend)
	assert.Zero(t, snap.LedgerRows, "refusals never charge the ledger")
	assert.Zero(t, snap.LedgerMicro)
	assert.Zero(t, snap.JobsSettled, "refusals never settle intents")
	assert.Equal(t, int64(4), snap.JobsNonTerminal)
	for scope, s := range snap.Scopes {
		assert.Equal(t, "active", s.Status, "scope %s stays active through the refusal", scope)
		assert.Zero(t, s.Returned, "scope %s: refusals never return money", scope)
		assert.Zero(t, s.SettledDec, "scope %s: refusals never settle money", scope)
	}
}

// TestN06P05T09Live_ConfigParityOldVsNewConvergeOneTruth: the same real
// crashed world driven under the old configuration (production release
// pass at the full §14 window, no fence) and under the new configuration
// (fenced verdict with the 30-minute override) converges to the identical
// terminal durable state. In the 1h band the old config refuses both doors
// while the new config resolves lawfully — the only allowed divergence is
// timing; the terminal truth is pinned column-for-column identical.
func TestN06P05T09Live_ConfigParityOldVsNewConvergeOneTruth(t *testing.T) {
	// Sequential by design: seedNext18dWorld resets the shared team/agent/
	// session spend rows, so the two legs must not overlap.
	ctx, pool, rdb := newNext18dEnv(t)
	store := budget.NewReservationStore(pool, silentLogger())
	reconciler := budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig())

	// Leg A — the OLD configuration: the §7.1 release pass at the full §14
	// window is the only recovery authority; no fence is involved.
	creditStore, bound := n06p5T09CrashedWorld(ctx, t, pool, rdb,
		"events:n06p5-t09-parity-a", "n06p5-t09-a-1", "req-n06p5-t09-parity-a")

	// The young band (1h lapsed): the new config may act here (its 30-minute
	// override), the old config must refuse both doors — the floored
	// unfenced acceleration and the not-yet-due release pass.
	n06p5T09Backdate(ctx, t, pool, n18dOrgEnf, 1)
	sum, err := store.CloseAbandonedReplica(ctx, "replica-"+n18dOrgEnf, 30*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(4), sum.SkippedLive, "old config: the floored window refuses every young row")
	assert.Zero(t, sum.Closed)
	assert.Zero(t, sum.ReturnedMicroUSD)
	relSum, err := reconciler.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, relSum.Released, "old config: nothing is old enough for the §14 release pass")
	assert.Zero(t, relSum.ReturnedMicroUSD)
	n06p5T09AssertFrozen(ctx, t, pool, n18dOrgEnf, bound)

	// The old config's window elapses: the release pass returns the whole
	// escrow exactly once.
	n06p5T09Backdate(ctx, t, pool, n18dOrgEnf, 3)
	relSum, err = reconciler.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(4), relSum.Released, "old config authority: the release pass")
	assert.Equal(t, bound*4, relSum.ReturnedMicroUSD, "4 × 12_000 µUSD returned exactly once")

	// The crashed claims lapse; the restarted worker's settle degrades to
	// ledger-only (the allowances are already released).
	n06p5JointAwaitExpiredLeases(ctx, t, pool, n18dOrgEnf, 4)
	wA := n06p5T09Worker(pool, creditStore)
	wA.tick(ctx)
	snapOld := n06p5T09Snapshot(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, snapOld.JobsWithKey, "old config: the post-recovery settle leaves no reconcile key")
	assert.Equal(t, int64(4), snapOld.JobsSettled)

	// Idempotent tails on the old-config world.
	wA.tick(ctx)
	reconciler.Tick(ctx)
	relSum, err = reconciler.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, relSum.Released)
	assert.Zero(t, relSum.ReturnedMicroUSD)

	// Leg B — the NEW configuration: the fenced verdict with the 30-minute
	// override is the recovery authority. Identical world, same crash.
	creditStore, bound = n06p5T09CrashedWorld(ctx, t, pool, rdb,
		"events:n06p5-t09-parity-b", "n06p5-t09-b-1", "req-n06p5-t09-parity-b")

	// The same young band: the new config acts lawfully at 30 minutes.
	n06p5T09Backdate(ctx, t, pool, n18dOrgEnf, 1)
	fence := budget.NewRecoveryFence(pool, silentLogger())
	lease, err := fence.Acquire(ctx, "replica-"+n18dOrgEnf, "t09-config-b", 5*time.Minute)
	require.NoError(t, err)
	fsum, err := store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(4), fsum.Closed, "new config: the fenced override honors the 30-minute window")
	assert.Equal(t, bound*4, fsum.ReturnedMicroUSD, "the same 4 × 12_000 µUSD, a quarter of the wall clock later")
	assert.Zero(t, fsum.SkippedLive)
	assert.Zero(t, fsum.AlreadyReleased)
	require.NoError(t, lease.Release(ctx))

	n06p5JointAwaitExpiredLeases(ctx, t, pool, n18dOrgEnf, 4)
	wB := n06p5T09Worker(pool, creditStore)
	wB.tick(ctx)
	snapNew := n06p5T09Snapshot(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, snapNew.JobsWithKey, "new config: the post-recovery settle leaves no reconcile key")
	assert.Equal(t, int64(4), snapNew.JobsSettled)

	// Idempotent tails on the new-config world.
	wB.tick(ctx)
	reconciler.Tick(ctx)
	relSum, err = reconciler.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, relSum.Released)
	assert.Zero(t, relSum.ReturnedMicroUSD)

	// PARITY: the two configurations converge to the identical terminal
	// durable state — per-scope allowances, reserves, spends, ledger, and
	// the job queue.
	require.Equal(t, snapOld, snapNew,
		"old and new configuration must converge to the identical terminal world")
	// Terminal truth diagnostics (implied by the parity above; explicit
	// messages keep a failure readable).
	assert.Zero(t, snapOld.ReserveTotal, "no reserve survives either configuration")
	assert.Equal(t, bound, snapOld.TeamSpend)
	assert.Equal(t, bound, snapOld.AgentCost)
	assert.Equal(t, bound, snapOld.SessionSpend)
	assert.Equal(t, int64(1), snapOld.LedgerRows, "exactly one ledger row under either configuration")
	assert.Equal(t, -bound, snapOld.LedgerMicro)
	assert.Zero(t, snapOld.JobsNonTerminal)
	for scope, s := range snapOld.Scopes {
		assert.Equal(t, "released", s.Status, "scope %s: terminal under either configuration", scope)
		assert.Equal(t, s.Granted, s.Returned, "scope %s: the full escrow returned once", scope)
		assert.Zero(t, s.SettledDec, "scope %s: the late settle is ledger-only", scope)
	}
}

// TestN06P05T09Live_UnsupportedLeaseRefusalsNeverPoisonTheWorld: on a real
// crashed world in the band where ONLY a fenced verdict may lawfully act,
// every unsupported recovery presentation is refused explicitly and never
// moves money — the floored unfenced acceleration, a nil lease, a second
// fence while one is held, and an expired fence lease. After the whole
// battery the supported consumer still converges exactly once and the late
// settle degrades to ledger-only: refusals never poison the world.
func TestN06P05T09Live_UnsupportedLeaseRefusalsNeverPoisonTheWorld(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	store := budget.NewReservationStore(pool, silentLogger())
	reconciler := budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig())

	creditStore, bound := n06p5T09CrashedWorld(ctx, t, pool, rdb,
		"events:n06p5-t09-refusal", "n06p5-t09-r-1", "req-n06p5-t09-refusal")

	// The band where only the fenced door with a ≤1h override may act.
	n06p5T09Backdate(ctx, t, pool, n18dOrgEnf, 1)

	// R1 — the unsupported acceleration attempt through the OLD config
	// door: the unfenced verdict asked for 30 minutes is floored back to
	// the §14 default; the refusal is the explicit SkippedLive summary.
	sum, err := store.CloseAbandonedReplica(ctx, "replica-"+n18dOrgEnf, 30*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(4), sum.SkippedLive, "the floored window guards every row against the unfenced acceleration")
	assert.Zero(t, sum.Closed)
	assert.Zero(t, sum.ReturnedMicroUSD)
	n06p5T09AssertFrozen(ctx, t, pool, n18dOrgEnf, bound)

	// R2 — a nil lease at the consumer seam: rejected without touching the
	// database (the stale-mutation contract, degenerate form).
	_, err = store.CloseAbandonedReplicaFenced(ctx, nil, 30*time.Minute)
	require.ErrorIs(t, err, budget.ErrStaleRecoveryFence)
	n06p5T09AssertFrozen(ctx, t, pool, n18dOrgEnf, bound)

	// R3 — mutual exclusion: while one verdict holds the fence, a second
	// owner's acquisition is refused (non-blocking) with the typed error.
	fence := budget.NewRecoveryFence(pool, silentLogger())
	l1, err := fence.Acquire(ctx, "replica-"+n18dOrgEnf, "t09-verdict-a", 5*time.Minute)
	require.NoError(t, err)
	_, err = fence.Acquire(ctx, "replica-"+n18dOrgEnf, "t09-verdict-b", 5*time.Minute)
	require.ErrorIs(t, err, budget.ErrRecoveryFenceHeld)
	require.NoError(t, l1.Release(ctx))
	n06p5T09AssertFrozen(ctx, t, pool, n18dOrgEnf, bound)

	// R4 — the TTL-bounded authority: an expired lease may present no
	// verdict; the override cannot outlive its lease.
	l2, err := fence.Acquire(ctx, "replica-"+n18dOrgEnf, "t09-verdict-c", 300*time.Millisecond)
	require.NoError(t, err)
	deadline := time.Now().Add(5 * time.Second)
	for !l2.Expired() {
		if time.Now().After(deadline) {
			t.Fatal("the 300ms fence lease never expired")
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, err = store.CloseAbandonedReplicaFenced(ctx, l2, 30*time.Minute)
	require.ErrorIs(t, err, budget.ErrRecoveryFenceExpired)
	require.NoError(t, l2.Release(ctx))
	n06p5T09AssertFrozen(ctx, t, pool, n18dOrgEnf, bound)

	// After the whole battery the SUPPORTED consumer still converges
	// exactly once: a fresh held lease drives the fenced verdict.
	l3, err := fence.Acquire(ctx, "replica-"+n18dOrgEnf, "t09-verdict-final", 5*time.Minute)
	require.NoError(t, err)
	fsum, err := store.CloseAbandonedReplicaFenced(ctx, l3, 30*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(4), fsum.Closed, "the supported verdict closes every scope row")
	assert.Equal(t, bound*4, fsum.ReturnedMicroUSD, "the escrow returns exactly once despite the refusals")
	assert.Zero(t, fsum.SkippedLive)
	assert.Zero(t, fsum.AlreadyReleased)
	require.NoError(t, l3.Release(ctx))

	// The late restart settles LEDGER-ONLY — the money was already
	// returned; the refusals left no residue on the queue.
	n06p5JointAwaitExpiredLeases(ctx, t, pool, n18dOrgEnf, 4)
	w := n06p5T09Worker(pool, creditStore)
	w.tick(ctx)
	snap := n06p5T09Snapshot(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, snap.JobsWithKey, "a post-recovery settle leaves no reconcile key — ledger-only")
	assert.Zero(t, snap.JobsNonTerminal)
	assert.Zero(t, snap.ReserveTotal)
	assert.Equal(t, bound, snap.TeamSpend)
	assert.Equal(t, bound, snap.AgentCost)
	assert.Equal(t, bound, snap.SessionSpend)
	assert.Equal(t, int64(1), snap.LedgerRows)
	assert.Equal(t, -bound, snap.LedgerMicro)

	// Idempotent tails: every authority is a no-op on the converged world.
	w.tick(ctx)
	reconciler.Tick(ctx)
	relSum, err := reconciler.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, relSum.Released)
	assert.Zero(t, relSum.ReturnedMicroUSD)
}

// TestN06P05T09Live_OldAndNewRecoveryInteropExactOnce: the old and new
// recovery authorities race the live settlement worker over one real
// crashed world — the fenced verdict (new config), the §7.1 release pass
// (old config) and the restarted worker all run concurrently. The union of
// the three money writers equals the granted escrow exactly once per scope
// whichever door wins each row; the ledger charges exactly once; every
// trailing pass is a no-op.
func TestN06P05T09Live_OldAndNewRecoveryInteropExactOnce(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	store := budget.NewReservationStore(pool, silentLogger())
	reconciler := budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig())

	creditStore, bound := n06p5T09CrashedWorld(ctx, t, pool, rdb,
		"events:n06p5-t09-interop", "n06p5-t09-i-1", "req-n06p5-t09-interop")

	// Past the §14 window both recovery doors are lawfully open; the claim
	// leases lapse so the restarted worker may join the race.
	n06p5T09Backdate(ctx, t, pool, n18dOrgEnf, 3)
	n06p5JointAwaitExpiredLeases(ctx, t, pool, n18dOrgEnf, 4)

	fence := budget.NewRecoveryFence(pool, silentLogger())
	lease, err := fence.Acquire(ctx, "replica-"+n18dOrgEnf, "t09-interop-verdict", 5*time.Minute)
	require.NoError(t, err)

	var (
		wg   sync.WaitGroup
		fsum budget.AbandonedReplicaSummary
		ferr error
		rsum budget.ReconcileSummary
		rerr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = lease.Release(ctx) }()
		// The NEW config door: the fenced verdict with the 30-minute override.
		fsum, ferr = store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The OLD config door: the production release pass at the §14 window.
		rsum, rerr = reconciler.ReleasePass(ctx)
	}()
	// The live settlement worker races both doors from the main goroutine.
	w := n06p5T09Worker(pool, creditStore)
	for i := 0; i < 300; i++ {
		w.tick(ctx)
		var left int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM settlement_jobs
			 WHERE org_id = $1 AND status IN ('pending','retry','processing')`, n18dOrgEnf).Scan(&left))
		if left == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	wg.Wait()
	require.NoError(t, ferr, "the fenced verdict must succeed under the race")
	require.NoError(t, rerr, "the release pass must succeed under the race")

	// Every row is released exactly once across the two recovery doors —
	// each writer counts only the rows it actually released.
	assert.Equal(t, int64(4), rsum.Released+fsum.Closed+fsum.AlreadyReleased,
		"release pass + fenced verdict must cover all four rows exactly once")
	assert.Zero(t, fsum.SkippedLive, "nothing is live once the §14 window has passed")
	// The returned µUSD across both doors plus the settle's decrements
	// equals the whole escrow exactly once.
	decs := n06p5KindDecrement(ctx, t, pool, n18dOrgEnf)
	var settledTotal int64
	for _, dec := range decs {
		settledTotal += dec
	}
	assert.Equal(t, bound*4, fsum.ReturnedMicroUSD+rsum.ReturnedMicroUSD+settledTotal,
		"returned (%d+%d) + settled (%d) == granted (4 × %d) exactly once",
		fsum.ReturnedMicroUSD, rsum.ReturnedMicroUSD, settledTotal, bound)

	// Per-scope union: whichever door won the row, returned + settled
	// decrement equals the granted escrow exactly once, and the row is
	// terminal.
	for _, pair := range []struct{ scope, kind string }{
		{"wallet", ChargeKindResaleDeduction},
		{"team_month", ChargeKindTeamSpend},
		{"agent_day", ChargeKindAgentSpend},
		{"session", ChargeKindSessionSpend},
	} {
		granted, returned, status := n06p5AllowanceScope(ctx, t, pool, n18dOrgEnf, pair.scope)
		assert.Equal(t, "released", status, "scope %s must reach the terminal state", pair.scope)
		assert.Equal(t, granted, returned+decs[pair.kind],
			"scope %s: returned (%d) + settled (%d) == granted (%d)",
			pair.scope, returned, decs[pair.kind], granted)
	}

	// The world converges: no reserves, one ledger row, exact spends, the
	// queue fully settled.
	snap := n06p5T09Snapshot(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, snap.ReserveTotal)
	assert.Equal(t, bound, snap.TeamSpend)
	assert.Equal(t, bound, snap.AgentCost)
	assert.Equal(t, bound, snap.SessionSpend)
	assert.Equal(t, int64(1), snap.LedgerRows, "exactly one ledger row across all three writers")
	assert.Equal(t, -bound, snap.LedgerMicro)
	assert.Zero(t, snap.JobsNonTerminal)
	assert.Equal(t, int64(4), snap.JobsSettled)

	// Idempotent tails: a fresh fenced verdict finds every row already
	// released, the release pass finds nothing, a trailing tick moves
	// nothing.
	lease2, err := fence.Acquire(ctx, "replica-"+n18dOrgEnf, "t09-interop-tail", 5*time.Minute)
	require.NoError(t, err)
	fsum2, err := store.CloseAbandonedReplicaFenced(ctx, lease2, 30*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(4), fsum2.AlreadyReleased, "the trailing verdict is the losing side everywhere")
	assert.Zero(t, fsum2.Closed)
	assert.Zero(t, fsum2.ReturnedMicroUSD)
	require.NoError(t, lease2.Release(ctx))
	relSum, err := reconciler.ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, relSum.Released)
	assert.Zero(t, relSum.ReturnedMicroUSD)
	w.tick(ctx)
	reconciler.Tick(ctx)
	snap2 := n06p5T09Snapshot(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, snap, snap2, "the converged world is inert under every trailing pass")
}
