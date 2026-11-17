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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

	// Every row is released exactly once across the two recovery doors:
	// only actual release transitions count — the release pass's Released
	// and the fenced verdict's Closed. AlreadyReleased is the verdict's
	// exactly-once OBSERVATION of rows the other door released, never a
	// transition of its own, so it must never be summed into one.
	assert.Equal(t, int64(4), rsum.Released+fsum.Closed,
		"release pass + fenced verdict must flip all four rows exactly once")
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

// n06p5T09GateDB wraps the real pool as a budget reservationDB for ONE
// recovery door: Begin returns the real transaction embedded in a gatedTx
// whose Exec parks the door's FIRST per-org advisory-lock statement
// (reservations.go:1042/:1375) on a channel until the test releases it.
// Parking there — not at the guarded release UPDATE (:1085/:1397) — is the
// load-bearing choice: by the time that UPDATE runs, its transaction
// already holds the per-org advisory lock and the allowance row lock, so
// parking after it would wedge the other door on the same advisory lock
// forever. Parking before the advisory Exec leaves the gated door holding
// nothing in PostgreSQL, so the other door and the live worker run against
// the real database unimpeded; after the unblock the gated door walks its
// full real path and lands in its exactly-once losing-side branch
// (AlreadyReleased for the fenced verdict, the silent skip at
// reservations.go:1060-1062 for the release pass). This is a test
// transport seam around the production constructors — no production hook.
type n06p5T09GateDB struct {
	pool    *pgxpool.Pool
	hit     chan struct{}
	release chan struct{}
	parked  atomic.Bool
}

func newN06p5T09GateDB(pool *pgxpool.Pool) *n06p5T09GateDB {
	return &n06p5T09GateDB{
		pool:    pool,
		hit:     make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (g *n06p5T09GateDB) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &n06p5T09GatedTx{Tx: tx, gate: g}, nil
}

func (g *n06p5T09GateDB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return g.pool.Exec(ctx, query, args...)
}

func (g *n06p5T09GateDB) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return g.pool.Query(ctx, query, args...)
}

func (g *n06p5T09GateDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return g.pool.QueryRow(ctx, query, args...)
}

// n06p5T09GatedTx embeds the real pgx.Tx and gates only Exec: the first
// advisory-lock statement signals hit and blocks on release BEFORE the
// statement is sent to PostgreSQL; every other call delegates untouched.
type n06p5T09GatedTx struct {
	pgx.Tx
	gate *n06p5T09GateDB
}

func (tx *n06p5T09GatedTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "pg_advisory_xact_lock") && tx.gate.parked.CompareAndSwap(false, true) {
		close(tx.gate.hit)
		select {
		case <-tx.gate.release:
		case <-ctx.Done():
			return pgconn.CommandTag{}, ctx.Err()
		}
	}
	return tx.Tx.Exec(ctx, sql, args...)
}

// n06p5T09AwaitGate blocks until the gated door reaches its first money
// statement, failing fast if the door exits (error) before parking.
func n06p5T09AwaitGate(t *testing.T, gate *n06p5T09GateDB, doorDone chan struct{}) {
	t.Helper()
	select {
	case <-gate.hit:
	case <-doorDone:
		t.Fatal("the gated door exited before reaching its first money statement")
	}
}

// n06p5T09RequireUndrained proves the world is untouched at park time: no
// settlement effects exist yet and the live worker has not even started —
// every settlement effect in this scenario will be produced while the
// losing door is parked.
func n06p5T09RequireUndrained(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var settled, nonTerminal int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM settlement_jobs WHERE org_id = $1 AND status = 'settled'`, n18dOrgEnf).Scan(&settled))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM settlement_jobs
		 WHERE org_id = $1 AND status IN ('pending','retry','processing')`, n18dOrgEnf).Scan(&nonTerminal))
	require.Zero(t, settled, "no settlement effects may exist when the gated window opens")
	require.Equal(t, int64(4), nonTerminal, "the crashed world must be fully unsettled at the park")
}

// n06p5T09StartWorker launches the live settlement worker against real
// PostgreSQL; it ticks until the queue is drained or cancelled.
func n06p5T09StartWorker(ctx context.Context, pool *pgxpool.Pool, creditStore *credits.Store) (context.CancelFunc, chan struct{}) {
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		w := n06p5T09Worker(pool, creditStore)
		for i := 0; i < 300; i++ {
			w.tick(wctx)
			var left int64
			if err := pool.QueryRow(wctx,
				`SELECT count(*) FROM settlement_jobs
				 WHERE org_id = $1 AND status IN ('pending','retry','processing')`, n18dOrgEnf).Scan(&left); err != nil {
				return
			}
			if left == 0 {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return cancel, done
}

// n06p5T09RequireDrained waits (positive-state observation only — the park
// already fixed the door order) until the live worker has produced ALL
// settlement effects while the losing door is still parked.
func n06p5T09RequireDrained(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	require.Eventually(t, func() bool {
		var left int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM settlement_jobs
			 WHERE org_id = $1 AND status IN ('pending','retry','processing')`, n18dOrgEnf).Scan(&left))
		return left == 0
	}, 30*time.Second, 50*time.Millisecond,
		"the live worker must produce all settlement effects while the losing door is parked")
	var settled int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM settlement_jobs WHERE org_id = $1 AND status = 'settled'`, n18dOrgEnf).Scan(&settled))
	require.Equal(t, int64(4), settled, "all four settlement effects must land inside the gated window")
}

// n06p5T09ReleasedRows counts terminal released allowance rows.
func n06p5T09ReleasedRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var released int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM budget_allowances WHERE org_id = $1 AND status = 'released'`, n18dOrgEnf).Scan(&released))
	return released
}

// n06p5T09AssertExactOnceWorld is the shared money/row/tail oracle of the
// concurrent race above, verbatim: the union of both doors' returns plus
// the settle decrements equals the granted escrow exactly once per scope,
// every row is terminal, the world converges, and every trailing pass —
// fenced verdict, release pass, worker tick — is a no-op.
func n06p5T09AssertExactOnceWorld(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	creditStore *credits.Store, bound int64, rsum budget.ReconcileSummary, fsum budget.AbandonedReplicaSummary) {
	t.Helper()
	decs := n06p5KindDecrement(ctx, t, pool, n18dOrgEnf)
	var settledTotal int64
	for _, dec := range decs {
		settledTotal += dec
	}
	assert.Equal(t, bound*4, fsum.ReturnedMicroUSD+rsum.ReturnedMicroUSD+settledTotal,
		"returned (%d+%d) + settled (%d) == granted (4 × %d) exactly once",
		fsum.ReturnedMicroUSD, rsum.ReturnedMicroUSD, settledTotal, bound)

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

	snap := n06p5T09Snapshot(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, snap.ReserveTotal)
	assert.Equal(t, bound, snap.TeamSpend)
	assert.Equal(t, bound, snap.AgentCost)
	assert.Equal(t, bound, snap.SessionSpend)
	assert.Equal(t, int64(1), snap.LedgerRows, "exactly one ledger row across all three writers")
	assert.Equal(t, -bound, snap.LedgerMicro)
	assert.Zero(t, snap.JobsNonTerminal)
	assert.Equal(t, int64(4), snap.JobsSettled)

	store := budget.NewReservationStore(pool, silentLogger())
	fence := budget.NewRecoveryFence(pool, silentLogger())
	reconciler := budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig())
	lease2, err := fence.Acquire(ctx, "replica-"+n18dOrgEnf, "t09-gated-tail", 5*time.Minute)
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
	n06p5T09Worker(pool, creditStore).tick(ctx)
	reconciler.Tick(ctx)
	snap2 := n06p5T09Snapshot(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, snap, snap2, "the converged world is inert under every trailing pass")
}

// TestN06P05T09Live_GatedDoorOverlapDeterministic: the old/new recovery
// doors overlap the LIVE settlement worker — never drained, never
// sequential — with each door's winner forced deterministically through the
// n06p5T09GateDB transport gate parked on the losing door's first per-org
// advisory-lock statement, while it holds nothing in PostgreSQL. Expected
// event sequence per subtest, with explicit barriers:
//
//	gated loser starts     → parks before its first money statement (hit)
//	world proved undrained → settled==0, non-terminal==4 at the park
//	live worker starts     → ticks against real PostgreSQL for the window
//	winner door (real PG)  → flips all four rows, runs to completion
//	worker drain observed  → all four settlement effects land in-window
//	loser unblocked        → walks its real path → losing-side counters
//
// Deterministic per-door counters, the same actual-transition oracle as the
// concurrent race (rsum.Released+fsum.Closed==4), and the full money/row/
// tail battery. No sleep-as-ordering: the park fixes the order; every wait
// observes positive database state.
func TestN06P05T09Live_GatedDoorOverlapDeterministic(t *testing.T) {
	t.Run("old_release_pass_wins", func(t *testing.T) {
		n06p5T09GatedOverlap(t, false)
	})
	t.Run("fenced_verdict_wins", func(t *testing.T) {
		n06p5T09GatedOverlap(t, true)
	})
}

// n06p5T09GatedOverlap runs one deterministic overlap ordering: fenceWins
// parks the §7.1 release pass and lets the fenced verdict win; otherwise
// the fenced verdict is parked and the release pass wins.
func n06p5T09GatedOverlap(t *testing.T, fenceWins bool) {
	ctx, pool, rdb := newNext18dEnv(t)
	creditStore, bound := n06p5T09CrashedWorld(ctx, t, pool, rdb,
		"events:n06p5-t09-gated", "n06p5-t09-g-1", "req-n06p5-t09-gated")
	n06p5T09Backdate(ctx, t, pool, n18dOrgEnf, 3)
	n06p5JointAwaitExpiredLeases(ctx, t, pool, n18dOrgEnf, 4)

	gate := newN06p5T09GateDB(pool)
	doorDone := make(chan struct{})
	var (
		rsum budget.ReconcileSummary
		fsum budget.AbandonedReplicaSummary
		derr error
	)

	if fenceWins {
		// Loser: the OLD §7.1 release pass through the gate.
		gatedReconciler := budget.NewReconcileWorker(gate, silentLogger(), budget.DefaultReconcileConfig())
		go func() {
			defer close(doorDone)
			rsum, derr = gatedReconciler.ReleasePass(ctx)
		}()
		n06p5T09AwaitGate(t, gate, doorDone)
		n06p5T09RequireUndrained(ctx, t, pool)
		cancelWorker, workerDone := n06p5T09StartWorker(ctx, pool, creditStore)
		defer func() {
			cancelWorker()
			<-workerDone
		}()

		// Winner: the fenced verdict against real PostgreSQL to completion.
		store := budget.NewReservationStore(pool, silentLogger())
		fence := budget.NewRecoveryFence(pool, silentLogger())
		lease, err := fence.Acquire(ctx, "replica-"+n18dOrgEnf, "t09-gated-verdict", 5*time.Minute)
		require.NoError(t, err)
		fsum, derr = store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
		require.NoError(t, derr, "the winning fenced verdict must succeed over real PostgreSQL")
		require.NoError(t, lease.Release(ctx))

		assert.Equal(t, int64(4), fsum.Closed, "fenced-verdict-wins: the verdict flips all four rows")
		assert.Zero(t, fsum.AlreadyReleased, "fenced-verdict-wins: nothing was released before the verdict ran")
		assert.Equal(t, int64(4), n06p5T09ReleasedRows(ctx, t, pool),
			"all four rows terminal while the loser is still parked")
		n06p5T09RequireDrained(ctx, t, pool)

		close(gate.release)
		<-doorDone
		require.NoError(t, derr, "the gated release pass must succeed after the unblock")
		assert.Zero(t, rsum.Released, "the gated release pass is the silent losing side")
		assert.Zero(t, rsum.ReturnedMicroUSD)

		assert.Zero(t, fsum.SkippedLive, "nothing is live once the §14 window has passed")
		n06p5T09AssertExactOnceWorld(t, ctx, pool, creditStore, bound, rsum, fsum)
		return
	}

	// Loser: the NEW fenced verdict through the gate.
	gatedStore := budget.NewReservationStoreWithConfig(gate, silentLogger(), budget.DefaultReservationConfig())
	gatedFence := budget.NewRecoveryFence(gate, silentLogger())
	go func() {
		defer close(doorDone)
		lease, err := gatedFence.Acquire(ctx, "replica-"+n18dOrgEnf, "t09-gated-verdict", 5*time.Minute)
		if err != nil {
			derr = err
			return
		}
		defer func() { _ = lease.Release(ctx) }()
		fsum, derr = gatedStore.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	}()
	n06p5T09AwaitGate(t, gate, doorDone)
	n06p5T09RequireUndrained(ctx, t, pool)
	cancelWorker, workerDone := n06p5T09StartWorker(ctx, pool, creditStore)
	defer func() {
		cancelWorker()
		<-workerDone
	}()

	// Winner: the production release pass against real PostgreSQL.
	reconciler := budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig())
	rsum, derr = reconciler.ReleasePass(ctx)
	require.NoError(t, derr, "the winning release pass must succeed over real PostgreSQL")

	assert.Equal(t, int64(4), rsum.Released, "old-release-wins: the pass flips all four rows")
	assert.Equal(t, int64(4), n06p5T09ReleasedRows(ctx, t, pool),
		"all four rows terminal while the loser is still parked")
	n06p5T09RequireDrained(ctx, t, pool)

	close(gate.release)
	<-doorDone
	require.NoError(t, derr, "the gated fenced verdict must succeed after the unblock")
	assert.Zero(t, fsum.Closed, "the gated verdict flips nothing after the unblock")
	assert.Equal(t, int64(4), fsum.AlreadyReleased, "the gated verdict observes the pass's four flips")
	assert.Zero(t, fsum.SkippedLive, "nothing is live once the §14 window has passed")

	n06p5T09AssertExactOnceWorld(t, ctx, pool, creditStore, bound, rsum, fsum)
}
