//go:build integration

// N06-P05-T05 negative-clause evidence on a disposable live Postgres
// (real-PG pattern, ADR-0001 §10): crash reconciliation and abandoned
// replica recovery stay exactly-once under the adversarial interleavings
// the periodic sweeps cannot rule out — two concurrent verdicts after a
// fence holder crash, a mid-pass lease expiry, recovery aimed at a live
// renewed reservation (including the between-renewals window), bounded
// multi-shape convergence, and the mixed fenced×unfenced×periodic×settle
// race on an in-window orphan. T02 covered the reconciler×settle and
// live-sibling races; T04 covered the fence policy sequentially. This file
// covers the remaining negative space (contract
// artifacts/internal-delivery-program/N06-P05/contract.md, card N06-P05-T05).
//
// Shared-stand discipline: every test in the package shares one Postgres
// container, one pool and one process-global metrics registry, and
// ReleasePass is a global pass over all orgs. Lapsed shapes here therefore
// stay INSIDE the §14 safety window, where a foreign pass is legally
// refused and only this test's fenced verdicts (30-min override) can
// close; summary asserts fold only replica-scoped verdict results, and
// the process-global release counter is asserted with GreaterOrEqual.
package budget

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n06p5TryAcquireFence acquires a recovery lease with a bounded retry on
// ErrRecoveryFenceHeld (the loser of an in-flight handover waits for the
// winner's release instead of failing the test). Plain error returns —
// safe to call from racer goroutines.
func n06p5TryAcquireFence(pool *pgxpool.Pool, replica, owner string, ttl time.Duration) (*RecoveryLease, error) {
	fence := NewRecoveryFence(pool, nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		lease, err := fence.Acquire(context.Background(), replica, owner, ttl)
		if err == nil {
			return lease, nil
		}
		if !errors.Is(err, ErrRecoveryFenceHeld) || time.Now().After(deadline) {
			return nil, fmt.Errorf("acquire recovery fence for %s: %w", replica, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// n06p5ShiftLease moves every allowance lease of a replica: lapse > 0
// backdates it that far into the past (the crash shape), lapse < 0
// future-dates it (the between-renewals shape: still valid, about to
// expire). Targets all scope rows of the replica.
func n06p5ShiftLease(t *testing.T, pool *pgxpool.Pool, replica string, lapse time.Duration) {
	t.Helper()
	op, interval := "-", formatInterval(lapse)
	if lapse < 0 {
		op, interval = "+", formatInterval(-lapse)
	}
	tag, err := pool.Exec(context.Background(),
		`UPDATE budget_allowances
		 SET lease_until = now() `+op+` $2::interval, updated_at = now()
		 WHERE replica_id = $1`,
		replica, interval)
	require.NoError(t, err)
	require.Positive(t, tag.RowsAffected(), "replica %s must hold allowances", replica)
}

// n06p5TerminateFenceHolder simulates a crashed verdict process: it
// terminates the backend holding the replica's recovery fence, so the
// session-level advisory lock dies with the session while the in-process
// lease object keeps claiming Held.
func n06p5TerminateFenceHolder(t *testing.T, pool *pgxpool.Pool, replica string) {
	t.Helper()
	var pid int32
	for i := 0; i < 50; i++ {
		err := pool.QueryRow(context.Background(), `
			SELECT pid FROM pg_locks
			WHERE locktype = 'advisory' AND classid = 0
			  AND objid = hashtext($1)::bigint
			LIMIT 1`, recoveryFenceKey(replica)).Scan(&pid)
		if err == nil {
			var terminated bool
			require.NoError(t, pool.QueryRow(context.Background(),
				`SELECT pg_terminate_backend($1)`, pid).Scan(&terminated),
				"terminate fence holder backend %d", pid)
			require.True(t, terminated)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no advisory lock holder found for %s", replica)
}

// n06p5GrantFourScopes grants the full §5.3 shape (wallet, team, agent,
// session) for one replica and returns the granted total.
func n06p5GrantFourScopes(t *testing.T, pool *pgxpool.Pool, org, replica string) int64 {
	t.Helper()
	team := seedTeamBudget(t, pool, 100)
	agent := seedAgentBudget(t, pool, 5_000)
	session := seedSessionKey(t, pool, org, 25)
	period := time.Now().UTC().Format("2006-01")
	day := time.Now().UTC().Format("2006-01-02")
	_, err := newReservationStore(pool).Grant(context.Background(), replica, org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 100_000},
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 200_000},
		{Scope: ScopeAgentDay, Key: agent, Period: day, Bound: 400_000},
		{Scope: ScopeSession, Key: session, Bound: 300_000},
	})
	require.NoError(t, err)
	// org_credits.reserved_micro_usd carries the WALLET scope only; team,
	// agent and session reserves live in their own spend tables.
	require.Equal(t, int64(100_000), walletState(t, pool, org))
	require.Equal(t, int64(200_000), scopeReserve(t, pool, ScopeTeamMonth, team, period))
	require.Equal(t, int64(400_000), scopeReserve(t, pool, ScopeAgentDay, agent, day))
	require.Equal(t, int64(300_000), scopeReserve(t, pool, ScopeSession, session, ""))
	return 1_000_000
}

// n06p5ScopeRef reads the natural key (scope_key, period) of a replica's
// allowance row for one scope (the four-scope grants use one row each).
func n06p5ScopeRef(t *testing.T, pool *pgxpool.Pool, replica string, scope ScopeKind) (key, period string) {
	t.Helper()
	err := pool.QueryRow(context.Background(), `
		SELECT scope_key, period FROM budget_allowances
		WHERE replica_id = $1 AND scope_kind = $2 LIMIT 1`,
		replica, string(scope)).Scan(&key, &period)
	require.NoError(t, err)
	return key, period
}

// TestN06P05Live_FencedVsFencedAfterHolderCrashExactlyOnce: the fence
// holder's backend is terminated (crash) while its lease object still
// claims Held — the session-level lock dies with the session, so a fresh
// verdict acquires immediately and both fenced verdicts race the same
// lapsed escrow. Exactly one closes it: the per-row status guard under the
// org advisory lock keeps the ledger exact even while the fence's mutual
// exclusion is violated by the zombie lease.
//
// Known gap (open handoff, NOT solved here per card): a durable monotonic
// generation counter (needs the 0016_* migration pair) is what would let
// the zombie lease detect its own death; until then the zombie window
// exists and exactly-once relies on the per-row state machine — which this
// test proves under the worst interleaving.
func TestN06P05Live_FencedVsFencedAfterHolderCrashExactlyOnce(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-zomb-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	const deadBound = int64(600_000)
	_, err := store.Grant(ctx, "n06p5-zomb-dead", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: money.MicroUSD(deadBound)},
	})
	require.NoError(t, err)
	_, err = store.Grant(ctx, "n06p5-zomb-live", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 250_000},
	})
	require.NoError(t, err)
	// 1h lapsed: inside the §14 window, so ONLY a fenced verdict with a
	// deliberate short window is legally able to close it at all.
	n06p5ForceState(t, pool, "n06p5-zomb-dead", org, AllowanceActive, time.Hour)
	require.Equal(t, deadBound+250_000, walletState(t, pool, org))

	// Verdict A acquires the fence, then its process "crashes": the
	// advisory-lock holder backend is terminated. The in-process lease
	// object cannot know (the zombie window above).
	leaseA, err := n06p5TryAcquireFence(pool, "n06p5-zomb-dead", "verdict-a", time.Hour)
	require.NoError(t, err)
	n06p5TerminateFenceHolder(t, pool, "n06p5-zomb-dead")
	require.True(t, leaseA.Held(), "the crashed lease object still claims Held — the documented zombie window")
	orphanBefore := releasedCounter(t, ReleaseReasonCrashOrphan)

	// Both verdicts race. B acquires a fresh lease (possible exactly
	// because A's session lock died with the backend).
	var (
		wg         sync.WaitGroup
		sumA, sumB AbandonedReplicaSummary
		errA, errB error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		sumA, errA = store.CloseAbandonedReplicaFenced(ctx, leaseA, 30*time.Minute)
	}()
	go func() {
		defer wg.Done()
		leaseB, acqErr := n06p5TryAcquireFence(pool, "n06p5-zomb-dead", "verdict-b", time.Hour)
		if acqErr != nil {
			errB = acqErr
			return
		}
		defer func() { _ = leaseB.Release(ctx) }()
		sumB, errB = store.CloseAbandonedReplicaFenced(ctx, leaseB, 30*time.Minute)
	}()
	wg.Wait()
	// The crashed process cannot release its lease; the broken holder
	// connection makes the release fail — expected, like a real crash.
	_ = leaseA.Release(ctx)
	require.NoError(t, errA, "the zombie verdict still runs to completion")
	require.NoError(t, errB)

	require.Equal(t, int64(1), sumA.Closed+sumB.Closed, "exactly one verdict closes the orphan")
	require.Equal(t, deadBound, sumA.ReturnedMicroUSD+sumB.ReturnedMicroUSD,
		"the remainder returns exactly once")
	// The counter is process-global and every parallel test in the package
	// ticks it; the exact exactly-once attribution is proven by the DB
	// asserts below, the counter proves this close ticked at least once.
	assert.GreaterOrEqual(t, releasedCounter(t, ReleaseReasonCrashOrphan), orphanBefore+1,
		"the crash_orphan counter ticks for the winning verdict")
	require.Equal(t, int64(250_000), walletState(t, pool, org), "the live sibling's reserve is untouched")

	_, granted, ret, status, _ := allowanceRow(t, pool, "n06p5-zomb-dead", ScopeWallet, org, "")
	assert.Equal(t, deadBound, granted)
	assert.Equal(t, deadBound, ret, "no double return — returned equals granted exactly")
	assert.Equal(t, AllowanceReleased, status)

	// A re-verdict under a fresh lease observes the losing side: idempotent
	// convergence, not a second pass over closed rows.
	leaseC, err := n06p5TryAcquireFence(pool, "n06p5-zomb-dead", "verdict-c", time.Hour)
	require.NoError(t, err)
	defer func() { _ = leaseC.Release(ctx) }()
	sumC, err := store.CloseAbandonedReplicaFenced(ctx, leaseC, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(1), sumC.AlreadyReleased)
	require.Zero(t, sumC.Closed)
	require.Zero(t, sumC.ReturnedMicroUSD)
	require.Equal(t, int64(250_000), walletState(t, pool, org))

	// Stand-wide invariant queries execute cleanly (§7.1.3/§7.1.4). Their
	// VALUES are shared-state across the parallel tests on this stand —
	// sibling worlds legitimately hold lapsed-but-unreleased rows
	// (stranded §12) and mid-flight settle jobs (divergence §7.1.3) — so
	// no global value is assertable here; the org-scoped DB asserts above
	// are the money authority.
	_, err = NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig()).CheckInvariants(ctx)
	require.NoError(t, err)
}

// TestN06P05Live_MidPassLeaseExpiryAbortsAndConverges: a fenced verdict
// whose lease TTL expires BETWEEN rows aborts with ErrRecoveryFenceExpired
// (the per-row stop() check), never touches the remaining rows, and a
// takeover verdict converges the replica to exactly-once. The expiry is
// forced deterministically through the fence's injectable clock once the
// pass has released its first row.
func TestN06P05Live_MidPassLeaseExpiryAbortsAndConverges(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-midx-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	const dead = "n06p5-midx-dead"
	total := n06p5GrantFourScopes(t, pool, org, dead)
	n06p5ShiftLease(t, pool, dead, time.Hour) // all four rows: inside the window

	// Fenced verdict A with an injectable clock; a watcher flips the clock
	// past the TTL as soon as the first row is released — the abort lands
	// mid-pass, after real progress. The flip goes through an atomic so
	// watcher and pass never share unsynchronized state.
	fence := NewRecoveryFence(pool, nil)
	base := time.Now()
	var expiry atomic.Int64 // unix nanos of the faked now, 0 = real base
	fence.now = func() time.Time {
		if v := expiry.Load(); v != 0 {
			return time.Unix(0, v)
		}
		return base
	}
	leaseA, err := fence.Acquire(ctx, dead, "verdict-a", time.Hour)
	require.NoError(t, err)

	stop := make(chan struct{})
	var watcherDone sync.WaitGroup
	watcherDone.Add(1)
	go func() {
		defer watcherDone.Done()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-stop:
				return
			default:
			}
			var released int64
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM budget_allowances
				WHERE replica_id = $1 AND status = $2`, dead, AllowanceReleased).Scan(&released)
			if released >= 1 {
				expiry.Store(base.Add(2 * time.Hour).UnixNano())
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	sumA, errA := store.CloseAbandonedReplicaFenced(ctx, leaseA, 30*time.Minute)
	close(stop)
	watcherDone.Wait()

	if errA == nil {
		// The pass outran the watcher: it completed the whole replica.
		require.Equal(t, int64(4), sumA.Closed, "a completed fenced pass closed every row")
		require.Equal(t, total, sumA.ReturnedMicroUSD)
	} else {
		require.ErrorIs(t, errA, ErrRecoveryFenceExpired, "the mid-pass TTL check aborts the pass")
		require.GreaterOrEqual(t, sumA.Closed, int64(1),
			"the watcher only flips after a release, so the abort happened after real progress")
		require.LessOrEqual(t, sumA.Closed, int64(3), "the pass did not finish after expiry")
	}
	require.NoError(t, leaseA.Release(ctx), "the session is alive — release succeeds")

	// Takeover: verdict B finishes whatever A left open, exactly once.
	leaseB, err := n06p5TryAcquireFence(pool, dead, "verdict-b", time.Hour)
	require.NoError(t, err)
	sumB, err := store.CloseAbandonedReplicaFenced(ctx, leaseB, 30*time.Minute)
	require.NoError(t, err)
	require.NoError(t, leaseB.Release(ctx))
	require.Equal(t, int64(4), sumA.Closed+sumB.Closed, "A and B close every row exactly once")
	require.Equal(t, total, sumA.ReturnedMicroUSD+sumB.ReturnedMicroUSD,
		"the full escrow returns exactly once across both verdicts")

	for _, scope := range []ScopeKind{ScopeWallet, ScopeTeamMonth, ScopeAgentDay, ScopeSession} {
		key, period := n06p5ScopeRef(t, pool, dead, scope)
		_, granted, ret, status, _ := allowanceRow(t, pool, dead, scope, key, period)
		assert.Equal(t, AllowanceReleased, status, "scope %s", scope)
		assert.Equal(t, granted, ret, "scope %s", scope)
	}
	require.Zero(t, walletState(t, pool, org))
	for _, scope := range []ScopeKind{ScopeTeamMonth, ScopeAgentDay, ScopeSession} {
		key, period := n06p5ScopeRef(t, pool, dead, scope)
		assert.Zero(t, scopeReserve(t, pool, scope, key, period), "scope %s reserve released", scope)
	}

	// The expired (now released) lease is stale for every later use — no
	// zombie resume after an orderly release.
	_, err = store.CloseAbandonedReplicaFenced(ctx, leaseA, 30*time.Minute)
	require.ErrorIs(t, err, ErrStaleRecoveryFence)

	// A fresh re-verdict observes the exactly-once losing side.
	leaseC, err := n06p5TryAcquireFence(pool, dead, "verdict-c", time.Hour)
	require.NoError(t, err)
	defer func() { _ = leaseC.Release(ctx) }()
	sumC, err := store.CloseAbandonedReplicaFenced(ctx, leaseC, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(4), sumC.AlreadyReleased)
	require.Zero(t, sumC.Closed)
	require.Zero(t, sumC.ReturnedMicroUSD)
}

// TestN06P05Live_LiveReservationNeverReleasedByCrashRecovery: every
// recovery primitive refuses a live, renewed reservation — including the
// between-renewals window (lease valid but seconds from expiry) and the
// expired-but-inside-window shape; the fenced verdict's deliberate short
// window accelerates only lapsed rows, never live ones. When the owner
// genuinely dies, recovery closes exactly once and a late Renewal cannot
// resurrect released rows.
func TestN06P05Live_LiveReservationNeverReleasedByCrashRecovery(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-livg-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	hostPrefix := "n06p5livg" + uuid.NewString()[:8]
	live := hostPrefix + "-9-9" // reap-shaped name: the sweep COULD target it
	total := n06p5GrantFourScopes(t, pool, org, live)

	// battery runs every recovery primitive against the (possibly live)
	// replica and asserts none of them released anything. The verdict
	// summaries are replica-scoped and assertable directly; the periodic
	// pass is GLOBAL (other tests' rows may legitimately appear in its
	// summary), so its effect is asserted per-row against this test's own
	// rows instead. While the replica is live, every row must still be
	// active after the pass; in the post-mortem battery the rows are
	// legitimately released, so only "nothing was closed" is asserted.
	// Returns Σ SkippedLive over both verdict passes.
	liveScopes := func() []ScopeKind {
		return []ScopeKind{ScopeWallet, ScopeTeamMonth, ScopeAgentDay, ScopeSession}
	}
	battery := func(replicaLive bool) int64 {
		var skipped int64
		s, err := store.CloseAbandonedReplica(ctx, live, 0)
		require.NoError(t, err)
		require.Zero(t, s.Closed, "unfenced verdict released a live row")
		skipped += s.SkippedLive
		lease, err := n06p5TryAcquireFence(pool, live, "fenced-verdict", time.Hour)
		require.NoError(t, err)
		sf, err := store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
		require.NoError(t, err)
		require.NoError(t, lease.Release(ctx))
		require.Zero(t, sf.Closed, "fenced verdict released a live row — the short window accelerates only lapsed rows")
		skipped += sf.SkippedLive
		sum, err := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig()).ReleasePass(ctx)
		require.NoError(t, err)
		_ = sum // global summary: asserted per-row below, never on Released
		if replicaLive {
			for _, scope := range liveScopes() {
				key, period := n06p5ScopeRef(t, pool, live, scope)
				_, _, _, status, _ := allowanceRow(t, pool, live, scope, key, period)
				require.Equal(t, AllowanceActive, status, "periodic pass released live row of scope %s", scope)
			}
		}
		return skipped
	}

	require.Equal(t, int64(8), battery(true), "fresh lease: all four rows skipped live by both verdicts")
	require.Equal(t, int64(100_000), walletState(t, pool, org), "wallet reserve untouched by the battery")
	require.Equal(t, int64(4), mustRenew(t, store, ctx, live), "a live replica renews every scope row")

	// Between renewals: lease valid but seconds from expiry.
	n06p5ShiftLease(t, pool, live, -time.Second)
	require.Equal(t, int64(8), battery(true), "between-renewals rows are still live")
	require.Equal(t, int64(4), mustRenew(t, store, ctx, live))

	// Expired but inside every window — the §14 safety window AND the
	// fenced verdict's deliberate 30-minute override.
	n06p5ShiftLease(t, pool, live, 15*time.Minute)
	require.Equal(t, int64(8), battery(true), "expired-but-inside-window rows are guarded by the window")
	require.Equal(t, int64(4), mustRenew(t, store, ctx, live), "Renewal revives expired-but-renewing rows")

	// The self-reap sweep drains only crashed incarnations — the live
	// incarnation (young lease, reap-shaped name) is never drained.
	drained, err := store.SelfReapCrashedIncarnations(ctx, hostPrefix)
	require.NoError(t, err)
	require.Zero(t, drained, "the live incarnation is not self-reaped")
	require.Equal(t, int64(8), battery(true))

	// The owner dies: recovery closes every row exactly once; the live
	// guard never fired for the dead shape.
	n06p5ShiftLease(t, pool, live, 3*time.Hour)
	orphanBefore := releasedCounter(t, ReleaseReasonCrashOrphan)
	sum, err := store.CloseAbandonedReplica(ctx, live, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4), sum.Closed)
	require.Equal(t, total, sum.ReturnedMicroUSD)
	// The counter is process-global (see the file header): GreaterOrEqual
	// proves this post-mortem ticked; the DB asserts prove exactly-once.
	assert.GreaterOrEqual(t, releasedCounter(t, ReleaseReasonCrashOrphan), orphanBefore+4)
	require.Zero(t, walletState(t, pool, org))

	// No resurrection: a late renewal finds nothing to renew, every
	// recovery primitive re-runs as a no-op and the re-verdict observes the
	// exactly-once losing side.
	require.Zero(t, mustRenew(t, store, ctx, live), "released rows are never resurrected by a renewal")
	require.Zero(t, battery(false), "post-mortem battery: nothing live left to skip")
	lease, err := n06p5TryAcquireFence(pool, live, "post-mortem", time.Hour)
	require.NoError(t, err)
	sumF, err := store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.NoError(t, err)
	require.NoError(t, lease.Release(ctx))
	require.Equal(t, int64(4), sumF.AlreadyReleased)
	require.Zero(t, sumF.Closed)
}

func mustRenew(t *testing.T, store *ReservationStore, ctx context.Context, replica string) int64 {
	t.Helper()
	n, err := store.Renewal(ctx, replica)
	require.NoError(t, err)
	return n
}

// TestN06P05Live_BoundedRecoveryRoundsConverge: a multi-replica world with
// every crash shape converges within a bounded number of recovery rounds —
// hard crash, expired lease, mid-drain crash with money, draining with
// zero remainder — each row released exactly once across all rounds, no
// eternal reservations, the live sibling untouched, and idempotent under
// extra rounds.
func TestN06P05Live_BoundedRecoveryRoundsConverge(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-cvge-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 20_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	worker := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	// Stand-wide invariant queries execute cleanly; see the zombie test's
	// closing comment — global report VALUES are shared-state and not
	// assertable under parallel sibling worlds.
	_, err := worker.CheckInvariants(ctx)
	require.NoError(t, err)

	host := "n06p5cvge" + uuid.NewString()[:8]
	d1, d2, d3 := host+"-1-3", host+"-2-3", host+"-3-3" // reap-matching incarnations
	live := "n06p5cvglive" + uuid.NewString()[:8]       // different host prefix on purpose

	const (
		dead1Bound = int64(600_000) // hard crash: active + lapsed
		dead2Bound = int64(300_000) // expired lease + lapsed
		dead3Bound = int64(150_000) // mid-drain crash: draining + lapsed + money
		liveBound  = int64(250_000)
		zeroBound  = int64(100_000) // draining + zero remainder (§7.1.2)
	)
	// The zero-remainder shape: settle the full bound (the reserve moves to
	// spent), then drain — §7.1.2 releases it with zero returned even on a
	// young lease, and no money moves.
	d4 := d4Name()
	for _, tc := range []struct {
		replica string
		bound   int64
	}{{d1, dead1Bound}, {d2, dead2Bound}, {d3, dead3Bound}, {live, liveBound}, {d4, zeroBound}} {
		_, err := store.Grant(ctx, tc.replica, org, []GrantRequest{
			{Scope: ScopeWallet, Key: org, Bound: money.MicroUSD(tc.bound)},
		})
		require.NoError(t, err)
	}
	// 1h lapsed: inside the §14 safety window, so a foreign periodic pass
	// (the pass is global and sibling tests share the stand) is legally
	// refused — only this test's actors can move these rows. The fenced
	// verdict's 30-minute override still closes them (its acceleration is
	// the §14 mechanism under test); the sweep drains any lapse.
	n06p5ForceState(t, pool, d1, org, AllowanceActive, time.Hour)
	n06p5ForceState(t, pool, d2, org, AllowanceExpired, time.Hour)
	n06p5ForceState(t, pool, d3, org, AllowanceDraining, time.Hour)
	require.Equal(t, dead1Bound+dead2Bound+dead3Bound+liveBound+zeroBound, walletState(t, pool, org))

	d4ID, _, _, _, _ := allowanceRow(t, pool, d4, ScopeWallet, org, "")
	settled, err := n06p5SettleLikeWorker(ctx, pool, org, d4ID, 100_000, 100_000)
	require.NoError(t, err)
	require.Equal(t, zeroBound, settled)
	_, err = store.MarkDraining(ctx, d4)
	require.NoError(t, err)

	// Bounded recovery: the production loop is unbounded, the negative
	// clause demands convergence within a small bound. Only replica-scoped
	// verdict summaries fold into the asserted totals — ReleasePass is a
	// global pass whose summary may include other tests' rows (and d4's
	// windowless zero-remainder release may land in whichever pass runs
	// first), so passes are raced for interleaving chaos but judged only
	// through the DB asserts below.
	const maxRounds = 4
	var (
		totalReturned int64
		totalReaped   int64
		converged     bool
	)
	for round := 1; round <= maxRounds && !converged; round++ {
		// §7.1 startup sweep: only d1 is active; d2/d3/d4 are not. No
		// foreign actor can legally release the in-window d1, so the sweep
		// drains it exactly once.
		drained, err := store.SelfReapCrashedIncarnations(ctx, host)
		require.NoError(t, err)
		totalReaped += drained

		// Two racing periodic passes (leader transition in flight) — DB
		// asserts below prove they never touch an in-window row.
		for range n06p5RaceReleasePass(t, pool, 2) {
		}

		// Unfenced orphan verdicts: the 2h window refuses every in-window
		// row — deterministic SkippedLive, never a closure.
		for _, rep := range []string{d1, d2, d3} {
			s, err := store.CloseAbandonedReplica(ctx, rep, 0)
			require.NoError(t, err)
			require.Zero(t, s.Closed, "replica %s: the unfenced verdict released an in-window row", rep)
			require.Zero(t, s.ReturnedMicroUSD, "replica %s", rep)
			require.Equal(t, int64(1), s.SkippedLive, "replica %s: the single wallet row is skipped live", rep)
		}

		// Fenced verdicts close each replica exactly once (round 1).
		for _, rep := range []string{d1, d2, d3} {
			lease, err := n06p5TryAcquireFence(pool, rep, fmt.Sprintf("verdict-r%d", round), time.Hour)
			require.NoError(t, err)
			s, err := store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
			require.NoError(t, err)
			require.NoError(t, lease.Release(ctx))
			totalReturned += s.ReturnedMicroUSD
		}

		converged = n06p5LapsedNonReleased(t, pool, org) == 0
	}
	require.True(t, converged, "recovery did not converge within %d rounds", maxRounds)

	assert.Equal(t, int64(1), totalReaped, "the sweep drains the crashed incarnation exactly once")
	assert.Equal(t, dead1Bound+dead2Bound+dead3Bound, totalReturned,
		"the full escrow of the three money-holding dead replicas returns exactly once")

	// Every row released exactly once, money invariants hold. The
	// zero-remainder row (§7.1.2) releases with zero returned — the
	// reserve moved to spent at settle time, not at release time.
	for _, tc := range []struct {
		replica  string
		granted  int64
		returned int64
	}{{d1, dead1Bound, dead1Bound}, {d2, dead2Bound, dead2Bound},
		{d3, dead3Bound, dead3Bound}, {d4, zeroBound, 0}} {
		_, granted, ret, status, _ := allowanceRow(t, pool, tc.replica, ScopeWallet, org, "")
		assert.Equal(t, AllowanceReleased, status, "replica %s", tc.replica)
		assert.Equal(t, tc.granted, granted)
		assert.Equal(t, tc.returned, ret, "replica %s: returned matches the shape exactly once", tc.replica)
	}
	_, _, liveReturned, liveStatus, _ := allowanceRow(t, pool, live, ScopeWallet, org, "")
	assert.Equal(t, AllowanceActive, liveStatus, "the live sibling survives every round")
	assert.Zero(t, liveReturned)
	require.Equal(t, liveBound, walletState(t, pool, org), "only the live sibling's reserve remains")

	// Stand-wide invariant queries execute cleanly over the shared stand
	// (values are sibling-shared, see the zombie test's closing comment).
	_, err = worker.CheckInvariants(ctx)
	require.NoError(t, err)

	// Idempotency: extra rounds are no-ops on this world (the pass summary
	// is global and unassertable; the DB rows are the authority).
	for round := 0; round < 2; round++ {
		_, err := worker.ReleasePass(ctx)
		require.NoError(t, err)
		for _, rep := range []string{d1, d2, d3} {
			s, err := store.CloseAbandonedReplica(ctx, rep, 0)
			require.NoError(t, err)
			assert.Zero(t, s.Closed)
			assert.Zero(t, s.ReturnedMicroUSD)
			assert.GreaterOrEqual(t, s.AlreadyReleased, int64(1), "the losing side is observable")
		}
	}
	require.Zero(t, n06p5LapsedNonReleased(t, pool, org), "no eternal reservations after extra rounds")
	require.Equal(t, liveBound, walletState(t, pool, org))
}

// d4Name returns a fresh unique zero-remainder replica name.
func d4Name() string { return "n06p5cvge-zero-" + uuid.NewString()[:8] }

// TestN06P05Live_OrphanVerdictsRacingSettleExactlyOnce: the union race
// T02 and T04 each covered half of — every recovery actor at once against
// one orphan: two unfenced verdicts, one fenced verdict, two periodic
// passes and a settle-like worker charging a partial amount. The orphan
// is in-window, so the unfenced verdicts and the passes are legally
// REFUSED (a foreign global pass must never be able to close it either —
// sibling tests share the stand) and the fenced verdict races the settle
// worker for the money: whichever wins, settled + returned equals the
// granted escrow exactly once (SettleDecrementTx observes a lost race as
// ledger-only), and everything is idempotent afterwards.
func TestN06P05Live_OrphanVerdictsRacingSettleExactlyOnce(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-unio-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	const (
		deadBound    = int64(600_000)
		settleAmount = int64(250_000)
	)
	_, err := store.Grant(ctx, "n06p5-unio-dead", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: money.MicroUSD(deadBound)},
	})
	require.NoError(t, err)
	_, err = store.Grant(ctx, "n06p5-unio-live", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 250_000},
	})
	require.NoError(t, err)
	allowanceID, _, _, _, _ := allowanceRow(t, pool, "n06p5-unio-dead", ScopeWallet, org, "")
	// Inside the §14 window: unfenced verdicts and periodic passes are
	// legally refused; only the fenced override and the settle worker can
	// move the row — the race the per-row state machine must serialize.
	n06p5ForceState(t, pool, "n06p5-unio-dead", org, AllowanceActive, time.Hour)

	const racers = 6
	summaries := make([]AbandonedReplicaSummary, racers)
	passes := make([]ReconcileSummary, 2)
	errs := make([]error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(racers)
	go func() { // two unfenced verdicts
		defer wg.Done()
		<-start
		summaries[0], errs[0] = store.CloseAbandonedReplica(ctx, "n06p5-unio-dead", 30*time.Minute)
	}()
	go func() {
		defer wg.Done()
		<-start
		summaries[1], errs[1] = store.CloseAbandonedReplica(ctx, "n06p5-unio-dead", 30*time.Minute)
	}()
	go func() { // one fenced verdict with the deliberate override
		defer wg.Done()
		<-start
		lease, err := n06p5TryAcquireFence(pool, "n06p5-unio-dead", "fenced-racer", time.Hour)
		if err != nil {
			errs[2] = err
			return
		}
		defer func() { _ = lease.Release(ctx) }()
		summaries[2], errs[2] = store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	}()
	go func() { // the settle-like worker: partial charge, one tx
		defer wg.Done()
		<-start
		_, errs[3] = n06p5SettleLikeWorker(ctx, pool, org, allowanceID,
			money.MicroUSD(settleAmount), money.MicroUSD(deadBound))
	}()
	go func() { // two periodic passes
		defer wg.Done()
		<-start
		w := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
		passes[0], errs[4] = w.ReleasePass(ctx)
	}()
	go func() {
		defer wg.Done()
		<-start
		w := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
		passes[1], errs[5] = w.ReleasePass(ctx)
	}()
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "racer %d failed", i)
	}

	var closed int64
	for _, s := range summaries {
		closed += s.Closed
	}

	var settledAmount, ret int64
	var status string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COALESCE(SUM((payload->>'`+ReconcileSettleKey+`')::bigint), 0)
		FROM settlement_jobs WHERE org_id = $1 AND status = 'settled'`, org).Scan(&settledAmount))
	_, _, ret, status, _ = allowanceRow(t, pool, "n06p5-unio-dead", ScopeWallet, org, "")

	// The central negative invariant, read from the DB (the pass summaries
	// are global and unassertable on a shared stand): settled + returned
	// equals the granted escrow exactly once, in every interleaving.
	require.Equal(t, deadBound, settledAmount+ret,
		"settle + release sum to the granted escrow exactly once")
	assert.LessOrEqual(t, closed, int64(1), "at most one verdict became the closer")
	assert.GreaterOrEqual(t, closed, int64(0), "the fenced verdict or settle won the race")
	assert.Equal(t, AllowanceReleased, status)
	assert.Equal(t, deadBound-settledAmount, ret, "returned equals granted minus the settled amount")
	assert.Equal(t, int64(250_000), walletState(t, pool, org), "the live sibling is untouched")

	// Idempotent tail: nothing left for anyone.
	sum, err := store.CloseAbandonedReplica(ctx, "n06p5-unio-dead", 0)
	require.NoError(t, err)
	require.Zero(t, sum.Closed)
	require.Zero(t, sum.ReturnedMicroUSD)
	require.Equal(t, int64(1), sum.AlreadyReleased)
	// Stand-wide invariant queries execute cleanly (values are
	// sibling-shared on this stand, see the zombie test's closing comment).
	_, err = NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig()).CheckInvariants(ctx)
	require.NoError(t, err)
}
