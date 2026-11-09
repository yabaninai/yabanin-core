//go:build integration

// N06-P05-T04 acceptance on a disposable live Postgres (ADR-0001 §10):
// the fencing lease serializes crash-recovery verdicts, the safety-window
// override only works under a held fence, a stale or expired verdict is
// rejected explicitly without moving money, and the old-owner-pause →
// new-owner-takeover → old-owner-resumes sequence converges to one ledger
// (packet contract examples 1–2, artifacts/internal-delivery-program/N06-P05/
// contract.md).
package budget

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestN06P05Live_FencedVerdictOverridesSafetyWindow: a 1h-lapsed orphan
// sits inside the §14 default window — an unfenced verdict cannot close
// it no matter what window it passes (fail-closed floor), while the same
// verdict under a held fencing lease closes it exactly once with the
// deliberate override; a re-verdict observes the losing side.
func TestN06P05Live_FencedVerdictOverridesSafetyWindow(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-fence1-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	_, err := store.Grant(ctx, "n06p5-fence1-dead", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 50_000},
	})
	require.NoError(t, err)
	n06p5ForceState(t, pool, "n06p5-fence1-dead", org, AllowanceActive, time.Hour)
	require.Equal(t, int64(50_000), walletState(t, pool, org))

	// Unfenced: the short override is floored back up to the §14 default —
	// the 1h-lapsed row is skipped live.
	s, err := store.CloseAbandonedReplica(ctx, "n06p5-fence1-dead", 30*time.Minute)
	require.NoError(t, err)
	require.Zero(t, s.Closed)
	require.Equal(t, int64(1), s.SkippedLive)
	require.Equal(t, int64(50_000), walletState(t, pool, org))

	// Fenced: the serialized, TTL-bounded override closes exactly once.
	orphanBefore := releasedCounter(t, ReleaseReasonCrashOrphan)
	fence := NewRecoveryFence(pool, nil)
	lease, err := fence.Acquire(ctx, "n06p5-fence1-dead", "verdict-a", time.Hour)
	require.NoError(t, err)
	defer lease.Release(ctx)
	s, err = store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(1), s.Closed)
	require.Equal(t, int64(50_000), s.ReturnedMicroUSD)
	require.Zero(t, s.SkippedLive)
	assert.InDelta(t, orphanBefore+1, releasedCounter(t, ReleaseReasonCrashOrphan), 0.001)
	require.Equal(t, int64(0), walletState(t, pool, org))

	_, granted, ret, status, _ := allowanceRow(t, pool, "n06p5-fence1-dead", ScopeWallet, org, "")
	assert.Equal(t, int64(50_000), granted)
	assert.Equal(t, int64(50_000), ret)
	assert.Equal(t, AllowanceReleased, status)

	// A fresh verdict after the fence was handed back observes the
	// exactly-once losing side — convergence, not a silent double pass.
	require.NoError(t, lease.Release(ctx))
	lease2, err := fence.Acquire(ctx, "n06p5-fence1-dead", "verdict-b", time.Hour)
	require.NoError(t, err)
	defer lease2.Release(ctx)
	s, err = store.CloseAbandonedReplicaFenced(ctx, lease2, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(1), s.AlreadyReleased)
	require.Zero(t, s.Closed)
	require.Zero(t, s.ReturnedMicroUSD)
	require.Equal(t, int64(0), walletState(t, pool, org))
}

// TestN06P05Live_FenceMutualExclusionOldOwnerPauseTakeoverResume: the
// contract's negative sequence. Verdict A pauses and its lease TTL
// elapses; while its session lives the fence excludes B (explicitly);
// once A's lock drops, B takes over and closes the orphan exactly once;
// when A resumes with its stale lease the DB rejects the mutation with
// ErrStaleRecoveryFence and no money moves; A can only continue under a
// fresh lease, and then only observes the already-released outcome.
func TestN06P05Live_FenceMutualExclusionOldOwnerPauseTakeoverResume(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-fence2-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	_, err := store.Grant(ctx, "n06p5-fence2-dead", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 50_000},
	})
	require.NoError(t, err)
	_, err = store.Grant(ctx, "n06p5-fence2-live", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 200_000},
	})
	require.NoError(t, err)
	n06p5ForceState(t, pool, "n06p5-fence2-dead", org, AllowanceActive, time.Hour)
	require.Equal(t, int64(250_000), walletState(t, pool, org))

	orphanBefore := releasedCounter(t, ReleaseReasonCrashOrphan)
	fence := NewRecoveryFence(pool, nil)

	// Old owner A: acquires, then pauses past its TTL (a hung verdict
	// process). The override is bounded — an expired lease cannot close.
	leaseA, err := fence.Acquire(ctx, "n06p5-fence2-dead", "verdict-a", 80*time.Millisecond)
	require.NoError(t, err)
	defer leaseA.Release(ctx)
	time.Sleep(250 * time.Millisecond)
	require.True(t, leaseA.Expired(), "A's lease TTL elapsed during the pause")
	_, err = store.CloseAbandonedReplicaFenced(ctx, leaseA, 30*time.Minute)
	require.ErrorIs(t, err, ErrRecoveryFenceExpired)
	require.Equal(t, int64(250_000), walletState(t, pool, org), "the expired verdict moved nothing")

	// New owner takeover attempt while A's session still lives: rejected
	// explicitly — the fence is mutual exclusion first.
	_, err = fence.Acquire(ctx, "n06p5-fence2-dead", "verdict-b", time.Hour)
	require.ErrorIs(t, err, ErrRecoveryFenceHeld)

	// A's lock drops (orderly release — in production the paused
	// process's connection dies and the session lock goes with it).
	require.NoError(t, leaseA.Release(ctx))

	// B takes over and closes the orphan exactly once.
	leaseB, err := fence.Acquire(ctx, "n06p5-fence2-dead", "verdict-b", time.Hour)
	require.NoError(t, err)
	defer leaseB.Release(ctx)
	sB, err := store.CloseAbandonedReplicaFenced(ctx, leaseB, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(1), sB.Closed)
	require.Equal(t, int64(50_000), sB.ReturnedMicroUSD)
	require.Equal(t, int64(200_000), walletState(t, pool, org))
	assert.InDelta(t, orphanBefore+1, releasedCounter(t, ReleaseReasonCrashOrphan), 0.001,
		"exactly one close across the whole takeover sequence")
	// B hands the fence back (its verdict is done).
	require.NoError(t, leaseB.Release(ctx))

	// Old owner A resumes with its stale (released) lease: the DB rejects
	// the mutation, nothing moves.
	_, err = store.CloseAbandonedReplicaFenced(ctx, leaseA, 30*time.Minute)
	require.ErrorIs(t, err, ErrStaleRecoveryFence)
	require.Equal(t, int64(200_000), walletState(t, pool, org), "the stale verdict moved nothing")

	// A can only continue under a fresh lease — and then only observes the
	// exactly-once losing side.
	leaseA2, err := fence.Acquire(ctx, "n06p5-fence2-dead", "verdict-a-retry", time.Hour)
	require.NoError(t, err)
	defer leaseA2.Release(ctx)
	sA, err := store.CloseAbandonedReplicaFenced(ctx, leaseA2, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(1), sA.AlreadyReleased)
	require.Zero(t, sA.Closed)
	require.Zero(t, sA.ReturnedMicroUSD)
	require.Equal(t, int64(200_000), walletState(t, pool, org))

	_, _, _, status, _ := allowanceRow(t, pool, "n06p5-fence2-dead", ScopeWallet, org, "")
	assert.Equal(t, AllowanceReleased, status)
	_, _, _, liveStatus, liveLease := allowanceRow(t, pool, "n06p5-fence2-live", ScopeWallet, org, "")
	assert.Equal(t, AllowanceActive, liveStatus, "live sibling untouched by the takeover")
	assert.True(t, time.Until(liveLease) > 9*time.Minute, "live lease intact")
	assert.Zero(t, n06p5LapsedNonReleased(t, pool, org), "no eternal reservations")
}

// TestN06P05Live_FencedOverrideRacesUnfencedExactlyOnce: the packet's
// negative criterion with the fence in the mix — a fenced verdict
// accelerating with a 30m window races four unfenced verdicts passing the
// same 30m window and two periodic reconcile passes on one 1h-lapsed
// orphan. Only the fence may close it: the unfenced racers are floored to
// the §14 default and skip (or observe the losing side), the passes find
// nothing beyond-window, and the money moves exactly once.
func TestN06P05Live_FencedOverrideRacesUnfencedExactlyOnce(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-fence3-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	worker := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	base, err := worker.CheckInvariants(ctx)
	require.NoError(t, err)

	_, err = store.Grant(ctx, "n06p5-fence3-dead", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 50_000},
	})
	require.NoError(t, err)
	_, err = store.Grant(ctx, "n06p5-fence3-live", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 200_000},
	})
	require.NoError(t, err)
	n06p5ForceState(t, pool, "n06p5-fence3-dead", org, AllowanceActive, time.Hour)
	require.Equal(t, int64(250_000), walletState(t, pool, org))

	orphanBefore := releasedCounter(t, ReleaseReasonCrashOrphan)

	const (
		unfenced = 4
		passes   = 2
	)
	fence := NewRecoveryFence(pool, nil)
	orphanSummaries := make([]AbandonedReplicaSummary, unfenced)
	orphanErrs := make([]error, unfenced)
	passSummaries := make([]ReconcileSummary, passes)
	passErrs := make([]error, passes)
	fencedSummary := AbandonedReplicaSummary{}
	var fencedErr error
	var lease *RecoveryLease

	start := make(chan struct{})
	var wg sync.WaitGroup
	racer := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; f() }()
	}
	for i := 0; i < unfenced; i++ {
		i := i
		racer(func() {
			// Same 30m window as the fenced verdict — the floor, not the
			// fence, is what must stop an unfenced accelerator.
			orphanSummaries[i], orphanErrs[i] = store.CloseAbandonedReplica(ctx, "n06p5-fence3-dead", 30*time.Minute)
		})
	}
	for i := 0; i < passes; i++ {
		i := i
		w := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
		racer(func() {
			passSummaries[i], passErrs[i] = w.ReleasePass(ctx)
		})
	}
	racer(func() {
		lease, fencedErr = fence.Acquire(ctx, "n06p5-fence3-dead", "verdict-fenced", time.Hour)
		if fencedErr != nil {
			return
		}
		fencedSummary, fencedErr = store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	})
	close(start)
	wg.Wait()
	for i, err := range orphanErrs {
		require.NoError(t, err, "unfenced closer %d failed", i)
	}
	for i, err := range passErrs {
		require.NoError(t, err, "pass %d failed", i)
	}
	require.NoError(t, fencedErr, "the fenced verdict must win the close")
	require.NotNil(t, lease)
	defer lease.Release(ctx)

	require.Equal(t, int64(1), fencedSummary.Closed, "only the fence closes the accelerated orphan")
	require.Equal(t, int64(50_000), fencedSummary.ReturnedMicroUSD)
	var returned int64
	for i, s := range orphanSummaries {
		require.Zero(t, s.Closed, "unfenced closer %d must never close under the floor", i)
		require.Zero(t, s.ReturnedMicroUSD, "unfenced closer %d must return nothing", i)
		require.Equal(t, int64(1), s.SkippedLive+s.AlreadyReleased,
			"unfenced closer %d either skipped live or observed the exactly-once losing side", i)
		returned += s.ReturnedMicroUSD
	}
	for _, s := range passSummaries {
		require.Zero(t, s.Released, "the periodic pass must not bypass the fence override")
		require.Zero(t, s.ReturnedMicroUSD)
	}
	require.Equal(t, int64(50_000), returned+fencedSummary.ReturnedMicroUSD,
		"the orphan remainder returned exactly once across all racers")
	assert.InDelta(t, orphanBefore+1, releasedCounter(t, ReleaseReasonCrashOrphan), 0.001,
		"crash_orphan counts the fenced close exactly once")
	require.Equal(t, int64(200_000), walletState(t, pool, org),
		"only the live sibling's escrow stays frozen")

	_, _, _, status, _ := allowanceRow(t, pool, "n06p5-fence3-dead", ScopeWallet, org, "")
	assert.Equal(t, AllowanceReleased, status)
	_, _, _, liveStatus, liveLease := allowanceRow(t, pool, "n06p5-fence3-live", ScopeWallet, org, "")
	assert.Equal(t, AllowanceActive, liveStatus)
	assert.True(t, time.Until(liveLease) > 9*time.Minute, "live lease intact")

	after, err := worker.CheckInvariants(ctx)
	require.NoError(t, err)
	assert.Equal(t, base.DivergencePerScope[ScopeWallet], after.DivergencePerScope[ScopeWallet],
		"the fenced race converges to one ledger")
	assert.Equal(t, base.StrandedMicroUSD, after.StrandedMicroUSD)
	assert.Equal(t, base.ReservedPerScope[ScopeWallet]+200_000, after.ReservedPerScope[ScopeWallet])
	assert.Zero(t, n06p5LapsedNonReleased(t, pool, org), "no eternal reservations")
}
