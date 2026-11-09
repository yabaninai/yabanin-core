// N06-P05-T08: interruption/retry/resume of crash recovery ITSELF (card
// «Проверить interruption/retry/resume и восстановление результатов без
// дубликатов и потерь»). Unit side, no database: the fence's verdict
// classification must be STABLE across arbitrarily many crash/retry
// cycles — a retrying verdict never talks a rejected lease back into
// authority, the expired→released transition permanently reclassifies the
// lease to stale (never the reverse), and an advancing clock never
// resurrects an expired lease. The store's DB is nil on purpose: any
// candidate-scan access in ANY cycle would panic, so the green run proves
// every rejection across every cycle happens before the database. The
// live-PG crash/retry chains live in n06p5t08_crash_cycles_int_test.go;
// the single-rejection boundaries themselves (exact TTL instant, exact
// pre-DB ordering) are T07's corpus (n06p5_boundary_test.go) — pinned
// there, not duplicated here.
package budget

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestN06P05T08_FenceClassificationStableAcrossCrashCycles: a crashed
// verdict's lease is retried by the recovery orchestration — possibly many
// times. Each retry must observe the SAME explicit classification as the
// first: held-but-expired stays the TTL rejection (the bounded override
// cannot be re-entered by repetition), and once the lease is released the
// classification flips to stale and stays there — no cycle count, clock
// position, or retry pattern resurrects authority.
func TestN06P05T08_FenceClassificationStableAcrossCrashCycles(t *testing.T) {
	t.Parallel()
	// Nil DB: any row access in any cycle panics — the classification
	// rejections must be pre-DB on EVERY retry, not only the first.
	store := NewReservationStoreWithConfig(nil, newBudgetTestLogger(), DefaultReservationConfig())
	base := time.Now()
	fence := newTestFence(t, base)

	// Phase 1 — held but expired: five retry cycles, same class each time.
	expired := &RecoveryLease{fence: fence, replica: "r", owner: "v1", expires: base}
	require.True(t, expired.Held(), "the expired lease is still held — only its authority ran out")
	for cycle := 1; cycle <= 5; cycle++ {
		sum, err := store.CloseAbandonedReplicaFenced(t.Context(), expired, 30*time.Minute)
		require.ErrorIs(t, err, ErrRecoveryFenceExpired, "cycle %d", cycle)
		require.NotErrorIs(t, err, ErrStaleRecoveryFence,
			"cycle %d: held-but-expired is the TTL rejection, never the stale one", cycle)
		require.Equal(t, AbandonedReplicaSummary{}, sum,
			"cycle %d: a rejected verdict reports an empty pass — no partial close", cycle)
	}

	// Phase 2 — the release transition (the flag Release swaps): the same
	// lease reclassifies to stale, permanently, across five more cycles.
	expired.released.Store(true)
	for cycle := 1; cycle <= 5; cycle++ {
		sum, err := store.CloseAbandonedReplicaFenced(t.Context(), expired, 30*time.Minute)
		require.ErrorIs(t, err, ErrStaleRecoveryFence, "cycle %d", cycle)
		require.NotErrorIs(t, err, ErrRecoveryFenceExpired,
			"cycle %d: a released lease is stale even though its TTL class was expired before", cycle)
		require.Equal(t, AbandonedReplicaSummary{}, sum, "cycle %d", cycle)
	}

	// Phase 3 — stale dominates TTL: a released lease with time LEFT on its
	// TTL is stale too, and stays stale across cycles. Release beats
	// remaining authority — the inverse transition does not exist.
	unexpired := &RecoveryLease{fence: fence, replica: "r", owner: "v2", expires: base.Add(time.Hour)}
	require.False(t, unexpired.Expired(), "the lease is inside its TTL")
	unexpired.released.Store(true)
	for cycle := 1; cycle <= 5; cycle++ {
		_, err := store.CloseAbandonedReplicaFenced(t.Context(), unexpired, 30*time.Minute)
		require.ErrorIs(t, err, ErrStaleRecoveryFence,
			"cycle %d: released beats unexpired — no resurrection via remaining TTL", cycle)
	}
}

// TestN06P05T08_ExpiryNeverResurrectsAcrossRetryCycles: a paused verdict's
// lease expires, the recovery loop retries across advancing (monotone)
// time — every retry observes the expired classification, the held flag
// never flips on its own, and after the eventual release the stale
// classification is terminal. Time moving forward never re-arms a dead
// lease.
func TestN06P05T08_ExpiryNeverResurrectsAcrossRetryCycles(t *testing.T) {
	t.Parallel()
	store := NewReservationStoreWithConfig(nil, newBudgetTestLogger(), DefaultReservationConfig())
	base := time.Now()
	fence := NewRecoveryFence(nil, newBudgetTestLogger())
	var nowNano atomic.Int64 // 0 → base; otherwise unix nanos of the fake now
	fence.now = func() time.Time {
		if v := nowNano.Load(); v != 0 {
			return time.Unix(0, v)
		}
		return base
	}

	const ttl = time.Hour
	lease := &RecoveryLease{fence: fence, replica: "r", owner: "v1", expires: base.Add(ttl)}

	for step := 0; step <= 4; step++ {
		nowNano.Store(base.Add(time.Duration(step) * 30 * time.Minute).UnixNano())
		live := step <= 1 // 0 and 30m are inside the TTL; 1h onward is past it
		require.Equal(t, !live, lease.Expired(), "step %d: Expired() tracks the advancing clock", step)
		require.True(t, lease.Held(), "step %d: expiry never releases the lease by itself", step)
		if live {
			continue // a live step drives no rejection (and would need a DB)
		}
		sum, err := store.CloseAbandonedReplicaFenced(t.Context(), lease, 30*time.Minute)
		require.ErrorIs(t, err, ErrRecoveryFenceExpired, "step %d", step)
		require.Equal(t, AbandonedReplicaSummary{}, sum, "step %d", step)
	}

	// The release at the end of the retry chain is terminal: from here on
	// every classification is stale, at any later clock position.
	lease.released.Store(true)
	for step := 5; step <= 7; step++ {
		nowNano.Store(base.Add(time.Duration(step) * 30 * time.Minute).UnixNano())
		sum, err := store.CloseAbandonedReplicaFenced(t.Context(), lease, 30*time.Minute)
		require.ErrorIs(t, err, ErrStaleRecoveryFence, "step %d", step)
		require.Equal(t, AbandonedReplicaSummary{}, sum, "step %d", step)
	}
}
