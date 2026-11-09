// N06-P05-T07 boundary corpus, unit side (no database): the exact fence
// instants the T04 unit file deliberately left open. Expired() at the TTL
// deadline itself — equality belongs to the expired side, fail-closed — and
// the fenced-verdict rejection at that instant (explicit error, zero
// summary, no database access; a nil store proves the fail-closed
// ordering). The live-PG boundary pins live in
// n06p5_boundary_corpus_int_test.go and the consumer seam in
// services/loggerd/consumer/n06p5_boundary_live_test.go.
package budget

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRecoveryLeaseExpiredExactTtlEquality pins the TTL instant itself:
// Expired() is !expires.After(now), so the deadline instant is already
// expired. A verdict may never treat "exactly at the deadline" as live
// time — the bounded override cannot stretch by an epsilon.
func TestRecoveryLeaseExpiredExactTtlEquality(t *testing.T) {
	t.Parallel()
	base := time.Now()
	fence := newTestFence(t, base)

	inside := &RecoveryLease{fence: fence, replica: "r", owner: "v1", expires: base.Add(time.Nanosecond)}
	assert.False(t, inside.Expired(), "one nanosecond inside the TTL is live time")

	exact := &RecoveryLease{fence: fence, replica: "r", owner: "v1", expires: base}
	assert.True(t, exact.Expired(), "at the exact deadline the lease is expired — equality is fail-closed")

	past := &RecoveryLease{fence: fence, replica: "r", owner: "v1", expires: base.Add(-time.Nanosecond)}
	assert.True(t, past.Expired(), "one nanosecond past the deadline is expired")
}

// TestCloseAbandonedReplicaFencedRejectsAtExactTtlBoundary: at the exact
// TTL instant the fenced verdict is rejected with the explicit TTL error,
// reports a ZERO summary (no partial close — the pass never started), and
// never touches the database. The store's DB is nil on purpose: any row
// access would panic, so the green run proves the rejection happens
// before the candidate scan.
func TestCloseAbandonedReplicaFencedRejectsAtExactTtlBoundary(t *testing.T) {
	t.Parallel()
	store := NewReservationStoreWithConfig(nil, newBudgetTestLogger(), DefaultReservationConfig())
	fence := newTestFence(t, time.Now())

	// Held, but exactly at its deadline: the TTL rejection, not the stale
	// one — the lease was never released, its authority just ran out.
	lease := &RecoveryLease{fence: fence, replica: "r", owner: "v1", expires: fence.now()}
	sum, err := store.CloseAbandonedReplicaFenced(t.Context(), lease, 30*time.Minute)
	require.ErrorIs(t, err, ErrRecoveryFenceExpired)
	require.NotErrorIs(t, err, ErrStaleRecoveryFence,
		"held-but-at-deadline is the TTL rejection, not the stale one")
	require.Equal(t, AbandonedReplicaSummary{}, sum,
		"the pre-verdict rejection reports an empty pass — no partial close")
}
