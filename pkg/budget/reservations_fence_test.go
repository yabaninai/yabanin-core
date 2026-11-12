// Unit tests for the crash-recovery fencing lease (N06-P05-T04): the
// safety-window policy (fail-closed floor for unfenced verdicts, honored
// override under a held fence), lease lifecycle semantics, and the
// explicit stale/expired rejections — all without a database; the
// live-PG behavior lives in reservations_fence_int_test.go. The bounded
// release path (N12-P03-T02) is pinned here too, also without a database.
package budget

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrphanWindowFloorsShortOverrides(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		window time.Duration
	}{
		{"zero falls back", 0},
		{"negative falls back", -time.Hour},
		{"millisecond override floored", time.Millisecond},
		{"30m override floored", 30 * time.Minute},
		{"just under the default floored", ReservationSafetyWindow - time.Nanosecond},
	}
	for _, tc := range cases {
		t.Run("unfenced "+tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, ReservationSafetyWindow, orphanWindow(tc.window),
				"an unfenced verdict never gets a window shorter than the §14 default")
		})
	}
	for _, w := range []time.Duration{ReservationSafetyWindow, 3 * time.Hour, 24 * time.Hour} {
		assert.Equal(t, w, orphanWindow(w), "a window at or above the default passes through")
	}
}

func TestOrphanFencedWindowHonorsDeliberateOverride(t *testing.T) {
	t.Parallel()
	// Under a held fence a positive window is the deliberate, serialized,
	// TTL-bounded override — honored as-is, however short.
	for _, w := range []time.Duration{time.Millisecond, 30 * time.Minute, ReservationSafetyWindow, 5 * time.Hour} {
		assert.Equal(t, w, orphanFencedWindow(w))
	}
	// But a lease does not think for the caller: no window → §14 default.
	assert.Equal(t, ReservationSafetyWindow, orphanFencedWindow(0))
	assert.Equal(t, ReservationSafetyWindow, orphanFencedWindow(-time.Minute))
}

func TestRecoveryFenceKeyNamespace(t *testing.T) {
	t.Parallel()
	key := recoveryFenceKey("replica-1")
	require.Equal(t, recoveryFenceNamespace+"replica-1", key)
	assert.Contains(t, key, "budget:recovery-fence:", "fence keys live in their own hashtext namespace")
	assert.Equal(t, key, recoveryFenceKey("replica-1"), "stable per replica")
}

// newTestFence builds a fence with a fake clock at base (no database —
// the lifecycle checks below never touch it).
func newTestFence(t *testing.T, base time.Time) *RecoveryFence {
	t.Helper()
	fence := NewRecoveryFence(nil, newBudgetTestLogger())
	fence.now = func() time.Time { return base }
	return fence
}

func TestRecoveryLeaseLifecycleSemantics(t *testing.T) {
	t.Parallel()
	base := time.Now()
	fence := newTestFence(t, base)

	lease := &RecoveryLease{fence: fence, replica: "r", owner: "v1", expires: base.Add(time.Hour)}
	require.True(t, lease.Held(), "a fresh lease is held")
	require.False(t, lease.Expired(), "inside the TTL")
	require.Equal(t, base.Add(time.Hour), lease.Expires())
	require.Equal(t, "r", lease.ReplicaID())
	require.Equal(t, "v1", lease.Owner())

	// TTL elapsed → expired, still held (release is a separate act).
	fence.now = func() time.Time { return base.Add(2 * time.Hour) }
	assert.True(t, lease.Expired())
	assert.True(t, lease.Held())

	// Released → not held, stale for every later use.
	lease.released.Store(true)
	assert.False(t, lease.Held())
	assert.True(t, lease.Expired())

	// Nil lease: stale and expired, but the accessors must not panic.
	var missing *RecoveryLease
	assert.False(t, missing.Held())
	assert.True(t, missing.Expired())
	assert.Empty(t, missing.ReplicaID())
	assert.Empty(t, missing.Owner())
	assert.True(t, missing.Expires().IsZero())
}

func TestRecoveryFenceAcquireValidation(t *testing.T) {
	t.Parallel()
	fence := newTestFence(t, time.Now())

	_, err := fence.Acquire(t.Context(), "", "v1", time.Hour)
	require.ErrorIs(t, err, ErrInvalidRequest)
	_, err = fence.Acquire(t.Context(), "replica", "", time.Hour)
	require.ErrorIs(t, err, ErrInvalidRequest)
	_, err = fence.Acquire(t.Context(), "replica", "v1", 0)
	require.ErrorIs(t, err, ErrInvalidRequest, "an unbounded lease would be an eternal recovery authority")
	_, err = fence.Acquire(t.Context(), "replica", "v1", -time.Minute)
	require.ErrorIs(t, err, ErrInvalidRequest)
}

func TestCloseAbandonedReplicaFencedRejectsStaleAndExpired(t *testing.T) {
	t.Parallel()
	store := NewReservationStoreWithConfig(nil, newBudgetTestLogger(), DefaultReservationConfig())
	fence := newTestFence(t, time.Now())

	// Never acquired.
	_, err := store.CloseAbandonedReplicaFenced(t.Context(), nil, 30*time.Minute)
	require.ErrorIs(t, err, ErrStaleRecoveryFence)

	// Released (e.g. a paused old verdict resumed after a new owner took
	// over) — the stale-mutation rejection.
	released := &RecoveryLease{fence: fence, replica: "r", owner: "v1", expires: time.Now().Add(time.Hour)}
	released.released.Store(true)
	_, err = store.CloseAbandonedReplicaFenced(t.Context(), released, 30*time.Minute)
	require.ErrorIs(t, err, ErrStaleRecoveryFence)

	// TTL elapsed — the bounded override refuses to run.
	expired := &RecoveryLease{fence: fence, replica: "r", owner: "v1", expires: time.Now().Add(-time.Second)}
	_, err = store.CloseAbandonedReplicaFenced(t.Context(), expired, 30*time.Minute)
	require.ErrorIs(t, err, ErrRecoveryFenceExpired)
	require.NotErrorIs(t, err, ErrStaleRecoveryFence, "held-but-expired is the TTL rejection, not the stale one")
}

// stalledUnlockTx pins the Release cleanup to exactly QueryRow + Rollback:
// the unlock Scan blocks until its context dies (a wedged connection), and
// any other pgx.Tx call panics through the embedded nil interface.
type stalledUnlockTx struct {
	pgx.Tx
	rolledBack bool
}

func (s *stalledUnlockTx) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	return stalledUnlockRow{ctx: ctx}
}

func (s *stalledUnlockTx) Rollback(context.Context) error {
	s.rolledBack = true
	return nil
}

type stalledUnlockRow struct {
	ctx context.Context
}

func (r stalledUnlockRow) Scan(_ ...any) error {
	<-r.ctx.Done()
	return r.ctx.Err()
}

// TestRecoveryLeaseReleaseBoundedWhenUnlockStalls pins the N12-P03-T02
// guarantee: a shutting-down verdict whose pooled connection wedges must not
// hang the drain — Release returns bounded, after still attempting the
// holder rollback, and a later double release stays a no-op.
func TestRecoveryLeaseReleaseBoundedWhenUnlockStalls(t *testing.T) {
	t.Parallel()
	fence := newTestFence(t, time.Now())
	fence.releaseDeadline = 50 * time.Millisecond
	tx := &stalledUnlockTx{}
	lease := &RecoveryLease{
		fence: fence, replica: "r", owner: "v1",
		expires: time.Now().Add(time.Hour), holder: tx,
	}

	start := time.Now()
	err := lease.Release(context.Background())
	elapsed := time.Since(start)

	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded,
		"the stalled unlock is aborted by the release deadline")
	assert.Less(t, elapsed, 5*time.Second, "Release must not hang on a wedged connection")
	assert.True(t, tx.rolledBack, "the holder rollback is still attempted after a stalled unlock")

	// The lease is consumed either way: an idempotent double release.
	require.NoError(t, lease.Release(context.Background()))
	assert.False(t, lease.Held())
}

// recordingTx is a healthy holder tx: the unlock reports success, the
// rollback is recorded. It pins the WithoutCancel semantics across the
// deadline change — a cancelled caller context must still release cleanly.
type recordingTx struct {
	pgx.Tx
	unlockQueried bool
	rolledBack    bool
}

func (r *recordingTx) QueryRow(context.Context, string, ...any) pgx.Row {
	r.unlockQueried = true
	return releasedRow{}
}

func (r *recordingTx) Rollback(context.Context) error {
	r.rolledBack = true
	return nil
}

type releasedRow struct{}

func (releasedRow) Scan(dest ...any) error {
	if b, ok := dest[0].(*bool); ok {
		*b = true
	}
	return nil
}

// ctxHonoringTx is a holder tx whose every operation honors the context it
// actually receives (review findings 1+2, s1-11 review 2026-10-28): the
// earlier recordingTx ignored ctx entirely, so a regression from
// WithTimeout(WithoutCancel(ctx), …) to WithTimeout(ctx, …) — or to one
// shared budget covering both unlock and rollback — would still pass.
// This fake makes both regressions observable.
type ctxHonoringTx struct {
	pgx.Tx
	rolledBack  bool
	rollbackErr error
}

func (c *ctxHonoringTx) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	return ctxRow{ctx: ctx}
}

func (c *ctxHonoringTx) Rollback(ctx context.Context) error {
	c.rolledBack = true
	<-ctx.Done()
	c.rollbackErr = ctx.Err()
	return c.rollbackErr
}

// ctxRow blocks in Scan on the captured context's Done and surfaces that
// context's own error — the wire-real shape of a statement waiting on a
// dead/expiring connection.
type ctxRow struct{ ctx context.Context }

func (r ctxRow) Scan(...any) error {
	<-r.ctx.Done()
	return r.ctx.Err()
}

// TestRecoveryLeaseReleaseCtxDerivationPins the two ctx contracts of the
// bounded release together:
//
//   - finding 1: the release contexts derive from WithoutCancel(ctx), so a
//     pre-cancelled caller context never short-circuits cleanup — the
//     unlock waits for its own bounded deadline and aborts with
//     DeadlineExceeded, NOT the caller's Canceled.
//   - finding 2: unlock and rollback each get a FRESH bounded budget —
//     after the unlock consumed its full 40ms deadline, the rollback still
//     gets its own 40ms (wall clock >= ~80ms total; a single shared budget
//     would complete in ~40ms with an instantly-expired rollback ctx).
func TestRecoveryLeaseReleaseCtxDerivationPins(t *testing.T) {
	t.Parallel()
	fence := newTestFence(t, time.Now())
	fence.releaseDeadline = 40 * time.Millisecond
	tx := &ctxHonoringTx{}
	lease := &RecoveryLease{
		fence: fence, replica: "r", owner: "v1",
		expires: time.Now().Add(time.Hour), holder: tx,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := lease.Release(ctx)
	elapsed := time.Since(start)

	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded,
		"the bounded deadline must abort the stalled unlock")
	require.NotErrorIs(t, err, context.Canceled,
		"finding 1: the release ctx must derive from WithoutCancel(ctx), not the cancelled caller")
	require.True(t, tx.rolledBack, "the holder rollback is still attempted after the stalled unlock")
	require.ErrorIs(t, tx.rollbackErr, context.DeadlineExceeded,
		"finding 2: the rollback runs under its own fresh bounded ctx, not the unlock's expired one")
	require.GreaterOrEqual(t, elapsed, 70*time.Millisecond,
		"finding 2: unlock and rollback each consume their own deadline (40ms+40ms); one shared budget would finish in ~40ms")
	assert.Less(t, elapsed, 5*time.Second, "Release stays bounded overall")
}

func TestRecoveryLeaseReleaseIgnoresCallerCancel(t *testing.T) {
	t.Parallel()
	fence := newTestFence(t, time.Now())
	tx := &recordingTx{}
	lease := &RecoveryLease{
		fence: fence, replica: "r", owner: "v1",
		expires: time.Now().Add(time.Hour), holder: tx,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, lease.Release(ctx))
	assert.True(t, tx.unlockQueried, "the unlock ran despite the cancelled caller context")
	assert.True(t, tx.rolledBack)
	assert.False(t, lease.Held())
}

// w40BlockingDB fakes an exhausted pool without Postgres: every operation
// waits for its context to die, exactly like puddle's acquire queue when
// every connection is pinned by a fence holder (W40).
type w40BlockingDB struct{}

func (w40BlockingDB) Begin(ctx context.Context) (pgx.Tx, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (w40BlockingDB) Exec(ctx context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	<-ctx.Done()
	return pgconn.CommandTag{}, ctx.Err()
}

func (w40BlockingDB) Query(ctx context.Context, _ string, _ ...any) (pgx.Rows, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (w40BlockingDB) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	return stalledUnlockRow{ctx: ctx}
}

// TestW40OrphanCloseBoundedAcquireSurfacesSentinel: with every pooled
// connection pinned, the orphan-close verdict must refuse to queue — the
// internal bound aborts the round-trip and surfaces as the retryable
// ErrOrphanAcquireTimeout (still carrying the underlying deadline), never
// as a hang or a fence-class rejection.
func TestW40OrphanCloseBoundedAcquireSurfacesSentinel(t *testing.T) {
	t.Parallel()
	store := NewReservationStoreWithConfig(w40BlockingDB{}, newBudgetTestLogger(), DefaultReservationConfig())
	store.orphanAcquireTimeout = 60 * time.Millisecond

	start := time.Now()
	_, err := store.CloseAbandonedReplica(context.Background(), "w40-dead", time.Hour)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, ErrOrphanAcquireTimeout)
	require.ErrorIs(t, err, context.DeadlineExceeded, "the underlying deadline stays in the chain")
	assert.Less(t, elapsed, 5*time.Second, "the bound fails fast instead of hanging")
	require.NotErrorIs(t, err, ErrRecoveryFenceExpired)
	require.NotErrorIs(t, err, ErrStaleRecoveryFence)
}

// TestW40OrphanCloseCallerDeadlineIsNotMisclassified: the mapping's
// negative control — a deadline coming from the CALLER's own context
// propagates unchanged; only the verdict's internal bound becomes the
// retryable busy refusal.
func TestW40OrphanCloseCallerDeadlineIsNotMisclassified(t *testing.T) {
	t.Parallel()
	store := NewReservationStoreWithConfig(w40BlockingDB{}, newBudgetTestLogger(), DefaultReservationConfig())
	store.orphanAcquireTimeout = time.Hour // effectively unbounded

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	_, err := store.CloseAbandonedReplica(ctx, "w40-dead", time.Hour)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NotErrorIs(t, err, ErrOrphanAcquireTimeout,
		"the caller's own deadline is the caller's error, not the store's busy refusal")
}
