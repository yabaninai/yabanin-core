// Fencing lease for crash-recovery verdicts (N06-P05-T04). A
// permanently-lost verdict must be fenced against a live replica and
// against other recovery writers: at most one recovery verdict acts on a
// replica's orphan reservations at a time, its authority is TTL-bounded,
// and a stale verdict that resumes after a new owner took over is
// rejected explicitly (packet contract example 2: the DB rejects the
// stale mutation and the event is available for diagnostics).
//
// The fence is one PostgreSQL session-level advisory lock
// (pg_try_advisory_lock(hashtext("budget:recovery-fence:" || replica)))
// held by a dedicated holder transaction: the lock serializes recovery
// verdicts per replica, dies with the session (a crashed verdict process
// cannot leak the fence), and the lease's TTL bounds any safety-window
// override in wall-clock time. The holder transaction stays open (idle in
// transaction) for the lease's lifetime — one pooled connection per
// active verdict, recovery-path only; callers MUST Release (defer), or
// the connection and the fence leak until the process dies.
//
// Lock order: the fence lock is taken before any per-org advisory lock
// and held across the verdict's per-row transactions (which each take
// exactly one org lock). Nobody takes an org lock and then a fence lock,
// so the fence → org order cannot cycle and the existing deadlock-freedom
// argument (fixed scope order, per-org keys) is preserved.

package budget

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// recoveryFenceNamespace prefixes the advisory-lock key of recovery
// fencing leases so their hashtext inputs are disjoint from the per-org
// keys (hashtext(org)) by construction.
const recoveryFenceNamespace = "budget:recovery-fence:"

// recoveryFenceReleaseDeadline bounds each blocking cleanup step of
// RecoveryLease.Release (the advisory unlock, the holder rollback). Release
// runs while the process is shutting down — often after the caller's
// deadline already elapsed — so its cleanup must not hang the drain
// (N12-P03-T02): worst case Release returns after ~2× the deadline (stalled
// unlock, then rollback) with an explicit error, and a broken connection is
// destroyed by the pool, which kills the session-scoped advisory lock. A
// lease can therefore never outlive the process by hanging the release path.
const recoveryFenceReleaseDeadline = 5 * time.Second

// recoveryFenceKey maps a replica to the fence's advisory-lock key.
func recoveryFenceKey(replicaID string) string {
	return recoveryFenceNamespace + replicaID
}

// Sentinel errors of the fencing lease. Callers map them for diagnostics:
// ErrRecoveryFenceHeld → another live verdict owns the recovery (retry
// later); ErrRecoveryFenceExpired → the lease's TTL elapsed (the override
// is bounded); ErrStaleRecoveryFence → the presented lease is not the
// held fence (released, or never acquired) — the stale-mutation
// rejection the contract requires.
var (
	ErrRecoveryFenceHeld    = errors.New("budget: recovery fence held by another owner")
	ErrRecoveryFenceExpired = errors.New("budget: recovery fence lease expired")
	ErrStaleRecoveryFence   = errors.New("budget: stale recovery fence")
)

// orphanWindow resolves the safety window of an UNFENCED orphan verdict
// (CloseAbandonedReplica). Fail-closed (N06-P05-T04): window <= 0 falls
// back to ReservationSafetyWindow, and any shorter override is floored
// back up to the §14 default — an unfenced verdict never gets a window
// shorter than D13, so a stale or mis-configured caller cannot release a
// reserve a live owner could still renew.
func orphanWindow(window time.Duration) time.Duration {
	if window < ReservationSafetyWindow {
		return ReservationSafetyWindow
	}
	return window
}

// orphanFencedWindow resolves the safety window of a FENCED verdict
// (CloseAbandonedReplicaFenced): window <= 0 still falls back to the §14
// default (a lease does not think for the caller), but any positive value
// is honored — the deliberate, serialized, TTL-bounded override.
func orphanFencedWindow(window time.Duration) time.Duration {
	if window <= 0 {
		return ReservationSafetyWindow
	}
	return window
}

// RecoveryFence issues fencing leases for crash-recovery verdicts over
// one replica's orphan reservations.
type RecoveryFence struct {
	db  reservationDB
	log *slog.Logger
	now func() time.Time
	// releaseDeadline bounds each cleanup step of RecoveryLease.Release;
	// 0 means recoveryFenceReleaseDeadline. Test seam — deployments use the
	// default.
	releaseDeadline time.Duration
}

// NewRecoveryFence builds a fence over a pool (or any reservationDB).
func NewRecoveryFence(db reservationDB, log *slog.Logger) *RecoveryFence {
	if log == nil {
		log = slog.Default()
	}
	return &RecoveryFence{
		db:  db,
		log: log.With("component", "budget-recovery-fence"),
		now: time.Now,
	}
}

// RecoveryLease is one held fencing lease: proof that THIS verdict is the
// serialized recovery for the replica, valid until Expires. A lease is
// owned by the verdict that acquired it and must be released exactly
// once (Release is idempotent against double release).
type RecoveryLease struct {
	fence    *RecoveryFence
	replica  string
	owner    string
	expires  time.Time
	holder   pgx.Tx // open holder tx pinning the lock's session
	released atomic.Bool
}

// ReplicaID names the replica the fence covers.
func (l *RecoveryLease) ReplicaID() string {
	if l == nil {
		return ""
	}
	return l.replica
}

// Owner names the verdict holding the fence (diagnostics only).
func (l *RecoveryLease) Owner() string {
	if l == nil {
		return ""
	}
	return l.owner
}

// Expires is the lease's TTL deadline (the bounded override).
func (l *RecoveryLease) Expires() time.Time {
	if l == nil {
		return time.Time{}
	}
	return l.expires
}

// Held reports whether the lease is still acquired — Acquire succeeded
// and Release has not run. Independent of the TTL.
func (l *RecoveryLease) Held() bool {
	return l != nil && !l.released.Load()
}

// Expired reports whether the lease's TTL elapsed. An expired lease must
// not drive further fenced closes — the safety-window override is bounded
// by construction, and a paused verdict cannot resume fencing after its
// TTL: it takes a fresh lease (or stands down).
func (l *RecoveryLease) Expired() bool {
	if l == nil {
		return true
	}
	return !l.expires.After(l.fence.now())
}

// Acquire takes the fencing lease for ONE replica. Non-blocking: when
// another live verdict owns the fence it returns ErrRecoveryFenceHeld —
// the recovery orchestration owns the retry policy. ttl must be positive:
// a lease without a bound would reintroduce an eternal recovery
// authority. The session-level lock dies with the holder's connection,
// so a crashed verdict process cannot leak the fence.
func (f *RecoveryFence) Acquire(ctx context.Context, replicaID, owner string, ttl time.Duration) (*RecoveryLease, error) {
	if replicaID == "" {
		return nil, fmt.Errorf("%w: replica_id is required", ErrInvalidRequest)
	}
	if owner == "" {
		return nil, fmt.Errorf("%w: fence owner is required", ErrInvalidRequest)
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("%w: fence ttl must be positive, got %s", ErrInvalidRequest, ttl)
	}
	holder, err := f.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("recovery fence holder tx: %w", err)
	}
	var acquired bool
	if err := holder.QueryRow(ctx,
		`SELECT pg_try_advisory_lock(hashtext($1)::bigint)`,
		recoveryFenceKey(replicaID)).Scan(&acquired); err != nil {
		_ = holder.Rollback(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("recovery fence try-lock: %w", err)
	}
	if !acquired {
		_ = holder.Rollback(context.WithoutCancel(ctx))
		f.log.Warn("recovery fence acquisition refused: held by another owner",
			"replica_id", replicaID, "owner", owner)
		return nil, fmt.Errorf("%w: replica %q wanted by %q", ErrRecoveryFenceHeld, replicaID, owner)
	}
	lease := &RecoveryLease{
		fence:   f,
		replica: replicaID,
		owner:   owner,
		expires: f.now().Add(ttl),
		holder:  holder,
	}
	f.log.Info("recovery fence acquired",
		"replica_id", replicaID, "owner", owner,
		"ttl", ttl.String(), "expires", lease.expires.UTC().Format(time.RFC3339Nano))
	return lease, nil
}

// Release releases the fencing lease: the session lock is unlocked BEFORE
// the holder transaction rolls back (a session-level advisory lock would
// survive the rollback and leak with the pooled connection otherwise).
// Idempotent; safe to defer. Every cleanup step runs on its own bounded
// context (recoveryFenceReleaseDeadline), so Release returns even when the
// caller's context is dead AND the connection is unhealthy — a shutting-down
// verdict cannot hang the drain on this path (N12-P03-T02). On any error the
// holder transaction is rolled back anyway — a broken connection drops the
// session, and with it the lock.
func (l *RecoveryLease) Release(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if l.released.Swap(true) {
		return nil // already released — idempotent double release
	}
	deadline := l.fence.releaseDeadline
	if deadline <= 0 {
		deadline = recoveryFenceReleaseDeadline
	}
	// Cleanup runs even when the caller's context died mid-verdict: an
	// orderly unlock beats force-closing the pooled connection. Each step
	// gets a fresh budget so a stalled unlock cannot eat the rollback's.
	// Rollback/unlock contexts are deliberately detached (WithoutCancel):
	// recovery fencing must survive cancellation of the request context.
	boundedCtx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.WithoutCancel(ctx), deadline)
	}
	rollback := func() error { //nolint:contextcheck // uses the deliberately detached bounded ctx
		rbCtx, rbCancel := boundedCtx()
		defer rbCancel()
		return l.holder.Rollback(rbCtx)
	}

	unlockCtx, unlockCancel := boundedCtx()
	var unlocked bool
	unlockErr := l.holder.QueryRow(unlockCtx, //nolint:contextcheck // unlock must outlive caller cancellation
		`SELECT pg_advisory_unlock(hashtext($1)::bigint)`,
		recoveryFenceKey(l.replica)).Scan(&unlocked)
	unlockCancel()
	if unlockErr != nil {
		_ = rollback()
		return fmt.Errorf("recovery fence unlock: %w", unlockErr)
	}
	if !unlocked {
		l.fence.log.Warn("recovery fence unlock reported the lock was not held",
			"replica_id", l.replica, "owner", l.owner)
	}
	if err := rollback(); err != nil {
		return fmt.Errorf("recovery fence holder rollback: %w", err)
	}
	l.fence.log.Info("recovery fence released", "replica_id", l.replica, "owner", l.owner)
	return nil
}

// CloseAbandonedReplicaFenced is the fenced variant of
// CloseAbandonedReplica (N06-P05-T04): the caller must present the
// currently-held fencing lease for the replica, and the lease's TTL must
// not have elapsed. Under the fence the verdict may shorten the §14
// safety window (orphanFencedWindow): the lease proves this is the one
// serialized recovery verdict for the replica, its lifetime is
// TTL-bounded, and the per-row §7.1.1 predicate still refuses every row a
// live owner could renew — the acceleration can never touch a live
// reserve, double-close, or outlive the lease.
//
// Rejections are explicit and never move money — the stale-mutation
// rejection the contract's old-owner-pause → new-owner-takeover →
// old-owner-resumes sequence requires:
//   - ErrStaleRecoveryFence: the presented lease was released (a paused
//     old verdict resumed after a new owner took over) or never held;
//   - ErrRecoveryFenceExpired: the TTL elapsed before (or during) the
//     pass — a partial summary may accompany the error, the remaining
//     rows stay frozen, and the caller must take a fresh lease.
//   - ErrOrphanAcquireTimeout: the bounded pool round-trip elapsed
//     (typically every connection pinned by fence holders); the pass is
//     retryable — a partial summary may accompany the error and a later
//     verdict finishes the remaining rows through the same per-row
//     exactly-once state machine.
func (s *ReservationStore) CloseAbandonedReplicaFenced(ctx context.Context, lease *RecoveryLease, window time.Duration) (AbandonedReplicaSummary, error) {
	replica, owner := lease.ReplicaID(), lease.Owner()
	if !lease.Held() {
		s.log.Warn("fenced orphan close rejected: stale recovery fence",
			"replica_id", replica, "owner", owner)
		return AbandonedReplicaSummary{}, ErrStaleRecoveryFence
	}
	if lease.Expired() {
		s.log.Warn("fenced orphan close rejected: recovery fence lease expired",
			"replica_id", replica, "owner", owner,
			"expires", lease.Expires().UTC().Format(time.RFC3339Nano))
		return AbandonedReplicaSummary{}, fmt.Errorf(
			"%w: replica %q owner %q", ErrRecoveryFenceExpired, replica, owner)
	}
	return s.closeAbandonedCandidates(ctx, replica, owner, orphanFencedWindow(window), func() error {
		if !lease.Expired() {
			return nil
		}
		s.log.Warn("fenced orphan close stopped: recovery fence lease expired mid-pass",
			"replica_id", replica, "owner", owner)
		return fmt.Errorf("%w: replica %q owner %q", ErrRecoveryFenceExpired, replica, owner)
	})
}
