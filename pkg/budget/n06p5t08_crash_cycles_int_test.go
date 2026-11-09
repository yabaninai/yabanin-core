//go:build integration

// N06-P05-T08: interruption/retry/resume of crash recovery ITSELF, on a
// disposable live Postgres (real-PG pattern, ADR-0001 §10). The accepted
// T04–T07 records pinned the fence policy, the adversarial single-race
// shapes and the exact single-pass boundaries; this file covers what only
// REPEATED crash/retry cycles can show:
//
//   - a recovery pass that aborts (TTL) and then CRASHES (holder backend
//     killed), repeatedly, in one chain: the retry resumes at the row
//     boundary, already-released rows are classified — never re-closed —
//     and the union of all cycles returns the escrow exactly once;
//   - a verdict whose fence holder is killed MID-PASS, in several
//     consecutive cycles: progress never regresses, no pass ever returns
//     more than the remaining escrow, and a final clean verdict converges
//     the replica to exactly-once (wallet monotone to zero, per-row
//     returned == granted).
//
// Shared-stand discipline (same as the T05/T07 files): one Postgres
// container, one pool and one process-global metrics registry per package.
// Lapsed shapes stay INSIDE the §14 safety window (foreign periodic passes
// legally refuse them; only these tests' fenced 30-minute overrides can
// close); summary asserts fold only replica-scoped verdicts; the `require`
// calls run on the main goroutine after wg.Wait — plain error/atomic state
// flows out of the watcher goroutines.
package budget

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n06p5t08ReleasedCount counts the replica's released allowance rows —
// plain-error variant for watcher goroutines (no testing.T inside racers).
func n06p5t08ReleasedCount(ctx context.Context, pool *pgxpool.Pool, replica string) (int64, error) {
	var released int64
	err := pool.QueryRow(ctx, `
		SELECT count(*) FROM budget_allowances
		WHERE replica_id = $1 AND status = $2`, replica, AllowanceReleased).Scan(&released)
	return released, err
}

// n06p5t08KillFenceHolder terminates the backend holding the replica's
// recovery fence — the crashed-verdict-process shape. Plain-error variant
// of n06p5TerminateFenceHolder, safe to call from watcher goroutines.
//
// The pg_locks predicate splits the signed 64-bit advisory key into its
// unsigned (classid, objid) halves: objid is an oid column, so
// `objid = hashtext($1)::bigint` fails with «OID out of range» whenever
// the hashtext is NEGATIVE (the single classid=0 comparison the T05
// helper uses silently relies on its constant keys hashing positive).
// The split comparison works for every hash; `granted` skips waiters.
func n06p5t08KillFenceHolder(ctx context.Context, pool *pgxpool.Pool, replica string) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		var pid int32
		err := pool.QueryRow(ctx, `
			SELECT pid FROM pg_locks,
			     (SELECT hashtext($1)::bigint AS key) k
			WHERE locktype = 'advisory' AND granted
			  AND classid = ((k.key >> 32) & 4294967295)
			  AND objid = (k.key & 4294967295)
			LIMIT 1`, recoveryFenceKey(replica)).Scan(&pid)
		if err == nil {
			var terminated bool
			if termErr := pool.QueryRow(ctx,
				`SELECT pg_terminate_backend($1)`, pid).Scan(&terminated); termErr != nil {
				return fmt.Errorf("terminate fence holder backend %d: %w", pid, termErr)
			}
			if !terminated {
				return fmt.Errorf("pg_terminate_backend(%d) reported false", pid)
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("fence holder lookup for %s: %w", replica, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no advisory lock holder found for %s", replica)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// n06p5t08KillAfterFirstRelease blocks until the replica's pass has
// released its first row, then kills the fence holder — the mid-pass crash.
func n06p5t08KillAfterFirstRelease(ctx context.Context, pool *pgxpool.Pool, replica string) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		released, err := n06p5t08ReleasedCount(ctx, pool, replica)
		if err == nil && released >= 1 {
			return n06p5t08KillFenceHolder(ctx, pool, replica)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no release observed for %s within the kill window", replica)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestN06P05T08Live_AbortThenCrashRetryChainResumesAtRowBoundaryExactlyOnce:
// one recovery chain, two crash cycles, deterministic placement. Cycle 1's
// verdict closes the wallet row and its TTL runs out (the paused verdict);
// its process then CRASHES (holder backend terminated — the in-process
// lease object keeps claiming Held, the release fails on the broken
// connection like a real dead process). Cycle 2 acquires immediately (the
// crashed holder's lock died with its session — no leaked fence), resumes
// at the row boundary: the wallet row is classified AlreadyReleased (its
// stop() still runs — the call-shape contract covers already-released
// candidates), the team row closes, the TTL aborts again, and cycle 2
// crashes the same way. Cycle 3 converges the tail. The union across all
// three cycles is the full escrow, exactly once; both crashed leases are
// permanently stale; no pass re-closes a row.
func TestN06P05T08Live_AbortThenCrashRetryChainResumesAtRowBoundaryExactlyOnce(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5t08-chn-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	const dead = "n06p5t08-chn-dead"
	total := n06p5GrantFourScopes(t, pool, org, dead)
	n06p5ShiftLease(t, pool, dead, time.Hour) // lapsed 1h: outside the 30m override, inside the 2h default

	// The chain's clock (T07 B2's call-shape seam): expired iff the read
	// count exceeds the per-pass threshold. The pass reads now() once
	// pre-verdict and once per stop() — before EVERY candidate row in id
	// order (wallet, team, agent, session), already-released ones included.
	fence := NewRecoveryFence(pool, nil)
	base := time.Now()
	var (
		calls       atomic.Int64
		expireAfter atomic.Int64
	)
	expireAfter.Store(math.MaxInt64)
	fence.now = func() time.Time {
		if calls.Add(1) > expireAfter.Load() {
			return base.Add(2 * time.Hour)
		}
		return base
	}
	acquire := func(owner string, ttl time.Duration, expireAfterCalls int64) *RecoveryLease {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			expireAfter.Store(math.MaxInt64) // acquisition attempts are always live
			calls.Store(0)
			lease, err := fence.Acquire(ctx, dead, owner, ttl)
			if err == nil {
				calls.Store(0) // per-pass accounting restarts at the pre-verdict check
				expireAfter.Store(expireAfterCalls)
				return lease
			}
			if !errors.Is(err, ErrRecoveryFenceHeld) || time.Now().After(deadline) {
				require.NoError(t, err, "acquire fence for %s", owner)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Cycle 1: close the wallet row, abort exactly before the team row.
	leaseA := acquire("t08-chain-a", time.Hour, 2)
	sumA, errA := store.CloseAbandonedReplicaFenced(ctx, leaseA, 30*time.Minute)
	require.ErrorIs(t, errA, ErrRecoveryFenceExpired)
	require.Equal(t, int64(1), sumA.Closed, "exactly the wallet row closed before the abort")
	require.Equal(t, int64(100_000), sumA.ReturnedMicroUSD)
	require.Zero(t, sumA.AlreadyReleased)
	require.True(t, leaseA.Held(), "the aborted pass does not release the lease — the paused verdict still owns the fence")

	// The paused verdict's process crashes.
	require.NoError(t, n06p5t08KillFenceHolder(ctx, pool, dead))
	require.True(t, leaseA.Held(), "the crashed lease object cannot observe its own death — the documented zombie window")
	_ = leaseA.Release(ctx) // the broken holder connection fails the unlock — crash semantics
	var active int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM budget_allowances WHERE replica_id = $1 AND status = $2`,
		dead, AllowanceActive).Scan(&active))
	require.Equal(t, int64(3), active, "the crash left the tail rows untouched — resume work exists")

	// Cycle 2: fresh verdict, immediate acquire, resume at the boundary.
	leaseB := acquire("t08-chain-b", time.Hour, 3)
	sumB, errB := store.CloseAbandonedReplicaFenced(ctx, leaseB, 30*time.Minute)
	require.ErrorIs(t, errB, ErrRecoveryFenceExpired)
	require.Equal(t, int64(1), sumB.Closed, "exactly the team row closed in cycle 2")
	require.Equal(t, int64(200_000), sumB.ReturnedMicroUSD)
	require.Equal(t, int64(1), sumB.AlreadyReleased, "the wallet row is the exactly-once losing side, not re-closed")
	require.Zero(t, sumB.SkippedLive)

	// Cycle 2's process crashes too.
	require.NoError(t, n06p5t08KillFenceHolder(ctx, pool, dead))
	_ = leaseB.Release(ctx)

	// Both crashed leases are stale on every reuse — stable across cycles.
	for cycle := 1; cycle <= 2; cycle++ {
		_, err := store.CloseAbandonedReplicaFenced(ctx, leaseA, 30*time.Minute)
		require.ErrorIs(t, err, ErrStaleRecoveryFence, "lease A reuse %d", cycle)
		_, err = store.CloseAbandonedReplicaFenced(ctx, leaseB, 30*time.Minute)
		require.ErrorIs(t, err, ErrStaleRecoveryFence, "lease B reuse %d", cycle)
	}

	// Cycle 3: a fresh verdict converges — only the tail closes.
	leaseC := acquire("t08-chain-c", time.Hour, math.MaxInt64)
	sumC, errC := store.CloseAbandonedReplicaFenced(ctx, leaseC, 30*time.Minute)
	require.NoError(t, errC)
	require.NoError(t, leaseC.Release(ctx))
	require.Equal(t, int64(2), sumC.Closed, "agent and session close in cycle 3")
	require.Equal(t, int64(700_000), sumC.ReturnedMicroUSD)
	require.Equal(t, int64(2), sumC.AlreadyReleased, "wallet and team are the losing side")
	require.Zero(t, sumC.SkippedLive)

	// The union across the interrupted chain is the full escrow, once.
	require.Equal(t, int64(4), sumA.Closed+sumB.Closed+sumC.Closed,
		"every row closed exactly once across all three cycles")
	require.Equal(t, total, sumA.ReturnedMicroUSD+sumB.ReturnedMicroUSD+sumC.ReturnedMicroUSD,
		"the escrow returned exactly once across all three crash/retry cycles")
	require.Zero(t, walletState(t, pool, org))
	for _, scope := range []ScopeKind{ScopeWallet, ScopeTeamMonth, ScopeAgentDay, ScopeSession} {
		key, period := n06p5ScopeRef(t, pool, dead, scope)
		_, granted, ret, status, _ := allowanceRow(t, pool, dead, scope, key, period)
		assert.Equal(t, AllowanceReleased, status, "scope %s", scope)
		assert.Equal(t, granted, ret, "scope %s: returned equals granted exactly once", scope)
	}
	for _, scope := range []ScopeKind{ScopeTeamMonth, ScopeAgentDay, ScopeSession} {
		key, period := n06p5ScopeRef(t, pool, dead, scope)
		assert.Zero(t, scopeReserve(t, pool, scope, key, period), "scope %s reserve released", scope)
	}

	// Tail: a fresh verdict observes only the losing side — the chain left
	// nothing for anyone.
	leaseD := acquire("t08-chain-d", time.Hour, math.MaxInt64)
	sumD, errD := store.CloseAbandonedReplicaFenced(ctx, leaseD, 30*time.Minute)
	require.NoError(t, errD)
	require.NoError(t, leaseD.Release(ctx))
	require.Equal(t, int64(4), sumD.AlreadyReleased)
	require.Zero(t, sumD.Closed)
	require.Zero(t, sumD.ReturnedMicroUSD)
	require.Zero(t, walletState(t, pool, org))
}

// TestN06P05T08Live_EscrowExactlyOnceAcrossRepeatedHolderCrashes: three
// consecutive verdict cycles over one lapsed escrow; in each cycle the
// fence holder's backend is terminated as soon as the pass has released
// its first row (the mid-pass crash). Whether the zombie pass then
// completes on its pool connections (T05's finding) or dies with a broken
// one, the escrow only ever moves forward: the wallet reserve is monotone
// non-increasing, released progress never regresses, no pass returns more
// than the escrow, a crashed pass never surfaces as a fence-class
// rejection, and the final clean verdict converges the replica — per-row
// returned == granted, wallet at zero, every reserve empty — and one more
// verdict reports only the losing side.
func TestN06P05T08Live_EscrowExactlyOnceAcrossRepeatedHolderCrashes(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5t08-cyc-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	const dead = "n06p5t08-cyc-dead"
	total := n06p5GrantFourScopes(t, pool, org, dead)
	n06p5ShiftLease(t, pool, dead, time.Hour)

	const cycles = 3
	var (
		sumClosed, sumReturned int64
		allClean               = true
		prevWallet             = total
		prevReleased           int64
	)
	for i := 1; i <= cycles; i++ {
		lease, err := n06p5TryAcquireFence(pool, dead, fmt.Sprintf("t08-cycle-%d", i), time.Hour)
		require.NoError(t, err)
		var (
			sum     AbandonedReplicaSummary
			passErr error
			killErr error
			wg      sync.WaitGroup
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			sum, passErr = store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
		}()
		go func() {
			defer wg.Done()
			killErr = n06p5t08KillAfterFirstRelease(ctx, pool, dead)
		}()
		wg.Wait()
		_ = lease.Release(ctx) // the crashed holder's connection fails the unlock — crash semantics

		require.NoError(t, killErr, "cycle %d: the kill watcher must observe the first release", i)
		if passErr == nil {
			require.Zero(t, sum.SkippedLive, "cycle %d: every lapsed row closes or reports the losing side", i)
			require.Equal(t, int64(4), sum.Closed+sum.AlreadyReleased,
				"cycle %d: a completed pass classifies every candidate exactly once", i)
			sumClosed += sum.Closed
			sumReturned += sum.ReturnedMicroUSD
		} else {
			allClean = false
			// A crashed pass may fail on a broken connection, but never with
			// a fence-class rejection: a fresh lease can neither expire (real
			// clock, 1h TTL) nor go stale mid-pass.
			require.NotErrorIs(t, passErr, ErrRecoveryFenceExpired, "cycle %d", i)
			require.NotErrorIs(t, passErr, ErrStaleRecoveryFence, "cycle %d", i)
		}
		require.LessOrEqual(t, sumReturned, total, "cycle %d: no pass ever returns more than the escrow", i)

		wallet := walletState(t, pool, org)
		require.LessOrEqual(t, wallet, prevWallet, "cycle %d: the wallet reserve never resurrects", i)
		require.GreaterOrEqual(t, wallet, int64(0), "cycle %d: the reserve never goes negative", i)
		prevWallet = wallet
		released, err := n06p5t08ReleasedCount(ctx, pool, dead)
		require.NoError(t, err)
		require.GreaterOrEqual(t, released, prevReleased, "cycle %d: released progress never regresses", i)
		prevReleased = released
	}

	// The final clean verdict converges: whatever the crashes left open
	// closes here; the DB rows carry the exactly-once authority.
	leaseFinal, errFinalAcq := n06p5TryAcquireFence(pool, dead, "t08-cycle-final", time.Hour)
	require.NoError(t, errFinalAcq)
	sumFinal, errFinal := store.CloseAbandonedReplicaFenced(ctx, leaseFinal, 30*time.Minute)
	require.NoError(t, errFinal)
	require.NoError(t, leaseFinal.Release(ctx))
	require.Equal(t, int64(4), sumFinal.Closed+sumFinal.AlreadyReleased,
		"the final pass classifies every row: the tail closes, the rest report the losing side")
	if allClean {
		require.Equal(t, int64(4), sumClosed+sumFinal.Closed,
			"every row closed exactly once across all cycles and the final pass")
		require.Equal(t, total, sumReturned+sumFinal.ReturnedMicroUSD,
			"the escrow returned exactly once across all cycles and the final pass")
	}
	require.Zero(t, walletState(t, pool, org))
	for _, scope := range []ScopeKind{ScopeWallet, ScopeTeamMonth, ScopeAgentDay, ScopeSession} {
		key, period := n06p5ScopeRef(t, pool, dead, scope)
		_, granted, ret, status, _ := allowanceRow(t, pool, dead, scope, key, period)
		assert.Equal(t, AllowanceReleased, status, "scope %s", scope)
		assert.Equal(t, granted, ret, "scope %s: returned equals granted exactly once", scope)
		if scope != ScopeWallet { // the wallet reserve is asserted above via walletState
			assert.Zero(t, scopeReserve(t, pool, scope, key, period), "scope %s reserve fully released", scope)
		}
	}

	// Idempotent tail: one more verdict observes only the losing side.
	leaseTail, errTailAcq := n06p5TryAcquireFence(pool, dead, "t08-cycle-tail", time.Hour)
	require.NoError(t, errTailAcq)
	sumTail, errTail := store.CloseAbandonedReplicaFenced(ctx, leaseTail, 30*time.Minute)
	require.NoError(t, errTail)
	require.NoError(t, leaseTail.Release(ctx))
	require.Equal(t, int64(4), sumTail.AlreadyReleased)
	require.Zero(t, sumTail.Closed)
	require.Zero(t, sumTail.ReturnedMicroUSD)
	require.Zero(t, walletState(t, pool, org))
}
