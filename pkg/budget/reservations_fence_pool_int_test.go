//go:build integration

// W40: the production pool-exhaustion hazard of the fenced orphan close
// (coordination ledger 2e04fda; W34 reproduced it on the test side). Each
// RecoveryLease pins one pooled connection for its lifetime, so N=MaxConns
// concurrent fenced verdicts pin every connection and then each need one
// more (the candidates scan / per-row transactions of
// closeAbandonedCandidates) — every verdict queues forever in
// puddle.Acquire with zero goroutines reaching Postgres. The orphan close
// must instead fail fast with an explicit retryable error, move no money,
// and stay recoverable: once the blocked verdicts hand their fences back,
// fresh verdicts converge the orphans exactly once.
package budget

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

func TestW40Live_FencedCloseBoundedUnderPoolExhaustion(t *testing.T) {
	t.Parallel()
	// MaxConns=2 is the production shape at its smallest: two lease holders
	// pin the whole pool while still needing one connection each — exactly
	// the N=MaxConns hazard, deterministic on a dedicated pool.
	pool := testdb.PostgresPool(t, func(c *pgxpool.Config) { c.MaxConns = 2 })
	store := newReservationStore(pool)
	// Short bound: the test proves fail-fast, not patience — production
	// uses the 5s default (orphanAcquireDefault).
	store.orphanAcquireTimeout = 400 * time.Millisecond
	ctx := context.Background()
	org := "org-w40-pool-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	const deadA, deadB = "w40-pool-dead-a", "w40-pool-dead-b"
	for _, replica := range []string{deadA, deadB} {
		_, err := store.Grant(ctx, replica, org, []GrantRequest{
			{Scope: ScopeWallet, Key: org, Bound: 50_000},
		})
		require.NoError(t, err)
		n06p5ForceState(t, pool, replica, org, AllowanceActive, time.Hour)
	}
	require.Equal(t, int64(100_000), walletState(t, pool, org))

	orphanBefore := releasedCounter(t, ReleaseReasonCrashOrphan)
	fence := NewRecoveryFence(pool, nil)
	leaseA, err := fence.Acquire(ctx, deadA, "w40-verdict-a", time.Hour)
	require.NoError(t, err)
	leaseB, err := fence.Acquire(ctx, deadB, "w40-verdict-b", time.Hour)
	require.NoError(t, err)

	// Both pinned verdicts need a second connection at the same time; the
	// pool has none and cannot grow one. A verdict that gives up releases
	// its fence (the recovery orchestration's defer) — that is the only
	// path back to capacity.
	start := make(chan struct{})
	var wg sync.WaitGroup
	sums := make([]AbandonedReplicaSummary, 2)
	errs := make([]error, 2)
	verdict := func(i int, lease *RecoveryLease) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			defer lease.Release(ctx)
			sums[i], errs[i] = store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
		}()
	}
	verdict(0, leaseA)
	verdict(1, leaseB)
	close(start)
	blocked := time.Now()
	wg.Wait()
	bounded := time.Since(blocked)

	for i, err := range errs {
		require.Error(t, err, "verdict %d: pinned-pool starvation must surface as an error", i)
		require.ErrorIs(t, err, ErrOrphanAcquireTimeout,
			"verdict %d: the bound surfaces as the retryable sentinel, not a hang", i)
		require.ErrorIs(t, err, context.DeadlineExceeded, "verdict %d", i)
		require.NotErrorIs(t, err, ErrRecoveryFenceExpired, "verdict %d", i)
		require.NotErrorIs(t, err, ErrStaleRecoveryFence, "verdict %d", i)
	}
	require.Less(t, bounded, 10*time.Second,
		"both starved verdicts return in ~one bound each, not a deadlock")
	require.Zero(t, sums[0].Closed+sums[1].Closed, "no row may close under starvation")
	require.Equal(t, int64(100_000), walletState(t, pool, org),
		"the starved verdicts moved no money")

	// Recovery: both blocked verdicts released above, so the pool has
	// capacity again — a fresh fenced verdict proceeds without deadlock and
	// the per-row exactly-once state machine closes each orphan once.
	leaseA2, err := fence.Acquire(ctx, deadA, "w40-verdict-a-retry", time.Hour)
	require.NoError(t, err)
	sA, err := store.CloseAbandonedReplicaFenced(ctx, leaseA2, 30*time.Minute)
	require.NoError(t, err)
	require.NoError(t, leaseA2.Release(ctx))
	require.Equal(t, int64(1), sA.Closed)
	require.Equal(t, int64(50_000), sA.ReturnedMicroUSD)

	leaseB2, err := fence.Acquire(ctx, deadB, "w40-verdict-b-retry", time.Hour)
	require.NoError(t, err)
	sB, err := store.CloseAbandonedReplicaFenced(ctx, leaseB2, 30*time.Minute)
	require.NoError(t, err)
	require.NoError(t, leaseB2.Release(ctx))
	require.Equal(t, int64(1), sB.Closed)
	require.Equal(t, int64(50_000), sB.ReturnedMicroUSD)

	require.Zero(t, walletState(t, pool, org), "both orphans returned exactly once")
	// Process-global counter: parallel verdict tests in this package race
	// the same label, so the shared-stand discipline asserts >=.
	require.GreaterOrEqual(t, releasedCounter(t, ReleaseReasonCrashOrphan), orphanBefore+2,
		"crash_orphan counts the two recovered closes exactly once each")
}
