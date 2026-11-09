//go:build integration

// Failure-boundary tests on a disposable live Postgres (owner
// decisions 2026-10-18 ratified D1–D3): the startup self-reap sweep is
// safe at its edges — an empty database is a clean no-op, concurrent
// restarts (two replacement processes booting at once, plus a racing
// reconcile pass) drain every crashed own-family row exactly once, and
// foreign hosts are never touched, including the dashed-prefix boundary
// (a host named gwbox-extra is NOT of the gwbox family even though a
// naive LIKE 'gwbox-%' would match it — found by this card, fixed with
// the anchored ^prefix-[0-9]+-[0-9]+$ family pattern).
package budget

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// r042EdgeIncarnation is one seeded replica row: bound µUSD granted into
// the wallet reserve; lapsed=true backdates the lease 15 minutes (the
// owner provably stopped renewing), false leaves it renewing (live).
type r042EdgeIncarnation struct {
	replica string
	bound   int64
	lapsed  bool
}

// seedR042EdgeWorld seeds the wallet plus one wallet-scope allowance per
// incarnation and returns (pool, org, totalReserved).
func seedR042EdgeWorld(t *testing.T, incarnations []r042EdgeIncarnation) (*pgxpool.Pool, string, int64) {
	t.Helper()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-r042e-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 1_000_000, nil) // $10 000
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	var total int64
	for _, inc := range incarnations {
		g, err := store.Grant(ctx, inc.replica, org, []GrantRequest{
			{Scope: ScopeWallet, Key: org, Bound: money.MicroUSD(inc.bound)},
		})
		require.NoError(t, err)
		if inc.lapsed {
			_, err = pool.Exec(ctx,
				`UPDATE budget_allowances SET lease_until = now() - interval '15 minutes' WHERE id = $1`,
				g[0].AllowanceID)
			require.NoError(t, err)
		}
		total += inc.bound
	}
	require.Equal(t, total, walletState(t, pool, org), "every grant froze its bound")
	return pool, org, total
}

// Edge: the sweep on an empty database (no allowance rows at all) is a
// clean no-op, and invalid input (empty prefix) is a diagnosable error,
// never a silent full-table sweep.
func TestR042Edges_SweepOnEmptyDatabaseAndInvalidInput(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()

	n, err := store.SelfReapCrashedIncarnations(ctx, "gwbox")
	require.NoError(t, err)
	assert.Zero(t, n, "empty database sweeps nothing")

	_, err = store.SelfReapCrashedIncarnations(ctx, "")
	require.Error(t, err, "an empty host prefix is rejected, never a wildcard sweep")
	assert.True(t, errors.Is(err, ErrInvalidRequest), "the rejection names its cause: %v", err)

	// The Admission seam degrades the same way: ModeOff never sweeps, and
	// a non-gateway-shaped replica id (no numeric pid/nanos tail) is a
	// safe no-op — nothing can be identified as this process's family.
	off := NewAdmission(store, ScopedRateSource{}, newBudgetTestLogger(),
		"gwbox-9999-1700000000000000001", ModeOff, nil, DefaultAdmissionConfig())
	t.Cleanup(off.Stop)
	n, err = off.ReapCrashedPredecessors(ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "ModeOff sweeps nothing")

	misshapen := NewAdmission(store, ScopedRateSource{}, newBudgetTestLogger(),
		"gwbox", ModeEnforce, nil, DefaultAdmissionConfig())
	t.Cleanup(misshapen.Stop)
	n, err = misshapen.ReapCrashedPredecessors(ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "a replica id without the pid/nanos tail sweeps nothing")
}

// Edge: foreign hosts never touched — the plain foreign host AND the
// dashed-prefix foreign host (gwbox-extra-…, whose replica id starts with
// "gwbox-" and would match a naive LIKE 'gwbox-%') stay active with their
// escrow frozen; only the crashed own-family row drains; the wallet total
// is unchanged (D3: the sweep itself never releases money).
func TestR042Edges_ForeignHostsIncludingDashedPrefixNeverTouched(t *testing.T) {
	pool, org, total := seedR042EdgeWorld(t, []r042EdgeIncarnation{
		{replica: "gwbox-4242-1699999999999999999", bound: 600_000, lapsed: true},      // crashed own family
		{replica: "gwbox-7777-1700000000000000000", bound: 200_000, lapsed: false},     // live sibling
		{replica: "gwbox-extra-111-1699999999999999998", bound: 300_000, lapsed: true}, // foreign host, dashed-prefix name
		{replica: "otherbox-111-1699999999999999999", bound: 300_000, lapsed: true},    // foreign host, plain name
	})
	store := newReservationStore(pool)
	ctx := context.Background()

	reapedBefore := budgetSelfReapedTotal()
	n, err := store.SelfReapCrashedIncarnations(ctx, "gwbox")
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "exactly the crashed own-family row is reaped")

	for replica, want := range map[string]string{
		"gwbox-4242-1699999999999999999":      AllowanceDraining, // drained
		"gwbox-7777-1700000000000000000":      AllowanceActive,   // live sibling
		"gwbox-extra-111-1699999999999999998": AllowanceActive,   // dashed-prefix foreign host untouched (D2)
		"otherbox-111-1699999999999999999":    AllowanceActive,   // plain foreign host untouched (D2)
	} {
		_, _, _, status, _ := allowanceRow(t, pool, replica, ScopeWallet, org, "")
		assert.Equal(t, want, status, "replica %s", replica)
	}
	assert.Equal(t, total, walletState(t, pool, org), "the sweep moved no money (D3)")
	assert.InDelta(t, reapedBefore+1, budgetSelfReapedTotal(), 0.001)

	// A sweeper on the dashed foreign host drains ITS family only: the
	// gwbox rows (crashed or not) are foreign to it.
	n, err = store.SelfReapCrashedIncarnations(ctx, "gwbox-extra")
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "the gwbox-extra crashed incarnation is its own family")
	_, _, _, status, _ := allowanceRow(t, pool, "gwbox-4242-1699999999999999999", ScopeWallet, org, "")
	assert.Equal(t, AllowanceDraining, status, "already draining — not re-reaped, not released")
	_, _, _, status, _ = allowanceRow(t, pool, "gwbox-7777-1700000000000000000", ScopeWallet, org, "")
	assert.Equal(t, AllowanceActive, status, "the gwbox live sibling stays foreign to gwbox-extra")
}

// Edge: concurrent restarts — two replacement processes boot on the same
// host at once (both run the startup sweep through the Admission seam or
// the store directly) while a reconcile pass races them. Every crashed
// own-family row flips active→draining EXACTLY once across all racers
// (Σ drained == rows, no row double-flipped), live siblings and foreign
// hosts stay active, and no money moves (D3).
func TestR042Edges_ConcurrentRestartsDrainEachRowOnce(t *testing.T) {
	pool, org, total := seedR042EdgeWorld(t, []r042EdgeIncarnation{
		{replica: "gwbox-4242-1699999999999999999", bound: 600_000, lapsed: true},
		{replica: "gwbox-4243-1699999999999999997", bound: 500_000, lapsed: true},
		{replica: "gwbox-7777-1700000000000000000", bound: 200_000, lapsed: false},
		{replica: "gwbox-extra-111-1699999999999999998", bound: 300_000, lapsed: true},
		{replica: "otherbox-111-1699999999999999999", bound: 300_000, lapsed: true},
	})
	store := newReservationStore(pool)
	ctx := context.Background()
	reaper := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())

	const racers = 8
	var drained int64 // summed atomically below via mutex
	var mu sync.Mutex
	var wg sync.WaitGroup
	errs := make(chan error, racers)
	metricBefore := budgetSelfReapedTotal()

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var n int64
			var err error
			switch {
			case i < 4: // direct store sweeps (replacement process, store seam)
				n, err = store.SelfReapCrashedIncarnations(ctx, "gwbox")
			case i < 6: // Admission seam — two fresh incarnations booting at once
				a := NewAdmission(store, ScopedRateSource{}, newBudgetTestLogger(),
					"gwbox-"+strconv.Itoa(9000+i)+"-1700000000000000001", ModeEnforce, nil, DefaultAdmissionConfig())
				defer a.Stop()
				n, err = a.ReapCrashedPredecessors(ctx)
			default: // racing reconcile passes (the periodic worker overlapping the boot)
				summary, rerr := reaper.ReleasePass(ctx)
				err = rerr
				n = 0
				if err == nil && summary.Released != 0 {
					err = errors.New("release pass moved money inside the safety window")
				}
			}
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			drained += n
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	require.Equal(t, int64(2), drained, "the two crashed own-family rows drained exactly once ACROSS all racers")
	for replica, want := range map[string]string{
		"gwbox-4242-1699999999999999999":      AllowanceDraining,
		"gwbox-4243-1699999999999999997":      AllowanceDraining,
		"gwbox-7777-1700000000000000000":      AllowanceActive,
		"gwbox-extra-111-1699999999999999998": AllowanceActive,
		"otherbox-111-1699999999999999999":    AllowanceActive,
	} {
		_, _, _, status, _ := allowanceRow(t, pool, replica, ScopeWallet, org, "")
		assert.Equal(t, want, status, "replica %s", replica)
	}
	assert.Equal(t, total, walletState(t, pool, org), "concurrent restarts moved no money (D3)")
	assert.InDelta(t, metricBefore+2, budgetSelfReapedTotal(), 0.001,
		"the reaped counter counts each row once")
}

// budgetSelfReapedTotal reads the sweep counter (shared across tests —
// only deltas are asserted).
func budgetSelfReapedTotal() float64 {
	return testutil.ToFloat64(metrics.BudgetSelfReapedAllowances)
}
