//go:build integration

// N06-P05-T02 negative-clause evidence on a disposable live Postgres
// (real-PG pattern, ADR-0001 §10): racing reconcilers converge crash
// recovery to one ledger — no double release, no double count against the
// reconcile×settle race, no live-reserve release, no eternal reservations
// (packet acceptance/negative; contract
// artifacts/internal-delivery-program/N06-P05/contract.md).
package budget

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n06p5LapseLease backdates a replica's wallet allowance to the crashed
// shape a dead replica leaves behind: status expired, lease lapsed 3h —
// beyond the 2h ReservationSafetyWindow.
func n06p5LapseLease(t *testing.T, pool *pgxpool.Pool, replica, org string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE budget_allowances
		 SET status = $2, lease_until = now() - interval '3 hours'
		 WHERE replica_id = $1 AND scope_kind = $3 AND scope_key = $4`,
		replica, AllowanceExpired, string(ScopeWallet), org)
	require.NoError(t, err)
}

// n06p5ForceState pins a replica's wallet allowance to an explicit
// lifecycle shape: the given status and, when leaseAge > 0, a lease lapsed
// that long ago (0 keeps the fresh grant lease). This builds the crash
// shapes the N06-P05 orphan verdicts must sort: hard crash (active +
// lapsed — the §7.1 sweep-eligible shape), mid-drain crash (draining +
// young), recent crash still inside the safety window…
func n06p5ForceState(t *testing.T, pool *pgxpool.Pool, replica, org, status string, leaseAge time.Duration) {
	t.Helper()
	var lapsed any
	if leaseAge > 0 {
		lapsed = formatInterval(leaseAge)
	}
	tag, err := pool.Exec(context.Background(),
		`UPDATE budget_allowances
		 SET status = $2,
		     lease_until = CASE WHEN $5::interval IS NULL THEN lease_until
		                        ELSE now() - $5::interval END,
		     updated_at = now()
		 WHERE replica_id = $1 AND scope_kind = $3 AND scope_key = $4`,
		replica, status, string(ScopeWallet), org, lapsed)
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected(), "allowance %s must exist", replica)
}

// n06p5RaceReleasePass runs n independent ReleasePass workers over the
// shared pool concurrently — the two-loggerd-replicas (leader transition in
// flight) shape of the packet's negative criterion. Each worker has its own
// ReconcileWorker, like a separate replica process.
func n06p5RaceReleasePass(t *testing.T, pool *pgxpool.Pool, n int) []ReconcileSummary {
	t.Helper()
	ctx := context.Background()
	summaries := make([]ReconcileSummary, n)
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
			<-start
			summaries[i], errs[i] = w.ReleasePass(ctx)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "racer %d failed", i)
	}
	return summaries
}

// n06p5SettleLikeWorker models the settlement worker's settle step (§5.3
// step 2, NEXT-18d) in the production shape of markSettledWithRelease: the
// job row is inserted without the reconcile key, SettleDecrementTx applies
// the reserve decrement under the per-org advisory lock, and the payload
// key lands exactly when the reserve moved — all in ONE transaction, so
// releaseOne's remainder (granted − returned − settled) stays consistent.
// Returns the applied amount (0 = ledger-only). Plain error returns — safe
// to call from a racer goroutine.
func n06p5SettleLikeWorker(ctx context.Context, pool *pgxpool.Pool, org string, allowanceID int64, actual, bound money.MicroUSD) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("settle tx begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var jobID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, allowance_id, payload, status)
		VALUES ($1, $2, 'wallet', $3, '{}'::jsonb, 'processing')
		RETURNING id`,
		org, "req-n06p5-settle-"+uuid.NewString(), allowanceID).Scan(&jobID); err != nil {
		return 0, fmt.Errorf("settle job insert: %w", err)
	}
	decrement, err := SettleDecrementTx(ctx, tx, org, allowanceID, actual, bound)
	if err != nil {
		return 0, fmt.Errorf("settle decrement: %w", err)
	}
	// markSettledQuery shape (consumer settlement.go): the reconcile key is
	// written exactly when the reserve moved, atomically with 'settled'.
	var decAmt any
	if decrement > 0 {
		decAmt = decrement
	}
	tag, err := tx.Exec(ctx, `
		UPDATE settlement_jobs SET
			status = 'settled',
			lease_until = NULL,
			last_error = NULL,
			updated_at = now(),
			payload = CASE WHEN $2::bigint IS NULL THEN payload
				ELSE jsonb_set(COALESCE(payload, '{}'::jsonb), '{`+ReconcileSettleKey+`}', to_jsonb($2::bigint), true) END
		WHERE id = $1 AND status = 'processing'`,
		jobID, decAmt)
	if err != nil {
		return 0, fmt.Errorf("mark settled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return 0, fmt.Errorf("mark settled: job %d is not in processing state", jobID)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("settle commit: %w", err)
	}
	return decrement, nil
}

// n06p5LapsedNonReleased counts org rows that still hold a lapsed lease
// without being released — the "eternal reservations" detector.
func n06p5LapsedNonReleased(t *testing.T, pool *pgxpool.Pool, org string) int64 {
	t.Helper()
	var n int64
	err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM budget_allowances
		WHERE org_id = $1 AND status <> $2 AND lease_until < now()`,
		org, AllowanceReleased).Scan(&n)
	require.NoError(t, err)
	return n
}

// TestN06P05Live_RacingReconcilersReleaseLapsedEscrowExactlyOnce: eight
// concurrent reconcile passes over one lapsed escrow release it exactly
// once, return the full remainder exactly once, leave the live sibling's
// reserve untouched, stay idempotent under a second racing round and
// converge the §7.1.3/§7.1.4 invariants with nothing stranded.
func TestN06P05Live_RacingReconcilersReleaseLapsedEscrowExactlyOnce(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-race-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	// Baseline-relative invariant anchors: the disposable container may
	// carry fixtures from other cards' tests (same pattern as the NEXT-18e
	// divergence detector test).
	worker := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	base, err := worker.CheckInvariants(ctx)
	require.NoError(t, err)

	_, err = store.Grant(ctx, "n06p5-dead-replica", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 600_000},
	})
	require.NoError(t, err)
	_, err = store.Grant(ctx, "n06p5-live-replica", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 200_000},
	})
	require.NoError(t, err)
	n06p5LapseLease(t, pool, "n06p5-dead-replica", org)
	require.Equal(t, int64(800_000), walletState(t, pool, org))

	before := releasedCounter(t, ReleaseReasonExpiredSafety)
	summaries := n06p5RaceReleasePass(t, pool, 8)

	var released, returned int64
	for i, s := range summaries {
		require.LessOrEqual(t, s.Released, int64(1), "racer %d released more than one row", i)
		released += s.Released
		returned += s.ReturnedMicroUSD
	}
	require.Equal(t, int64(1), released, "exactly one reconciler released the lapsed escrow")
	require.Equal(t, int64(600_000), returned, "remainder returned exactly once, full amount")

	assert.InDelta(t, before+1, releasedCounter(t, ReleaseReasonExpiredSafety), 0.001)
	_, granted, ret, status, _ := allowanceRow(t, pool, "n06p5-dead-replica", ScopeWallet, org, "")
	assert.Equal(t, int64(600_000), granted)
	assert.Equal(t, AllowanceReleased, status)
	assert.Equal(t, int64(600_000), ret)
	_, _, _, liveStatus, liveLease := allowanceRow(t, pool, "n06p5-live-replica", ScopeWallet, org, "")
	assert.Equal(t, AllowanceActive, liveStatus, "live sibling untouched by the race")
	assert.True(t, time.Until(liveLease) > 9*time.Minute, "live lease intact")
	require.Equal(t, int64(200_000), walletState(t, pool, org),
		"only the live sibling's escrow stays frozen")

	// Idempotence under race: another round of concurrent passes releases
	// nothing more.
	for _, s := range n06p5RaceReleasePass(t, pool, 8) {
		require.Zero(t, s.Released)
		require.Zero(t, s.ReturnedMicroUSD)
	}
	require.Equal(t, int64(200_000), walletState(t, pool, org))

	// Convergence to one ledger: divergence/stranded unchanged from the
	// baseline, reserved exactly the live sibling, no lapsed non-released
	// rows left (no eternal reservations).
	after, err := worker.CheckInvariants(ctx)
	require.NoError(t, err)
	assert.Equal(t, base.DivergencePerScope[ScopeWallet], after.DivergencePerScope[ScopeWallet],
		"wallet divergence unchanged by the crash cycle")
	assert.Equal(t, base.ReservedPerScope[ScopeWallet]+200_000, after.ReservedPerScope[ScopeWallet])
	assert.Equal(t, base.StrandedMicroUSD, after.StrandedMicroUSD, "no stranded capacity left behind")
	assert.Zero(t, n06p5LapsedNonReleased(t, pool, org), "no eternal reservations")
}

// TestN06P05Live_ReconcileVsSettleReleaseReserveExactlyOnce: a settlement
// worker (job row + SettleDecrementTx in one tx) races eight reconcile
// passes on the same lapsed allowance. Either interleaving order removes
// exactly the granted amount from the scope reserve — settle-first lets the
// pass return only the unsold remainder, release-first makes the settle
// ledger-only — and a second late settle cannot move the reserve again.
func TestN06P05Live_ReconcileVsSettleReleaseReserveExactlyOnce(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-vs-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 1_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	worker := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	base, err := worker.CheckInvariants(ctx)
	require.NoError(t, err)

	g, err := store.Grant(ctx, "n06p5-vs-replica", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 1_000_000},
	})
	require.NoError(t, err)
	n06p5LapseLease(t, pool, "n06p5-vs-replica", org)
	require.Equal(t, int64(1_000_000), walletState(t, pool, org))

	const racers = 8
	errs := make([]error, racers+1)
	summaries := make([]ReconcileSummary, racers)
	var settledApplied int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
			<-start
			summaries[i], errs[i] = w.ReleasePass(ctx)
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		settledApplied, errs[racers] = n06p5SettleLikeWorker(ctx, pool, org, g[0].AllowanceID, 250_000, 400_000)
	}()
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "racer %d failed", i)
	}
	if settledApplied != 0 {
		require.Equal(t, int64(250_000), settledApplied, "applied settle is capped at min(actual, bound)")
	}
	var returned int64
	for _, s := range summaries {
		returned += s.ReturnedMicroUSD
	}
	// Either order, the reserve loses exactly the granted amount — the
	// reconcile×settle race never double-spends and never over-releases.
	require.Equal(t, int64(1_000_000), returned+settledApplied,
		"reserve removed exactly once across the reconcile×settle race")
	require.Zero(t, walletState(t, pool, org), "escrow fully unwound, no negative reserve")
	_, _, ret, status, _ := allowanceRow(t, pool, "n06p5-vs-replica", ScopeWallet, org, "")
	assert.Equal(t, AllowanceReleased, status)
	assert.Equal(t, int64(1_000_000)-settledApplied, ret, "released remainder = granted − settled")

	// A late settle after the release is ledger-only: no reserve movement,
	// convergence stays put.
	late, err := store.SettleDecrement(ctx, org, g[0].AllowanceID, 250_000, 400_000)
	require.NoError(t, err)
	assert.False(t, late.Applied, "late settle after release must not touch the reserve")
	require.Zero(t, walletState(t, pool, org))

	after, err := worker.CheckInvariants(ctx)
	require.NoError(t, err)
	assert.Equal(t, base.DivergencePerScope[ScopeWallet], after.DivergencePerScope[ScopeWallet],
		"race converges to one ledger")
	assert.Equal(t, base.StrandedMicroUSD, after.StrandedMicroUSD)
	assert.Zero(t, n06p5LapsedNonReleased(t, pool, org), "no eternal reservations")
}

// TestN06P05Live_RacingReconcilersNeverReleaseLiveReserve: an active
// renewing sibling and a drain that crashed mid-way (draining, remainder
// still held, lease young) keep their escrow frozen through racing
// reconcile passes; once the drain completes (zero remainder) the release
// happens exactly once even under a race, with no money returned twice.
func TestN06P05Live_RacingReconcilersNeverReleaseLiveReserve(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-live-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 1_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	// Live renewing sibling (fresh lease, money frozen) …
	_, err := store.Grant(ctx, "n06p5-live2-replica", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 200_000},
	})
	require.NoError(t, err)
	// … and a graceful drain that crashed mid-way: draining with the full
	// remainder still held, lease still young.
	_, err = store.Grant(ctx, "n06p5-middrain-replica", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 300_000},
	})
	require.NoError(t, err)
	n, err := store.MarkDraining(ctx, "n06p5-middrain-replica")
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	require.Equal(t, int64(500_000), walletState(t, pool, org))

	// Racing reconcilers release nothing: an active row is not a
	// candidate, and draining-with-remainder on a young lease is skipped
	// (§7.1.1 safety: money still owned must not move under a race).
	for _, s := range n06p5RaceReleasePass(t, pool, 8) {
		require.Zero(t, s.Released, "live reserve must never be released")
		require.Zero(t, s.ReturnedMicroUSD)
	}
	require.Equal(t, int64(500_000), walletState(t, pool, org), "escrow frozen through the race")
	_, _, _, status, lease := allowanceRow(t, pool, "n06p5-live2-replica", ScopeWallet, org, "")
	assert.Equal(t, AllowanceActive, status)
	assert.True(t, time.Until(lease) > 9*time.Minute, "live lease intact")
	_, _, _, status, _ = allowanceRow(t, pool, "n06p5-middrain-replica", ScopeWallet, org, "")
	assert.Equal(t, AllowanceDraining, status)

	// The drain completes (full return) → zero remainder is releasable
	// immediately (§7.1.2) and exactly once even under a race.
	sum, err := store.ReturnRemaining(ctx, org, "n06p5-middrain-replica", []RemainingRequest{
		{Scope: ScopeWallet, Key: org, Holdback: 0},
	})
	require.NoError(t, err)
	require.Equal(t, int64(300_000), sum.ReturnedMicroUSD)
	require.Equal(t, int64(200_000), walletState(t, pool, org))

	before := releasedCounter(t, ReleaseReasonZeroRemainder)
	var released int64
	for _, s := range n06p5RaceReleasePass(t, pool, 8) {
		released += s.Released
		require.Zero(t, s.ReturnedMicroUSD, "zero-remainder release returns no money")
	}
	require.Equal(t, int64(1), released, "exactly one racer flips draining→released")
	assert.InDelta(t, before+1, releasedCounter(t, ReleaseReasonZeroRemainder), 0.001)
	require.Equal(t, int64(200_000), walletState(t, pool, org), "no double return")
	assert.Zero(t, n06p5LapsedNonReleased(t, pool, org), "no eternal reservations")
}

// TestN06P05Live_CloseAbandonedReplicaRacesReconcilersExactlyOnce: the
// packet's negative criterion aimed at the new primitive — several
// operators (and the periodic pass racing them) all conclude the same
// replica is permanently lost. The lapsed row closes exactly once, the
// remainder returns exactly once, the losing closers observe the
// already-released outcome instead of double-spending, and the live
// sibling's reserve never moves.
func TestN06P05Live_CloseAbandonedReplicaRacesReconcilersExactlyOnce(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-orphrace-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	worker := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	base, err := worker.CheckInvariants(ctx)
	require.NoError(t, err)

	_, err = store.Grant(ctx, "n06p5-orphrace-dead", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 600_000},
	})
	require.NoError(t, err)
	_, err = store.Grant(ctx, "n06p5-orphrace-live", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 200_000},
	})
	require.NoError(t, err)
	// Hard-crash shape: still active, lease lapsed 3h — beyond the §14
	// safety window, so the verdict may close it.
	n06p5ForceState(t, pool, "n06p5-orphrace-dead", org, AllowanceActive, 3*time.Hour)
	require.Equal(t, int64(800_000), walletState(t, pool, org))

	orphanBefore := releasedCounter(t, ReleaseReasonCrashOrphan)

	const racers = 4
	summaries := make([]AbandonedReplicaSummary, racers)
	errs := make([]error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// window 0 → the §14 ReservationSafetyWindow fallback, like a
			// caller that does not override the default.
			<-start
			summaries[i], errs[i] = store.CloseAbandonedReplica(ctx, "n06p5-orphrace-dead", 0)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "closer %d failed", i)
	}

	var closed, returned, already, skipped int64
	for i, s := range summaries {
		require.LessOrEqual(t, s.Closed, int64(1), "closer %d closed more than one row", i)
		require.Zero(t, s.ReturnedMicroUSD-int64(600_000)*s.Closed,
			"closer %d must only return what it closed", i)
		closed += s.Closed
		returned += s.ReturnedMicroUSD
		already += s.AlreadyReleased
		skipped += s.SkippedLive
	}
	require.Equal(t, int64(1), closed, "exactly one reconciler closed the orphan")
	require.Equal(t, int64(600_000), returned, "remainder returned exactly once, full amount")
	require.Zero(t, skipped, "a lapsed orphan is closable — nothing live in the way")
	require.Equal(t, int64(racers-1), already, "losing closers see the exactly-once outcome")
	assert.InDelta(t, orphanBefore+1, releasedCounter(t, ReleaseReasonCrashOrphan), 0.001,
		"crash_orphan counter counts the verdict exactly once")

	_, granted, ret, status, _ := allowanceRow(t, pool, "n06p5-orphrace-dead", ScopeWallet, org, "")
	assert.Equal(t, int64(600_000), granted)
	assert.Equal(t, AllowanceReleased, status)
	assert.Equal(t, int64(600_000), ret)
	_, _, _, liveStatus, liveLease := allowanceRow(t, pool, "n06p5-orphrace-live", ScopeWallet, org, "")
	assert.Equal(t, AllowanceActive, liveStatus, "live sibling untouched by the verdict race")
	assert.True(t, time.Until(liveLease) > 9*time.Minute, "live lease intact")
	require.Equal(t, int64(200_000), walletState(t, pool, org),
		"only the live sibling's escrow stays frozen")

	// The periodic pass racing afterwards changes nothing: §7.1.1 window
	// release and the verdict share one exactly-once state machine.
	sum, err := worker.ReleasePass(ctx)
	require.NoError(t, err)
	require.Zero(t, sum.Released)
	require.Zero(t, sum.ReturnedMicroUSD)
	require.Equal(t, int64(200_000), walletState(t, pool, org))

	after, err := worker.CheckInvariants(ctx)
	require.NoError(t, err)
	assert.Equal(t, base.DivergencePerScope[ScopeWallet], after.DivergencePerScope[ScopeWallet],
		"verdict race converges to one ledger")
	assert.Equal(t, base.StrandedMicroUSD, after.StrandedMicroUSD)
	assert.Equal(t, base.ReservedPerScope[ScopeWallet]+200_000, after.ReservedPerScope[ScopeWallet])
	assert.Zero(t, n06p5LapsedNonReleased(t, pool, org), "no eternal reservations")
}

// TestN06P05Live_CrashRecoveryConvergesWithRacingReconcilers: the packet
// acceptance end to end. After a replica is permanently lost, the full
// recovery funnel — the restarted host's startup sweep (drain), racing
// periodic reconcile passes, and the targeted permanently-lost verdict on
// every dead replica across hosts — converges to one ledger: each orphan
// released exactly once with its full remainder, sweeps never move money,
// the live reserve stays frozen, a repeated convergence round is a no-op,
// invariants stay clean and no lapsed non-released rows remain.
func TestN06P05Live_CrashRecoveryConvergesWithRacingReconcilers(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5-conv-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	worker := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	base, err := worker.CheckInvariants(ctx)
	require.NoError(t, err)

	// Two dead incarnations of the restarted host family (the sweep's
	// regex target) and one dead replica on a foreign host only the
	// targeted verdict can close; all in the hard-crash shape. Plus one
	// live renewing sibling that must survive untouched.
	const (
		hostA1 = "n06p5-conv-hostA-111-1"
		hostA2 = "n06p5-conv-hostA-222-2"
		hostB  = "n06p5-conv-hostB-333-3"
	)
	grants := map[string]money.MicroUSD{hostA1: 600_000, hostA2: 300_000, hostB: 500_000}
	for replica, bound := range grants {
		_, err := store.Grant(ctx, replica, org, []GrantRequest{
			{Scope: ScopeWallet, Key: org, Bound: bound},
		})
		require.NoError(t, err)
		n06p5ForceState(t, pool, replica, org, AllowanceActive, 3*time.Hour)
	}
	_, err = store.Grant(ctx, "n06p5-conv-live", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 200_000},
	})
	require.NoError(t, err)
	require.Equal(t, int64(1_600_000), walletState(t, pool, org))

	expiredBefore := releasedCounter(t, ReleaseReasonExpiredSafety)
	orphanBefore := releasedCounter(t, ReleaseReasonCrashOrphan)

	// Eight racers funnel into the same lapsed rows: two startup sweeps of
	// the restarted host, two periodic reconcile passes (their own worker,
	// like separate replica processes), and the permanently-lost verdict
	// for each of the three dead replicas.
	const (
		sweeps = 2
		passes = 2
		closes = 3
	)
	sweepErrs := make([]error, sweeps)
	sweepDrained := make([]int64, sweeps)
	passSummaries := make([]ReconcileSummary, passes)
	passErrs := make([]error, passes)
	closeSummaries := make([]AbandonedReplicaSummary, closes)
	closeErrs := make([]error, closes)
	start := make(chan struct{})
	var wg sync.WaitGroup
	racer := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; f() }()
	}
	for i := 0; i < sweeps; i++ {
		i := i
		racer(func() {
			sweepDrained[i], sweepErrs[i] = store.SelfReapCrashedIncarnations(ctx, "n06p5-conv-hostA")
		})
	}
	for i := 0; i < passes; i++ {
		i := i
		w := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
		racer(func() {
			passSummaries[i], passErrs[i] = w.ReleasePass(ctx)
		})
	}
	deadReplicas := []string{hostA1, hostA2, hostB}
	for i, replica := range deadReplicas {
		i, replica := i, replica
		racer(func() {
			closeSummaries[i], closeErrs[i] = store.CloseAbandonedReplica(ctx, replica, 0)
		})
	}
	close(start)
	wg.Wait()
	for i, err := range sweepErrs {
		require.NoError(t, err, "sweep %d failed", i)
	}
	for i, err := range passErrs {
		require.NoError(t, err, "pass %d failed", i)
	}
	for i, err := range closeErrs {
		require.NoError(t, err, "close %d failed", i)
	}

	var passReleased, passReturned, passExpired, passZeroRem int64
	for _, s := range passSummaries {
		passReleased += s.Released
		passReturned += s.ReturnedMicroUSD
		passExpired += s.ExpiredSafetyReleased
		passZeroRem += s.ZeroRemainderReleased
	}
	var closed, closedReturned int64
	for _, c := range closeSummaries {
		closed += c.Closed
		closedReturned += c.ReturnedMicroUSD
	}
	require.LessOrEqual(t, sweepDrained[0]+sweepDrained[1], int64(2),
		"sweeps drain at most the two crashed A-family rows and never move money")
	// Money moved exactly once: sweeps never return money, and the passes
	// plus the verdict together return each orphan remainder exactly once —
	// 600k + 300k + 500k, never a µUSD more.
	require.Equal(t, int64(1_400_000), passReturned+closedReturned,
		"crash recovery returns each orphan remainder exactly once")
	require.Equal(t, int64(3), passReleased+closed,
		"all three orphans closed exactly once across the whole funnel")
	require.Zero(t, passZeroRem, "positive-remainder orphans are not zero-remainder releases")
	assert.InDelta(t, orphanBefore+float64(closed), releasedCounter(t, ReleaseReasonCrashOrphan), 0.001)
	assert.InDelta(t, expiredBefore+float64(passExpired), releasedCounter(t, ReleaseReasonExpiredSafety), 0.001)

	for replica, bound := range grants {
		_, granted, ret, status, _ := allowanceRow(t, pool, replica, ScopeWallet, org, "")
		assert.Equal(t, AllowanceReleased, status, "orphan %s released", replica)
		assert.Equal(t, int64(bound), granted)
		assert.Equal(t, int64(bound), ret, "orphan %s returned exactly its remainder", replica)
	}
	_, _, _, liveStatus, liveLease := allowanceRow(t, pool, "n06p5-conv-live", ScopeWallet, org, "")
	assert.Equal(t, AllowanceActive, liveStatus, "live sibling survives the whole funnel")
	assert.True(t, time.Until(liveLease) > 9*time.Minute, "live lease intact")
	require.Equal(t, int64(200_000), walletState(t, pool, org),
		"only the live sibling's escrow stays frozen")

	// A second, sequential convergence round (sweep + pass + verdicts) is
	// a verified no-op — recovery is stable, not merely lucky.
	drained, err := store.SelfReapCrashedIncarnations(ctx, "n06p5-conv-hostA")
	require.NoError(t, err)
	sum2, err := worker.ReleasePass(ctx)
	require.NoError(t, err)
	closed2 := int64(0)
	for _, replica := range deadReplicas {
		c, err := store.CloseAbandonedReplica(ctx, replica, 0)
		require.NoError(t, err)
		closed2 += c.Closed
		require.Zero(t, c.ReturnedMicroUSD, "already-closed orphan returns nothing")
	}
	require.Zero(t, drained+sum2.Released+closed2, "converged recovery is a no-op")
	require.Zero(t, sum2.ReturnedMicroUSD)
	require.Equal(t, int64(200_000), walletState(t, pool, org))

	after, err := worker.CheckInvariants(ctx)
	require.NoError(t, err)
	assert.Equal(t, base.DivergencePerScope[ScopeWallet], after.DivergencePerScope[ScopeWallet],
		"recovery converges to one ledger")
	assert.Equal(t, base.ReservedPerScope[ScopeWallet]+200_000, after.ReservedPerScope[ScopeWallet])
	assert.Equal(t, base.StrandedMicroUSD, after.StrandedMicroUSD)
	assert.Zero(t, n06p5LapsedNonReleased(t, pool, org), "no eternal reservations")
}
