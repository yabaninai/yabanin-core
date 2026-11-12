//go:build integration

// N06-P05-T07 boundary corpus, verdict side (contract
// artifacts/internal-delivery-program/N06-P05/contract.md). T02/T04/T05/T06 covered
// the negative scenarios and joint user flows under live interleavings;
// this corpus freezes the BOUNDARIES themselves, deterministically:
//
//   - the fence TTL instant (exactly at the deadline → rejected before any
//     DB access; one microsecond earlier → the same lease drives a full
//     exactly-once pass);
//   - the mid-pass abort ROW boundary (the TTL check lands exactly on the
//     stop() before row K+1 — rows 1..K closed, the rest untouched);
//   - the money boundaries of the §7.1 remainder formula (settled ==
//     granted closes a young row; granted−1 keeps it frozen and later
//     returns exactly one µUSD; an over-mark drift clamps to zero — never
//     a negative return);
//   - the §14 safety-window edges (fenced override 30m: inside/outside;
//     unfenced default 2h: the inside edge that keeps every µUSD frozen).
//   - the fence's mutual-exclusion storm (exactly one Acquire winner, no
//     leak after release, no double close across storms).
//
// Shared-stand discipline (same as the T05 file): one Postgres container,
// one pool and one process-global metrics registry per package. Lapsed
// shapes stay INSIDE the §14 default window wherever a foreign periodic
// pass must legally refuse them (the fenced 30-minute override pins both
// of its edges inside that safe zone); the past-window closes here carry
// the same negligible foreign-sweep exposure the accepted T05 convergence
// tests carry. Summary asserts fold only replica-scoped verdicts; the
// process-global release counter is asserted with GreaterOrEqual.
package budget

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n06p5bShiftScopeLease backdates ONE scope row of a replica — the window
// edge tests need per-row offsets, unlike the whole-replica
// n06p5ShiftLease.
func n06p5bShiftScopeLease(t *testing.T, pool *pgxpool.Pool, replica string, scope ScopeKind, lapse time.Duration) {
	t.Helper()
	tag, err := pool.Exec(context.Background(),
		`UPDATE budget_allowances
		 SET lease_until = now() - $2::interval, updated_at = now()
		 WHERE replica_id = $1 AND scope_kind = $3`,
		replica, formatInterval(lapse), string(scope))
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected(),
		"exactly the %s row of %s must shift", scope, replica)
}

// n06p5bSettledKeys sums the reconcile settle keys of one allowance — the
// µUSD the settlement side removed from its scope reserve (the same shape
// the reconcile's remainder input reads).
func n06p5bSettledKeys(t *testing.T, pool *pgxpool.Pool, allowanceID int64) int64 {
	t.Helper()
	var settled int64
	err := pool.QueryRow(context.Background(), `
		SELECT COALESCE(SUM(CASE WHEN status = 'settled'
		                         THEN COALESCE((payload->>$2)::bigint, 0)
		                         ELSE 0 END), 0)
		FROM settlement_jobs WHERE allowance_id = $1`,
		allowanceID, reconcileSettleKey).Scan(&settled)
	require.NoError(t, err)
	return settled
}

func TestN06P05BoundaryLive_FenceTtlExactEqualityEdge(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5b-ttl-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	const dead = "n06p5b-ttl-dead"
	total := n06p5GrantFourScopes(t, pool, org, dead)
	n06p5ShiftLease(t, pool, dead, time.Hour) // lapsed 1h: outside the 30m fenced override, inside the 2h default

	fence := NewRecoveryFence(n06p5FenceHolderPool(pool), nil)
	base := time.Now()
	var now atomic.Int64 // unix nanos of the faked now, 0 = acquisition base
	fence.now = func() time.Time {
		if v := now.Load(); v != 0 {
			return time.Unix(0, v)
		}
		return base
	}
	const ttl = 45 * time.Minute
	lease, err := fence.Acquire(ctx, dead, "verdict-ttl", ttl)
	require.NoError(t, err)
	expires := lease.Expires()
	require.Equal(t, base.Add(ttl), expires, "the fake clock makes the TTL deadline exact")

	// Case A: the exact TTL instant. !expires.After(expires) — at its own
	// deadline the lease is already expired, and the verdict is rejected
	// before the candidate scan: zero summary, no row touched, no reserve
	// moved (the failure is the observable, exactly as the contract's
	// stale-mutation clause requires).
	now.Store(expires.UnixNano())
	sum, err := store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.ErrorIs(t, err, ErrRecoveryFenceExpired)
	require.NotErrorIs(t, err, ErrStaleRecoveryFence)
	require.Equal(t, AbandonedReplicaSummary{}, sum, "the pre-verdict rejection reports an empty pass")
	var active int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM budget_allowances WHERE replica_id = $1 AND status = $2`,
		dead, AllowanceActive).Scan(&active))
	require.Equal(t, int64(4), active, "the rejected verdict touched no row")
	require.Equal(t, int64(100_000), walletState(t, pool, org), "no reserve moved at the exact-TTL rejection")

	// Case B: one microsecond EARLIER the very same lease drives a full
	// pass — the entire corpus of what the equality edge protects.
	now.Store(expires.Add(-time.Microsecond).UnixNano())
	sum, err = store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(4), sum.Closed)
	require.Equal(t, total, sum.ReturnedMicroUSD)
	require.Zero(t, sum.SkippedLive)
	require.NoError(t, lease.Release(ctx))
	require.Zero(t, walletState(t, pool, org))
}

// TestN06P05BoundaryLive_MidPassExpiryLandsOnExactRowBoundary pins the
// mid-pass TTL check to the exact candidate row: rows 1..K close, and the
// stop() before row K+1 refuses with the TTL error. The T05 mid-pass test
// placed the abort with a racing watcher (anywhere after the first
// release); the corpus pins the boundary deterministically via the clock's
// call shape: the pass calls now() once for the pre-verdict Expired check
// and once per stop() — one per candidate row in id order (Grant issues
// the four scopes in request order, so ids ascend wallet, team, agent,
// session). If the production loop shape ever changes (extra clock reads,
// batched rows), this test fails loudly and the boundary must be re-pinned.
func TestN06P05BoundaryLive_MidPassExpiryLandsOnExactRowBoundary(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5b-mid-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	const dead = "n06p5b-mid-dead"
	total := n06p5GrantFourScopes(t, pool, org, dead)
	n06p5ShiftLease(t, pool, dead, time.Hour)

	const (
		ttl          = time.Hour
		closeFirstK  = 2 // rows 1..K close; the abort lands exactly before row K+1
		stoppedAfter = 300_000
	)
	fence := NewRecoveryFence(n06p5FenceHolderPool(pool), nil)
	base := time.Now()
	var calls atomic.Int64
	fence.now = func() time.Time {
		if calls.Add(1) > int64(closeFirstK)+1 { // pre-verdict (#1) + K stops (#2..#K+1) stay live
			return base.Add(2 * ttl)
		}
		return base
	}
	lease, err := fence.Acquire(ctx, dead, "verdict-boundary", ttl) // consumes its own now() before the pass
	require.NoError(t, err)
	calls.Store(0) // counting restarts at the verdict's pre-verdict check

	sum, err := store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.ErrorIs(t, err, ErrRecoveryFenceExpired, "the stop() before row K+1 refuses with the TTL error")
	require.Equal(t, int64(closeFirstK), sum.Closed, "exactly the first K rows closed")
	require.Equal(t, int64(stoppedAfter), sum.ReturnedMicroUSD, "wallet+team grants returned, nothing else")
	require.Zero(t, sum.SkippedLive, "no row after the boundary was even classified")
	var activeScopes []string
	rows, err := pool.Query(ctx,
		`SELECT scope_kind FROM budget_allowances WHERE replica_id = $1 AND status = $2 ORDER BY id`,
		dead, AllowanceActive)
	require.NoError(t, err)
	for rows.Next() {
		var scope string
		require.NoError(t, rows.Scan(&scope))
		activeScopes = append(activeScopes, scope)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, []string{"agent_day", "session"}, activeScopes,
		"the pass stopped at the row boundary: the tail rows are untouched")
	require.NoError(t, lease.Release(ctx))

	// Takeover: a fresh lease finishes exactly what the aborted pass left —
	// the union is the full escrow, exactly once.
	leaseB, err := n06p5TryAcquireFence(ctx, pool, dead, "verdict-boundary-b", time.Hour)
	require.NoError(t, err)
	sumB, err := store.CloseAbandonedReplicaFenced(ctx, leaseB, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(2), sumB.Closed, "the finishing verdict closes exactly the tail rows")
	require.Equal(t, int64(700_000), sumB.ReturnedMicroUSD)
	require.Equal(t, total, sum.ReturnedMicroUSD+sumB.ReturnedMicroUSD,
		"the escrow returned exactly once across the aborted and finishing verdicts")
	require.NoError(t, leaseB.Release(ctx))
	require.Zero(t, walletState(t, pool, org))

	// The released aborted lease is stale for every later use, and a fresh
	// verdict observes the exactly-once losing side.
	_, err = store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.ErrorIs(t, err, ErrStaleRecoveryFence)
	leaseC, err := n06p5TryAcquireFence(ctx, pool, dead, "verdict-boundary-c", time.Hour)
	require.NoError(t, err)
	defer func() { _ = leaseC.Release(ctx) }()
	sumC, err := store.CloseAbandonedReplicaFenced(ctx, leaseC, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(4), sumC.AlreadyReleased)
	require.Zero(t, sumC.Closed)
	require.Zero(t, sumC.ReturnedMicroUSD)
}

// TestN06P05BoundaryLive_MoneyRemainderEdgesOneVerdict pins the §7.1
// remainder boundaries on four sibling rows of one replica with one
// verdict per phase: settled == granted closes a YOUNG row (§7.1.2 with
// nothing left to protect); granted−1 keeps a young row frozen and later
// returns exactly one µUSD; an over-mark ledger drift clamps the negative
// remainder to zero (close, return nothing — never a negative return,
// never resurrected money); a full live remainder stays frozen until the
// window lapses and then returns in full.
func TestN06P05BoundaryLive_MoneyRemainderEdgesOneVerdict(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5b-money-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	const dead = "n06p5b-money-dead"
	n06p5GrantFourScopes(t, pool, org, dead) // wallet 100k, team 200k, agent 400k, session 300k — all young
	walletKey, walletPeriod := n06p5ScopeRef(t, pool, dead, ScopeWallet)
	walletID, _, _, _, _ := allowanceRow(t, pool, dead, ScopeWallet, walletKey, walletPeriod)
	teamKey, teamPeriod := n06p5ScopeRef(t, pool, dead, ScopeTeamMonth)
	teamID, _, _, _, _ := allowanceRow(t, pool, dead, ScopeTeamMonth, teamKey, teamPeriod)
	agentKey, agentPeriod := n06p5ScopeRef(t, pool, dead, ScopeAgentDay)
	agentID, _, _, _, _ := allowanceRow(t, pool, dead, ScopeAgentDay, agentKey, agentPeriod)

	// Wallet: settled == granted exactly — the zero-remainder close on a
	// young lease.
	_, err := n06p5SettleLikeWorker(ctx, pool, org, walletID, 100_000, 100_000)
	require.NoError(t, err)
	// Team: granted−1 — one µUSD of live remainder must keep the row
	// frozen.
	_, err = n06p5SettleLikeWorker(ctx, pool, org, teamID, 199_999, 200_000)
	require.NoError(t, err)
	// Agent: settled == granted, plus injected ledger drift (Σ keys >
	// granted). The production settle path cannot over-mark —
	// SettleDecrementTx floors at min(actual, bound) and the scope reserves
	// CHECK at zero — so the corpus injects the mark directly to pin the
	// verdict's defensive clamp.
	_, err = n06p5SettleLikeWorker(ctx, pool, org, agentID, 400_000, 400_000)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, allowance_id, payload, status)
		VALUES ($1, $2, 'wallet', $3, jsonb_build_object($4::text, $5::bigint), 'settled')`,
		org, "req-n06p5b-drift-"+uuid.NewString(), agentID, reconcileSettleKey, 5_000)
	require.NoError(t, err)
	// Session: untouched — the full live remainder.

	// Phase 1: a fenced verdict over the young rows. Zero remainders close
	// immediately and return nothing; live remainders freeze.
	lease, err := n06p5TryAcquireFence(ctx, pool, dead, "verdict-money", time.Hour)
	require.NoError(t, err)
	sum, err := store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.NoError(t, err)
	require.NoError(t, lease.Release(ctx))
	require.Equal(t, int64(2), sum.Closed, "wallet (settled==granted) and agent (over-mark clamped) close on young leases")
	require.Zero(t, sum.ReturnedMicroUSD, "a zero remainder returns nothing — no money moves")
	require.Equal(t, int64(2), sum.SkippedLive, "team (granted−1) and session (full) hold live remainders")
	require.Equal(t, int64(0), walletState(t, pool, org))
	require.Equal(t, int64(1), scopeReserve(t, pool, ScopeTeamMonth, teamKey, teamPeriod),
		"exactly the one µUSD remainder stays reserved")
	require.Equal(t, int64(0), scopeReserve(t, pool, ScopeAgentDay, agentKey, agentPeriod),
		"the drift mark moved no reserve; the settled decrement drained it")
	sessKey, sessPeriod := n06p5ScopeRef(t, pool, dead, ScopeSession)
	require.Equal(t, int64(300_000), scopeReserve(t, pool, ScopeSession, sessKey, sessPeriod))

	// Phase 2: after the window lapses the frozen rows close and return
	// exactly their remainders — team's is one µUSD.
	n06p5ShiftLease(t, pool, dead, 3*time.Hour)
	sum2, err := store.CloseAbandonedReplica(ctx, dead, 0)
	require.NoError(t, err)
	// A concurrent §7.1.1 reconcile sweep is ALLOWED to win the lapsed
	// team/session rows on the shared container: ReconcileRelease is a
	// global pass (no org filter) and by design the targeted verdict and
	// the periodic sweep can never both move the same money. The pins
	// therefore hold the exactly-once STATE rather than assuming THIS
	// verdict won the race: both lapsed rows end released, their scope
	// reserves drain, and each row's money returned exactly once —
	// whichever closer flipped it.
	require.Zero(t, sum2.SkippedLive, "every row is lapsed now; nothing stays frozen")
	require.Equal(t, int64(4), sum2.Closed+sum2.AlreadyReleased+sum2.SkippedLive,
		"all four candidate rows got a terminal classification")
	require.Zero(t, scopeReserve(t, pool, ScopeTeamMonth, teamKey, teamPeriod))
	require.Zero(t, scopeReserve(t, pool, ScopeSession, sessKey, sessPeriod))
	_, _, teamReturnedFinal, teamStatusFinal, _ := allowanceRow(t, pool, dead, ScopeTeamMonth, teamKey, teamPeriod)
	require.Equal(t, AllowanceReleased, teamStatusFinal)
	require.Equal(t, int64(1), teamReturnedFinal, "team's one µUSD remainder returned exactly once")
	_, _, sessReturnedFinal, sessStatusFinal, _ := allowanceRow(t, pool, dead, ScopeSession, sessKey, sessPeriod)
	require.Equal(t, AllowanceReleased, sessStatusFinal)
	require.Equal(t, int64(300_000), sessReturnedFinal, "session escrow returned exactly once")

	// Per-row conservation for the HONEST ledgers: returned + Σ settled
	// keys == granted, whatever the split between the settle path and the
	// verdicts. The over-mark row's invariant is the clamp itself: returned
	// stays zero (no negative-return compensation, no double return) while
	// Σ keys keeps the injected drift — the verdict never rewrites history.
	for _, tc := range []struct {
		name        string
		id, granted int64
		scope       ScopeKind
	}{
		{"wallet", walletID, 100_000, ScopeWallet},
		{"team", teamID, 200_000, ScopeTeamMonth},
	} {
		key, period := n06p5ScopeRef(t, pool, dead, tc.scope)
		_, _, returned, status, _ := allowanceRow(t, pool, dead, tc.scope, key, period)
		assert.Equal(t, AllowanceReleased, status, tc.name)
		assert.Equal(t, tc.granted, returned+n06p5bSettledKeys(t, pool, tc.id),
			"%s: returned + settled == granted exactly once", tc.name)
	}
	_, _, agentReturned, agentStatus, _ := allowanceRow(t, pool, dead, ScopeAgentDay, agentKey, agentPeriod)
	assert.Equal(t, AllowanceReleased, agentStatus)
	assert.Zero(t, agentReturned,
		"the clamp returns nothing: no negative-return compensation for the drift")
	assert.Equal(t, int64(405_000), n06p5bSettledKeys(t, pool, agentID),
		"Σ settled keys == granted + injected drift, untouched by the verdict")

	// Idempotent tail: every later verdict only reports the losing side.
	lease2, err := n06p5TryAcquireFence(ctx, pool, dead, "verdict-money-tail", time.Hour)
	require.NoError(t, err)
	sum3, err := store.CloseAbandonedReplicaFenced(ctx, lease2, 30*time.Minute)
	require.NoError(t, err)
	require.NoError(t, lease2.Release(ctx))
	require.Equal(t, int64(4), sum3.AlreadyReleased)
	require.Zero(t, sum3.Closed)
	require.Zero(t, sum3.ReturnedMicroUSD)
	// Wallet and agent (young, zero-remainder rows no sweep can select —
	// their lease_until is still in the future) are closed by THIS verdict
	// deterministically; team/session may legitimately have been taken by
	// a concurrent sweep under expired_safety_window, so the crash_orphan
	// floor is the two verdict-owned rows.
	require.GreaterOrEqual(t, releasedCounter(t, ReleaseReasonCrashOrphan), float64(2),
		"the verdict-owned closes count once under the crash_orphan reason")
}

// TestN06P05BoundaryLive_SafetyWindowEdgesBothSides pins the §14 window
// edges with 10-second margins around them (the exact instant
// lease_until == now() − window is not externally pinnable against the
// live PG clock; the predicate is strict `<`, so equality is fail-closed —
// the unit corpus pins that instant for the fence TTL). Both fenced
// override edges stay inside the 2h default window, where foreign
// periodic passes legally refuse the rows.
func TestN06P05BoundaryLive_SafetyWindowEdgesBothSides(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()

	// Fenced override edge (30m): one row just inside, one just outside,
	// two young. The outside row closes; the inside row and the young rows
	// freeze.
	orgF := "org-n06p5b-winf-" + uuid.NewString()[:8]
	setWallet(t, pool, orgF, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, orgF) })
	const fenced = "n06p5b-winf-dead"
	n06p5GrantFourScopes(t, pool, orgF, fenced)
	n06p5bShiftScopeLease(t, pool, fenced, ScopeWallet, 30*time.Minute-10*time.Second)
	n06p5bShiftScopeLease(t, pool, fenced, ScopeTeamMonth, 30*time.Minute+10*time.Second)

	lease, err := n06p5TryAcquireFence(ctx, pool, fenced, "verdict-winf", time.Hour)
	require.NoError(t, err)
	sum, err := store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.NoError(t, err)
	require.NoError(t, lease.Release(ctx))
	require.Equal(t, int64(1), sum.Closed, "only the outside-the-override row closes")
	require.Equal(t, int64(200_000), sum.ReturnedMicroUSD)
	require.Equal(t, int64(3), sum.SkippedLive, "inside-the-override and young rows freeze")
	teamKey, teamPeriod := n06p5ScopeRef(t, pool, fenced, ScopeTeamMonth)
	require.Zero(t, scopeReserve(t, pool, ScopeTeamMonth, teamKey, teamPeriod))

	// Ten seconds later the inside row crosses the same edge and closes
	// under an identical verdict — the edge itself is what separates them.
	n06p5bShiftScopeLease(t, pool, fenced, ScopeWallet, 30*time.Minute+10*time.Second)
	lease2, err := n06p5TryAcquireFence(ctx, pool, fenced, "verdict-winf-2", time.Hour)
	require.NoError(t, err)
	sum2, err := store.CloseAbandonedReplicaFenced(ctx, lease2, 30*time.Minute)
	require.NoError(t, err)
	require.NoError(t, lease2.Release(ctx))
	require.Equal(t, int64(1), sum2.Closed, "the formerly inside row now closes")
	require.Equal(t, int64(100_000), sum2.ReturnedMicroUSD)
	require.Equal(t, int64(1), sum2.AlreadyReleased, "the team row is the exactly-once losing side")
	require.Equal(t, int64(2), sum2.SkippedLive, "the young rows still freeze")
	require.Zero(t, walletState(t, pool, orgF))

	// Unfenced default edge (2h): every row just inside the default window
	// freezes under the unfenced verdict — no µUSD moves before the window
	// lapses, even though the caller asserts the replica is permanently
	// lost (the fail-closed negative edge; the outside side is the shape
	// every T05/T06 convergence close already runs).
	orgU := "org-n06p5b-winu-" + uuid.NewString()[:8]
	setWallet(t, pool, orgU, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, orgU) })
	const unfenced = "n06p5b-winu-dead"
	n06p5GrantFourScopes(t, pool, orgU, unfenced)
	n06p5ShiftLease(t, pool, unfenced, 2*time.Hour-10*time.Second)
	sumU, err := store.CloseAbandonedReplica(ctx, unfenced, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4), sumU.SkippedLive, "every row inside the default window freezes")
	require.Zero(t, sumU.Closed)
	require.Zero(t, sumU.ReturnedMicroUSD)
	require.Equal(t, int64(100_000), walletState(t, pool, orgU), "the wallet escrow stays reserved")
}

// TestN06P05BoundaryLive_FenceAcquireStormExactlyOneWinner pins the fence
// mutual exclusion under a concurrent acquisition storm: exactly one
// storm member wins, every loser observes ErrRecoveryFenceHeld, the
// winner's verdict closes the escrow exactly once, and after release a
// second storm immediately re-acquires (no leak) — its verdict only sees
// the exactly-once losing side.
func TestN06P05BoundaryLive_FenceAcquireStormExactlyOneWinner(t *testing.T) {
	t.Parallel()
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-n06p5b-storm-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 10_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	const dead = "n06p5b-storm-dead"
	total := n06p5GrantFourScopes(t, pool, org, dead)
	n06p5ShiftLease(t, pool, dead, time.Hour)

	stormAcquire := func(round string) *RecoveryLease {
		t.Helper()
		const storm = 8
		leases := make([]*RecoveryLease, storm)
		errs := make([]error, storm)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < storm; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				fence := NewRecoveryFence(n06p5FenceHolderPool(pool), nil)
				<-start
				leases[i], errs[i] = fence.Acquire(ctx, dead, fmt.Sprintf("%s-storm-%d", round, i), time.Hour)
			}(i)
		}
		close(start)
		wg.Wait()
		winners := 0
		var lease *RecoveryLease
		for i, err := range errs {
			if err == nil {
				winners++
				lease = leases[i]
				continue
			}
			require.ErrorIs(t, err, ErrRecoveryFenceHeld, "%s: loser %d must observe the held error", round, i)
		}
		require.Equal(t, 1, winners, "%s: exactly one storm member owns the fence", round)
		require.NotNil(t, lease)
		return lease
	}

	// Storm 1: one winner closes the whole escrow exactly once.
	lease := stormAcquire("first")
	sum, err := store.CloseAbandonedReplicaFenced(ctx, lease, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(4), sum.Closed)
	require.Equal(t, total, sum.ReturnedMicroUSD)
	require.NoError(t, lease.Release(ctx))
	require.Zero(t, walletState(t, pool, org))

	// Storm 2: the released fence is immediately available again, and the
	// new winner can only report the losing side — no double close, no
	// leaked lock.
	lease2 := stormAcquire("second")
	sum2, err := store.CloseAbandonedReplicaFenced(ctx, lease2, 30*time.Minute)
	require.NoError(t, err)
	require.NoError(t, lease2.Release(ctx))
	require.Equal(t, int64(4), sum2.AlreadyReleased)
	require.Zero(t, sum2.Closed)
	require.Zero(t, sum2.ReturnedMicroUSD)
	require.GreaterOrEqual(t, releasedCounter(t, ReleaseReasonCrashOrphan), float64(4))
}
