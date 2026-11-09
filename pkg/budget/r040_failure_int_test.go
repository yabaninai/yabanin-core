//go:build integration

// Failure and boundary modes for the overbudget allowance paths
//   - DB error propagation through every allowance mutation (grant / probe /
//     return / settle / reconcile): an outage is an internal error, never a
//     capacity verdict (deny) and never a partial commit — partial/unknown
//     states do not count as success, and the retry after recovery works;
//   - the D2 decrease edges: limit decreased to EXACTLY spend+reserved
//     (free = 0) and below the reserved amount alone — deny-next, escrow
//     untouched, capacity restored once the escrow drains;
//   - the concurrent limit-change race: a decrease committing between the
//     grant's capacity read and its reserve write is closed by the SQL
//     capacity predicate (the settings layer's sibling of the CAS rollback
//     precondition, pinned in pkg/adminstore);
//   - the escrow-expiry boundaries that end a deny-next: the strict
//     safety-window edge and the wallet floor shrink followed by expiry +
//     reconcile recovery.
package budget

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

// --- fault injection ---------------------------------------------------------

// errRow is a pgx.Row whose Scan always fails.
type errRow struct{ err error }

func (r errRow) Scan(_ ...any) error { return r.err }

// txFaultCommit is the marker for failing the transaction's Commit itself.
const txFaultCommit = "\x00tx-commit"

// txFault fails the FIRST statement whose SQL contains Marker (Exec or
// QueryRow), or the commit when Marker is txFaultCommit. Single-shot: the
// fault fires once, later statements pass through untouched.
type txFault struct {
	Marker string
	Err    error
	fired  bool
}

func (f *txFault) match(sql string) bool {
	if f == nil || f.fired || f.Marker == "" || f.Marker == txFaultCommit || !strings.Contains(sql, f.Marker) {
		return false
	}
	f.fired = true
	return true
}

// faultTx wraps a real transaction and injects the fault.
type faultTx struct {
	pgx.Tx
	fault *txFault
}

func (t *faultTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if t.fault.match(sql) {
		return pgconn.CommandTag{}, t.fault.Err
	}
	return t.Tx.Exec(ctx, sql, args...)
}

func (t *faultTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if t.fault.match(sql) {
		return errRow{err: t.fault.Err}
	}
	return t.Tx.QueryRow(ctx, sql, args...)
}

func (t *faultTx) Commit(ctx context.Context) error {
	if t.fault != nil && t.fault.Marker == txFaultCommit && !t.fault.fired {
		t.fault.fired = true
		return t.fault.Err
	}
	return t.Tx.Commit(ctx)
}

// faultPoolDB wraps the pool: every Begin carries the tx fault; the pool
// level QueryRow (the probe path) and Query (the reconcile candidate scan)
// carry their own one-shot faults.
type faultPoolDB struct {
	*pgxpool.Pool
	txFault    *txFault
	poolRowErr error
	poolQryErr error
}

func (d *faultPoolDB) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &faultTx{Tx: tx, fault: d.txFault}, nil
}

func (d *faultPoolDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if d.poolRowErr != nil {
		return errRow{err: d.poolRowErr}
	}
	return d.Pool.QueryRow(ctx, sql, args...)
}

func (d *faultPoolDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if d.poolQryErr != nil {
		return nil, d.poolQryErr
	}
	return d.Pool.Query(ctx, sql, args...)
}

// orgAllowanceCount reads how many allowance rows an org holds.
func orgAllowanceCount(t *testing.T, pool *pgxpool.Pool, org string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM budget_allowances WHERE org_id = $1`, org).Scan(&n))
	return n
}

// TestR040_GrantDBError_PropagatesWithoutPartialState: every statement of
// the grant path propagates a DB outage as a wrapped internal error — never
// as a capacity verdict (deny) and never as silent success — and the
// transaction leaves no partial state; the retry on the recovered pool
// succeeds and reserves exactly the bound.
func TestR040_GrantDBError_PropagatesWithoutPartialState(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-r040-grantfault"

	cases := []struct {
		name   string
		marker string
		wrap   string
	}{
		{"advisory lock", "pg_advisory_xact_lock", "grant advisory lock"},
		{"wallet capacity read", "FROM org_credits WHERE org_id = $1 FOR UPDATE", "grant wallet read"},
		{"reserve update", "UPDATE org_credits SET", "grant reserve update"},
		{"allowance upsert", "INSERT INTO budget_allowances", "grant allowance upsert"},
		{"commit", txFaultCommit, "grant commit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setWallet(t, pool, org, 100_000, nil) // resets allowances + reserve
			db := &faultPoolDB{Pool: pool, txFault: &txFault{Marker: tc.marker, Err: errors.New("injected outage")}}
			store := NewReservationStoreWithConfig(db, nil, ReservationConfig{})

			_, err := store.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 500_000}})
			require.Error(t, err, "the outage must surface")
			assert.Contains(t, err.Error(), tc.wrap)
			assert.NotErrorIs(t, err, ErrInsufficientCapacity, "an outage is not a capacity denial")
			assert.NotErrorIs(t, err, ErrNoCapacitySource, "an outage is not the missing-source denial")
			assert.NotErrorIs(t, err, ErrInvalidRequest)

			// No partial state survived the rollback.
			assert.EqualValues(t, 0, walletState(t, pool, org), "reserve untouched")
			assert.Zero(t, orgAllowanceCount(t, pool, org), "no allowance row half-created")

			// Recovery: the same grant on the healthy pool succeeds and
			// reserves exactly the bound (the retry is applicable).
			ok := NewReservationStore(pool, nil)
			_, err = ok.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 500_000}})
			require.NoError(t, err)
			assert.EqualValues(t, 500_000, walletState(t, pool, org))
		})
	}
}

// TestR040_GrantDBError_MultiScopeIsAtomic: a fault on the SECOND scope's
// reserve update rolls the whole grant back — the first scope's wallet
// reserve stays untouched (a multi-scope request is admitted as a whole or
// not at all; partial/unknown is never success).
func TestR040_GrantDBError_MultiScopeIsAtomic(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-r040-multifault"
	team := seedTeamBudget(t, pool, 200)
	period := time.Now().UTC().Format("2006-01")
	setWallet(t, pool, org, 100_000, nil)

	db := &faultPoolDB{Pool: pool, txFault: &txFault{Marker: "UPDATE team_spend_monthly SET", Err: errors.New("injected outage")}}
	store := NewReservationStoreWithConfig(db, nil, ReservationConfig{})

	_, err := store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 1_000_000},
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 2_000_000},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "grant reserve update")

	assert.EqualValues(t, 0, walletState(t, pool, org), "wallet scope rolled back with the refused team scope")
	// The team's period row was created inside the rolled-back transaction
	// too — an absent row reserves nothing.
	var teamReserved int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT reserved_micro_usd FROM team_spend_monthly
		                  WHERE team_id = $1::uuid AND period = $2), 0)`,
		team, period).Scan(&teamReserved))
	assert.EqualValues(t, 0, teamReserved)
	assert.Zero(t, orgAllowanceCount(t, pool, org))
}

// TestR040_ProbeDBError_IsUnknownNotAVerdict: the read-only probe propagates
// a DB outage explicitly (wrapped error) and never degrades it to the
// missing-source verdict — unknown capacity is not "no setting".
func TestR040_ProbeDBError_IsUnknownNotAVerdict(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-r040-probefault"
	setWallet(t, pool, org, 100_000, nil)

	db := &faultPoolDB{Pool: pool, poolRowErr: errors.New("injected probe outage")}
	store := NewReservationStoreWithConfig(db, nil, ReservationConfig{})

	_, err := store.ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeWallet, Key: org, Bound: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "probe wallet read")
	assert.NotErrorIs(t, err, ErrNoCapacitySource, "an outage is unknown, not fail-closed-missing")

	free, err := NewReservationStore(pool, nil).ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeWallet, Key: org, Bound: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 1_001_000_000, free, "recovery: $1000 balance + $1 platform-default floor")
}

// TestR040_ReturnAndSettleDBError_NoPartialRelease: faults inside the
// return and settle paths leave the escrow exactly as it was (no partial
// release) and the retry after recovery applies — operation repeat works.
func TestR040_ReturnAndSettleDBError_NoPartialRelease(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-r040-retfault"
	setWallet(t, pool, org, 100_000, nil)

	clean := NewReservationStore(pool, nil)
	g, err := clean.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 1_000_000}})
	require.NoError(t, err)
	require.EqualValues(t, 1_000_000, walletState(t, pool, org))

	// Return faults on its allowance update: nothing is released.
	faultStore := NewReservationStoreWithConfig(
		&faultPoolDB{Pool: pool, txFault: &txFault{Marker: "returned_micro_usd = returned_micro_usd + $2", Err: errors.New("injected outage")}},
		nil, ReservationConfig{})
	err = faultStore.Return(ctx, org, testReplica, []ReturnRequest{{Scope: ScopeWallet, Key: org, Amount: 1_000_000}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "return allowance update")
	assert.EqualValues(t, 1_000_000, walletState(t, pool, org), "no partial return")
	_, granted, returned, status, _ := allowanceRow(t, pool, testReplica, ScopeWallet, org, "")
	assert.EqualValues(t, 1_000_000, granted)
	assert.EqualValues(t, 0, returned)
	assert.Equal(t, AllowanceActive, status)

	// Retry on the recovered store applies in full.
	require.NoError(t, clean.Return(ctx, org, testReplica, []ReturnRequest{{Scope: ScopeWallet, Key: org, Amount: 1_000_000}}))
	assert.EqualValues(t, 0, walletState(t, pool, org))

	// Settle faults on its scope decrement: the reserve does not move.
	_, err = clean.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 700_000}})
	require.NoError(t, err)
	settleFault := NewReservationStoreWithConfig(
		&faultPoolDB{Pool: pool, txFault: &txFault{Marker: "reserved_micro_usd = reserved_micro_usd - $2", Err: errors.New("injected outage")}},
		nil, ReservationConfig{})
	_, err = settleFault.SettleDecrement(ctx, org, g[0].AllowanceID, 300_000, 700_000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserve decrement")
	assert.EqualValues(t, 700_000, walletState(t, pool, org), "no partial settle")

	res, err := clean.SettleDecrement(ctx, org, g[0].AllowanceID, 300_000, 700_000)
	require.NoError(t, err)
	assert.True(t, res.Applied)
	assert.EqualValues(t, 300_000, res.Amount)
	assert.EqualValues(t, 400_000, walletState(t, pool, org))
}

// TestR040_ReconcileDBError_NoReleaseAndRecovery: a fault while scanning
// reconcile candidates fails the pass explicitly (zero summary, reserve
// kept — the fail-safe freeze direction); the recovered pass releases.
func TestR040_ReconcileDBError_NoReleaseAndRecovery(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-r040-recfault"
	setWallet(t, pool, org, 100_000, nil)

	clean := NewReservationStore(pool, nil)
	g, err := clean.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 1_000_000}})
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - interval '3 hours' WHERE id = $1`, g[0].AllowanceID)
	require.NoError(t, err)

	faultStore := NewReservationStoreWithConfig(
		&faultPoolDB{Pool: pool, poolQryErr: errors.New("injected scan outage")}, nil, ReservationConfig{})
	summary, err := faultStore.ReconcileRelease(ctx, ReservationSafetyWindow)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reconcile candidates")
	assert.EqualValues(t, 0, summary.Released)
	assert.EqualValues(t, 1_000_000, walletState(t, pool, org), "capacity stays frozen (safe direction)")

	summary, err = clean.ReconcileRelease(ctx, ReservationSafetyWindow)
	require.NoError(t, err)
	assert.EqualValues(t, 1, summary.Released)
	assert.EqualValues(t, 0, walletState(t, pool, org))
}

// --- D2 decrease edges -------------------------------------------------------

// TestR040_DecreaseExactlyAtSpendPlusReserved: the exactly-at boundary of
// D2. A limit decreased to EXACTLY spend+reserved (free = 0) denies every
// positive bound but still admits costless (zero-bound) work with a zero
// increment; a limit leaving free exactly equal to the bound admits once,
// reserving to the limit exactly, then denies.
func TestR040_DecreaseExactlyAtSpendPlusReserved(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	team := seedTeamBudget(t, pool, 200)
	period := time.Now().UTC().Format("2006-01")
	store := newReservationStore(pool)
	org := "org-r040-exact"

	setTeamSpend(t, pool, team, period, 120_000_000)
	_, err := store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 30_000_000},
	})
	require.NoError(t, err)

	// Decrease to exactly spend ($120) + reserved ($30): free = 0.
	_, err = pool.Exec(ctx, `UPDATE team_budgets SET monthly_limit_usd = 150 WHERE team_id = $1::uuid`, team)
	require.NoError(t, err)

	free, err := store.ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 0, free, "exactly-at: free is exactly zero, not negative")

	_, err = store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 1},
	})
	require.ErrorIs(t, err, ErrInsufficientCapacity, "any positive bound is denied at free = 0")

	_, err = store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 0},
	})
	require.NoError(t, err, "costless work still admitted at exactly-at")
	assert.EqualValues(t, 30_000_000, scopeReserve(t, pool, ScopeTeamMonth, team, period), "zero increment reserved")

	// Free exactly equal to the bound: admitted once, to the limit exactly.
	_, err = pool.Exec(ctx, `UPDATE team_budgets SET monthly_limit_usd = 151 WHERE team_id = $1::uuid`, team)
	require.NoError(t, err)
	_, err = store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 1_000_000},
	})
	require.NoError(t, err)
	assert.EqualValues(t, 31_000_000, scopeReserve(t, pool, ScopeTeamMonth, team, period),
		"spend+reserved now equals the limit exactly")
	free, err = store.ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 0, free)
	_, err = store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 1},
	})
	require.ErrorIs(t, err, ErrInsufficientCapacity)
}

// TestR040_DecreaseBelowReservedAlone_ReturnRecovers: a limit decreased
// below the reserved amount ALONE (spend still zero) makes free negative —
// deny-next with the escrow untouched (no clamp, no drain) — and the
// capacity recovers as soon as the replica returns its escrow.
func TestR040_DecreaseBelowReservedAlone_ReturnRecovers(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	team := seedTeamBudget(t, pool, 200)
	period := time.Now().UTC().Format("2006-01")
	store := newReservationStore(pool)
	org := "org-r040-belowres"

	_, err := store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 120_000_000},
	})
	require.NoError(t, err)

	// Decrease below the reserved amount alone: free = 100 − 0 − 120.
	_, err = pool.Exec(ctx, `UPDATE team_budgets SET monthly_limit_usd = 100 WHERE team_id = $1::uuid`, team)
	require.NoError(t, err)

	free, err := store.ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 1})
	require.NoError(t, err)
	assert.EqualValues(t, -20_000_000, free)

	_, err = store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 1},
	})
	require.ErrorIs(t, err, ErrInsufficientCapacity, "deny-next below-reserved")
	assert.EqualValues(t, 120_000_000, scopeReserve(t, pool, ScopeTeamMonth, team, period),
		"the live escrow is neither clamped nor drained")

	// Recovery: the replica returns its escrow (idle return path).
	require.NoError(t, store.Return(ctx, org, testReplica, []ReturnRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Amount: 120_000_000},
	}))
	assert.EqualValues(t, 0, scopeReserve(t, pool, ScopeTeamMonth, team, period))

	free, err = store.ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 100_000_000, free, "capacity restored under the new limit")

	_, err = store.Grant(ctx, testReplica, org, []GrantRequest{
		{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 90_000_000},
	})
	require.NoError(t, err, "admissions resume within the new limit")
	assert.EqualValues(t, 90_000_000, scopeReserve(t, pool, ScopeTeamMonth, team, period))
}

// TestR040_ConcurrentLimitDecrease_CapacityPredicateDefends: the money-layer
// sibling of the CAS rollback race. A limit decrease committing BETWEEN the
// grant's capacity read and its reserve write cannot over-admit: the
// applyReserve WHERE predicate re-reads the limit inside the UPDATE, so the
// grant refuses (deny-next) instead of reserving beyond the new operator
// limit. Deterministic two-session interleave on real Postgres.
func TestR040_ConcurrentLimitDecrease_CapacityPredicateDefends(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org, team := seedOrgTeam(t, pool, "r040-race")
	period := time.Now().UTC().Format("2006-01")
	_, err := pool.Exec(ctx,
		`INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit) VALUES ($1::uuid, 200, true)`, team)
	require.NoError(t, err)
	setTeamSpend(t, pool, team, period, 100_000_000)
	store := newReservationStore(pool)

	// The grant's transaction: advisory lock, capacity read (limit 200 →
	// free = $100), holding only the period-row lock from here on.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, org)
	require.NoError(t, err)

	req := GrantRequest{Scope: ScopeTeamMonth, Key: team, Period: period, Bound: 30_000_000}
	free, unlimited, err := store.scopeFreeCapacity(ctx, tx, org, req)
	require.NoError(t, err)
	require.False(t, unlimited)
	require.EqualValues(t, 100_000_000, free, "capacity read still sees the old limit")

	// The concurrent operator decrease commits in this window (a different
	// table: not blocked by the grant's period-row lock).
	_, err = pool.Exec(ctx, `UPDATE team_budgets SET monthly_limit_usd = 110 WHERE team_id = $1::uuid`, team)
	require.NoError(t, err)

	// Δ was sized against the stale free (30M fits: 100−0−30 ≥ 0)…
	delta, err := grantDelta(int64(free), int64(req.Bound), 0, 0, false, store.cfg)
	require.NoError(t, err)
	require.EqualValues(t, 30_000_000, delta)

	// …but the SQL capacity predicate re-reads the NEW limit:
	// reserved(0) + 30M ≤ 110M − 100M is false → 0 rows → refusal.
	err = store.applyReserve(ctx, tx, org, req, delta, free, unlimited)
	require.ErrorIs(t, err, ErrInsufficientCapacity,
		"the predicate closes the read-then-write race against the concurrent decrease")

	require.NoError(t, tx.Rollback(ctx))
	assert.EqualValues(t, 0, scopeReserve(t, pool, ScopeTeamMonth, team, period), "nothing reserved past the new limit")
}

// --- escrow-expiry boundaries -------------------------------------------------

// TestR040_EscrowExpirySafetyWindowBoundary: the reconcile release edge is
// strict — a lease lapsed but still INSIDE the safety window keeps the money
// frozen (renewal may still save the allowance); one lapsed past the window
// releases it. This boundary is what eventually ends a D2 deny-next.
func TestR040_EscrowExpirySafetyWindowBoundary(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-r040-window"
	setWallet(t, pool, org, 100_000, nil)
	store := newReservationStore(pool)

	g, err := store.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 5_000_000}})
	require.NoError(t, err)
	require.EqualValues(t, 5_000_000, walletState(t, pool, org))

	// Young lease: not a candidate at all.
	summary, err := store.ReconcileRelease(ctx, 2*time.Hour)
	require.NoError(t, err)
	assert.EqualValues(t, 0, summary.Released)
	assert.EqualValues(t, 5_000_000, walletState(t, pool, org))

	// Lapsed 90m: INSIDE the 2h window — still frozen (strict <).
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - interval '90 minutes' WHERE id = $1`, g[0].AllowanceID)
	require.NoError(t, err)
	summary, err = store.ReconcileRelease(ctx, 2*time.Hour)
	require.NoError(t, err)
	assert.EqualValues(t, 0, summary.Released, "inside the safety window the escrow stays frozen")
	assert.EqualValues(t, 5_000_000, walletState(t, pool, org))

	// Lapsed 3h: past the window — released, money returned.
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - interval '3 hours' WHERE id = $1`, g[0].AllowanceID)
	require.NoError(t, err)
	summary, err = store.ReconcileRelease(ctx, 2*time.Hour)
	require.NoError(t, err)
	assert.EqualValues(t, 1, summary.Released)
	assert.EqualValues(t, 1, summary.ExpiredSafetyReleased, "money was still frozen past the window")
	assert.EqualValues(t, 0, walletState(t, pool, org))
}

// TestR040_FloorShrinkDenyNext_EndedByEscrowExpiry: the wallet-floor face of
// D2 is not permanent — after the tightened floor denies new admissions, the
// normal escrow lifecycle (lease expiry past the safety window + reconcile)
// returns the reserve and admissions resume within the new capacity.
func TestR040_FloorShrinkDenyNext_EndedByEscrowExpiry(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-r040-shrinkexp"
	store := newReservationStore(pool)

	// $10 balance, −$50 floor → free $60; a $50 escrow goes live.
	floor := int64(-5000)
	setWallet(t, pool, org, 1000, &floor)
	_, err := store.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 50_000_000}})
	require.NoError(t, err)
	require.EqualValues(t, 50_000_000, walletState(t, pool, org))

	// D2: tighten the floor to 0 — allowed, deny-next (free = −$40).
	_, err = pool.Exec(ctx, `UPDATE org_credits SET grace_floor_cents = 0 WHERE org_id = $1`, org)
	require.NoError(t, err)
	_, err = store.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 1}})
	require.ErrorIs(t, err, ErrInsufficientCapacity)

	// The replica stops renewing (crash/idle): lease lapses past the window.
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - interval '3 hours' WHERE org_id = $1`, org)
	require.NoError(t, err)
	summary, err := store.ReconcileRelease(ctx, ReservationSafetyWindow)
	require.NoError(t, err)
	assert.EqualValues(t, 1, summary.Released)
	assert.EqualValues(t, 0, walletState(t, pool, org), "the escrow returned to the wallet")

	// Admissions resume within the new capacity: free = $10.
	free, err := store.ProbeFreeCapacity(ctx, org, GrantRequest{Scope: ScopeWallet, Key: org, Bound: 1})
	require.NoError(t, err)
	assert.EqualValues(t, 10_000_000, free)
	_, err = store.Grant(ctx, testReplica, org, []GrantRequest{{Scope: ScopeWallet, Key: org, Bound: 9_000_000}})
	require.NoError(t, err)
	assert.EqualValues(t, 9_000_000, walletState(t, pool, org))
}
