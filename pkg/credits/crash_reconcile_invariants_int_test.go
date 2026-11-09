//go:build integration

// Independent invariant verification for the credits wallet crash
// reconciliation (real-PG pattern, ADR-0001 §10). The compatibility suite
// pins consumer behavior; this file verifies the invariants underneath it
// from four independent angles:
//
//   - rights: the whole recovery path — grant, two-sided settle, crash
//     backdating, sweep, verdict, deduction — runs unchanged on a
//     production-shaped pool whose every connection is downgraded to the
//     non-owner yabanin_app role, and the database CHECK constraints
//     backstop the money invariants even against that role's raw DML
//     rights;
//   - resource limits: the wallet-scope grant capacity is an exact edge —
//     balance minus sub-cent remainder plus the grace-floor overdraft
//     headroom — where the exact-fit grant succeeds and one micro-USD more
//     is refused without touching the frozen reserve;
//   - data: the reconcile remainder math tolerates settlement_jobs rows
//     with non-object payloads (legacy/malformed writes contribute zero,
//     never invent or destroy money);
//   - negative scenarios: a settle naming a foreign organization fails
//     loudly (reserved-underflow) and moves nothing, negative settle
//     amounts clamp to a no-op, unknown allowances and unknown or empty
//     replica verdicts are explicit refusals.
//
// Shared-stand discipline mirrors crash_reconcile_compat_int_test.go: one
// Postgres container per test binary, per-run token identifiers, cleanup
// removes exactly the seeded rows, and the fixture restores the production
// wallet shape before seeding because other tests in this package may have
// dropped the tables into a legacy shape under -shuffle.
package credits

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

const (
	// criEscrow is the wallet-scope escrow bound used across the
	// invariant scenarios: $3.00 of reserved µUSD.
	criEscrow = money.MicroUSD(3_000_000)
	// criSettled is the settled part of the escrow: $0.50, a whole-cent
	// amount so the ledger projection is exact.
	criSettled = money.MicroUSD(500_000)
)

// criExpectCheckViolation asserts that the statement fails with a
// check_constraint_violation (SQLSTATE 23514) — a database-enforced
// invariant, not an application-side guard.
func criExpectCheckViolation(ctx context.Context, t *testing.T, pool *pgxpool.Pool, q string, args ...any) {
	t.Helper()
	_, err := pool.Exec(ctx, q, args...)
	require.Error(t, err, "statement must be refused: %s", q)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "refusal must be a Postgres error")
	require.Equal(t, "23514", pgErr.Code, "refusal must be a check constraint, got %s", pgErr.Code)
}

// TestCrashReconcileInvariants_AppRoleRunsFullRecovery walks the whole
// recovery path on a production-shaped pool: every connection of the app
// pool is downgraded to the non-owner yabanin_app role (the role regional
// pools run under in production), so the converging recovery proves the
// surface needs no owner rights anywhere — grants, settles, crash
// backdating, the periodic sweep, the abandoned-replica verdict and the
// post-recovery credits consumer are all plain DML. Convergence assertions
// mirror the compatibility suite: one ledger, the remainder returned
// exactly once, the reserve drained, replay-idempotent deduction and the
// explicit refusal below the configured floor.
func TestCrashReconcileInvariants_AppRoleRunsFullRecovery(t *testing.T) {
	owner := testdb.Postgres(t)
	app := testdb.PostgresApp(t, "test")
	ctx := context.Background()

	var role string
	require.NoError(t, app.QueryRow(ctx, `SELECT current_user`).Scan(&role))
	require.Equal(t, "yabanin_app", role, "the app pool must run as the non-owner role")

	fx := crcNewCompatFixture(ctx, t, owner, "approle", 5000, 1234, int64Ptr(-500))
	replica := fx.token + "-replica-lost"

	creditsStore := NewStoreWithConfig(app, nil, Config{GracePeriodCents: -100, CacheTTL: time.Millisecond})
	reservations := budget.NewReservationStoreWithConfig(app, nil, budget.ReservationConfig{DefaultGraceFloorCents: -100})

	allowanceID := crcGrantWalletEscrow(ctx, t, app, reservations, replica, fx.org, criEscrow)
	crcApplySettledUsage(ctx, t, app, reservations, fx, allowanceID, criSettled, criEscrow, fx.token+"-req-settled")
	_, _, reservedAfterSettle, _ := crcWallet(ctx, t, app, fx.org)
	require.Equal(t, int64(criEscrow-criSettled), reservedAfterSettle)

	crcCrashReplica(ctx, t, app, replica, crcCrashLapse)
	sweep, err := reservations.ReconcileRelease(ctx, budget.ReservationSafetyWindow)
	require.NoError(t, err)
	require.GreaterOrEqual(t, sweep.Released, int64(1), "the lapsed escrow is a release candidate")

	id, granted, returned, status := crcAllowance(ctx, t, app, replica)
	require.Equal(t, budget.AllowanceReleased, status)
	require.Equal(t, int64(criEscrow), granted)
	require.Equal(t, int64(criEscrow-criSettled), returned, "the remainder returns exactly once")
	_, _, reserved, _ := crcWallet(ctx, t, app, fx.org)
	require.Zero(t, reserved, "no eternal reservations")
	ledgerRows, ledgerMicro := crcLedgerUsage(ctx, t, app, fx.org)
	require.Equal(t, int64(1), ledgerRows, "recovery writes no ledger rows")
	require.Equal(t, -int64(criSettled), ledgerMicro)
	require.Equal(t, int64(id), allowanceID, "the row identity never changes during recovery")

	verdict, err := reservations.CloseAbandonedReplica(ctx, replica, 0)
	require.NoError(t, err)
	require.Zero(t, verdict.Closed)
	require.Equal(t, int64(1), verdict.AlreadyReleased, "the released row is classified, never re-closed")

	deduct := money.MicroUSD(250_000) // $0.25
	_, err = creditsStore.CheckBalance(ctx, fx.org)
	require.NoError(t, err, "the wallet admits again after the escrow returned")
	require.NoError(t, creditsStore.DeductMicro(ctx, fx.org, deduct, fx.token+"-req-after", nil))
	require.NoError(t, creditsStore.DeductMicro(ctx, fx.org, deduct, fx.token+"-req-after", nil),
		"replaying the same request id must stay a no-op")
	balance, _, reservedAfterDeduct, _ := crcWallet(ctx, t, app, fx.org)
	require.Equal(t, int64(5000-50-25), balance,
		"exactly one deduction applied on top of the settled charge (5000 − 50 − 25)")
	require.Zero(t, reservedAfterDeduct)

	err = creditsStore.DeductMicro(ctx, fx.org, money.MicroUSD(5500*int64(money.MicroPerCent)), fx.token+"-req-refused", nil)
	require.ErrorIs(t, err, ErrInsufficientCredits,
		"a charge below the org floor must be refused: 4925 − 5500 = −575 ≤ −500")
}

// TestCrashReconcileInvariants_AppRoleCannotViolateDBInvariants proves the
// money invariants are database-enforced, not application-enforced: the
// app role holds broad DML grants, yet every raw write that would break a
// wallet or allowance invariant is refused by a CHECK constraint, while a
// lawful write through the same role passes.
func TestCrashReconcileInvariants_AppRoleCannotViolateDBInvariants(t *testing.T) {
	owner := testdb.Postgres(t)
	app := testdb.PostgresApp(t, "test")
	ctx := context.Background()

	fx := crcNewCompatFixture(ctx, t, owner, "backstop", 5000, 1234, int64Ptr(-500))

	// Control: the same role can write lawfully.
	_, err := app.Exec(ctx, `UPDATE org_credits SET balance_cents = balance_cents WHERE org_id = $1`, fx.org)
	require.NoError(t, err, "the app role can execute lawful wallet DML")

	criExpectCheckViolation(ctx, t, app,
		`UPDATE org_credits SET reserved_micro_usd = -1 WHERE org_id = $1`, fx.org)
	criExpectCheckViolation(ctx, t, app,
		`UPDATE org_credits SET remainder_micro_usd = 20000 WHERE org_id = $1`, fx.org)
	criExpectCheckViolation(ctx, t, app,
		`UPDATE org_credits SET grace_floor_cents = -200000 WHERE org_id = $1`, fx.org)
	criExpectCheckViolation(ctx, t, app,
		`INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, period, org_id, granted_micro_usd, returned_micro_usd, status, lease_until)
		 VALUES ($1, 'wallet', $2, '', $2, -1, 0, 'active', now())`, fx.token+"-probe-granted", fx.org)
	criExpectCheckViolation(ctx, t, app,
		`INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, period, org_id, granted_micro_usd, returned_micro_usd, status, lease_until)
		 VALUES ($1, 'wallet', $2, '', $2, 0, -1, 'active', now())`, fx.token+"-probe-returned", fx.org)
	criExpectCheckViolation(ctx, t, app,
		`INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, period, org_id, granted_micro_usd, returned_micro_usd, status, lease_until)
		 VALUES ($1, 'wallet', $2, '', $2, 0, 0, 'deleted', now())`, fx.token+"-probe-status", fx.org)
	criExpectCheckViolation(ctx, t, app,
		`INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type) VALUES ($1, -1, 0, 'refund')`, fx.org)

	_, _, reserved, _ := crcWallet(ctx, t, app, fx.org)
	require.Zero(t, reserved, "no refused probe left a partial write behind")
}

// TestCrashReconcileInvariants_GrantCapacityEdgeIncludesFloorAndRemainder
// pins the wallet grant capacity as an exact micro-USD edge: reserved may
// grow up to balance minus the sub-cent remainder plus the grace-floor
// overdraft headroom — under the old configuration (NULL floor column,
// platform default) and the new one (explicit org floor) alike. The
// exact-fit escrow freezes, one micro-USD more is refused with the reserve
// untouched, and recovery of the crashed exact-fit escrow returns exactly
// the capacity back, draining the reserve to zero.
func TestCrashReconcileInvariants_GrantCapacityEdgeIncludesFloorAndRemainder(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		// floor is the wallet's grace_floor_cents column (nil = legacy
		// platform-default configuration, resolved by the store config).
		floor *int64
		// defaultFloorCents is the store's platform default.
		defaultFloorCents int64
		// capacityMicro = 5000c*10000 − 1234 remainder − floor*10000.
		capacityMicro int64
	}{
		{
			name:              "platform_default_floor",
			floor:             nil,
			defaultFloorCents: -100,
			capacityMicro:     50_000_000 - 1234 + 1_000_000,
		},
		{
			name:              "explicit_org_floor",
			floor:             int64Ptr(-250),
			defaultFloorCents: -100,
			capacityMicro:     50_000_000 - 1234 + 2_500_000,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := crcNewCompatFixture(ctx, t, pool, "capedge", 5000, 1234, tc.floor)
			reservations := budget.NewReservationStoreWithConfig(pool, nil,
				budget.ReservationConfig{DefaultGraceFloorCents: tc.defaultFloorCents})

			fitReplica := fx.token + "-replica-fits"
			fatReplica := fx.token + "-replica-over"
			capacity := money.MicroUSD(tc.capacityMicro)

			crcGrantWalletEscrow(ctx, t, pool, reservations, fitReplica, fx.org, capacity)
			_, _, reserved, _ := crcWallet(ctx, t, pool, fx.org)
			require.Equal(t, tc.capacityMicro, reserved, "the exact-fit escrow freezes completely")

			_, err := reservations.Grant(ctx, fatReplica, fx.org, []budget.GrantRequest{
				{Scope: budget.ScopeWallet, Key: fx.org, Bound: capacity + 1},
			})
			require.ErrorIs(t, err, budget.ErrInsufficientCapacity,
				"one micro-USD past the edge must be refused")
			_, _, reservedAfterRefusal, _ := crcWallet(ctx, t, pool, fx.org)
			require.Equal(t, tc.capacityMicro, reservedAfterRefusal,
				"a refused grant never touches the frozen reserve")
			var fatRows int64
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM budget_allowances WHERE replica_id = $1`, fatReplica).Scan(&fatRows))
			require.Zero(t, fatRows, "a refused grant creates no allowance row")

			crcCrashReplica(ctx, t, pool, fitReplica, crcCrashLapse)
			sweep, err := reservations.ReconcileRelease(ctx, budget.ReservationSafetyWindow)
			require.NoError(t, err)
			require.Equal(t, int64(1), sweep.Released)
			require.Equal(t, tc.capacityMicro, sweep.ReturnedMicroUSD,
				"the crashed exact-fit escrow returns exactly the capacity")
			_, grantedFinal, returnedFinal, status := crcAllowance(ctx, t, pool, fitReplica)
			require.Equal(t, budget.AllowanceReleased, status)
			require.Equal(t, tc.capacityMicro, grantedFinal)
			require.Equal(t, tc.capacityMicro, returnedFinal,
				"the escrow had no settled part: it returns whole")
			_, _, reservedAfterSweep, _ := crcWallet(ctx, t, pool, fx.org)
			require.Zero(t, reservedAfterSweep, "no eternal reservations")
		})
	}
}

// TestCrashReconcileInvariants_SettleGuardRefusalsAndDataTolerance
// verifies the settle-side guards and the remainder math's data tolerance
// on one lapsed escrow: a settle naming a foreign organization fails loudly
// and moves nothing on either wallet, a negative settle amount clamps to a
// no-op, an unknown allowance id is an explicit error, a verdict on an
// empty or unknown replica is an explicit refusal or a classified no-op,
// and a settlement job with a non-object payload (legacy or malformed
// write) contributes zero to the reconcile remainder — the recovery
// returns exactly the money that is really frozen, never more, never less.
func TestCrashReconcileInvariants_SettleGuardRefusalsAndDataTolerance(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	fx := crcNewCompatFixture(ctx, t, pool, "guards", 5000, 0, nil)
	foreign := crcNewCompatFixture(ctx, t, pool, "foreign", 5000, 0, nil)
	replica := fx.token + "-replica-tol"
	reservations := budget.NewReservationStore(pool, nil)

	allowanceID := crcGrantWalletEscrow(ctx, t, pool, reservations, replica, fx.org, criEscrow)

	// A settle naming the foreign organization cannot move money: the
	// reserve decrement targets the caller's wallet row, which holds no
	// matching reserve, so the drift surfaces as a reserved-underflow error
	// and both wallets keep their exact state.
	_, err := reservations.SettleDecrement(ctx, foreign.org, allowanceID, criSettled, criEscrow)
	require.ErrorIs(t, err, budget.ErrReservedUnderflow,
		"a cross-organization settle must fail loudly, never silently")
	_, _, reservedA, _ := crcWallet(ctx, t, pool, fx.org)
	require.Equal(t, int64(criEscrow), reservedA, "the escrow owner's reserve is untouched")
	_, _, reservedB, _ := crcWallet(ctx, t, pool, foreign.org)
	require.Zero(t, reservedB, "the foreign wallet is untouched")
	_, _, returnedAfterCross, statusAfterCross := crcAllowance(ctx, t, pool, replica)
	require.Zero(t, returnedAfterCross)
	require.Equal(t, budget.AllowanceActive, statusAfterCross)

	// A negative settle amount clamps to a documented no-op: applied with
	// zero amount, the reserve unchanged.
	negative, err := reservations.SettleDecrement(ctx, fx.org, allowanceID, money.MicroUSD(-1), criEscrow)
	require.NoError(t, err)
	require.True(t, negative.Applied)
	require.Zero(t, negative.Amount)
	_, _, reservedAfterNegative, _ := crcWallet(ctx, t, pool, fx.org)
	require.Equal(t, int64(criEscrow), reservedAfterNegative)

	// An unknown allowance id is an explicit error.
	_, err = reservations.SettleDecrement(ctx, fx.org, 999999999, criSettled, criEscrow)
	require.ErrorIs(t, err, budget.ErrAllowanceNotFound)

	// The real settle applies once, on both sides.
	crcApplySettledUsage(ctx, t, pool, reservations, fx, allowanceID, criSettled, criEscrow, fx.token+"-req-settled")
	_, _, reservedAfterSettle, _ := crcWallet(ctx, t, pool, fx.org)
	require.Equal(t, int64(criEscrow-criSettled), reservedAfterSettle)

	// A settlement job with a non-object payload claims 200k µUSD but can
	// never have been reserve-linked: the remainder math must treat it as
	// contributing zero, not as settled money.
	_, err = pool.Exec(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, amount_cents, status, amount_micro_usd, allowance_id, payload)
		VALUES ($1, $2, 'resale_deduction', 20, 'settled', 200000, $3, '[]'::jsonb)`,
		fx.org, fx.token+"-req-malformed", allowanceID)
	require.NoError(t, err, "the malformed legacy job seeds")

	// Verdict refusals on an empty and an unknown replica identity.
	_, err = reservations.CloseAbandonedReplica(ctx, "", 0)
	require.ErrorIs(t, err, budget.ErrInvalidRequest)
	ghostVerdict, err := reservations.CloseAbandonedReplica(ctx, fx.token+"-replica-never-existed", 0)
	require.NoError(t, err)
	require.Zero(t, ghostVerdict.Closed)
	require.Zero(t, ghostVerdict.SkippedLive)
	require.Zero(t, ghostVerdict.AlreadyReleased)
	require.Zero(t, ghostVerdict.ReturnedMicroUSD)

	// Recovery converges on the real frozen money only: the remainder is
	// granted minus the object-payload settle, the malformed claim changes
	// nothing, and the reserve drains exactly to zero.
	crcCrashReplica(ctx, t, pool, replica, crcCrashLapse)
	sweep, err := reservations.ReconcileRelease(ctx, budget.ReservationSafetyWindow)
	require.NoError(t, err)
	require.Equal(t, int64(1), sweep.Released)
	require.Equal(t, int64(criEscrow-criSettled), sweep.ReturnedMicroUSD,
		"the malformed payload contributes zero to the remainder math")
	_, grantedFinal, returnedFinal, statusFinal := crcAllowance(ctx, t, pool, replica)
	require.Equal(t, budget.AllowanceReleased, statusFinal)
	require.Equal(t, int64(criEscrow), grantedFinal)
	require.Equal(t, int64(criEscrow-criSettled), returnedFinal)
	require.Equal(t, int64(criEscrow), returnedFinal+int64(criSettled),
		"one ledger: returned plus the real settle accounts for the whole escrow")
	_, _, reservedFinal, _ := crcWallet(ctx, t, pool, fx.org)
	require.Zero(t, reservedFinal, "no eternal reservations")
	ledgerRows, ledgerMicro := crcLedgerUsage(ctx, t, pool, fx.org)
	require.Equal(t, int64(1), ledgerRows, "recovery and the reserve-side settle write no ledger rows")
	require.Equal(t, -int64(criSettled), ledgerMicro)
}
