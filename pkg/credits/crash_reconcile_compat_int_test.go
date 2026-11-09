//go:build integration

// Crash-reconciliation compatibility for the credits wallet (real-PG
// pattern, ADR-0001 §10). The wallet row (org_credits) is both the
// capacity source of the wallet scope and the ledger of confirmed spend,
// so recovery convergence — one ledger, no eternal reservations — is
// pinned here against the real supported consumers: the credits ledger
// store that charges the wallet and the reservation store that grants and
// returns its escrow. The old wallet configuration (platform-default grace
// floor, NULL grace_floor_cents) and the new one (per-org explicit floor)
// must converge identically.
//
// Exactly-once is pinned on final STATE, never on "this verdict won the
// race": the targeted lost-replica verdict and the periodic sweep are two
// callers of the same release mechanics and may close a lapsed row in
// either order (a sweep is a global pass, so summary counters can also
// include foreign rows on a shared stand; wallet-scope assertions here are
// per-org and replica-scoped and therefore immune to that noise).
//
// Shared-stand discipline: one Postgres container and one process-global
// metrics registry per test binary. Every identifier carries a per-run
// token, cleanup removes exactly the seeded rows, and the production
// wallet columns are restored additively before seeding because other
// tests in this package may have dropped the tables into a legacy shape
// under -shuffle.
package credits

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

const (
	// crcCrashLapse puts a lease well past the default safety window so
	// both the sweep and the unfenced verdict (floored to the same window)
	// qualify the row for release.
	crcCrashLapse = 3 * time.Hour
	// crcEscrowBound is the wallet-scope escrow bound of the crashed
	// replica: $3.00 of reserved µUSD.
	crcEscrowBound = money.MicroUSD(3_000_000)
	// crcSettledPart is the portion a real consumer already charged from
	// the escrow before the crash: $1.00, a whole-cent amount so the
	// ledger projection is exact.
	crcSettledPart = money.MicroUSD(1_000_000)
)

// crcCompatFixture owns one seeded org wallet plus its dependent rows for
// one test: token-scoped identifiers, defensive schema restoration and
// exact cleanup on the shared stand.
type crcCompatFixture struct {
	t     *testing.T
	pool  *pgxpool.Pool
	token string
	org   string
}

// crcNewCompatFixture restores the production wallet shape (base tables in
// the migrated layout plus the reservation columns), seeds one wallet and
// registers cleanup for every row the test can create. ctx is the
// test-lifetime context the caller already holds (Background in this
// file), so the registered cleanup may safely keep using it after the
// test body returns.
func crcNewCompatFixture(ctx context.Context, t *testing.T, pool *pgxpool.Pool, name string, balanceCents, remainder int64, floor *int64) *crcCompatFixture {
	t.Helper()
	token := fmt.Sprintf("crc%s%s%x", name, time.Now().Format("150405"), time.Now().UnixNano()%1e6)

	// Order-independence: store_test.go owns legacy table shapes and drops
	// the tables on teardown; under -shuffle this file can run before or
	// after any of that, so make sure the base tables and the reservation
	// columns exist exactly as the migrated schema defines them.
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS org_credits (
			org_id TEXT PRIMARY KEY,
			balance_cents BIGINT NOT NULL DEFAULT 0,
			remainder_micro_usd BIGINT NOT NULL DEFAULT 0 CHECK (remainder_micro_usd >= 0 AND remainder_micro_usd < 10000),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	require.NoError(t, err, "ensure the base org_credits table")
	_, err = pool.Exec(ctx, `
		ALTER TABLE org_credits
			ADD COLUMN IF NOT EXISTS reserved_micro_usd bigint NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0),
			ADD COLUMN IF NOT EXISTS grace_floor_cents bigint CHECK (grace_floor_cents BETWEEN -100000 AND 0)`)
	require.NoError(t, err, "restore the reservation wallet columns")
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS credit_transactions (
			id BIGSERIAL PRIMARY KEY,
			org_id TEXT NOT NULL,
			amount_cents BIGINT NOT NULL,
			balance_after BIGINT NOT NULL,
			type TEXT NOT NULL CHECK (type IN ('topup', 'usage')),
			request_id TEXT,
			invoice_ref TEXT,
			metadata JSONB DEFAULT '{}',
			amount_micro_usd BIGINT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	require.NoError(t, err, "ensure the base credit_transactions table")

	fx := &crcCompatFixture{t: t, pool: pool, token: token, org: token + "-org"}
	_, err = pool.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd, reserved_micro_usd, grace_floor_cents)
		VALUES ($1, $2, $3, 0, $4)`, fx.org, balanceCents, remainder, floor)
	require.NoError(t, err, "seed wallet %s", fx.org)

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("crash reconcile compat cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM settlement_jobs WHERE org_id = $1`, fx.org)
		cleanup(`DELETE FROM budget_allowances WHERE org_id = $1`, fx.org)
		cleanup(`DELETE FROM credit_transactions WHERE org_id = $1`, fx.org)
		cleanup(`DELETE FROM org_credits WHERE org_id = $1`, fx.org)
	})
	return fx
}

// crcWallet reads the raw wallet row: balance cents, sub-cent remainder,
// frozen reserve and the explicit floor (nil = platform default).
func crcWallet(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) (balanceCents, remainder, reserved int64, floor *int64) {
	t.Helper()
	err := pool.QueryRow(ctx, `
		SELECT balance_cents, remainder_micro_usd, reserved_micro_usd, grace_floor_cents
		FROM org_credits WHERE org_id = $1`, org).
		Scan(&balanceCents, &remainder, &reserved, &floor)
	require.NoError(t, err, "read wallet %s", org)
	return balanceCents, remainder, reserved, floor
}

// crcAllowance reads the single escrow row of a replica: id, granted,
// returned and status.
func crcAllowance(ctx context.Context, t *testing.T, pool *pgxpool.Pool, replica string) (id, granted, returned int64, status string) {
	t.Helper()
	err := pool.QueryRow(ctx, `
		SELECT id, granted_micro_usd, returned_micro_usd, status
		FROM budget_allowances WHERE replica_id = $1`, replica).
		Scan(&id, &granted, &returned, &status)
	require.NoError(t, err, "read allowance of %s", replica)
	return id, granted, returned, status
}

// crcLedgerUsage returns the count and exact micro sum of the org's usage
// ledger rows — the confirmed-spend side of the single-ledger invariant.
func crcLedgerUsage(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) (rows int64, microSum int64) {
	t.Helper()
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(SUM(amount_micro_usd), 0)
		FROM credit_transactions WHERE org_id = $1 AND type = 'usage'`, org).
		Scan(&rows, &microSum)
	require.NoError(t, err, "read usage ledger of %s", org)
	return rows, microSum
}

// crcCrashReplica backdates every lease of a replica into the past — the
// crash shape: the owner is gone and nothing renews.
func crcCrashReplica(ctx context.Context, t *testing.T, pool *pgxpool.Pool, replica string, lapse time.Duration) {
	t.Helper()
	tag, err := pool.Exec(ctx, `
		UPDATE budget_allowances
		SET lease_until = now() - make_interval(secs => $2), updated_at = now()
		WHERE replica_id = $1`, replica, lapse.Seconds())
	require.NoError(t, err, "crash replica %s", replica)
	require.Equal(t, int64(1), tag.RowsAffected(), "replica %s must hold exactly one escrow row", replica)
}

// crcApplySettledUsage emulates the settlement consumer's two-sided write:
// the ledger side commits a whole-cent usage charge on the wallet, its
// ledger row and a settled job carrying the reserve-decrement payload key
// the reconcile remainder math sums; the reserve side applies the
// settle-decrement primitive against the same amount. Returns the reserve
// outcome for assertions about live escrows.
func crcApplySettledUsage(ctx context.Context, t *testing.T, pool *pgxpool.Pool, store *budget.ReservationStore, fx *crcCompatFixture, allowanceID int64, amount, bound money.MicroUSD, requestID string) budget.SettleResult {
	t.Helper()
	require.Zero(t, int64(amount)%int64(money.MicroPerCent),
		"fixture settles whole cents only; the sub-cent residue is the AF-05 path")
	cents := amount.Cents()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	var balanceAfter int64
	require.NoError(t, tx.QueryRow(ctx,
		`UPDATE org_credits SET balance_cents = balance_cents - $2, updated_at = now()
		 WHERE org_id = $1 RETURNING balance_cents`, fx.org, cents).Scan(&balanceAfter))
	_, err = tx.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id, amount_micro_usd)
		VALUES ($1, $2, $3, 'usage', $4, $5)`, fx.org, -cents, balanceAfter, requestID, -int64(amount))
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, amount_cents, status, amount_micro_usd, allowance_id, payload)
		VALUES ($1, $2, 'resale_deduction', $3, 'settled', $4, $5, jsonb_build_object($6::text, $4::bigint))`,
		fx.org, requestID, cents, int64(amount), allowanceID, budget.ReconcileSettleKey)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	settle, err := store.SettleDecrement(ctx, fx.org, allowanceID, amount, bound)
	require.NoError(t, err, "the reserve side of the settle applies")
	return settle
}

// crcGrantWalletEscrow grants the wallet-scope escrow of one replica and
// returns the allowance id. Rate and average bound stay zero so the grant
// degenerates to exactly the request bound.
func crcGrantWalletEscrow(ctx context.Context, t *testing.T, pool *pgxpool.Pool, store *budget.ReservationStore, replica, org string, bound money.MicroUSD) int64 {
	t.Helper()
	grants, err := store.Grant(ctx, replica, org, []budget.GrantRequest{
		{Scope: budget.ScopeWallet, Key: org, Bound: bound},
	})
	require.NoError(t, err, "grant wallet escrow for %s", replica)
	require.Len(t, grants, 1)
	require.Equal(t, bound, grants[0].Delta, "a zero-rate grant reserves exactly the bound")
	_, granted, returned, status := crcAllowance(ctx, t, pool, replica)
	require.Equal(t, int64(bound), granted)
	require.Zero(t, returned)
	require.Equal(t, budget.AllowanceActive, status)
	return grants[0].AllowanceID
}

// crcReleasedDelta sums the process-global released-allowance counter over
// both release reasons — whichever reconciler closes a row, exactly one
// reason is incremented exactly once.
func crcReleasedDelta(t *testing.T, before float64) float64 {
	t.Helper()
	expired := testutil.ToFloat64(metrics.BudgetAllowanceReleasedTotal.WithLabelValues(budget.ReleaseReasonExpiredSafety))
	orphan := testutil.ToFloat64(metrics.BudgetAllowanceReleasedTotal.WithLabelValues(budget.ReleaseReasonCrashOrphan))
	return expired + orphan - before
}

// TestCrashReconcileWalletCompat_FloorConfigurationsConverges walks the
// old and the new wallet configuration through the same crash: a replica
// crashes holding wallet escrow of which a real consumer already settled a
// part. Recovery must converge both configurations to one ledger — the
// settled part stays the only confirmed spend, the remainder returns to
// the reserve exactly once, the reserve drains to zero (no eternal
// reservations) — and the credits consumer keeps its semantics after
// recovery: idempotent deduction and explicit refusal of a charge that
// would cross the configured floor.
func TestCrashReconcileWalletCompat_FloorConfigurationsConverges(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		// floor is the wallet's grace_floor_cents column (nil = legacy
		// platform-default configuration).
		floor *int64
		// refuseCents is a whole-cent charge that would push the wallet
		// below this configuration's floor and must be refused explicitly.
		refuseCents int64
	}{
		{
			name:        "platform_default_floor",
			floor:       nil,
			refuseCents: 5100, // 4975 − 5100 = −125 ≤ default floor −100
		},
		{
			name:        "explicit_org_floor",
			floor:       int64Ptr(-500),
			refuseCents: 5550, // 4975 − 5550 = −575 ≤ floor −500
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := crcNewCompatFixture(ctx, t, pool, "floor", 5000, 1234, tc.floor)
			replica := fx.token + "-replica-crashed"

			// The stores under test: the credits ledger store on the same
			// grace configuration and the reservation store with the
			// matching platform default (an explicit org column wins over
			// it inside the SQL COALESCE).
			creditsStore := NewStoreWithConfig(pool, nil, Config{GracePeriodCents: -100, CacheTTL: time.Millisecond})
			reservations := budget.NewReservationStoreWithConfig(pool, nil, budget.ReservationConfig{DefaultGraceFloorCents: -100})

			allowanceID := crcGrantWalletEscrow(ctx, t, pool, reservations, replica, fx.org, crcEscrowBound)
			_, _, reservedBefore, _ := crcWallet(ctx, t, pool, fx.org)
			require.Equal(t, int64(crcEscrowBound), reservedBefore, "the grant freezes the escrow on the wallet")

			// A real consumer charges $1.00 of the escrow before the crash:
			// confirmed spend on the wallet ledger plus the settled job and
			// reserve decrement the reconcile remainder math reads.
			crcApplySettledUsage(ctx, t, pool, reservations, fx, allowanceID, crcSettledPart, crcEscrowBound, fx.token+"-req-settled")
			balanceAfterSettle, remainderAfterSettle, reservedAfterSettle, _ := crcWallet(ctx, t, pool, fx.org)
			require.Equal(t, int64(4900), balanceAfterSettle)
			require.Equal(t, int64(crcEscrowBound-crcSettledPart), reservedAfterSettle)

			// The replica crashes; a periodic sweep recovers the lapsed row.
			crcCrashReplica(ctx, t, pool, replica, crcCrashLapse)
			sweep, err := reservations.ReconcileRelease(ctx, budget.ReservationSafetyWindow)
			require.NoError(t, err)
			require.GreaterOrEqual(t, sweep.Released, int64(1), "the lapsed escrow is a release candidate")

			// Converged state, per row and per org — the same in both
			// configurations:
			id, granted, returned, status := crcAllowance(ctx, t, pool, replica)
			require.Equal(t, budget.AllowanceReleased, status)
			require.Equal(t, int64(crcEscrowBound), granted)
			require.Equal(t, int64(crcEscrowBound-crcSettledPart), returned,
				"the remainder returns exactly once: granted minus what was already settled")
			balance, remainder, reserved, _ := crcWallet(ctx, t, pool, fx.org)
			require.Zero(t, reserved, "no eternal reservations: the reserve drains to zero")
			require.Equal(t, balanceAfterSettle, balance, "a release returns to the reserve pool, never to the balance")
			require.Equal(t, remainderAfterSettle, remainder)
			ledgerRows, ledgerMicro := crcLedgerUsage(ctx, t, pool, fx.org)
			require.Equal(t, int64(1), ledgerRows, "recovery writes no ledger rows: the settled charge stays the only spend")
			require.Equal(t, -int64(crcSettledPart), ledgerMicro)
			require.Equal(t, int64(crcEscrowBound), returned+int64(crcSettledPart),
				"one ledger: returned plus settled accounts for the whole escrow")
			require.Equal(t, int64(id), allowanceID, "the row identity never changes during recovery")

			// A second sweep and an explicit verdict on the already-released
			// replica are pure no-ops: money moves never, the losing side is
			// reported as exactly-once classified.
			_, err = reservations.ReconcileRelease(ctx, budget.ReservationSafetyWindow)
			require.NoError(t, err)
			verdict, err := reservations.CloseAbandonedReplica(ctx, replica, 0)
			require.NoError(t, err)
			require.Zero(t, verdict.Closed)
			require.Zero(t, verdict.ReturnedMicroUSD)
			require.Zero(t, verdict.SkippedLive)
			require.Equal(t, int64(1), verdict.AlreadyReleased,
				"the released row is classified, never re-closed")
			_, _, returnedAfter, statusAfter := crcAllowance(ctx, t, pool, replica)
			require.Equal(t, budget.AllowanceReleased, statusAfter)
			require.Equal(t, returned, returnedAfter)
			_, _, reservedAfterNoOp, _ := crcWallet(ctx, t, pool, fx.org)
			require.Zero(t, reservedAfterNoOp)

			// Consumer compatibility after recovery: admission works again
			// on the unfrozen capacity, a deduction applies exactly once and
			// its replay is a no-op.
			_, err = creditsStore.CheckBalance(ctx, fx.org)
			require.NoError(t, err, "the wallet admits again after the escrow returned")
			deduct := money.MicroUSD(250_000) // $0.25
			require.NoError(t, creditsStore.DeductMicro(ctx, fx.org, deduct, fx.token+"-req-after", nil))
			require.NoError(t, creditsStore.DeductMicro(ctx, fx.org, deduct, fx.token+"-req-after", nil),
				"replaying the same request id must stay a no-op")
			balance, _, reserved, _ = crcWallet(ctx, t, pool, fx.org)
			require.Equal(t, int64(4900-25), balance, "exactly one deduction applied")
			require.Zero(t, reserved, "a plain deduction never freezes reserve")

			// Explicit refusal: a charge crossing this configuration's floor
			// is rejected, recovery must not have relaxed the admission
			// semantics.
			err = creditsStore.DeductMicro(ctx, fx.org, money.MicroUSD(tc.refuseCents*int64(money.MicroPerCent)), fx.token+"-req-refused", nil)
			require.ErrorIs(t, err, ErrInsufficientCredits,
				"a charge below the %s floor must be refused", tc.name)
		})
	}
}

// TestCrashReconcileWalletCompat_TwoReconcilersExactlyOnce is the double-
// reconciler negative scenario: the lost-replica verdict and the periodic
// sweep race over the same lapsed escrow, then a late settlement from the
// crashed replica arrives. The money must move exactly once — the reserve
// drains by the remainder exactly once, the ledger stays the settled part
// only, the late settle cannot decrement the released row again — and
// neither reconciler may fail.
func TestCrashReconcileWalletCompat_TwoReconcilersExactlyOnce(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	fx := crcNewCompatFixture(ctx, t, pool, "tworec", 5000, 0, nil)
	replica := fx.token + "-replica-lost"
	reservations := budget.NewReservationStore(pool, nil)

	allowanceID := crcGrantWalletEscrow(ctx, t, pool, reservations, replica, fx.org, crcEscrowBound)
	crcApplySettledUsage(ctx, t, pool, reservations, fx, allowanceID, crcSettledPart, crcEscrowBound, fx.token+"-req-settled")
	crcCrashReplica(ctx, t, pool, replica, crcCrashLapse)
	releasedBefore := crcReleasedCounter(t)

	// Two reconcilers start together and race for the same row.
	type reconcileOutcome struct {
		name    string
		closed  int64
		returns int64
		err     error
	}
	start := make(chan struct{})
	outcomes := make(chan reconcileOutcome, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		summary, err := reservations.CloseAbandonedReplica(ctx, replica, 0)
		out := reconcileOutcome{name: "verdict", err: err}
		if err == nil {
			out.closed, out.returns = summary.Closed, summary.ReturnedMicroUSD
		}
		outcomes <- out
	}()
	go func() {
		defer wg.Done()
		<-start
		summary, err := reservations.ReconcileRelease(ctx, budget.ReservationSafetyWindow)
		out := reconcileOutcome{name: "sweep", err: err}
		if err == nil {
			out.closed, out.returns = summary.Released, summary.ReturnedMicroUSD
		}
		outcomes <- out
	}()
	close(start)
	wg.Wait()
	close(outcomes)

	// Neither reconciler may fail: the loser of the race observes the
	// released row and classifies it instead of double-returning.
	verdictClosed := int64(0)
	sweepClosed := int64(0)
	returnedTotal := int64(0)
	for out := range outcomes {
		require.NoError(t, out.err, "%s reconciler must converge without error", out.name)
		returnedTotal += out.returns
		switch out.name {
		case "verdict":
			verdictClosed = out.closed
		case "sweep":
			sweepClosed = out.closed
		}
	}
	// The row is lapsed, so exactly one reconciler closes it and the other
	// classifies the release. The release counter moves iff the verdict was
	// the winner (the periodic sweep path keeps no per-row metric) — never
	// by both reconcilers.
	require.Equal(t, int64(1), verdictClosed+sweepClosed,
		"exactly one reconciler closes the lapsed row")
	require.InDelta(t, float64(verdictClosed), crcReleasedDelta(t, releasedBefore), 0,
		"the row's money moved under exactly one release reason, exactly once")

	// Exactly-once final state, independent of who won: the remainder
	// returned once, the reserve drained exactly to zero, the ledger still
	// carries only the settled charge, and the reported returns never
	// exceed the real remainder.
	id, granted, returned, status := crcAllowance(ctx, t, pool, replica)
	require.Equal(t, budget.AllowanceReleased, status)
	require.Equal(t, int64(crcEscrowBound), granted)
	require.Equal(t, int64(crcEscrowBound-crcSettledPart), returned,
		"the escrow remainder is returned exactly once across both reconcilers")
	require.LessOrEqual(t, returnedTotal, int64(crcEscrowBound-crcSettledPart),
		"no reconciler reports more returned money than exists")
	_, _, reserved, _ := crcWallet(ctx, t, pool, fx.org)
	require.Zero(t, reserved, "no eternal reservations after both reconcilers settle")
	_, grantedCheck, returnedCheck, _ := crcAllowance(ctx, t, pool, replica)
	require.Equal(t, granted, grantedCheck)
	require.Equal(t, returned, returnedCheck)
	require.Equal(t, int64(id), allowanceID)
	ledgerRows, ledgerMicro := crcLedgerUsage(ctx, t, pool, fx.org)
	require.Equal(t, int64(1), ledgerRows, "reconciliation writes no ledger rows")
	require.Equal(t, -int64(crcSettledPart), ledgerMicro)

	// A follow-up pass pair converges as a no-op: everything already
	// terminal, nothing new released, no double reason counted.
	_, err := reservations.ReconcileRelease(ctx, budget.ReservationSafetyWindow)
	require.NoError(t, err)
	verdict, err := reservations.CloseAbandonedReplica(ctx, replica, 0)
	require.NoError(t, err)
	require.Zero(t, verdict.Closed)
	require.Equal(t, int64(1), verdict.AlreadyReleased)
	require.InDelta(t, float64(verdictClosed), crcReleasedDelta(t, releasedBefore), 0,
		"the follow-up passes release nothing")

	// The late settlement of the crashed replica arrives after release:
	// ledger-only, the reserve is never decremented twice for the same
	// escrow.
	late, err := reservations.SettleDecrement(ctx, fx.org, allowanceID, 500_000, crcEscrowBound)
	require.NoError(t, err)
	require.False(t, late.Applied, "a late settle against a released escrow is ledger-only")
	require.Zero(t, late.Amount)
	_, _, reservedAfterLate, _ := crcWallet(ctx, t, pool, fx.org)
	require.Zero(t, reservedAfterLate, "the late settle must not touch the drained reserve")
	_, _, returnedAfterLate, _ := crcAllowance(ctx, t, pool, replica)
	require.Equal(t, returned, returnedAfterLate, "the late settle must not mutate the released row")

	// The confirmed-spend consumer stays exactly-once after the race: one
	// deduction, replay no-op.
	creditsStore := NewStore(pool, nil)
	require.NoError(t, creditsStore.DeductMicro(ctx, fx.org, 100_000, fx.token+"-req-final", nil))
	require.NoError(t, creditsStore.DeductMicro(ctx, fx.org, 100_000, fx.token+"-req-final", nil))
	rows, micro := crcLedgerUsage(ctx, t, pool, fx.org)
	require.Equal(t, int64(2), rows, "the settled charge plus exactly one post-recovery deduction")
	require.Equal(t, -(int64(crcSettledPart) + 100_000), micro)
}

// TestCrashReconcileWalletCompat_LiveReserveUntouched is the live-reserve
// negative scenario: two replicas share one org wallet, one crashes while
// the other is alive and renewing. No combination of reconcilers — verdict
// on the dead replica, global sweep, even a wrong verdict aimed at the
// live replica — may release the live reserve. Full convergence to a
// single drained reserve happens only once the live replica stops
// renewing too.
func TestCrashReconcileWalletCompat_LiveReserveUntouched(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	fx := crcNewCompatFixture(ctx, t, pool, "live", 5000, 0, nil)
	deadReplica := fx.token + "-replica-dead"
	liveReplica := fx.token + "-replica-live"
	reservations := budget.NewReservationStore(pool, nil)

	const (
		deadBound = money.MicroUSD(2_500_000)
		liveBound = money.MicroUSD(1_500_000)
		liveSpent = money.MicroUSD(300_000) // the live consumer settles part of its escrow
	)

	crcGrantWalletEscrow(ctx, t, pool, reservations, deadReplica, fx.org, deadBound)
	liveID := crcGrantWalletEscrow(ctx, t, pool, reservations, liveReplica, fx.org, liveBound)
	crcApplySettledUsage(ctx, t, pool, reservations, fx, liveID, liveSpent, liveBound, fx.token+"-req-live-settled")
	_, _, reservedFresh, _ := crcWallet(ctx, t, pool, fx.org)
	require.Equal(t, int64(deadBound+liveBound-liveSpent), reservedFresh,
		"both escrows minus the settled part are frozen on the shared wallet")

	// The dead replica's lease lapses while the live one keeps renewing.
	crcCrashReplica(ctx, t, pool, deadReplica, crcCrashLapse)
	releasedBefore := crcReleasedCounter(t)

	// Verdict on the dead replica and the global sweep race as before;
	// neither may touch the live sibling's money.
	type deadOutcome struct {
		name   string
		closed int64
		err    error
	}
	start := make(chan struct{})
	deadOutcomes := make(chan deadOutcome, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		summary, err := reservations.CloseAbandonedReplica(ctx, deadReplica, 0)
		out := deadOutcome{name: "verdict", err: err}
		if err == nil {
			out.closed = summary.Closed
		}
		deadOutcomes <- out
	}()
	go func() {
		defer wg.Done()
		<-start
		summary, err := reservations.ReconcileRelease(ctx, budget.ReservationSafetyWindow)
		out := deadOutcome{name: "sweep", err: err}
		if err == nil {
			out.closed = summary.Released
		}
		deadOutcomes <- out
	}()
	close(start)
	wg.Wait()
	close(deadOutcomes)
	deadVerdictClosed := int64(0)
	deadSweepClosed := int64(0)
	for out := range deadOutcomes {
		require.NoError(t, out.err, "%s reconciler must converge without error", out.name)
		switch out.name {
		case "verdict":
			deadVerdictClosed = out.closed
		case "sweep":
			deadSweepClosed = out.closed
		}
	}
	// Exactly one reconciler closes the lapsed dead escrow; the release
	// counter moves iff the verdict was the winner (the periodic sweep path
	// keeps no per-row metric). Either way the LIVE sibling's money never
	// moves — pinned by the row states below.
	require.Equal(t, int64(1), deadVerdictClosed+deadSweepClosed,
		"exactly one reconciler closes the dead escrow")
	require.InDelta(t, float64(deadVerdictClosed), crcReleasedDelta(t, releasedBefore), 0,
		"only the dead replica's row was released")

	_, deadGranted, deadReturned, deadStatus := crcAllowance(ctx, t, pool, deadReplica)
	require.Equal(t, budget.AllowanceReleased, deadStatus)
	require.Equal(t, int64(deadBound), deadGranted)
	require.Equal(t, int64(deadBound), deadReturned, "the dead escrow had no settled part: it returns whole")
	_, liveGranted, liveReturned, liveStatus := crcAllowance(ctx, t, pool, liveReplica)
	require.Equal(t, budget.AllowanceActive, liveStatus, "the live sibling's escrow stays active")
	require.Equal(t, int64(liveBound), liveGranted)
	require.Zero(t, liveReturned, "the live sibling's escrow is never returned by a dead-replica recovery")
	_, _, reserved, _ := crcWallet(ctx, t, pool, fx.org)
	require.Equal(t, int64(liveBound-liveSpent), reserved,
		"the live reserve stays frozen: recovery converges the dead escrow only")

	// A wrong verdict claims the LIVE replica is gone: the young,
	// renewing lease keeps every row of it frozen — the live-reserve
	// guard refuses the closure explicitly.
	liveVerdict, err := reservations.CloseAbandonedReplica(ctx, liveReplica, 0)
	require.NoError(t, err)
	require.Zero(t, liveVerdict.Closed, "a live reserve is never closed")
	require.Equal(t, int64(1), liveVerdict.SkippedLive)
	require.Zero(t, liveVerdict.AlreadyReleased)
	require.Zero(t, liveVerdict.ReturnedMicroUSD)
	_, _, _, liveStatusAfterVerdict := crcAllowance(ctx, t, pool, liveReplica)
	require.Equal(t, budget.AllowanceActive, liveStatusAfterVerdict)
	_, _, reservedAfterWrongVerdict, _ := crcWallet(ctx, t, pool, fx.org)
	require.Equal(t, int64(liveBound-liveSpent), reservedAfterWrongVerdict,
		"the wrong verdict must not free the live reserve")

	// The live consumer keeps working while its escrow is frozen: a second
	// settled charge applies on both sides — the ledger and the reserve.
	liveSettle := crcApplySettledUsage(ctx, t, pool, reservations, fx, liveID, liveSpent, liveBound, fx.token+"-req-live-settled-2")
	require.True(t, liveSettle.Applied, "a settle against a live escrow applies")
	require.Equal(t, liveSpent, liveSettle.Amount)
	_, _, reservedAfterSettle, _ := crcWallet(ctx, t, pool, fx.org)
	require.Equal(t, int64(liveBound-2*liveSpent), reservedAfterSettle)

	// Only when the live replica stops renewing does its escrow become
	// recoverable — then convergence completes with no eternal
	// reservations and the previously settled part stays accounted for.
	crcCrashReplica(ctx, t, pool, liveReplica, crcCrashLapse)
	liveVerdict2, err := reservations.CloseAbandonedReplica(ctx, liveReplica, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), liveVerdict2.Closed)
	require.Equal(t, int64(liveBound-2*liveSpent), liveVerdict2.ReturnedMicroUSD,
		"the closure returns the remainder exactly once: escrow minus both settles")
	_, _, _, liveStatusFinal := crcAllowance(ctx, t, pool, liveReplica)
	require.Equal(t, budget.AllowanceReleased, liveStatusFinal)
	_, _, reservedFinal, _ := crcWallet(ctx, t, pool, fx.org)
	require.Zero(t, reservedFinal, "one ledger, no eternal reservations")
	_, liveGrantedFinal, liveReturnedFinal, _ := crcAllowance(ctx, t, pool, liveReplica)
	require.Equal(t, int64(liveBound), liveGrantedFinal)
	require.Equal(t, int64(liveBound-2*liveSpent), liveReturnedFinal,
		"returned plus both settled parts accounts for the whole live escrow")
	ledgerRowsFinal, ledgerMicroFinal := crcLedgerUsage(ctx, t, pool, fx.org)
	require.Equal(t, int64(2), ledgerRowsFinal,
		"the ledger stays the two settled charges the fixture wrote; neither releases nor the reserve-side settle writes ledger rows")
	require.Equal(t, -int64(2*liveSpent), ledgerMicroFinal)
}

// crcReleasedCounter reads the global released-allowance counter summed
// over both release reasons.
func crcReleasedCounter(t *testing.T) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.BudgetAllowanceReleasedTotal.WithLabelValues(budget.ReleaseReasonExpiredSafety)) +
		testutil.ToFloat64(metrics.BudgetAllowanceReleasedTotal.WithLabelValues(budget.ReleaseReasonCrashOrphan))
}

// int64Ptr is a small helper for the configuration table.
func int64Ptr(v int64) *int64 { return &v }
