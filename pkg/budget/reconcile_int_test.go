//go:build integration

// NEXT-18e acceptance tests on a disposable live Postgres (ADR-0001 §10,
// heavy runs under the machine semaphore): the reconcile worker releases
// expired-past-safety-window escrow without touching active allowances,
// releases zero-remainder draining rows immediately, detects §7.1.3/§7.1.4
// invariant divergence, keeps the §7.1.5 retention bounded and feeds the
// §5.4 settlement-lag gauge.
package budget

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cleanupReservationState removes every trace of a test org: settlement
// jobs, allowances and the wallet row (the shared container must stay
// consistent for the invariant tests of the next run).
func cleanupReservationState(t *testing.T, pool *pgxpool.Pool, orgs ...string) {
	t.Helper()
	ctx := context.Background()
	for _, org := range orgs {
		_, _ = pool.Exec(ctx, `DELETE FROM settlement_jobs WHERE org_id = $1`, org)
		_, _ = pool.Exec(ctx, `DELETE FROM budget_allowances WHERE org_id = $1`, org)
		_, _ = pool.Exec(ctx, `DELETE FROM org_credits WHERE org_id = $1`, org)
	}
}

// releasedCounter reads the reason-labelled release counter (testutil
// creates the child on first read; deltas are what the tests assert).
func releasedCounter(t *testing.T, reason string) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.BudgetAllowanceReleasedTotal.WithLabelValues(reason))
}

// TestNext18eLive_ReconcileWorkerReleasesExpiredNotActive: a §7.1 tick
// releases an allowance whose lease lapsed past the safety window (remainder
// = granted − settled decrement returns to the wallet, reason
// expired_safety_window) and leaves a young active allowance untouched.
func TestNext18eLive_ReconcileWorkerReleasesExpiredNotActive(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-18e-release-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 1_000_000, nil) // $10 000
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	// Dead replica: lease lapsed 3h ago (window is 2h), 200k already
	// settled against it by the worker.
	gone, err := store.Grant(ctx, "18e-dead-replica", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 1_000_000},
	})
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, allowance_id, payload, status)
		VALUES ($1, $2, 'wallet', $3, $4::jsonb, 'settled')`,
		org, "req-18e-release-"+uuid.NewString(), gone[0].AllowanceID,
		`{"settle_decrement_micro_usd": 200000}`)
	require.NoError(t, err)
	// The settle-decrement payload documents what the settlement worker
	// removed from the scope reserve (§5.3 Settle step 2); replicate that
	// side effect so the fixture is invariant-consistent before the tick.
	_, err = pool.Exec(ctx,
		`UPDATE org_credits SET reserved_micro_usd = reserved_micro_usd - 200000 WHERE org_id = $1`,
		org)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET status = 'expired', lease_until = now() - interval '3 hours' WHERE id = $1`,
		gone[0].AllowanceID)
	require.NoError(t, err)

	// Live replica: active, young lease — reconcile must not touch it.
	_, err = store.Grant(ctx, "18e-live-replica", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 500_000},
	})
	require.NoError(t, err)

	require.Equal(t, int64(1_300_000), walletState(t, pool, org),
		"1.5M granted − 200k settled by the worker")
	before := releasedCounter(t, ReleaseReasonExpiredSafety)

	w := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	w.Tick(ctx)

	assert.InDelta(t, before+1, releasedCounter(t, ReleaseReasonExpiredSafety), 0.001,
		"expired_safety_window release is counted")
	require.Equal(t, int64(500_000), walletState(t, pool, org),
		"1.3M − 800k remainder released")

	_, granted, returned, status, _ := allowanceRow(t, pool, "18e-dead-replica", ScopeWallet, org, "")
	assert.Equal(t, AllowanceReleased, status)
	assert.Equal(t, int64(1_000_000), granted)
	assert.Equal(t, int64(800_000), returned, "remainder = granted − settled(200k)")

	_, _, _, status, _ = allowanceRow(t, pool, "18e-live-replica", ScopeWallet, org, "")
	assert.Equal(t, AllowanceActive, status, "active allowance is untouched")
	_, _, _, _, lease := allowanceRow(t, pool, "18e-live-replica", ScopeWallet, org, "")
	assert.True(t, time.Until(lease) > 9*time.Minute, "live lease intact")
}

// TestNext18eLive_ZeroRemainderDrainingReleasedImmediately (§7.1.2): a
// draining allowance with nothing left to return is released on the first
// tick even though its lease is young.
func TestNext18eLive_ZeroRemainderDrainingReleasedImmediately(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-18e-drain-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 100_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	_, err := store.Grant(ctx, "18e-drain-replica", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 300_000},
	})
	require.NoError(t, err)
	n, err := store.MarkDraining(ctx, "18e-drain-replica")
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	sum, err := store.ReturnRemaining(ctx, org, "18e-drain-replica", []RemainingRequest{
		{Scope: ScopeWallet, Key: org, Holdback: 0},
	})
	require.NoError(t, err)
	require.Equal(t, int64(300_000), sum.ReturnedMicroUSD, "drained out: remainder zero")
	require.Zero(t, walletState(t, pool, org))

	before := releasedCounter(t, ReleaseReasonZeroRemainder)
	w := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	w.Tick(ctx)

	assert.InDelta(t, before+1, releasedCounter(t, ReleaseReasonZeroRemainder), 0.001)
	_, _, _, status, _ := allowanceRow(t, pool, "18e-drain-replica", ScopeWallet, org, "")
	assert.Equal(t, AllowanceReleased, status, "zero remainder releases without waiting for the window")
	require.Zero(t, walletState(t, pool, org), "no double return")
}

// TestNext18eLive_ScopeInvariantDivergenceDetector (§7.1.3): a grant keeps
// the container's baseline divergence unchanged (my scope row is exact);
// manually drifted reserved money is caught (the detector) and restoring
// the value returns the divergence to the baseline. The container may carry
// fixture leftovers from other cards' tests, so every assertion is
// baseline-relative — the detector itself is org-exact by construction
// (per-row match, not per-kind totals).
func TestNext18eLive_ScopeInvariantDivergenceDetector(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-18e-div-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 1_000_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	w := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	base, err := w.CheckInvariants(ctx)
	require.NoError(t, err)
	baseDiv := base.DivergencePerScope[ScopeWallet]
	baseRes := base.ReservedPerScope[ScopeWallet]

	_, err = store.Grant(ctx, "18e-div-replica", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 400_000},
	})
	require.NoError(t, err)

	report, err := w.CheckInvariants(ctx)
	require.NoError(t, err)
	assert.Equal(t, baseDiv, report.DivergencePerScope[ScopeWallet],
		"granted=reserved=400k, no settled jobs → invariant holds exactly")
	assert.Equal(t, baseRes+400_000, report.ReservedPerScope[ScopeWallet])
	require.NoError(t, w.checkInvariants(ctx))
	assert.InDelta(t, float64(report.DivergencePerScope[ScopeWallet]),
		testutil.ToFloat64(metrics.BudgetReservedDivergenceMicroUSD.WithLabelValues("wallet")), 0.001)

	// Drift: +250µ reserved that no allowance explains (the exact shape a
	// double-decrement or manual tampering would produce).
	_, err = pool.Exec(ctx, `UPDATE org_credits SET reserved_micro_usd = reserved_micro_usd + 250 WHERE org_id = $1`, org)
	require.NoError(t, err)

	report, err = w.CheckInvariants(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, report.DivergencePerScope[ScopeWallet], baseDiv+250,
		"detector must catch the drift")
	require.NoError(t, w.checkInvariants(ctx))
	assert.InDelta(t, float64(report.DivergencePerScope[ScopeWallet]),
		testutil.ToFloat64(metrics.BudgetReservedDivergenceMicroUSD.WithLabelValues("wallet")), 0.001)

	// Restore: the alarm clears back to the container baseline.
	_, err = pool.Exec(ctx, `UPDATE org_credits SET reserved_micro_usd = reserved_micro_usd - 250 WHERE org_id = $1`, org)
	require.NoError(t, err)
	report, err = w.CheckInvariants(ctx)
	require.NoError(t, err)
	assert.Equal(t, baseDiv, report.DivergencePerScope[ScopeWallet], "restored state is consistent again")
}

// TestNext18eLive_WalletInvariantViolation (§7.1.4): an org whose balance
// dropped below floor + reserved is reported; the violating org is named in
// the report (log carries identifiers, metrics do not).
func TestNext18eLive_WalletInvariantViolation(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-18e-wallet-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 1, nil) // $0.01, global floor −$1
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	_, err := store.Grant(ctx, "18e-wallet-replica", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 15_000}, // $0.15 reserved
	})
	require.NoError(t, err)

	cfg := DefaultReconcileConfig()
	cfg.ViolationLogLimit = 5000 // cover every violating org on a shared container
	w := NewReconcileWorker(pool, newBudgetTestLogger(), cfg)
	report, err := w.CheckInvariants(ctx)
	require.NoError(t, err)
	assert.NotContains(t, report.WalletViolatingOrgs, org,
		"headroom = 0.01 + 1(grace) − 0.15 > 0 — no violation yet")

	// Balance sinks below floor + reserved → §7.1.4 LHS negative.
	_, err = pool.Exec(ctx, `UPDATE org_credits SET balance_cents = -200 WHERE org_id = $1`, org)
	require.NoError(t, err)

	report, err = w.CheckInvariants(ctx)
	require.NoError(t, err)
	assert.Contains(t, report.WalletViolatingOrgs, org)
	assert.Less(t, report.WalletHeadroomMin, int64(0))
	require.NoError(t, w.checkInvariants(ctx))
	assert.GreaterOrEqual(t, testutil.ToFloat64(metrics.BudgetWalletInvariantViolations), float64(1))
}

// TestNext18eLive_RetentionBounded (§7.1.5): only 'released' rows past the
// window go, in bounded batches — expired rows and fresh releases stay.
func TestNext18eLive_RetentionBounded(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-18e-retention"
	replica := "18e-retention-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM budget_allowances WHERE org_id = $1 OR replica_id = $2`, org, replica)
	})

	insert := func(status string, age string) {
		t.Helper()
		_, err := pool.Exec(ctx, `
			INSERT INTO budget_allowances
				(replica_id, scope_kind, scope_key, period, org_id, granted_micro_usd, returned_micro_usd, status, lease_until, updated_at)
			VALUES ($1, 'wallet', $2, '', $3, 100, 100, $4, now(), now() - $5::interval)`,
			replica, org+"-"+uuid.NewString()[:8], org, status, age)
		require.NoError(t, err)
	}
	for i := 0; i < 5; i++ { // oldest rows in the table → first out
		insert(AllowanceReleased, "400 days")
	}
	insert(AllowanceReleased, "1 second") // fresh release survives
	insert(AllowanceExpired, "400 days")  // live reconcile input survives

	countStatus := func(status string) int {
		t.Helper()
		var n int
		err := pool.QueryRow(ctx,
			`SELECT count(*) FROM budget_allowances WHERE replica_id = $1 AND status = $2`, replica, status).
			Scan(&n)
		require.NoError(t, err)
		return n
	}
	countOldReleased := func() int {
		t.Helper()
		var n int
		err := pool.QueryRow(ctx,
			`SELECT count(*) FROM budget_allowances WHERE replica_id = $1 AND status = $2 AND updated_at < now() - interval '1 hour'`,
			replica, AllowanceReleased).Scan(&n)
		require.NoError(t, err)
		return n
	}
	require.Equal(t, 5, countOldReleased(), "5 past-window rows seeded")

	w := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	w.cfg.ReleasedRetention = 24 * time.Hour
	w.cfg.RetentionBatch = 2
	w.cfg.RetentionPasses = 2 // 2 × 2 = 4 rows max per pass

	deleted, err := w.RetentionPass(ctx)
	require.NoError(t, err)
	assert.LessOrEqual(t, deleted, int64(4), "bounded by passes × batch")
	assert.Equal(t, 1, countOldReleased(),
		"exactly one 400d released row remains after the bounded pass (4 of 5 oldest-first)")
	assert.Equal(t, 1, countStatus(AllowanceReleased)-1,
		"the fresh release survives the pass")
	assert.Equal(t, 1, countStatus(AllowanceExpired), "expired rows are reconcile input, never retention output")

	// A second pass drains the rest of the window (the fresh row stays).
	deleted, err = w.RetentionPass(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
	assert.Zero(t, countOldReleased())
	assert.Equal(t, 1, countStatus(AllowanceReleased), "only the fresh release remains")
}

// TestNext18eLive_SettlementLagGauge (§5.4): the gauge ages the oldest
// unsettled job — the alert threshold (30 min) lives in the runbook.
func TestNext18eLive_SettlementLagGauge(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "org-18e-lag-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM settlement_jobs WHERE org_id = $1`, org)
	})
	_, err := pool.Exec(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, status, created_at)
		VALUES ($1, $2, 'wallet', 'pending', now() - interval '2 hours')`,
		org, "req-18e-lag-"+uuid.NewString())
	require.NoError(t, err)

	w := NewReconcileWorker(pool, newBudgetTestLogger(), DefaultReconcileConfig())
	require.NoError(t, w.checkSettlementLag(ctx))
	lag := testutil.ToFloat64(metrics.SettlementLagSeconds)
	assert.GreaterOrEqual(t, lag, float64(time.Hour/time.Second),
		"oldest unsettled job is ≥ 2h old (my fixture); the gauge must show it")
	assert.LessOrEqual(t, lag, float64(6*time.Hour/time.Second),
		"and not claim more than the fixture horizon allows")
}

// TestNext18eLive_TickerReleasesOverTime: Run() performs an immediate pass
// (a fresh deployment reconciles without waiting an interval) and stops on
// context cancel.
func TestNext18eLive_TickerReleasesOverTime(t *testing.T) {
	pool := testdb.Postgres(t)
	store := newReservationStore(pool)
	ctx := context.Background()
	org := "org-18e-run-" + uuid.NewString()[:8]
	setWallet(t, pool, org, 100_000, nil)
	t.Cleanup(func() { cleanupReservationState(t, pool, org) })

	g, err := store.Grant(ctx, "18e-run-replica", org, []GrantRequest{
		{Scope: ScopeWallet, Key: org, Bound: 50_000},
	})
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET status = 'expired', lease_until = now() - interval '3 hours' WHERE id = $1`,
		g[0].AllowanceID)
	require.NoError(t, err)

	w := NewReconcileWorker(pool, newBudgetTestLogger(), ReconcileConfig{Interval: 50 * time.Millisecond})
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- w.Run(runCtx) }()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if walletState(t, pool, org) == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.Zero(t, walletState(t, pool, org), "immediate first pass released the lapsed escrow")

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}
