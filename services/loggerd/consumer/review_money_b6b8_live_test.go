package consumer

// Rule-13 review regressions for findings B6 and B8 (review receipt
// admin-money-review-e8ecb74, source e8ecb74 = 7e58716 for these paths).
//
// Every expectation below is stated independently of the implementation:
// wallet balances and remainders, credit_transactions rows and settlement
// job status/attempts/last_error are read back with raw SQL. The tests
// pin the org-floor contract (an explicit org grace_floor_cents wins over
// the global grace period on EVERY settlement path — batch, singleton and
// fallback), the terminal-first-attempt classification of invocation
// identity conflicts, and the no-reexecution guarantee across a
// commit-response-loss window.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
)

const (
	// moneyReviewFloorZero is the explicit org-level grace floor the
	// counterexamples use; the global store floor stays at −100¢ so a path
	// that ignores the org column overdraws instead of parking.
	moneyReviewFloorZero = 0
	moneyReviewCent      = money.MicroUSD(10000) // 1¢ in µUSD
	moneyReviewGlobal    = -100                  // global grace floor for every store built here
)

// --- fixtures -----------------------------------------------------------

// moneyReviewOrg provisions a wallet with an explicit balance and grace
// floor (floorCents nil = SQL NULL so the global floor applies); a nil
// balance removes the wallet row entirely (the no-wallet state).
func moneyReviewOrg(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID string, balanceCents, floorCents *int64) {
	t.Helper()
	if balanceCents == nil {
		_, err := pool.Exec(ctx, `DELETE FROM org_credits WHERE org_id = $1`, orgID)
		require.NoError(t, err)
		return
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, grace_floor_cents)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id) DO UPDATE
			SET balance_cents = EXCLUDED.balance_cents,
				remainder_micro_usd = 0,
				grace_floor_cents = EXCLUDED.grace_floor_cents`,
		orgID, *balanceCents, floorCents)
	require.NoError(t, err)
}

// moneyReviewReset clears the money tables the shared live env does not.
func moneyReviewReset(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `TRUNCATE credit_transactions, org_credits`)
	require.NoError(t, err)
}

// moneyReviewSeedUsage inserts a durable usage ledger row the way a
// committed deduction leaves it (negative µUSD amount).
func moneyReviewSeedUsage(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, requestID, invocationID string, amountMicro int64) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO credit_transactions
			(org_id, amount_cents, balance_after, type, request_id, invocation_id, amount_micro_usd)
		VALUES ($1, $2, 0, 'usage', $3, NULLIF($4, ''), $5)`,
		orgID, money.MicroUSD(amountMicro).Cents(), requestID, invocationID, amountMicro)
	require.NoError(t, err)
}

// moneyReviewSeedJob inserts a pending resale intent with an optional
// invocation identity ("" = legacy NULL-invocation domain).
func moneyReviewSeedJob(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, requestID, invocationID string, amountMicro int64) int64 {
	t.Helper()
	payload, err := json.Marshal(resaleChargePayload{Model: "review-model", TokensIn: 1, TokensOut: 1})
	require.NoError(t, err)
	var id int64
	err = pool.QueryRow(ctx, `
		INSERT INTO settlement_jobs
			(org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload, invocation_id)
		VALUES ($1, $2, $3, $4, $5, 'pending', $6, NULLIF($7, ''))
		RETURNING id`,
		orgID, requestID, ChargeKindResaleDeduction, money.MicroUSD(amountMicro).Cents(), amountMicro, payload, invocationID).Scan(&id)
	require.NoError(t, err, "seed resale settlement job")
	return id
}

// --- independent state readers ------------------------------------------

func moneyReviewWallet(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID string) (balanceCents, remainderMicro int64, exists bool) {
	t.Helper()
	err := pool.QueryRow(ctx,
		`SELECT balance_cents, remainder_micro_usd FROM org_credits WHERE org_id = $1`, orgID).
		Scan(&balanceCents, &remainderMicro)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, false
	}
	require.NoError(t, err)
	return balanceCents, remainderMicro, true
}

// moneyReviewUsage returns the global durable usage-row count plus the
// exact amount list for orgID.
func moneyReviewUsage(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID string) (total int64, orgAmounts []int64) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM credit_transactions WHERE type = 'usage'`).Scan(&total))
	rows, err := pool.Query(ctx,
		`SELECT amount_micro_usd FROM credit_transactions
		 WHERE type = 'usage' AND org_id = $1 ORDER BY id`, orgID)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var amt *int64
		require.NoError(t, rows.Scan(&amt))
		if amt != nil {
			orgAmounts = append(orgAmounts, *amt)
		}
	}
	require.NoError(t, rows.Err())
	return total, orgAmounts
}

// --- worker / logger harness ---------------------------------------------

// moneyReviewLog captures slog records so the deduction-layer diagnostics
// are asserted directly (finding B6: the no-wallet branch must speak with
// its own voice, not the insufficient-balance one).
type moneyReviewLog struct {
	mu      sync.Mutex
	records []string
}

func (l *moneyReviewLog) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (l *moneyReviewLog) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, r.Message)
	return nil
}

func (l *moneyReviewLog) WithAttrs(_ []slog.Attr) slog.Handler { return l }

func (l *moneyReviewLog) WithGroup(_ string) slog.Handler { return l }

func (l *moneyReviewLog) messages() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.records))
	copy(out, l.records)
	return out
}

// moneyReviewWorker builds a SettlementWorker over db (default: the
// physical pool) with a store whose global grace floor is −100¢.
func moneyReviewWorker(t *testing.T, pool *pgxpool.Pool, log *moneyReviewLog, db ...SettlementDB) (*SettlementWorker, SettlementDB) {
	t.Helper()
	logger := slog.New(log)
	store := credits.NewStoreWithConfig(pool, logger, credits.Config{GracePeriodCents: moneyReviewGlobal})
	workerDB := SettlementDB(pool)
	if len(db) > 0 && db[0] != nil {
		workerDB = db[0]
	}
	return NewSettlementWorker(workerDB, store, nil, logger), workerDB
}

// --- failure-injection wrapper -------------------------------------------

// moneyReviewDB routes real statements to the physical pool but can fail
// named tx QueryRow statements once (pre-commit batch failures) and run a
// hook after a batch Commit actually landed before reporting an error
// (the commit-response-loss window: the commit IS durable, the caller
// observes failure).
type moneyReviewDB struct {
	inner        SettlementDB
	mu           sync.Mutex
	failQuerySub string // fail the next tx QueryRow whose query contains this
	commitHook   func() // run once after a successful inner Commit
	hookDone     bool
}

func (d *moneyReviewDB) armQueryFailure(sub string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failQuerySub = sub
}

func (d *moneyReviewDB) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.inner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &moneyReviewTx{inner: tx, parent: d}, nil
}

func (d *moneyReviewDB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return d.inner.Exec(ctx, query, args...)
}

func (d *moneyReviewDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return d.inner.QueryRow(ctx, query, args...)
}

func (d *moneyReviewDB) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return d.inner.Query(ctx, query, args...)
}

func (d *moneyReviewDB) takeQueryFailure(query string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failQuerySub != "" && strings.Contains(query, d.failQuerySub) {
		d.failQuerySub = ""
		return true
	}
	return false
}

func (d *moneyReviewDB) runCommitHook() {
	d.mu.Lock()
	hook, done := d.commitHook, d.hookDone
	d.hookDone = true
	d.mu.Unlock()
	if hook != nil && !done {
		hook()
	}
}

type moneyReviewTx struct {
	pgx.Tx // nil-embedded: only the exercised statements are intercepted
	inner  pgx.Tx
	parent *moneyReviewDB
}

func (t *moneyReviewTx) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	if t.parent.takeQueryFailure(query) {
		return moneyReviewErrRow{err: errors.New("moneyReviewDB: injected batch read failure")}
	}
	return t.inner.QueryRow(ctx, query, args...)
}

func (t *moneyReviewTx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return t.inner.Exec(ctx, query, args...)
}

func (t *moneyReviewTx) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return t.inner.Query(ctx, query, args...)
}

func (t *moneyReviewTx) Commit(ctx context.Context) error {
	err := t.inner.Commit(ctx)
	if err == nil && t.parent.commitHook != nil {
		// The commit IS durable; simulate the response-loss window, then
		// report failure to the caller.
		t.parent.runCommitHook()
		return errors.New("moneyReviewDB: injected commit response loss")
	}
	return err
}

func (t *moneyReviewTx) Rollback(ctx context.Context) error { return t.inner.Rollback(ctx) }

// moneyReviewErrRow is a pgx.Row that always fails.
type moneyReviewErrRow struct{ err error }

func (r moneyReviewErrRow) Scan(dest ...any) error { return r.err }

// batchWalletReadMarker matches the batch executor's wallet read (a bare
// SELECT with the org column, no CTE prefix), never the per-job deduction
// statement (which opens WITH wallet AS ...).
const batchWalletReadMarker = "grace_floor_cents FROM org_credits"

// Compile-time guard that the wrapper satisfies the worker's DB contract.
var _ SettlementDB = (*moneyReviewDB)(nil)

// --- B6: identity conflicts are terminal on the first attempt -----------

// The ledger already carries a usage row under this invocation for ANOTHER
// org (global invocation idempotency). The deduction path must park the
// job as requires_attention on the FIRST attempt with the conflicting
// invocation named, leaving both wallets and the ledger untouched — never
// burn the retry budget on a permanent integrity conflict.
func TestMoneyReview_B6_IdentityConflictDifferentOrgTerminalOnFirstAttempt(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	moneyReviewReset(t, ctx, pool)

	orgA, orgB := "b6-conflict-org-a", "b6-conflict-org-b"
	hundred := int64(100)
	floorZero := int64(moneyReviewFloorZero)
	moneyReviewOrg(t, ctx, pool, orgA, &hundred, &floorZero)
	moneyReviewOrg(t, ctx, pool, orgB, &hundred, &floorZero)

	const inv = "b6000000-0000-4000-8000-00000000b601"
	moneyReviewSeedUsage(t, ctx, pool, orgA, "b6-orga-req", inv, -int64(moneyReviewCent))

	job := moneyReviewSeedJob(t, ctx, pool, orgB, "b6-orgb-req", inv, int64(moneyReviewCent))

	reviewLog := &moneyReviewLog{}
	w, db := moneyReviewWorker(t, pool, reviewLog)
	drainSettlementQueue(ctx, t, w, db, orgB, ChargeKindResaleDeduction)

	status, attempts, lastErr := jobStatus(ctx, t, db, job)
	assert.Equal(t, "requires_attention", status, "an identity conflict is permanent: park, never settle")
	assert.Equal(t, 1, attempts, "the FIRST attempt must classify the conflict terminal (retry budget untouched)")
	assert.Contains(t, lastErr, "charge identity conflict", "the durable record must name the integrity conflict")

	balanceB, _, existsB := moneyReviewWallet(t, ctx, pool, orgB)
	require.True(t, existsB)
	assert.Equal(t, int64(100), balanceB, "org B wallet unchanged")
	balanceA, _, _ := moneyReviewWallet(t, ctx, pool, orgA)
	assert.Equal(t, int64(100), balanceA, "org A wallet unchanged")

	total, amountsB := moneyReviewUsage(t, ctx, pool, orgB)
	assert.Equal(t, int64(1), total, "the only usage row is the pre-existing org A one")
	assert.Empty(t, amountsB, "org B must gain no usage row")
}

// Same invocation id already charged with a different amount for the same
// org — the amount half of the identity contract. Same expectations:
// terminal on the first attempt, no money movement.
func TestMoneyReview_B6_IdentityConflictDifferentAmountTerminalOnFirstAttempt(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	moneyReviewReset(t, ctx, pool)

	org := "b6-conflict-org-amt"
	hundred := int64(100)
	floorZero := int64(moneyReviewFloorZero)
	moneyReviewOrg(t, ctx, pool, org, &hundred, &floorZero)

	const inv = "b6000000-0000-4000-8000-00000000b602"
	moneyReviewSeedUsage(t, ctx, pool, org, "b6-amt-req", inv, -int64(moneyReviewCent))

	job := moneyReviewSeedJob(t, ctx, pool, org, "b6-amt-req", inv, 2*int64(moneyReviewCent)) // 2¢ vs recorded 1¢

	reviewLog := &moneyReviewLog{}
	w, db := moneyReviewWorker(t, pool, reviewLog)
	drainSettlementQueue(ctx, t, w, db, org, ChargeKindResaleDeduction)

	status, attempts, lastErr := jobStatus(ctx, t, db, job)
	assert.Equal(t, "requires_attention", status)
	assert.Equal(t, 1, attempts, "a same-invocation amount mismatch is terminal on the first attempt")
	assert.Contains(t, lastErr, "charge identity conflict")

	balance, _, _ := moneyReviewWallet(t, ctx, pool, org)
	assert.Equal(t, int64(100), balance, "no money may move on an identity conflict")
	total, amounts := moneyReviewUsage(t, ctx, pool, org)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, []int64{-int64(moneyReviewCent)}, amounts, "the recorded 1¢ row is untouched")
}

// Missing wallet and floor rejection are different facts and must stay
// distinguishable end to end: the disposition counters, the deduction log
// voice and the job record. (a) no wallet → no_wallet; (b) wallet at 0¢
// with an org floor of 0 rejecting a 1¢ charge → insufficient_credits.
// The batch executor already distinguishes the pair; the singleton path
// must match it (B8 reason parity) and the deduction layer must not fold
// no-wallet into the insufficient-balance branch.
func TestMoneyReview_B6_NoWalletVsFloorRejectionDiagnostics(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	moneyReviewReset(t, ctx, pool)

	floorZero := int64(moneyReviewFloorZero)
	zero := int64(0)

	reviewLog := &moneyReviewLog{}
	w, db := moneyReviewWorker(t, pool, reviewLog)

	// (a) org with NO billing wallet row at all.
	orgNW := "b6-no-wallet-org"
	moneyReviewOrg(t, ctx, pool, orgNW, nil, nil)
	jobNW := moneyReviewSeedJob(t, ctx, pool, orgNW, "b6-nw-req", "", int64(moneyReviewCent))

	noWalletBefore := testutil.ToFloat64(metrics.CreditDeductionSkippedTotal.WithLabelValues("no_wallet"))
	insufficientBefore := testutil.ToFloat64(metrics.CreditDeductionSkippedTotal.WithLabelValues("insufficient"))
	drainSettlementQueue(ctx, t, w, db, orgNW, ChargeKindResaleDeduction)
	assert.Equal(t, noWalletBefore+1, testutil.ToFloat64(metrics.CreditDeductionSkippedTotal.WithLabelValues("no_wallet")),
		"a missing wallet must count as no_wallet, matching the batch disposition")
	assert.Equal(t, insufficientBefore, testutil.ToFloat64(metrics.CreditDeductionSkippedTotal.WithLabelValues("insufficient")),
		"no-wallet must not be counted as insufficient credits")

	status, _, lastErr := jobStatus(ctx, t, db, jobNW)
	assert.Equal(t, "requires_attention", status)
	assert.Contains(t, lastErr, "wallet", "the durable record must speak of the missing wallet")
	msgsNW := strings.Join(reviewLog.messages(), "\n")
	assert.Contains(t, msgsNW, "no wallet", "the deduction log must use the no-wallet voice")
	assert.NotContains(t, msgsNW, "insufficient balance", "no-wallet must not be logged as insufficient balance")

	// (b) wallet exists at balance 0 with org floor 0: a 1¢ charge would
	// land below the floor → genuine insufficient credits.
	orgFR := "b6-floor-reject-org"
	moneyReviewOrg(t, ctx, pool, orgFR, &zero, &floorZero)
	jobFR := moneyReviewSeedJob(t, ctx, pool, orgFR, "b6-fr-req", "", int64(moneyReviewCent))

	noWalletBefore = testutil.ToFloat64(metrics.CreditDeductionSkippedTotal.WithLabelValues("no_wallet"))
	insufficientBefore = testutil.ToFloat64(metrics.CreditDeductionSkippedTotal.WithLabelValues("insufficient"))
	drainSettlementQueue(ctx, t, w, db, orgFR, ChargeKindResaleDeduction)
	assert.Equal(t, insufficientBefore+1, testutil.ToFloat64(metrics.CreditDeductionSkippedTotal.WithLabelValues("insufficient")),
		"a floor rejection must count as insufficient credits")
	assert.Equal(t, noWalletBefore, testutil.ToFloat64(metrics.CreditDeductionSkippedTotal.WithLabelValues("no_wallet")),
		"a floor rejection must not be counted as no_wallet")

	status, _, _ = jobStatus(ctx, t, db, jobFR)
	assert.Equal(t, "requires_attention", status, "below-floor charges park as durable debt")
	msgsFR := strings.Join(reviewLog.messages(), "\n")
	assert.Contains(t, msgsFR, "insufficient balance", "a genuine floor rejection keeps the insufficient voice")
	balance, _, _ := moneyReviewWallet(t, ctx, pool, orgFR)
	assert.Equal(t, int64(0), balance, "the wallet must stay at the floor")
	total, amounts := moneyReviewUsage(t, ctx, pool, orgFR)
	assert.Equal(t, int64(0), total)
	assert.Empty(t, amounts)
}

// --- B8: the org floor must not depend on queue composition -------------

// Batch path (2-job group): with an explicit org floor of 0 and a 0¢
// wallet, both 1¢ charges park as insufficient. Pins the batch executor's
// existing org-floor contract.
func TestMoneyReview_B8_BatchParksAtOrgFloor(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	moneyReviewReset(t, ctx, pool)

	org := "b8-batch-org"
	zero := int64(0)
	floorZero := int64(moneyReviewFloorZero)
	moneyReviewOrg(t, ctx, pool, org, &zero, &floorZero)

	job1 := moneyReviewSeedJob(t, ctx, pool, org, "b8-batch-req-1", "b8000000-0000-4000-8000-00000000b801", int64(moneyReviewCent))
	job2 := moneyReviewSeedJob(t, ctx, pool, org, "b8-batch-req-2", "b8000000-0000-4000-8000-00000000b802", int64(moneyReviewCent))

	reviewLog := &moneyReviewLog{}
	w, db := moneyReviewWorker(t, pool, reviewLog)
	drainSettlementQueue(ctx, t, w, db, org, ChargeKindResaleDeduction)

	for _, job := range []int64{job1, job2} {
		status, _, lastErr := jobStatus(ctx, t, db, job)
		assert.Equal(t, "requires_attention", status, "both jobs park at the org floor")
		assert.Equal(t, budget.ReasonInsufficientCredits, lastErr, "the batch records the disposition reason durably")
	}
	balance, _, _ := moneyReviewWallet(t, ctx, pool, org)
	assert.Equal(t, int64(0), balance, "nothing may be charged below the org floor")
	total, amounts := moneyReviewUsage(t, ctx, pool, org)
	assert.Equal(t, int64(0), total)
	assert.Empty(t, amounts)
}

// Singleton path: the IDENTICAL wallet/floor state reached through ONE
// claimed job must produce the identical outcome. The one-cent
// counterexample: org floor 0, global floor −100, wallet 0 — the job must
// park, not overdraw to −1 (queue composition must not decide the floor).
func TestMoneyReview_B8_SingletonMatchesBatchAtOrgFloor(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	moneyReviewReset(t, ctx, pool)

	org := "b8-singleton-org"
	zero := int64(0)
	floorZero := int64(moneyReviewFloorZero)
	moneyReviewOrg(t, ctx, pool, org, &zero, &floorZero)

	job := moneyReviewSeedJob(t, ctx, pool, org, "b8-single-req", "b8000000-0000-4000-8000-00000000b803", int64(moneyReviewCent))

	reviewLog := &moneyReviewLog{}
	w, db := moneyReviewWorker(t, pool, reviewLog)
	drainSettlementQueue(ctx, t, w, db, org, ChargeKindResaleDeduction)

	status, _, lastErr := jobStatus(ctx, t, db, job)
	assert.Equal(t, "requires_attention", status, "the singleton must park exactly like the 2-job batch")
	assert.Equal(t, budget.ReasonInsufficientCredits, lastErr)
	balance, _, _ := moneyReviewWallet(t, ctx, pool, org)
	assert.Equal(t, int64(0), balance, "the wallet must not be driven below the org floor (the global −100¢ is not the effective floor)")
	total, amounts := moneyReviewUsage(t, ctx, pool, org)
	assert.Equal(t, int64(0), total)
	assert.Empty(t, amounts)
}

// Fallback path: a batch that fails BEFORE commit re-runs the group
// per-job; that path must honor the org floor exactly like the batch it
// replaces — both jobs park, nothing overdraws.
func TestMoneyReview_B8_FallbackMatchesBatchAtOrgFloor(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	moneyReviewReset(t, ctx, pool)

	org := "b8-fallback-org"
	zero := int64(0)
	floorZero := int64(moneyReviewFloorZero)
	moneyReviewOrg(t, ctx, pool, org, &zero, &floorZero)

	job1 := moneyReviewSeedJob(t, ctx, pool, org, "b8-fb-req-1", "b8000000-0000-4000-8000-00000000b804", int64(moneyReviewCent))
	job2 := moneyReviewSeedJob(t, ctx, pool, org, "b8-fb-req-2", "b8000000-0000-4000-8000-00000000b805", int64(moneyReviewCent))

	reviewLog := &moneyReviewLog{}
	injected := &moneyReviewDB{inner: pool}
	// Fail the batch's own wallet read once: the transaction aborts before
	// commit and the caller falls back to per-job execution.
	injected.armQueryFailure(batchWalletReadMarker)
	w, db := moneyReviewWorker(t, pool, reviewLog, injected)
	drainSettlementQueue(ctx, t, w, db, org, ChargeKindResaleDeduction)

	for _, job := range []int64{job1, job2} {
		status, _, lastErr := jobStatus(ctx, t, db, job)
		assert.Equal(t, "requires_attention", status, "the per-job fallback parks at the org floor like the batch")
		assert.Equal(t, budget.ReasonInsufficientCredits, lastErr)
	}
	balance, _, _ := moneyReviewWallet(t, ctx, pool, org)
	assert.Equal(t, int64(0), balance, "fallback must not overdraw below the org floor")
	total, amounts := moneyReviewUsage(t, ctx, pool, org)
	assert.Equal(t, int64(0), total)
	assert.Empty(t, amounts)
}

// Commit-response loss: a mixed batch (one chargeable job, one job parked
// for insufficient funds) commits durably, the caller observes a commit
// error, and funds arrive in the response-loss window. The parked job
// must NOT be re-executed by any fallback: the durable state is already
// terminal (settled + parked), and a re-execution would charge a wallet
// the ledger just recorded as uncollectable debt.
func TestMoneyReview_B8_CommitResponseLossNeverReexecutes(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	moneyReviewReset(t, ctx, pool)

	org := "b8-commit-loss-org"
	one := int64(1) // funds exactly the first 1¢ charge; the second parks
	floorZero := int64(moneyReviewFloorZero)
	moneyReviewOrg(t, ctx, pool, org, &one, &floorZero)

	jobSettled := moneyReviewSeedJob(t, ctx, pool, org, "b8-cl-req-1", "b8000000-0000-4000-8000-00000000b806", int64(moneyReviewCent))
	jobParked := moneyReviewSeedJob(t, ctx, pool, org, "b8-cl-req-2", "b8000000-0000-4000-8000-00000000b807", int64(moneyReviewCent))

	reviewLog := &moneyReviewLog{}
	injected := &moneyReviewDB{inner: pool}
	// Response-loss window: after the batch commit lands, funds arrive,
	// THEN the caller learns of a commit failure.
	injected.commitHook = func() {
		_, err := pool.Exec(ctx, `UPDATE org_credits SET balance_cents = balance_cents + 1 WHERE org_id = $1`, org)
		require.NoError(t, err)
	}
	w, db := moneyReviewWorker(t, pool, reviewLog, injected)
	drainSettlementQueue(ctx, t, w, db, org, ChargeKindResaleDeduction)

	statusS, _, _ := jobStatus(ctx, t, db, jobSettled)
	assert.Equal(t, "settled", statusS, "the chargeable job is durably settled by the committed batch")
	statusP, _, lastErrP := jobStatus(ctx, t, db, jobParked)
	assert.Equal(t, "requires_attention", statusP, "the parked job stays parked")
	assert.Equal(t, budget.ReasonInsufficientCredits, lastErrP)

	balance, _, _ := moneyReviewWallet(t, ctx, pool, org)
	assert.Equal(t, int64(1), balance,
		"wallet = 1¢ committed away + 1¢ arriving in the window; the parked job must NOT be re-charged")
	total, amounts := moneyReviewUsage(t, ctx, pool, org)
	assert.Equal(t, int64(1), total, "exactly one usage row: the committed batch's charge — no fallback re-execution")
	assert.Equal(t, []int64{-int64(moneyReviewCent)}, amounts)
}

// The genuine pre-commit failure must KEEP falling back: the same mixed
// group with a failed batch wallet read recovers per-job — one settle,
// one park, no overdraw. Guards the uncertain-commit handling from
// turning every batch error into an abandoned group.
func TestMoneyReview_B8_GenuineRollbackStillFallsBack(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	moneyReviewReset(t, ctx, pool)

	org := "b8-rollback-org"
	one := int64(1)
	floorZero := int64(moneyReviewFloorZero)
	moneyReviewOrg(t, ctx, pool, org, &one, &floorZero)

	jobSettled := moneyReviewSeedJob(t, ctx, pool, org, "b8-rb-req-1", "b8000000-0000-4000-8000-00000000b808", int64(moneyReviewCent))
	jobParked := moneyReviewSeedJob(t, ctx, pool, org, "b8-rb-req-2", "b8000000-0000-4000-8000-00000000b809", int64(moneyReviewCent))

	reviewLog := &moneyReviewLog{}
	injected := &moneyReviewDB{inner: pool}
	injected.armQueryFailure(batchWalletReadMarker) // pre-commit failure only
	w, db := moneyReviewWorker(t, pool, reviewLog, injected)
	drainSettlementQueue(ctx, t, w, db, org, ChargeKindResaleDeduction)

	statusS, _, _ := jobStatus(ctx, t, db, jobSettled)
	assert.Equal(t, "settled", statusS, "a pre-commit failure still falls back and settles the chargeable job")
	statusP, _, _ := jobStatus(ctx, t, db, jobParked)
	assert.Equal(t, "requires_attention", statusP, "the insufficient job parks through the fallback path")

	balance, _, _ := moneyReviewWallet(t, ctx, pool, org)
	assert.Equal(t, int64(0), balance, "the fallback charges exactly once at the org floor")
	total, amounts := moneyReviewUsage(t, ctx, pool, org)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, []int64{-int64(moneyReviewCent)}, amounts)
}
