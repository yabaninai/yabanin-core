package consumer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AF-06 live acceptance (disposable PG+Redis, same stand contract as the
// AF-04 inbox tests): the settlement worker executes durable intents with
// exactly-once money semantics across DB errors, restarts and replicas.

const af06AgentUUID = "a6600000-0000-4000-8000-00000000af06"

func newSettlementLiveEnv(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx, pool, _ := newInboxLiveEnv(t)
	setupCreditTables(ctx, t, pool)
	// Stand hygiene: some package tests tear the credits tables down and
	// this helper recreates them WITHOUT the production idempotency index.
	// The AF-06 acceptance (same request id, foreign org) is defined against
	// the real schema, so the migrated shape is enforced here.
	_, err := pool.Exec(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS uniq_credit_transactions_usage_request_id
		ON credit_transactions (request_id)
		WHERE request_id IS NOT NULL AND type = 'usage'`)
	require.NoError(t, err)
	return ctx, pool
}

// flakySettlementDB injects deterministic failures at exact statement
// boundaries (the crash windows) while everything else goes to the real pool.
type flakySettlementDB struct {
	inner    SettlementDB
	mu       sync.Mutex
	failNext map[string]int // statement substring -> remaining failures
	failErr  error
}

func (w *flakySettlementDB) reserve(query string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for sub, n := range w.failNext {
		if strings.Contains(query, sub) && n > 0 {
			w.failNext[sub] = n - 1
			return w.failErr
		}
	}
	return nil
}

func (w *flakySettlementDB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if err := w.reserve(query); err != nil {
		return pgconn.CommandTag{}, err
	}
	return w.inner.Exec(ctx, query, args...)
}

func (w *flakySettlementDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return w.inner.QueryRow(ctx, query, args...)
}

func (w *flakySettlementDB) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return w.inner.Query(ctx, query, args...)
}

func (w *flakySettlementDB) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := w.inner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &flakySettlementTx{inner: tx, parent: w}, nil
}

type flakySettlementTx struct {
	pgx.Tx // nil-embedded: only Exec/Commit/Rollback are exercised
	inner  pgx.Tx
	parent *flakySettlementDB
}

func (t *flakySettlementTx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if err := t.parent.reserve(query); err != nil {
		return pgconn.CommandTag{}, err
	}
	return t.inner.Exec(ctx, query, args...)
}

// QueryRow/Query delegate unwrapped: only statements (Exec) sit on the
// deterministic failure boundaries the crash windows need.
func (t *flakySettlementTx) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return t.inner.QueryRow(ctx, query, args...)
}

func (t *flakySettlementTx) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return t.inner.Query(ctx, query, args...)
}

func (t *flakySettlementTx) Commit(ctx context.Context) error   { return t.inner.Commit(ctx) }
func (t *flakySettlementTx) Rollback(ctx context.Context) error { return t.inner.Rollback(ctx) }

func liveSettlementConfig() SettlementConfig {
	return SettlementConfig{
		Interval:           50 * time.Millisecond,
		BatchSize:          25,
		MaxBatchesPerTick:  10,
		LeaseTTL:           2 * time.Second,
		BackoffBase:        5 * time.Millisecond,
		BackoffMax:         50 * time.Millisecond,
		MaxAttempts:        5,
		InboxRetention:     30 * 24 * time.Hour,
		InboxCleanupEvery:  time.Hour,
		InboxCleanupBatch:  500,
		InboxCleanupPasses: 40,
	}
}

// drainSettlementQueue ticks the worker until every job of the org/kind
// reached a terminal state (bounded — a stuck queue fails the test instead
// of spinning forever).
func drainSettlementQueue(ctx context.Context, t *testing.T, w *SettlementWorker, pool SettlementDB, orgID, kind string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		w.tick(ctx)
		var left int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM settlement_jobs
			 WHERE org_id=$1 AND charge_kind=$2 AND status IN ('pending','retry','processing')`,
			orgID, kind).Scan(&left))
		if left == 0 {
			return
		}
	}
	t.Fatal("settlement queue did not drain within the bounded tick budget")
}

// seedSettlementJob inserts a pending intent the way the consumer's delivery
// transaction would (exact micro amount, rounded compat cents).
func seedSettlementJob(ctx context.Context, t *testing.T, pool SettlementDB, orgID, requestID, kind string, amountMicro int64, payload []byte) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload)
		VALUES ($1, $2, $3, $4, $5, 'pending', $6)
		RETURNING id`,
		orgID, requestID, kind, money.MicroUSD(amountMicro).Cents(), amountMicro, payload).Scan(&id)
	require.NoError(t, err, "seed settlement job")
	return id
}

func jobStatus(ctx context.Context, t *testing.T, pool SettlementDB, id int64) (string, int, string) {
	t.Helper()
	var status string
	var attempts int
	var lastErr *string
	err := pool.QueryRow(ctx, `SELECT status, attempts, last_error FROM settlement_jobs WHERE id=$1`, id).Scan(&status, &attempts, &lastErr)
	require.NoError(t, err)
	errText := ""
	if lastErr != nil {
		errText = *lastErr
	}
	return status, attempts, errText
}

func forceLeaseExpiry(ctx context.Context, t *testing.T, pool SettlementDB, id int64) {
	t.Helper()
	_, err := pool.Exec(ctx, `UPDATE settlement_jobs SET status='processing', lease_until = now() - interval '1 second' WHERE id = $1`, id)
	require.NoError(t, err)
}

func forceJobDue(ctx context.Context, t *testing.T, pool SettlementDB, id int64) {
	t.Helper()
	_, err := pool.Exec(ctx, `UPDATE settlement_jobs SET next_attempt_at = now() - interval '1 second' WHERE id = $1`, id)
	require.NoError(t, err)
}

func seedWalletOrg(ctx context.Context, t *testing.T, pool SettlementDB, orgID string, balanceCents int64) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $2)
		ON CONFLICT (id) DO NOTHING`, orgID, "af06-"+orgID[:8])
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd)
		VALUES ($1, $2, 0)
		ON CONFLICT (org_id) DO UPDATE SET balance_cents = $2, remainder_micro_usd = 0`, orgID, balanceCents)
	require.NoError(t, err)
}

func requireWalletState(ctx context.Context, t *testing.T, pool SettlementDB, orgID string) (int64, int64) {
	t.Helper()
	var balanceCents, remainder int64
	err := pool.QueryRow(ctx,
		`SELECT balance_cents, remainder_micro_usd FROM org_credits WHERE org_id = $1`, orgID).Scan(&balanceCents, &remainder)
	require.NoError(t, err)
	return balanceCents, remainder
}

func ledgerUsage(ctx context.Context, t *testing.T, pool SettlementDB, orgID, requestID string) (int64, int64) {
	t.Helper()
	var rows, microSum int64
	err := pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(SUM(amount_micro_usd), 0)
		FROM credit_transactions
		WHERE org_id = $1 AND request_id = $2 AND type = 'usage'`, orgID, requestID).Scan(&rows, &microSum)
	require.NoError(t, err)
	return rows, microSum
}

const (
	af06OrgA = "af06aaaa-0000-4000-8000-00000000000a"
	af06OrgB = "af06bbbb-0000-4000-8000-00000000000b"
)

// Acceptance "DB error → restart → retry → одно списание", including the
// "crash after log commit before deduction" window: the consumer committed
// log + intent; the worker's first settle-mark fails AFTER the charge
// committed (crash); a restarted worker recovers the lease and completes
// with exactly one charge.
func TestSettlementLive_TransientSettleMarkFailureRetriesSingleCharge(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	seedWalletOrg(ctx, t, pool, af06OrgA, 1000)

	// The consumer committed log + intent (AF-04 contract, exercised live in
	// the inbox tests); here the intent exists and no charge has run yet.
	jobID := seedSettlementJob(ctx, t, pool, af06OrgA, "req-af06-retry", ChargeKindResaleDeduction, 250_000,
		[]byte(`{"model":"gpt-4","tokens_in":10,"tokens_out":5,"cost_usd":0.02,"resale_usd":0.025}`))

	// First worker: charge commits, then the settle mark fails (the crash
	// window after the deduction, before job completion).
	flaky := &flakySettlementDB{inner: pool, failNext: map[string]int{"status = 'settled'": 1}, failErr: errors.New("transient database outage")}
	crashed := NewSettlementWorker(flaky, credits.NewStore(pool, silentLogger()), nil, silentLogger()).WithConfig(liveSettlementConfig())
	crashed.tick(ctx)

	rows, microSum := ledgerUsage(ctx, t, pool, af06OrgA, "req-af06-retry")
	assert.Equal(t, int64(1), rows, "the charge from the crashed attempt is committed")
	assert.Equal(t, int64(-250_000), microSum, "exact micro amount charged once")

	status, _, _ := jobStatus(ctx, t, pool, jobID)
	assert.NotEqual(t, "settled", status, "the unmarked job must not read as settled")

	// Restart: a fresh worker recovers the expired lease and finishes.
	forceLeaseExpiry(ctx, t, pool, jobID)
	restarted := NewSettlementWorker(pool, credits.NewStore(pool, silentLogger()), nil, silentLogger()).WithConfig(liveSettlementConfig())
	restarted.tick(ctx)

	status, attempts, lastErr := jobStatus(ctx, t, pool, jobID)
	assert.Equal(t, "settled", status)
	assert.Empty(t, lastErr)
	assert.Equal(t, 2, attempts, "original attempt + idempotent recovery")

	rows, microSum = ledgerUsage(ctx, t, pool, af06OrgA, "req-af06-retry")
	assert.Equal(t, int64(1), rows, "retry must not double-charge")
	assert.Equal(t, int64(-250_000), microSum)

	balance, remainder := requireWalletState(ctx, t, pool, af06OrgA)
	assert.Equal(t, int64(975), balance, "wallet charged exactly 250_000µ = 25 cents once")
	assert.Equal(t, int64(0), remainder)
}

// Acceptance "crash после deduction до job completion": the executor died
// right after the committed charge; the dead lease is recovered and the
// idempotent re-execution settles without a second charge.
func TestSettlementLive_CrashAfterDeductionBeforeCompletion(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	seedWalletOrg(ctx, t, pool, af06OrgA, 1000)

	jobID := seedSettlementJob(ctx, t, pool, af06OrgA, "req-af06-crash", ChargeKindResaleDeduction, 100_000,
		[]byte(`{"model":"gpt-4","tokens_in":1,"tokens_out":1}`))

	store := credits.NewStore(pool, silentLogger())
	// The crash: the deduction committed, the job never completed.
	require.NoError(t, store.DeductMicro(ctx, af06OrgA, 100_000, "req-af06-crash", nil))
	_, err := pool.Exec(ctx, `UPDATE settlement_jobs SET status='processing', attempts=1, lease_until = now() - interval '1 second' WHERE id=$1`, jobID)
	require.NoError(t, err)

	w := NewSettlementWorker(pool, store, nil, silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	status, _, _ := jobStatus(ctx, t, pool, jobID)
	assert.Equal(t, "settled", status)
	rows, microSum := ledgerUsage(ctx, t, pool, af06OrgA, "req-af06-crash")
	assert.Equal(t, int64(1), rows)
	assert.Equal(t, int64(-100_000), microSum, "exactly one charge across the crash")
}

// Acceptance "две replicas": concurrent workers drain the same queue via
// SKIP LOCKED; every job settles exactly once with exact totals.
func TestSettlementLive_TwoReplicasSettleEachJobOnce(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	seedWalletOrg(ctx, t, pool, af06OrgA, 10_000)
	// The shared stand keeps credit history across tests: scope this run.
	_, err := pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id=$1`, af06OrgA)
	require.NoError(t, err)

	const jobs = 12
	ids := make([]int64, jobs)
	for i := 0; i < jobs; i++ {
		ids[i] = seedSettlementJob(ctx, t, pool, af06OrgA, fmt.Sprintf("req-af06-rep-%02d", i),
			ChargeKindResaleDeduction, 1_000+int64(i)*100, []byte(`{"model":"gpt-4"}`))
	}

	var wg sync.WaitGroup
	for replica := 0; replica < 2; replica++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A separate worker (its own credits store) models a second
			// process; the pool/DB is the shared coordination point.
			w := NewSettlementWorker(pool, credits.NewStore(pool, silentLogger()), nil, silentLogger()).WithConfig(liveSettlementConfig())
			for tick := 0; tick < 40; tick++ {
				w.tick(ctx)
			}
		}()
	}
	wg.Wait()

	var settled, processing, retry int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status='settled'),
		       count(*) FILTER (WHERE status='processing'),
		       count(*) FILTER (WHERE status='retry')
		FROM settlement_jobs`).Scan(&settled, &processing, &retry))
	assert.Equal(t, int64(jobs), settled, "every job settled")
	assert.Zero(t, processing)
	assert.Zero(t, retry)

	var microSum int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount_micro_usd),0) FROM settlement_jobs WHERE status='settled'`).Scan(&microSum))

	var ledgerRows, ledgerMicro int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(SUM(amount_micro_usd),0) FROM credit_transactions
		WHERE org_id=$1 AND type='usage'`, af06OrgA).Scan(&ledgerRows, &ledgerMicro))
	assert.Equal(t, int64(jobs), ledgerRows, "one ledger row per job")
	assert.Equal(t, microSum, -ledgerMicro, "charged exactly the settled amounts, no extra")

	// Effective wallet micro equals top-up minus the exact settled total
	// (sub-cent charges accumulate durably as the remainder).
	var walletMicro int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents*10000 - remainder_micro_usd FROM org_credits WHERE org_id=$1`, af06OrgA).Scan(&walletMicro))
	assert.Equal(t, int64(10_000)*10_000-microSum, walletMicro, "wallet reflects exactly the settled amounts")
}

// Acceptance "insufficient … не исчезают из reconcile/metrics": after the
// cost was incurred, a charge the wallet cannot cover becomes durable debt
// (requires_attention) — the floor is not bypassed and nothing is silently
// zeroed.
func TestSettlementLive_InsufficientFundsBecomesDurableDebt(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	// The wallet sits exactly at the grace floor (default grace: -$1.00):
	// any charge would breach it, so the deduction is rejected.
	seedWalletOrg(ctx, t, pool, af06OrgA, -100)

	jobID := seedSettlementJob(ctx, t, pool, af06OrgA, "req-af06-debt", ChargeKindResaleDeduction, 500_000,
		[]byte(`{"model":"gpt-4"}`))

	w := NewSettlementWorker(pool, credits.NewStore(pool, silentLogger()), nil, silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	status, _, lastErr := jobStatus(ctx, t, pool, jobID)
	assert.Equal(t, "requires_attention", status)
	assert.Contains(t, lastErr, "insufficient credits", "the durable record names the reason")

	balance, _ := requireWalletState(ctx, t, pool, af06OrgA)
	assert.Equal(t, int64(-100), balance, "floor is not bypassed: wallet untouched")
	rows, _ := ledgerUsage(ctx, t, pool, af06OrgA, "req-af06-debt")
	assert.Zero(t, rows, "no silent partial charge")

	assert.GreaterOrEqual(t, testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("requires_attention")), float64(1),
		"debt is visible in the backlog metric")
}

// No wallet: the job is parked as requires_attention and remains resolvable
// — once the wallet exists and the job is requeued, it settles once.
func TestSettlementLive_NoWalletRequiresAttentionThenResolves(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	seedWalletOrg(ctx, t, pool, af06OrgA, 0)
	_, err := pool.Exec(ctx, `DELETE FROM org_credits WHERE org_id=$1`, af06OrgA)
	require.NoError(t, err)

	jobID := seedSettlementJob(ctx, t, pool, af06OrgA, "req-af06-nowallet", ChargeKindResaleDeduction, 50_000,
		[]byte(`{"model":"gpt-4"}`))

	w := NewSettlementWorker(pool, credits.NewStore(pool, silentLogger()), nil, silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	status, _, lastErr := jobStatus(ctx, t, pool, jobID)
	assert.Equal(t, "requires_attention", status)
	// credits.Store reports a missing wallet row as an insufficient-balance
	// rejection at the wallet read; either way the reason is durable and
	// named on the record (never a silent zero).
	assert.True(t,
		strings.Contains(lastErr, "insufficient") || strings.Contains(lastErr, "wallet"),
		"durable record names the reason, got: %q", lastErr)

	// The org gets a wallet (admin action); the debt record is requeued.
	seedWalletOrg(ctx, t, pool, af06OrgA, 1000)
	_, err = pool.Exec(ctx, `UPDATE settlement_jobs SET status='pending', next_attempt_at=now() WHERE id=$1`, jobID)
	require.NoError(t, err)
	w.tick(ctx)

	status, _, _ = jobStatus(ctx, t, pool, jobID)
	assert.Equal(t, "settled", status)
	rows, microSum := ledgerUsage(ctx, t, pool, af06OrgA, "req-af06-nowallet")
	assert.Equal(t, int64(1), rows)
	assert.Equal(t, int64(-50_000), microSum)
}

// Acceptance "одинаковый ID чужой org не засчитывает её charge": the usage
// idempotency index is global on request_id — a second org's job for the
// same request identity conflicts and is parked as a diagnostic; the first
// org's charge is intact.
func TestSettlementLive_SameRequestOtherOrgDoesNotStealCharge(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	seedWalletOrg(ctx, t, pool, af06OrgA, 1000)
	seedWalletOrg(ctx, t, pool, af06OrgB, 1000)

	jobA := seedSettlementJob(ctx, t, pool, af06OrgA, "req-af06-shared", ChargeKindResaleDeduction, 100_000, []byte(`{}`))
	jobB := seedSettlementJob(ctx, t, pool, af06OrgB, "req-af06-shared", ChargeKindResaleDeduction, 100_000, []byte(`{}`))

	w := NewSettlementWorker(pool, credits.NewStore(pool, silentLogger()), nil, silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	statusA, _, _ := jobStatus(ctx, t, pool, jobA)
	assert.Equal(t, "settled", statusA)
	statusB, _, lastErrB := jobStatus(ctx, t, pool, jobB)
	assert.Equal(t, "requires_attention", statusB, "identity conflict is a diagnostic, not a charge")
	assert.Contains(t, strings.ToLower(lastErrB), "duplicate", "last_error names the unique violation")

	rowsA, microA := ledgerUsage(ctx, t, pool, af06OrgA, "req-af06-shared")
	assert.Equal(t, int64(1), rowsA)
	assert.Equal(t, int64(-100_000), microA)
	rowsB, _ := ledgerUsage(ctx, t, pool, af06OrgB, "req-af06-shared")
	assert.Zero(t, rowsB, "the foreign org is not charged for a request id it does not own")
	balanceB, _ := requireWalletState(ctx, t, pool, af06OrgB)
	assert.Equal(t, int64(1000), balanceB)
}

// Acceptance "retry не добавляет agent spend второй раз": a crash inside the
// spend transaction rolls the spend back; the retry re-executes cleanly; the
// exact micro amount lands once.
func TestSettlementLive_AgentSpendRetryDoesNotDoubleAdd(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	seedWalletOrg(ctx, t, pool, af06OrgA, 0)

	// Clean slate for this agent's daily rollup (shared stand hygiene).
	_, err := pool.Exec(ctx, `DELETE FROM agent_spend_daily WHERE agent_id=$1`, af06AgentUUID)
	require.NoError(t, err)

	jobID := seedSettlementJob(ctx, t, pool, af06OrgA, "req-af06-agent", ChargeKindAgentSpend, 12_300,
		[]byte(fmt.Sprintf(`{"agent_id":%q,"tokens_in":10,"tokens_out":5}`, af06AgentUUID)))

	// First attempt: the spend INSERT fails inside the transaction — both the
	// spend and the settle mark roll back together.
	flaky := &flakySettlementDB{inner: pool, failNext: map[string]int{"INSERT INTO agent_spend_daily": 1}, failErr: errors.New("transient")}
	flakyWorker := NewSettlementWorker(flaky, nil, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	flakyWorker.tick(ctx)

	// Durable facts after the failed attempt. The live backoff is full-jitter
	// (base 5ms), so the SAME tick's next claim batch may legitimately
	// re-claim the job and complete it before this read; both interleavings
	// pin the same contract: the failed attempt itself never settles
	// (settled ⇒ a re-execution happened), and a still-unsettled job carries
	// no spend from the rolled-back transaction.
	status, attempts, lastErr := jobStatus(ctx, t, pool, jobID)
	var spendMicro int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(cost_micro_usd),0) FROM agent_spend_daily WHERE agent_id=$1 AND day=(now() AT TIME ZONE 'utc')::date`,
		af06AgentUUID).Scan(&spendMicro))
	switch status {
	case "settled":
		assert.GreaterOrEqual(t, attempts, 2, "a failed attempt must never be the settling one")
		assert.Equal(t, int64(12_300), spendMicro, "the legitimate retry records exactly one spend")
	case "retry":
		assert.Equal(t, 1, attempts, "exactly the failed attempt happened")
		assert.Zero(t, spendMicro, "rolled-back attempt must not leave spend behind")
		assert.Contains(t, lastErr, "transient", "the durable record names the failure")
	default:
		t.Fatalf("unexpected disposition after the failed attempt: %q (attempts=%d)", status, attempts)
	}

	// Retry: fresh worker, the job settles with the spend in one tx. When the
	// same-tick retry above already completed the job, this pass is a no-op.
	forceJobDue(ctx, t, pool, jobID)
	restarted := NewSettlementWorker(pool, nil, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	restarted.tick(ctx)

	status, attempts, lastErr = jobStatus(ctx, t, pool, jobID)
	assert.Equal(t, "settled", status)
	assert.Empty(t, lastErr)
	assert.Equal(t, 2, attempts, "failed attempt + exactly one successful execution")

	var spendRows int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*), COALESCE(SUM(cost_micro_usd),0) FROM agent_spend_daily WHERE agent_id=$1 AND day=(now() AT TIME ZONE 'utc')::date`,
		af06AgentUUID).Scan(&spendRows, &spendMicro))
	assert.Equal(t, int64(1), spendRows)
	assert.Equal(t, int64(12_300), spendMicro, "exact micro amount recorded exactly once")
	var tokensIn, tokensOut int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT SUM(tokens_in), SUM(tokens_out) FROM agent_spend_daily WHERE agent_id=$1 AND day=(now() AT TIME ZONE 'utc')::date`,
		af06AgentUUID).Scan(&tokensIn, &tokensOut))
	assert.Equal(t, int64(10), tokensIn)
	assert.Equal(t, int64(5), tokensOut, "no double add on retry")
}

// Acceptance "изменённый amount для уже settled identity → conflict /
// diagnostic, а не второе списание": a duplicate delivery of the same
// (org, request) identity with a different resale amount is diagnosed; the
// first amount stays authoritative and only it settles.
func TestSettlementLive_ConflictingAmountForSettledIdentity(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)
	setupCreditTables(ctx, t, pool)
	seedWalletOrg(ctx, t, pool, af06OrgA, 1000)

	consumer1 := NewWithCreditStore(NewRedisOps(rdb), NewDBOps(pool), "events:af06-conflict", silentLogger(), credits.NewStore(pool, silentLogger()))
	msg := func(id string, resale string) redis.XMessage {
		return redis.XMessage{ID: id, Values: map[string]interface{}{
			"event_type": "request.completed", "source": "gateway-live",
			"request_id": "req-af06-amt", "org_id": af06OrgA,
			"model_requested": "gpt-4", "model_used": "gpt-4",
			"status_code": "200", "resale_cost_usd": resale,
		}}
	}

	require.NoError(t, consumer1.processMessage(ctx, msg("700-0", "0.07")))
	conflictsBefore := testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues(ChargeKindResaleDeduction))

	// A different event (new stream entry id) for the SAME settlement
	// identity claims a different amount.
	require.NoError(t, consumer1.processMessage(ctx, msg("700-1", "0.09")))
	conflictsAfter := testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues(ChargeKindResaleDeduction))
	assert.Greater(t, conflictsAfter, conflictsBefore, "the amount change is reported as a conflict diagnostic")

	var jobCount, knownAmount int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*), max(amount_micro_usd) FROM settlement_jobs
		WHERE org_id=$1 AND request_id='req-af06-amt' AND charge_kind=$2`,
		af06OrgA, ChargeKindResaleDeduction).Scan(&jobCount, &knownAmount))
	assert.Equal(t, int64(1), jobCount, "one durable identity, the second delivery does not overwrite")
	assert.Equal(t, int64(70_000), knownAmount, "the first amount stays authoritative")

	w := NewSettlementWorker(pool, credits.NewStore(pool, silentLogger()), nil, silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	rows, microSum := ledgerUsage(ctx, t, pool, af06OrgA, "req-af06-amt")
	assert.Equal(t, int64(1), rows, "exactly one charge for the settled identity")
	assert.Equal(t, int64(-70_000), microSum, "the original amount, not the conflicting one")
	balance, _ := requireWalletState(ctx, t, pool, af06OrgA)
	assert.Equal(t, int64(993), balance, "wallet charged the original 7 cents exactly once")
}

// Retention (AF-04 risk closed here): expired event_inbox rows are removed
// in bounded batches per pass, fresh rows survive the cutoff.
func TestSettlementLive_EventInboxRetentionBounded(t *testing.T) {
	ctx, pool, _ := newInboxLiveEnv(t)

	const oldRows = 25
	for i := 0; i < oldRows; i++ {
		_, err := pool.Exec(ctx, `INSERT INTO event_inbox (source, consumer, event_id) VALUES ($1, $2, $3)`,
			"events:af06-retention", "loggerd-workers", fmt.Sprintf("%d-0", i))
		require.NoError(t, err)
	}
	_, err := pool.Exec(ctx, `UPDATE event_inbox SET created_at = now() - interval '40 days' WHERE source=$1`, "events:af06-retention")
	require.NoError(t, err)
	const freshRows = 5
	for i := 0; i < freshRows; i++ {
		_, err := pool.Exec(ctx, `INSERT INTO event_inbox (source, consumer, event_id) VALUES ($1, $2, $3)`,
			"events:af06-fresh", "loggerd-workers", fmt.Sprintf("%d-0", i))
		require.NoError(t, err)
	}

	w := NewSettlementWorker(pool, nil, nil, silentLogger()).WithConfig(SettlementConfig{
		Interval:           time.Hour,
		InboxCleanupEvery:  time.Nanosecond, // always due
		InboxCleanupBatch:  10,
		InboxCleanupPasses: 2, // bounded: at most 20 rows per cleanup run
		InboxRetention:     30 * 24 * time.Hour,
	})
	w.tick(ctx)

	var oldLeft, freshLeft int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM event_inbox WHERE source='events:af06-retention'`).Scan(&oldLeft))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM event_inbox WHERE source='events:af06-fresh'`).Scan(&freshLeft))
	assert.Equal(t, int64(oldRows-20), oldLeft, "cleanup is bounded to BatchSize×Passes per run")
	assert.Equal(t, int64(freshRows), freshLeft, "fresh rows survive the retention cutoff")

	w.tick(ctx) // next bounded pass removes the rest of the expired rows
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM event_inbox WHERE source='events:af06-retention'`).Scan(&oldLeft))
	assert.Zero(t, oldLeft)
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM event_inbox WHERE source='events:af06-fresh'`).Scan(&freshLeft))
	assert.Equal(t, int64(freshRows), freshLeft)
}

// Reconcile visibility: the backlog gauge reflects the actual job states
// after a tick (nothing unprocessed is invisible).
func TestSettlementLive_BacklogMetricsPublished(t *testing.T) {
	ctx, pool := newSettlementLiveEnv(t)
	seedWalletOrg(ctx, t, pool, af06OrgA, 1000)
	// The debt org sits exactly at the grace floor: any charge is rejected.
	seedWalletOrg(ctx, t, pool, af06OrgB, -100)

	seedSettlementJob(ctx, t, pool, af06OrgA, "req-af06-bl-1", ChargeKindResaleDeduction, 10_000, []byte(`{}`))
	seedSettlementJob(ctx, t, pool, af06OrgA, "req-af06-bl-2", ChargeKindResaleDeduction, 10_000, []byte(`{}`))
	debtID := seedSettlementJob(ctx, t, pool, af06OrgB, "req-af06-bl-debt", ChargeKindResaleDeduction, 10_000, []byte(`{}`))

	w := NewSettlementWorker(pool, credits.NewStore(pool, silentLogger()), nil, silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	status, _, _ := jobStatus(ctx, t, pool, debtID)
	assert.Equal(t, "requires_attention", status)

	assert.InDelta(t, float64(0), testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("pending")), 0.001)
	assert.InDelta(t, float64(0), testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("retry")), 0.001)
	assert.InDelta(t, float64(0), testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("processing")), 0.001)
	assert.InDelta(t, float64(1), testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("requires_attention")), 0.001,
		"unresolved debt stays visible in reconcile metrics")
}
