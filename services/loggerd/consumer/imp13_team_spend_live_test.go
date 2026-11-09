package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// live tests): team spends become a durable side effect of settlement — a
// team-attributed request creates a 'team_spend' charge intent (identity
// (org_id, request_id, kind)), the AF-06 worker records the exact micro-USD
// amount into team_spend_monthly for the request-time period, replays and
// crashes never double-count, and CheckBudget enforces a hard monthly limit
// against the exact column.

const (
	imp13OrgA  = "1d130000-0000-4000-8000-00000000000a"
	imp13TeamA = "1d13aaaa-0000-4000-8000-00000000000a"
	imp13TeamB = "1d13bbbb-0000-4000-8000-00000000000b"
)

func newTeamSpendLiveEnv(t *testing.T) (context.Context, *pgxpool.Pool, *redis.Client) {
	t.Helper()
	ctx, pool, rdb := newInboxLiveEnv(t)
	// Team spend needs no wallet: only the org row (the team FK target),
	// the teams and their budget rows.
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1, 'imp13-org', 'imp13-org')
		ON CONFLICT (id) DO NOTHING`, imp13OrgA)
	require.NoError(t, err)
	seedTeamSpendFixtures(ctx, t, pool)
	return ctx, pool, rdb
}

// seedTeamSpendFixtures inserts the teams (the team_spend_monthly FK target)
// and hard-limit budget rows; per-test spend rows are cleaned because the
// stand keeps team tables across tests.
func seedTeamSpendFixtures(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, team := range []string{imp13TeamA, imp13TeamB} {
		_, err := pool.Exec(ctx, `
			INSERT INTO organizations_teams (id, org_id, name, slug)
			VALUES ($1, $2, $3, $3)
			ON CONFLICT (id) DO NOTHING`, team, imp13OrgA, "imp13-"+team[:8])
		require.NoError(t, err, "seed team")
		_, err = pool.Exec(ctx, `
			INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
			VALUES ($1, 0.01, true)
			ON CONFLICT (team_id) DO UPDATE SET monthly_limit_usd = 0.01, hard_limit = true`, team)
		require.NoError(t, err, "seed team budget")
		_, err = pool.Exec(ctx, `DELETE FROM team_spend_monthly WHERE team_id = $1`, team)
		require.NoError(t, err, "clean team spend rows")
	}
	// W-VER-style flake fix: the flakySettlementDB failure injection is
	// GLOBAL (fails the next INSERT regardless of which job it belongs to).
	// Stale pending jobs of this org left by a previous test on the shared
	// stand get picked up by the same batch tick, consume the injection, and
	// leave the assertion's job committed behind a "rollback". Purge the
	// org's settlement queue so the tick sees exactly the seeded job.
	_, err := pool.Exec(ctx, `DELETE FROM settlement_jobs WHERE org_id = $1`, imp13OrgA)
	require.NoError(t, err, "clean stale settlement jobs")
}

func teamSpendRow(ctx context.Context, t *testing.T, pool *pgxpool.Pool, teamID, period string) (rows, micro int64, spendUSD float64, requestCount int64) {
	t.Helper()
	err := pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(SUM(spend_micro_usd), 0), COALESCE(SUM(spend_usd), 0), COALESCE(SUM(request_count), 0)
		FROM team_spend_monthly WHERE team_id = $1 AND period = $2`,
		teamID, period).Scan(&rows, &micro, &spendUSD, &requestCount)
	require.NoError(t, err, "read team_spend_monthly")
	return rows, micro, spendUSD, requestCount
}

func imp13CompletedMsg(entryID, requestID, teamID, costUSD string) redis.XMessage {
	return redis.XMessage{ID: entryID, Values: map[string]interface{}{
		"event_type": "request.completed", "source": "gateway-live",
		"request_id": requestID, "org_id": imp13OrgA, "team_id": teamID,
		"model_requested": "gpt-4", "model_used": "gpt-4",
		"status_code": "200", "tokens_in": "100", "tokens_out": "20",
		"estimated_cost_usd": costUSD,
	}}
}

// Acceptance "запрос команды → строка периода с точной суммой": the delivery
// commits a pending team_spend intent with the exact base-cost micro amount;
// the settlement worker records it into team_spend_monthly (exact µ column,
// spend_usd projection, request count). The sub-cent amount ($0.004) is the
// regression core of the card: it must survive, not round away.
func TestTeamSpendLive_RequestRecordsExactPeriodSpend(t *testing.T) {
	ctx, pool, rdb := newTeamSpendLiveEnv(t)
	period := time.Now().UTC().Format("2006-01")

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:imp13", silentLogger())
	require.NoError(t, c.processMessage(ctx, imp13CompletedMsg("1300-0", "req-imp13-exact", imp13TeamA, "0.004")))

	// The intent exists inside the delivery commit: exact µ amount, rounded
	// cents compatibility projection, request-time period in the payload.
	var amountMicro, amountCents int64
	var payload []byte
	var status string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT amount_micro_usd, amount_cents, payload, status FROM settlement_jobs
		WHERE org_id=$1 AND request_id=$2 AND charge_kind=$3`,
		imp13OrgA, "req-imp13-exact", ChargeKindTeamSpend).Scan(&amountMicro, &amountCents, &payload, &status))
	assert.Equal(t, "pending", status)
	assert.Equal(t, int64(4_000), amountMicro, "exact micro amount on the intent")
	assert.Equal(t, int64(0), amountCents, "rounded cents projection of a sub-cent charge")
	var decoded teamSpendPayload
	require.NoError(t, json.Unmarshal(payload, &decoded))
	assert.Equal(t, imp13TeamA, decoded.TeamID)
	assert.Equal(t, period, decoded.Period, "request-time period frozen in the intent")

	// Worker executes: one period row with the exact amount and projection.
	w := NewSettlementWorker(pool, nil, nil, silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	rows, micro, spendUSD, requestCount := teamSpendRow(ctx, t, pool, imp13TeamA, period)
	assert.Equal(t, int64(1), rows)
	assert.Equal(t, int64(4_000), micro, "exact micro-USD recorded")
	assert.InDelta(t, 0.004, spendUSD, 1e-9, "spend_usd stays the compatible projection")
	assert.Equal(t, int64(1), requestCount)

	var jobStatusStr string
	require.NoError(t, pool.QueryRow(ctx, `SELECT status FROM settlement_jobs WHERE org_id=$1 AND request_id=$2 AND charge_kind=$3`,
		imp13OrgA, "req-imp13-exact", ChargeKindTeamSpend).Scan(&jobStatusStr))
	assert.Equal(t, "settled", jobStatusStr)
}

// Acceptance "hard_limit=true и малый лимит — отказ бюджета срабатывает":
// CheckBudget reads the exact column and denies once the accumulated exact
// spend reaches the limit (429 budget_exceeded path at the gateway).
func TestTeamSpendLive_CheckBudgetDeniesAtExactHardLimit(t *testing.T) {
	ctx, pool, rdb := newTeamSpendLiveEnv(t)
	enf := budget.NewEnforcer(pool, silentLogger())

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:imp13", silentLogger())
	require.NoError(t, c.processMessage(ctx, imp13CompletedMsg("1301-0", "req-imp13-b1", imp13TeamA, "0.004")))
	require.NoError(t, c.processMessage(ctx, imp13CompletedMsg("1301-1", "req-imp13-b2", imp13TeamA, "0.004")))

	w := NewSettlementWorker(pool, nil, nil, silentLogger()).WithConfig(liveSettlementConfig())
	drainSettlementQueue(ctx, t, w, pool, imp13OrgA, ChargeKindTeamSpend)

	// 8000µ spent of a 10000µ limit: the next request still passes.
	require.NoError(t, enf.CheckBudget(ctx, imp13TeamA))

	require.NoError(t, c.processMessage(ctx, imp13CompletedMsg("1301-2", "req-imp13-b3", imp13TeamA, "0.004")))
	drainSettlementQueue(ctx, t, w, pool, imp13OrgA, ChargeKindTeamSpend)

	// 12000µ >= 10000µ: the hard limit fires on exact accounting.
	err := enf.CheckBudget(ctx, imp13TeamA)
	require.ErrorIs(t, err, budget.ErrBudgetExceeded)
}

// Acceptance "replay и дубль события — одно списание": the same event
// redelivered (same stream entry id) and a duplicate event under the same
// settlement identity (different entry id) collapse into ONE period
// increment; a second worker pass over a settled job adds nothing.
func TestTeamSpendLive_ReplayAndDuplicateSingleSpend(t *testing.T) {
	ctx, pool, rdb := newTeamSpendLiveEnv(t)
	period := time.Now().UTC().Format("2006-01")

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:imp13", silentLogger())
	msg := imp13CompletedMsg("1302-0", "req-imp13-dup", imp13TeamA, "0.012")
	require.NoError(t, c.processMessage(ctx, msg))
	require.NoError(t, c.processMessage(ctx, msg), "redelivery before ACK")

	duplicate := imp13CompletedMsg("1302-1", "req-imp13-dup", imp13TeamA, "0.012")
	require.NoError(t, c.processMessage(ctx, duplicate), "duplicate event, same identity")

	var jobs int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM settlement_jobs WHERE org_id=$1 AND request_id=$2 AND charge_kind=$3`,
		imp13OrgA, "req-imp13-dup", ChargeKindTeamSpend).Scan(&jobs))
	assert.Equal(t, int64(1), jobs, "one durable identity across replays")

	w := NewSettlementWorker(pool, nil, nil, silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)
	drainSettlementQueue(ctx, t, w, pool, imp13OrgA, ChargeKindTeamSpend)

	_, micro, _, requestCount := teamSpendRow(ctx, t, pool, imp13TeamA, period)
	assert.Equal(t, int64(12_000), micro, "exactly one spend of 12000µ")
	assert.Equal(t, int64(1), requestCount, "the duplicate never re-counts")
}

// Acceptance "рестарт loggerd между commit и ACK — без дубля": a committed
// delivery whose ACK was lost is replayed by a FRESH consumer (restart); the
// durable inbox dedupes, and a fresh worker records the spend exactly once.
func TestTeamSpendLive_RestartBetweenCommitAndACKNoDuplicate(t *testing.T) {
	ctx, pool, rdb := newTeamSpendLiveEnv(t)
	period := time.Now().UTC().Format("2006-01")

	crashed := New(NewRedisOps(rdb), NewDBOps(pool), "events:imp13", silentLogger())
	msg := imp13CompletedMsg("1303-0", "req-imp13-restart", imp13TeamA, "0.006")
	require.NoError(t, crashed.processMessage(ctx, msg))

	// Restart: Redis state lost (ACK + markers gone), only the committed
	// inbox row remains; a fresh consumer replays the same message.
	require.NoError(t, rdb.FlushDB(ctx).Err())
	restarted := New(NewRedisOps(rdb), NewDBOps(pool), "events:imp13", silentLogger())
	require.NoError(t, restarted.processMessage(ctx, msg))

	var jobs int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM settlement_jobs WHERE org_id=$1 AND request_id=$2 AND charge_kind=$3`,
		imp13OrgA, "req-imp13-restart", ChargeKindTeamSpend).Scan(&jobs))
	assert.Equal(t, int64(1), jobs, "restart replay must not duplicate the intent")

	w := NewSettlementWorker(pool, nil, nil, silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	_, micro, _, _ := teamSpendRow(ctx, t, pool, imp13TeamA, period)
	assert.Equal(t, int64(6_000), micro, "exactly one spend across the restart")
}

// Acceptance "граница месяца": spend lands in the period fixed by the
// request-time payload, and CheckBudget sees only the current period —
// spend recorded under another month never counts toward this month's
// hard limit.
func TestTeamSpendLive_MonthBoundaryIsolation(t *testing.T) {
	ctx, pool, _ := newTeamSpendLiveEnv(t)
	currentPeriod := time.Now().UTC().Format("2006-01")

	seedSettlementJob(ctx, t, pool, imp13OrgA, "req-imp13-sep", ChargeKindTeamSpend, 9_000,
		[]byte(fmt.Sprintf(`{"team_id":%q,"period":"2099-09"}`, imp13TeamA)))
	seedSettlementJob(ctx, t, pool, imp13OrgA, "req-imp13-oct", ChargeKindTeamSpend, 5_000,
		[]byte(fmt.Sprintf(`{"team_id":%q,"period":"2099-10"}`, imp13TeamA)))

	w := NewSettlementWorker(pool, nil, nil, silentLogger()).WithConfig(liveSettlementConfig())
	drainSettlementQueue(ctx, t, w, pool, imp13OrgA, ChargeKindTeamSpend)

	_, sepMicro, _, _ := teamSpendRow(ctx, t, pool, imp13TeamA, "2099-09")
	_, octMicro, _, _ := teamSpendRow(ctx, t, pool, imp13TeamA, "2099-10")
	assert.Equal(t, int64(9_000), sepMicro)
	assert.Equal(t, int64(5_000), octMicro, "periods are separate rows, never merged")

	// The current period has no spend: the hard limit does not fire even
	// though other periods hold spend.
	enf := budget.NewEnforcer(pool, silentLogger())
	require.NoError(t, enf.CheckBudget(ctx, imp13TeamA))

	// Spend in the CURRENT period (request-time period) crosses the limit
	// while the other months stay isolated.
	seedSettlementJob(ctx, t, pool, imp13OrgA, "req-imp13-now", ChargeKindTeamSpend, 10_000,
		[]byte(fmt.Sprintf(`{"team_id":%q,"period":%q}`, imp13TeamA, currentPeriod)))
	drainSettlementQueue(ctx, t, w, pool, imp13OrgA, ChargeKindTeamSpend)
	require.ErrorIs(t, enf.CheckBudget(ctx, imp13TeamA), budget.ErrBudgetExceeded)

	// The enforcer's period matches the request-time period by construction:
	// a different team's spend stays isolated too.
	_, bMicro, _, _ := teamSpendRow(ctx, t, pool, imp13TeamB, currentPeriod)
	assert.Equal(t, int64(0), bMicro)
	require.NoError(t, budget.NewEnforcer(pool, silentLogger()).CheckBudget(ctx, imp13TeamB))
}

// Crash inside the spend transaction: the spend and the settle mark roll
// back TOGETHER (one transaction), the retry re-executes and records exactly
// once. The resale-style "charge committed but settle mark failed" window
// cannot exist for team spend: the settle mark is part of the same
// transaction as the spend.
func TestTeamSpendLive_CrashInsideSpendTXRollsBackBoth(t *testing.T) {
	ctx, pool, _ := newTeamSpendLiveEnv(t)
	period := time.Now().UTC().Format("2006-01")

	jobID := seedSettlementJob(ctx, t, pool, imp13OrgA, "req-imp13-crash", ChargeKindTeamSpend, 7_700,
		[]byte(fmt.Sprintf(`{"team_id":%q,"period":%q}`, imp13TeamA, period)))

	flaky := &flakySettlementDB{inner: pool, failNext: map[string]int{"INSERT INTO team_spend_monthly": 1}, failErr: errors.New("transient")}
	// The injected failure must not be retried INSIDE this same tick: the
	// shared live config's full-jitter backoff is uniform over [0, 5ms), so
	// on a fast/idle machine the very next claimBatch of this tick re-claims
	// the job, the second attempt commits the spend, and the rollback
	// assertion races the worker (deflake: backoff far outside the tick and
	// one batch per tick make the "no spend after the crash" read
	// deterministic; the retry itself is driven by forceJobDue below).
	flakyCfg := liveSettlementConfig()
	flakyCfg.BackoffBase = time.Hour
	flakyCfg.BackoffMax = time.Hour
	flakyCfg.MaxBatchesPerTick = 1
	flakyWorker := NewSettlementWorker(flaky, nil, nil, silentLogger()).WithConfig(flakyCfg)
	flakyWorker.tick(ctx)

	_, micro, _, _ := teamSpendRow(ctx, t, pool, imp13TeamA, period)
	assert.Equal(t, int64(0), micro, "the rolled-back attempt leaves no spend behind")

	forceJobDue(ctx, t, pool, jobID)
	restarted := NewSettlementWorker(pool, nil, nil, silentLogger()).WithConfig(liveSettlementConfig())
	drainSettlementQueue(ctx, t, restarted, pool, imp13OrgA, ChargeKindTeamSpend)

	status, attempts, lastErr := jobStatus(ctx, t, pool, jobID)
	assert.Equal(t, "settled", status)
	assert.Empty(t, lastErr)
	assert.Equal(t, 2, attempts, "failed attempt + exactly one successful execution")

	_, micro, spendUSD, requestCount := teamSpendRow(ctx, t, pool, imp13TeamA, period)
	assert.Equal(t, int64(7_700), micro, "exact amount recorded exactly once")
	assert.InDelta(t, 0.0077, spendUSD, 1e-9)
	assert.Equal(t, int64(1), requestCount)
}

// Shadow mirrors and failed/budget-blocked requests with a team attribution
// never create charge intents; a zero-cost completed request (cache hit
// publishes estimated_cost_usd=0) still settles as a genuine zero — the
// request is counted, no money moves.
func TestTeamSpendLive_ShadowAndFailedNeverBill(t *testing.T) {
	ctx, pool, rdb := newTeamSpendLiveEnv(t)
	period := time.Now().UTC().Format("2006-01")

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:imp13", silentLogger())

	shadow := imp13CompletedMsg("1304-0", "req-imp13-shadow", imp13TeamA, "0.5")
	shadow.Values["event_type"] = "request.shadow_completed"
	require.NoError(t, c.processMessage(ctx, shadow))

	failed := imp13CompletedMsg("1304-1", "req-imp13-failed", imp13TeamA, "0.5")
	failed.Values["event_type"] = "request.failed"
	failed.Values["status_code"] = "503"
	require.NoError(t, c.processMessage(ctx, failed))

	var intents int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM settlement_jobs WHERE charge_kind=$1`, ChargeKindTeamSpend).Scan(&intents))
	assert.Zero(t, intents, "shadow and failed requests are never billed")

	cacheHit := imp13CompletedMsg("1304-2", "req-imp13-cache", imp13TeamA, "0")
	require.NoError(t, c.processMessage(ctx, cacheHit))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM settlement_jobs WHERE charge_kind=$1 AND request_id='req-imp13-cache'`, ChargeKindTeamSpend).Scan(&intents))
	assert.Equal(t, int64(1), intents, "cache-hit completed event settles per the settlement contract")

	w := NewSettlementWorker(pool, nil, nil, silentLogger()).WithConfig(liveSettlementConfig())
	drainSettlementQueue(ctx, t, w, pool, imp13OrgA, ChargeKindTeamSpend)
	_, micro, _, requestCount := teamSpendRow(ctx, t, pool, imp13TeamA, period)
	assert.Equal(t, int64(0), micro, "zero-cost request moves no money")
	assert.Equal(t, int64(1), requestCount, "the team request is still counted")

	// And the zero spend cannot alone trigger the hard limit.
	require.NoError(t, budget.NewEnforcer(pool, silentLogger()).CheckBudget(ctx, imp13TeamA))
}
