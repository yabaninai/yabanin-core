package consumer

// step 2): the PER-JOB settlement paths — singletons (a group of one) and
// the fallback after a failed org batch — apply the same §5.3 semantics as
// the batch executor (NEXT-18d): the scope-row reserve drops by
// min(actual, bound) and the settle_decrement_micro_usd reconcile key
// commits atomically with status='settled'. A released allowance settles
// ledger-only (the reserve is never decremented twice), a replayed settle
// whose charge already committed is an idempotent no-op, and §7.1.3
// (reserved = Σ granted − returned − settled) holds after every pass.
//
// The §13 reservation objects come from applyConsumerReservationFixture
// (next18d_live_test.go) — the same idempotent DDL block the production
// migration covers.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// imp99r1ScopeStates is the n18dScopeStates projection the single-intent
// checks assert against.
type imp99r1ScopeStates struct {
	walletReserved  int64
	teamReserved    int64
	teamSpend       int64
	agentReserved   int64
	agentCost       int64
	sessionReserved int64
	sessionSpent    int64
	ledgerRows      int64
	ledgerMicro     int64
}

func imp99r1ReadScopeStates(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) imp99r1ScopeStates {
	t.Helper()
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, org)
	return imp99r1ScopeStates{
		walletReserved:  walletReserved,
		teamReserved:    teamReserved,
		teamSpend:       teamSpend,
		agentReserved:   agentReserved,
		agentCost:       agentCost,
		sessionReserved: sessionReserved,
		sessionSpent:    sessionSpent,
		ledgerRows:      ledgerRows,
		ledgerMicro:     ledgerMicro,
	}
}

// imp99r1SeedJob inserts one settlement job with the production intent
// shape: the scope payload plus the allowance linkage (payload keys and
// the allowance_id column, §5.3 Finalize tuple).
func imp99r1SeedJob(ctx context.Context, t *testing.T, pool SettlementDB, org, requestID, kind string, amountMicro int64, payload map[string]any, allowanceID int64) int64 {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)
	var id int64
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload, allowance_id)
		VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)
		RETURNING id`,
		org, requestID, kind, money.MicroUSD(amountMicro).Cents(), amountMicro, payloadBytes, allowanceID).Scan(&id),
		"seed settlement job")
	return id
}

func imp99r1SettleKey(ctx context.Context, t *testing.T, pool SettlementDB, jobID int64) *int64 {
	t.Helper()
	var key *int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT (payload->>'settle_decrement_micro_usd')::bigint FROM settlement_jobs WHERE id = $1`, jobID).Scan(&key),
		"read reconcile settle key")
	return key
}

// imp99r1Worker builds a worker whose queue runs over db (the real pool or
// a flaky wrapper) while the money stores stay on the real pool — the same
// wiring the crash-window tests use.
func imp99r1Worker(db SettlementDB, pool *pgxpool.Pool) *SettlementWorker {
	return NewSettlementWorker(db,
		credits.NewStore(pool, silentLogger()),
		budget.NewAgentEnforcer(pool, silentLogger()),
		silentLogger()).WithConfig(liveSettlementConfig())
}

// Acceptance «одиночный intent с линком → reserved уменьшился,
// payload-ключ записан»: every charge kind settles through the per-job
// executor when its org group holds exactly one job — the money side
// effect, the §5.3 reserve release and the reconcile key commit together.
func TestImp99R1Live_SingleIntentPerJobSettleReleasesReserve(t *testing.T) {
	const bound = int64(12_000)
	tests := []struct {
		name      string
		kind      string
		allowance func(fx n18dFixture) int64
		payload   func(allowanceID int64) map[string]any
		check     func(st imp99r1ScopeStates)
	}{
		{
			name:      "wallet/resale",
			kind:      ChargeKindResaleDeduction,
			allowance: func(fx n18dFixture) int64 { return fx.walletAllowance },
			payload: func(id int64) map[string]any {
				return map[string]any{"model": "gpt-4", "tokens_in": 10, "tokens_out": 5, "allowance_id": id, "bound_micro_usd": bound}
			},
			check: func(st imp99r1ScopeStates) {
				assert.Zero(t, st.walletReserved, "wallet reserve released by the per-job settle")
				assert.Equal(t, int64(1), st.ledgerRows, "one usage row")
				assert.Equal(t, -bound, st.ledgerMicro, "wallet charged the exact amount")
			},
		},
		{
			name:      "team_month",
			kind:      ChargeKindTeamSpend,
			allowance: func(fx n18dFixture) int64 { return fx.teamAllowance },
			payload: func(id int64) map[string]any {
				return map[string]any{"team_id": n18dTeam, "period": "2026-10", "allowance_id": id, "bound_micro_usd": bound}
			},
			check: func(st imp99r1ScopeStates) {
				assert.Zero(t, st.teamReserved, "team reserve released")
				assert.Equal(t, bound, st.teamSpend, "team exact spend")
			},
		},
		{
			name:      "agent_day",
			kind:      ChargeKindAgentSpend,
			allowance: func(fx n18dFixture) int64 { return fx.agentAllowance },
			payload: func(id int64) map[string]any {
				return map[string]any{"agent_id": n18dAgent, "tokens_in": 10, "tokens_out": 5, "allowance_id": id, "bound_micro_usd": bound}
			},
			check: func(st imp99r1ScopeStates) {
				assert.Zero(t, st.agentReserved, "agent reserve released")
				assert.Equal(t, bound, st.agentCost, "agent exact spend")
			},
		},
		{
			name:      "session",
			kind:      ChargeKindSessionSpend,
			allowance: func(fx n18dFixture) int64 { return fx.sessionAllowance },
			payload: func(id int64) map[string]any {
				return map[string]any{"session_key_id": n18dSession, "allowance_id": id, "bound_micro_usd": bound}
			},
			check: func(st imp99r1ScopeStates) {
				assert.Zero(t, st.sessionReserved, "session reserve released")
				assert.Equal(t, bound, st.sessionSpent, "session exact spend")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, pool, _ := newNext18dEnv(t)
			fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

			allowanceID := tt.allowance(fx)
			jobID := imp99r1SeedJob(ctx, t, pool, n18dOrg, "req-imp99r1-single", tt.kind, bound, tt.payload(allowanceID), allowanceID)

			// Exactly one job in the queue → group of one → per-job path.
			imp99r1Worker(pool, pool).tick(ctx)

			status, attempts, lastErr := jobStatus(ctx, t, pool, jobID)
			require.Equal(t, "settled", status, "attempts=%d last_err=%s", attempts, lastErr)
			key := imp99r1SettleKey(ctx, t, pool, jobID)
			require.NotNil(t, key, "the reconcile settle key is written")
			assert.Equal(t, bound, *key, "min(actual, bound) recorded for the reconcile")
			tt.check(imp99r1ReadScopeStates(ctx, t, pool, n18dOrg))
		})
	}
}

// Acceptance «поздний settle после reconcile»: a released allowance settles
// ledger-only — the reserve is not decremented twice and no reconcile key
// is written (§5.3).
func TestImp99R1Live_SingleIntentReleasedAllowanceLedgerOnly(t *testing.T) {
	ctx, pool, _ := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	const bound = int64(12_000)
	jobID := imp99r1SeedJob(ctx, t, pool, n18dOrg, "req-imp99r1-released", ChargeKindResaleDeduction, bound,
		map[string]any{"model": "gpt-4", "allowance_id": fx.walletAllowance, "bound_micro_usd": bound}, fx.walletAllowance)
	_, err := pool.Exec(ctx, `UPDATE budget_allowances SET status = 'released' WHERE id = $1`, fx.walletAllowance)
	require.NoError(t, err)

	imp99r1Worker(pool, pool).tick(ctx)

	status, _, _ := jobStatus(ctx, t, pool, jobID)
	require.Equal(t, "settled", status)
	st := imp99r1ReadScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, bound, st.walletReserved, "reserve untouched — reconcile already owns it")
	assert.Nil(t, imp99r1SettleKey(ctx, t, pool, jobID), "no reconcile key without a decrement")
}

// Acceptance «crash-окно charge→settle закрыто»: a re-claimed resale job
// whose charge committed but whose settle transaction never ran (no
// reconcile key in the payload) applies the missed §5.3 release on the
// retry — one charge, one decrement, the key lands with status='settled'.
// A job whose payload ALREADY carries the key (settled once, mark
// externally lost) re-marks settled without a second decrement — that
// replay shape is TestNext18dLive_CrashBetweenCommitAndAckNoDoubleCharge.
func TestImp99R1Live_ResaleCrashWindowAppliesMissedRelease(t *testing.T) {
	ctx, pool, _ := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	const bound = int64(12_000)
	jobID := imp99r1SeedJob(ctx, t, pool, n18dOrg, "req-imp99r1-crash", ChargeKindResaleDeduction, bound,
		map[string]any{"model": "gpt-4", "allowance_id": fx.walletAllowance, "bound_micro_usd": bound}, fx.walletAllowance)
	// The charge of the earlier run: committed; its settle (and therefore
	// the reserve release) never committed — the job is back in the queue.
	_, err := pool.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id, metadata, amount_micro_usd)
		VALUES ($1, -120, 880, 'usage', $2, '{}'::jsonb, $3)`, n18dOrg, "req-imp99r1-crash", -bound)
	require.NoError(t, err)

	imp99r1Worker(pool, pool).tick(ctx)

	status, _, _ := jobStatus(ctx, t, pool, jobID)
	require.Equal(t, "settled", status)
	st := imp99r1ReadScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, st.walletReserved, "the missed §5.3 release is applied on the retry")
	assert.Equal(t, int64(1), st.ledgerRows, "the replayed charge is an idempotent no-op")
	key := imp99r1SettleKey(ctx, t, pool, jobID)
	require.NotNil(t, key)
	assert.Equal(t, bound, *key, "the key commits exactly when the reserve moves")
}

// Acceptance «fallback после отказавшего батча»: the org batch transaction
// fails (transient outage on its first statement), nothing commits, and the
// per-job executor re-runs the whole group from scratch — every refused job
// applies its money side effect, its §5.3 reserve release and its reconcile
// key; a second tick changes nothing (exactly once).
func TestImp99R1Live_BatchFailureFallbackAppliesReserveRelease(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:imp99r1", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("imp99r1-fb1", "req-imp99r1-fb", n18dOrg, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "four scope intents, one org group → batch path first")

	// The batch's very first statement (the per-org advisory lock) fails
	// once: SettleOrgBatch commits NOTHING and the worker falls back to the
	// per-job executor — the reference semantics for this fallback.
	flaky := &flakySettlementDB{
		inner:    pool,
		failNext: map[string]int{"pg_advisory_xact_lock": 1},
		failErr:  errors.New("injected batch outage"),
	}
	w := NewSettlementWorker(flaky,
		credits.NewStore(pool, silentLogger()),
		budget.NewAgentEnforcer(pool, silentLogger()),
		silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	var settled, withKey int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'settled'),
		       count(*) FILTER (WHERE payload ? 'settle_decrement_micro_usd')
		FROM settlement_jobs WHERE org_id = $1`, n18dOrg).Scan(&settled, &withKey))
	assert.Equal(t, int64(4), settled, "every refused job settled through the per-job fallback")
	assert.Equal(t, int64(4), withKey, "every fallback settle carries its reconcile key")

	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved+teamReserved+agentReserved+sessionReserved,
		"§7.1.3: every scope reserve released exactly once after the fallback")
	assert.Equal(t, int64(fx.bound), teamSpend)
	assert.Equal(t, int64(fx.bound), agentCost)
	assert.Equal(t, int64(fx.bound), sessionSpent)
	assert.Equal(t, int64(1), ledgerRows)
	assert.Equal(t, -int64(fx.bound), ledgerMicro)

	// Idempotence: the settled queue never re-bills or re-decrements.
	w.tick(ctx)
	walletReserved2, teamReserved2, teamSpend2, agentReserved2, agentCost2, sessionReserved2, sessionSpent2, ledgerRows2, ledgerMicro2 := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved2+teamReserved2+agentReserved2+sessionReserved2)
	assert.Equal(t, teamSpend, teamSpend2)
	assert.Equal(t, agentCost, agentCost2)
	assert.Equal(t, sessionSpent, sessionSpent2)
	assert.Equal(t, ledgerRows, ledgerRows2)
	assert.Equal(t, ledgerMicro, ledgerMicro2)
}
