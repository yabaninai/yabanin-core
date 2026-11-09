package consumer

import (
	"context"
	"encoding/json"

	"testing"

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

// NEXT-18d live acceptance (disposable PG+Redis, ADR-0001 rev. 3 §10.5/10.6):
// reservation-backed events create settlement intents for EVERY scope, the
// worker settles them as one batch per org (ledger + spend upserts + job
// transitions + reserve decrement in one transaction), replays and crash
// recoveries never double-charge, partial usage bills in enforce and only
// counts metrics in shadow, and unknown usage is the distinct uncharged
// state.
//
// The §13 reservation schema (budget_allowances, reserved columns,
// session_spend, allowance_id, reservations_mode) lands with NEXT-18a's
// 0023 migration; the fixture applies the same idempotent DDL block so the
// tests run before and after that merge.

const (
	n18dOrg       = "181d0000-0000-4000-8000-00000000000a"
	n18dOrgShadow = "181d0000-0000-4000-8000-00000000000b"
	n18dOrgEnf    = "181d0000-0000-4000-8000-00000000000c"
	n18dTeam      = "181dab00-0000-4000-8000-00000000000a"
	n18dAgent     = "181dac00-0000-4000-8000-00000000000a"
	n18dSession   = "181dad00-0000-4000-8000-00000000000a"
)

// n18dFixture is one seeded reservation world: four allowances with their
// scope rows holding the reserved bounds.
type n18dFixture struct {
	walletAllowance  int64
	teamAllowance    int64
	agentAllowance   int64
	sessionAllowance int64
	bound            money.MicroUSD
}

func newNext18dEnv(t *testing.T) (context.Context, *pgxpool.Pool, *redis.Client) {
	t.Helper()
	ctx, pool, rdb := newInboxLiveEnv(t)
	// deductor_test tears the credit tables down on cleanup; recreate them
	// (the fixture's ADD COLUMN IF NOT EXISTS restores the §13 columns).
	setupCreditTables(ctx, t, pool)
	applyConsumerReservationFixture(ctx, t, pool)
	return ctx, pool, rdb
}

// applyConsumerReservationFixture mirrors the §13 schema block (ADR-0001
// rev. 3) for the consumer-package live tests. Idempotent additive DDL —
// a no-op once NEXT-18a's 0023 migration is applied by the runner.
func applyConsumerReservationFixture(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS budget_allowances (
			id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			replica_id text NOT NULL,
			scope_kind text NOT NULL CHECK (scope_kind IN ('wallet','team_month','agent_day','session')),
			scope_key text NOT NULL,
			period text NOT NULL DEFAULT '',
			org_id text NOT NULL,
			granted_micro_usd bigint NOT NULL DEFAULT 0 CHECK (granted_micro_usd >= 0),
			returned_micro_usd bigint NOT NULL DEFAULT 0 CHECK (returned_micro_usd >= 0),
			status text NOT NULL DEFAULT 'active'
				CHECK (status IN ('active','expired','draining','released')),
			lease_until timestamptz NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT budget_allowances_key UNIQUE (replica_id, scope_kind, scope_key, period)
		)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		ALTER TABLE org_credits ADD COLUMN IF NOT EXISTS reserved_micro_usd bigint NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0),
		                 ADD COLUMN IF NOT EXISTS grace_floor_cents bigint CHECK (grace_floor_cents BETWEEN -100000 AND 0)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		ALTER TABLE team_spend_monthly ADD COLUMN IF NOT EXISTS spend_micro_usd bigint NOT NULL DEFAULT 0,
		                               ADD COLUMN IF NOT EXISTS reserved_micro_usd bigint NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `ALTER TABLE agent_spend_daily ADD COLUMN IF NOT EXISTS reserved_micro_usd bigint NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS session_spend (
			session_key_id uuid PRIMARY KEY,
			spent_micro_usd bigint NOT NULL DEFAULT 0,
			reserved_micro_usd bigint NOT NULL DEFAULT 0 CHECK (reserved_micro_usd >= 0),
			updated_at timestamptz NOT NULL DEFAULT now()
		)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `ALTER TABLE settlement_jobs ADD COLUMN IF NOT EXISTS allowance_id bigint`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		ALTER TABLE organizations ADD COLUMN IF NOT EXISTS reservations_mode text NOT NULL DEFAULT 'off'
		                          CHECK (reservations_mode IN ('off','shadow','enforce')),
		                          ADD COLUMN IF NOT EXISTS default_output_cap_tokens integer CHECK (default_output_cap_tokens > 0)`)
	require.NoError(t, err)
	// The production usage idempotency index (some package tests drop it).
	_, err = pool.Exec(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS uniq_credit_transactions_usage_request_id
		ON credit_transactions (request_id)
		WHERE request_id IS NOT NULL AND type = 'usage'`)
	require.NoError(t, err)
}

// seedNext18dWorld creates the orgs (with their reservations modes), the
// wallet, the team and the per-scope allowance rows; each scope row holds
// reserved = bound (one in-flight request).
func seedNext18dWorld(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string, balanceCents int64) n18dFixture {
	t.Helper()
	for _, o := range []struct {
		id   string
		mode string
	}{{n18dOrg, "off"}, {n18dOrgShadow, "shadow"}, {n18dOrgEnf, "enforce"}} {
		_, err := pool.Exec(ctx, `
			INSERT INTO organizations (id, name, slug, reservations_mode)
			VALUES ($1, $2, $2, $3)
			ON CONFLICT (id) DO UPDATE SET reservations_mode = EXCLUDED.reservations_mode`, o.id, "n18d-"+o.id[26:], o.mode)
		require.NoError(t, err)
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations_teams (id, org_id, name, slug) VALUES ($1, $2, 'n18d-team', 'n18d-team')
		ON CONFLICT (id) DO NOTHING`, n18dTeam, org)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit) VALUES ($1, 100, true)
		ON CONFLICT (team_id) DO UPDATE SET monthly_limit_usd = 100, hard_limit = true`, n18dTeam)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM team_spend_monthly WHERE team_id = $1`, n18dTeam)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM agent_spend_daily WHERE agent_id = $1`, n18dAgent)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM session_spend WHERE session_key_id = $1`, n18dSession)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM budget_allowances WHERE org_id = $1 OR replica_id = $2`, org, "replica-"+org)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd)
		VALUES ($1, $2, 0)
		ON CONFLICT (org_id) DO UPDATE SET balance_cents = EXCLUDED.balance_cents,
			remainder_micro_usd = 0, reserved_micro_usd = 0`, org, balanceCents)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, org)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM settlement_jobs WHERE org_id = $1`, org)
	require.NoError(t, err)

	const bound = int64(12_000) // $0.012 per request, every scope
	// The allowance natural key (replica, scope_kind, scope_key, period)
	// excludes org_id — a per-org replica id keeps tests (and multi-org
	// reality) collision-free.
	replica := "replica-" + org
	seedAllowance := func(scope, key, period string) int64 {
		var id int64
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, period, org_id, granted_micro_usd, status, lease_until)
			VALUES ($1, $2, $3, $4, $5, $6, 'active', now() + interval '10 minutes')
			RETURNING id`, replica, scope, key, period, org, bound).Scan(&id))
		return id
	}
	fx := n18dFixture{
		walletAllowance:  seedAllowance("wallet", org, ""),
		teamAllowance:    seedAllowance("team_month", n18dTeam, "2026-10"),
		agentAllowance:   seedAllowance("agent_day", n18dAgent, "2026-10-02"),
		sessionAllowance: seedAllowance("session", n18dSession, ""),
		bound:            money.MicroUSD(bound),
	}
	_, err = pool.Exec(ctx, `UPDATE org_credits SET reserved_micro_usd = $2 WHERE org_id = $1`, org, bound)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO team_spend_monthly (team_id, period, reserved_micro_usd) VALUES ($1, '2026-10', $2)
		ON CONFLICT (team_id, period) DO UPDATE SET reserved_micro_usd = $2`, n18dTeam, bound)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO agent_spend_daily (agent_id, day, reserved_micro_usd) VALUES ($1, '2026-10-02', $2)
		ON CONFLICT (agent_id, day) DO UPDATE SET reserved_micro_usd = $2`, n18dAgent, bound)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO session_spend (session_key_id, reserved_micro_usd) VALUES ($1, $2)
		ON CONFLICT (session_key_id) DO UPDATE SET reserved_micro_usd = $2`, n18dSession, bound)
	require.NoError(t, err)
	return fx
}

// n18dCompletedMsg builds a reservation-backed request.completed event with
// the §5.3 Finalize tuples and termination.
func n18dCompletedMsg(entryID, requestID, org string, fx n18dFixture) redis.XMessage {
	tuples := []map[string]any{
		{"scope_kind": "wallet", "scope_key": org, "period": "", "allowance_id": fx.walletAllowance, "bound_micro_usd": int64(fx.bound)},
		{"scope_kind": "team_month", "scope_key": n18dTeam, "period": "2026-10", "allowance_id": fx.teamAllowance, "bound_micro_usd": int64(fx.bound)},
		{"scope_kind": "agent_day", "scope_key": n18dAgent, "period": "2026-10-02", "allowance_id": fx.agentAllowance, "bound_micro_usd": int64(fx.bound)},
		{"scope_kind": "session", "scope_key": n18dSession, "period": "", "allowance_id": fx.sessionAllowance, "bound_micro_usd": int64(fx.bound)},
	}
	reservations, err := json.Marshal(tuples)
	if err != nil {
		panic(err) // static structure — never happens
	}
	return redis.XMessage{ID: entryID, Values: map[string]interface{}{
		"event_type": "request.completed", "source": "gateway",
		"request_id": requestID, "org_id": org,
		"model_requested": "gpt-4", "model_used": "gpt-4",
		"status_code": "200", "tokens_in": "100", "tokens_out": "20",
		"estimated_cost_usd": "0.012",
		"team_id":            n18dTeam, "agent_id": n18dAgent, "session_key_id": n18dSession,
		"termination":  "completed",
		"reservations": string(reservations),
	}}
}

func n18dJobCount(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM settlement_jobs WHERE org_id = $1`, org).Scan(&n))
	return n
}

func n18dScopeStates(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) (walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro int64) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, org).Scan(&walletReserved))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(reserved_micro_usd),0), COALESCE(SUM(spend_micro_usd),0) FROM team_spend_monthly WHERE team_id = $1`, n18dTeam).Scan(&teamReserved, &teamSpend))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(reserved_micro_usd),0), COALESCE(SUM(cost_micro_usd),0) FROM agent_spend_daily WHERE agent_id = $1`, n18dAgent).Scan(&agentReserved, &agentCost))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(reserved_micro_usd),0), COALESCE(SUM(spent_micro_usd),0) FROM session_spend WHERE session_key_id = $1`, n18dSession).Scan(&sessionReserved, &sessionSpent))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*), COALESCE(SUM(amount_micro_usd),0) FROM credit_transactions WHERE org_id = $1 AND type = 'usage'`, org).Scan(&ledgerRows, &ledgerMicro))
	return
}

// Acceptance "интенты по всем областям + одно пакетное списание": a
// completed event carrying four reserve tuples creates one intent per
// scope; the worker settles them in one batch transaction — wallet ledger,
// exact spend upserts, settled jobs and the reserve decrements of all four
// scopes commit together; reserved drops by min(actual, bound) per scope.
func TestNext18dLive_IntentsForAllScopesBatchSettle(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n18d", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("181d-1", "req-n18d-all", n18dOrg, fx)))

	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "one intent per reserve scope")

	// The intents carry the allowance linkage: payload keys + the column.
	var link struct {
		AllowanceID   int64  `json:"allowance_id"`
		BoundMicroUSD int64  `json:"bound_micro_usd"`
		Kind          string `json:"-"`
	}
	var allowanceCol int64
	rows, err := pool.Query(ctx, `SELECT charge_kind, payload, allowance_id FROM settlement_jobs WHERE org_id = $1`, n18dOrg)
	require.NoError(t, err)
	seen := map[string]bool{}
	for rows.Next() {
		var kind string
		var payload []byte
		require.NoError(t, rows.Scan(&kind, &payload, &allowanceCol))
		require.NoError(t, json.Unmarshal(payload, &link))
		seen[kind] = true
		assert.NotZero(t, allowanceCol, "kind %s: allowance_id column set", kind)
		assert.Equal(t, int64(fx.bound), link.BoundMicroUSD, "kind %s: bound in payload", kind)
		assert.NotZero(t, link.AllowanceID, "kind %s: allowance in payload", kind)
	}
	rows.Close()
	assert.True(t, seen[ChargeKindResaleDeduction] && seen[ChargeKindTeamSpend] &&
		seen[ChargeKindAgentSpend] && seen[ChargeKindSessionSpend], "all four scope intents exist: %v", seen)

	// Worker: the four jobs of the org settle as ONE batch transaction.
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved, "wallet reserve released by the settle")
	assert.Zero(t, teamReserved, "team reserve released")
	assert.Zero(t, agentReserved, "agent reserve released")
	assert.Zero(t, sessionReserved, "session reserve released")
	assert.Equal(t, int64(fx.bound), teamSpend, "team exact spend")
	assert.Equal(t, int64(fx.bound), agentCost, "agent exact spend")
	assert.Equal(t, int64(fx.bound), sessionSpent, "session exact spend")
	assert.Equal(t, int64(1), ledgerRows, "one wallet usage row")
	assert.Equal(t, -int64(fx.bound), ledgerMicro, "wallet exact charge (ledger deduction)")

	// Every job settled, every applied decrement recorded for the reconcile.
	var settled, withKey int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'settled'),
		       count(*) FILTER (WHERE payload ? 'settle_decrement_micro_usd')
		FROM settlement_jobs WHERE org_id = $1`, n18dOrg).Scan(&settled, &withKey))
	assert.Equal(t, int64(4), settled)
	assert.Equal(t, int64(4), withKey, "reconcile key on every reserve-linked settle")

	// The settled queue never re-bills: a second tick changes nothing.
	w.tick(ctx)
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved)
	assert.Zero(t, teamReserved)
	assert.Zero(t, agentReserved)
	assert.Zero(t, sessionReserved)
	assert.Equal(t, int64(fx.bound), teamSpend, "one team charge after the second tick")
	assert.Equal(t, int64(fx.bound), agentCost)
	assert.Equal(t, int64(fx.bound), sessionSpent)
	assert.Equal(t, int64(1), ledgerRows)
	assert.Equal(t, -int64(fx.bound), ledgerMicro)
}

// Acceptance "replay/дубль — одно списание по всем областям": the same
// event delivered twice (fresh stream entries) keeps one job per identity
// and one charge per scope; the replayed delivery never creates a second
// charge or a second decrement.
func TestNext18dLive_ReplayDuplicateSingleCharge(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n18d", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("181d-r1", "req-n18d-replay", n18dOrg, fx)))
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("181d-r2", "req-n18d-replay", n18dOrg, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "duplicate delivery adds no intents")

	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)
	w.tick(ctx)

	walletReserved, _, teamSpend, _, agentCost, _, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved)
	assert.Equal(t, int64(1), ledgerRows, "one wallet charge")
	assert.Equal(t, -int64(fx.bound), ledgerMicro)
	assert.Equal(t, int64(fx.bound), teamSpend)
	assert.Equal(t, int64(fx.bound), agentCost)
	assert.Equal(t, int64(fx.bound), sessionSpent)
}

// Acceptance "crash между commit и ACK — без дубля": a committed wallet
// charge whose job lost its settle-mark (forced back to retry — the crash
// window of the per-job path and of any pre-batch job) replays as an
// idempotent no-op: the ledger keeps one row, the wallet is not debited
// twice and the reserve is not decremented twice. The spend upserts
// (team/agent/session) commit atomically with their settle-mark inside the
// batch transaction, so no replay of them can exist — their jobs stay
// settled and untouched.
func TestNext18dLive_CrashBetweenCommitAndAckNoDoubleCharge(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n18d", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("181d-c1", "req-n18d-crash", n18dOrg, fx)))

	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)
	before, _, teamSpend, _, agentCost, _, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	require.Zero(t, before)
	require.Equal(t, int64(1), ledgerRows)

	// Crash simulation: the wallet job back to the retry queue (lost
	// settle mark, money already committed).
	_, err := pool.Exec(ctx, `
		UPDATE settlement_jobs SET status = 'retry', next_attempt_at = now() - interval '1 second', lease_until = NULL
		WHERE org_id = $1 AND charge_kind = $2`, n18dOrg, ChargeKindResaleDeduction)
	require.NoError(t, err)
	w.tick(ctx)

	walletReserved, _, teamSpend2, _, agentCost2, _, sessionSpent2, ledgerRows2, ledgerMicro2 := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved, "reserve decremented exactly once")
	assert.Equal(t, ledgerRows, ledgerRows2, "no second ledger row")
	assert.Equal(t, ledgerMicro, ledgerMicro2, "no second wallet debit")
	assert.Equal(t, teamSpend, teamSpend2, "no second team spend")
	assert.Equal(t, agentCost, agentCost2, "no second agent spend")
	assert.Equal(t, sessionSpent, sessionSpent2, "no second session spend")

	var settled int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM settlement_jobs WHERE org_id = $1 AND status = 'settled'`, n18dOrg).Scan(&settled))
	assert.Equal(t, int64(4), settled, "replayed wallet job settles as a no-op")
}

// Acceptance "частичный usage enforce биллится": a request.failed that
// reached the provider with a known price bills every reserved scope in
// client-side interrupt kinds — upstream_error is absorbed by the platform
// and never bills (see r041_settlement_cancel_live_test.go); a failed
func TestNext18dLive_PartialUsageEnforceBills(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgEnf, 1000)

	msg := n18dCompletedMsg("181d-p1", "req-n18d-partial", n18dOrgEnf, fx)
	msg.Values["event_type"] = "request.failed"
	msg.Values["termination"] = "client_cancel"
	msg.Values["usage_source"] = "provider"
	msg.Values["status_code"] = "499"
	msg.Values["error"] = "client disconnected after first tokens"

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n18d", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, msg))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrgEnf), "partial usage bills every reserved scope")

	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, walletReserved)
	assert.Zero(t, teamReserved)
	assert.Zero(t, agentReserved)
	assert.Zero(t, sessionReserved)
	assert.Equal(t, -int64(fx.bound), ledgerMicro, "wallet billed the partial usage exactly once")
	assert.Equal(t, int64(fx.bound), teamSpend, "team billed the partial usage")
	assert.Equal(t, int64(fx.bound), agentCost, "agent billed the partial usage")
	assert.Equal(t, int64(fx.bound), sessionSpent, "session billed the partial usage")
	assert.Equal(t, int64(1), ledgerRows)
}

// Acceptance "shadow — только метрика": the same partial-usage failure in
// shadow mode bills nothing and counts would_bill_partial_micro_usd.
func TestNext18dLive_PartialUsageShadowMetricOnly(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgShadow, 1000)

	msg := n18dCompletedMsg("181d-s1", "req-n18d-shadow", n18dOrgShadow, fx)
	msg.Values["event_type"] = "request.failed"
	msg.Values["termination"] = "client_cancel"
	msg.Values["usage_source"] = "provider"
	msg.Values["status_code"] = "499"

	walletBefore := testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet"))
	teamBefore := testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("team_month"))
	sessionBefore := testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("session"))

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n18d", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, msg))
	require.Zero(t, n18dJobCount(ctx, t, pool, n18dOrgShadow), "shadow never bills")

	_, _, _, _, _, _, _, ledgerRows, _ := n18dScopeStates(ctx, t, pool, n18dOrgShadow)
	assert.Zero(t, ledgerRows)

	assert.InDelta(t, walletBefore+float64(fx.bound),
		testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet")), 0.001)
	assert.InDelta(t, teamBefore+float64(fx.bound),
		testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("team_month")), 0.001)
	assert.InDelta(t, sessionBefore+float64(fx.bound),
		testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("session")), 0.001)
}

// Acceptance "unknown usage → не ноль": an unknown price/usage with a
// reserve bills nothing, counts uncharged_unknown_total per scope and
// leaves the reserve to the reconcile (never reported as a silent zero).
func TestNext18dLive_UnknownUsageUncharged(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	msg := n18dCompletedMsg("181d-u1", "req-n18d-unknown", n18dOrg, fx)
	delete(msg.Values, "estimated_cost_usd") // unknown price

	walletBefore := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet"))
	sessionBefore := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("session"))

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n18d", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, msg))

	// request is counted, amount 0 for an unknown price) still exist for
	// adds the non-charge pending_price visibility record for the unknown
	// cost — a fourth row with no amount and no billing semantics.
	var zeroAmount, pendingPrice, total int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE amount_micro_usd = 0 AND charge_kind <> 'pending_price'),
		       count(*) FILTER (WHERE charge_kind = 'pending_price' AND status = 'pending_price'),
		       count(*)
		FROM settlement_jobs WHERE org_id = $1`, n18dOrg).Scan(&zeroAmount, &pendingPrice, &total))
	assert.Equal(t, int64(3), zeroAmount, "team/agent/session count intents stay at zero amount")
	assert.Equal(t, int64(1), pendingPrice, "the unknown cost is visible as one pending_price record")
	assert.Equal(t, int64(4), total, "no wallet intent for an unknown price")

	assert.InDelta(t, walletBefore+float64(fx.bound),
		testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001, "wallet bound counted uncharged")
	assert.InDelta(t, sessionBefore+float64(fx.bound),
		testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("session")), 0.001, "session bound counted uncharged")

	// The reserve of the uncharged event stays until reconcile releases it
	// (§6): the wallet job that never existed cannot decrement it, and the
	// zero-amount team/agent settles decrement min(0, bound) = 0.
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)
	walletReserved, _, _, _, _, sessionReserved, sessionSpent, ledgerRows, _ := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(fx.bound), walletReserved, "unknown-usage reserve intact for reconcile")
	assert.Equal(t, int64(fx.bound), sessionReserved)
	assert.Zero(t, sessionSpent)
	assert.Zero(t, ledgerRows)
}

// The settled batch keeps the §5.3 invariant on a mixed world: reserved =
// Σ (granted − returned − settled) of live allowances after the settle.
func TestNext18dLive_ReservedInvariantConsistent(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n18d", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("181d-i1", "req-n18d-inv", n18dOrg, fx)))

	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	// Σ settle keys of settled jobs per allowance == the decrement that
	// left every scope row: wallet granted(12k) − settled(12k) = 0.
	var sumWallet, sumTeam, sumAgent, sumSession int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN a.scope_kind = 'wallet' THEN (j.payload->>'settle_decrement_micro_usd')::bigint ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN a.scope_kind = 'team_month' THEN (j.payload->>'settle_decrement_micro_usd')::bigint ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN a.scope_kind = 'agent_day' THEN (j.payload->>'settle_decrement_micro_usd')::bigint ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN a.scope_kind = 'session' THEN (j.payload->>'settle_decrement_micro_usd')::bigint ELSE 0 END), 0)
		FROM settlement_jobs j JOIN budget_allowances a ON a.id = j.allowance_id
		WHERE j.org_id = $1 AND j.status = 'settled'`, n18dOrg).Scan(&sumWallet, &sumTeam, &sumAgent, &sumSession))
	assert.Equal(t, int64(fx.bound), sumWallet)
	assert.Equal(t, int64(fx.bound), sumTeam)
	assert.Equal(t, int64(fx.bound), sumAgent)
	assert.Equal(t, int64(fx.bound), sumSession)

	walletReserved, teamReserved, _, agentReserved, _, sessionReserved, _, _, _ := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved+teamReserved+agentReserved+sessionReserved,
		"reserved(S) = granted − settled after the settle, per scope row")
}

// Partial usage of a request denied BEFORE the provider (no usage) bills
// nothing in any mode — the reserve is released without a charge (§6).
func TestNext18dLive_PolicyDeniedBeforeProviderBillsNothing(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgEnf, 1000)

	msg := n18dCompletedMsg("181d-d1", "req-n18d-denied", n18dOrgEnf, fx)
	msg.Values["event_type"] = "request.failed"
	msg.Values["termination"] = "policy_denied"
	msg.Values["usage_source"] = "none"
	msg.Values["status_code"] = "403"
	msg.Values["error"] = "model_unpriced"

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n18d", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, msg))
	assert.Zero(t, n18dJobCount(ctx, t, pool, n18dOrgEnf), "no intents without usage")

	_, _, _, _, _, _, _, ledgerRows, _ := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, ledgerRows)
}
