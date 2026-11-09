package budget

// fully migrated Postgres (testdb.Postgres, no build tag — the harness
// posture of pkg/adminstore sqlcontract_int_test.go). The contract runs the
// production SQL of the team/agent enforcers, the 0023 reservation store
// (all four §4.1 scopes incl. reserved_micro_usd / grace_floor_cents) and
// the batched settlement executor, failing on any *pgconn.PgError (rejected
// columns/types/placeholders) or rows breakage. Business outcomes (no
// budget row, capacity refusal, floor crossing) are asserted where they pin
// the semantics. estimator.go has no SQL — pure bound math.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sqlc03fBudgetContract fails the test when Postgres rejects the SQL (any
// *pgconn.PgError); other errors are business answers and only logged.
func sqlc03fBudgetContract(t *testing.T, name string, fn func(ctx context.Context) error) {
	t.Helper()
	err := fn(context.Background())
	if err == nil {
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		t.Errorf("%s: Postgres rejected the SQL: %s (code %s, where %s, detail %q)",
			name, pgErr.Message, pgErr.Code, pgErr.Where, pgErr.Detail)
		return
	}
	t.Logf("%s: non-SQL error tolerated by the contract: %v", name, err)
}

type sqlc03fBudgetFixture struct {
	Token           string
	WalletOrg       string
	NoWalletOrg     string
	TeamHard        string // 100 USD hard — grant scopes
	TeamExceed      string // 2 USD hard — exceeded by the exact spend
	TeamSoft        string // 1 USD soft — advisory warn path
	AgentSpend      string // 500 cents/day — grants + cents spend
	AgentBatch      string // 500 cents/day — exceeded via exact micro
	SessionCapped   string // max_cost_usd = 1
	SessionUncapped string // max_cost_usd NULL — fail-closed scope
	Period          string
	Day             string
	ReconcileJobID  int64
	PayloadObjJobID int64
	PayloadArrJobID int64
	BatchJobResale  int64
	BatchJobTeam    int64
	BatchJobAgent   int64
	BatchJobSession int64
	BatchJobPoison  int64
	NoWalletJobID   int64
}

// sqlc03fBudgetScalar reads one integer for invariant assertions.
func sqlc03fBudgetScalar(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int64 {
	t.Helper()
	var v int64
	require.NoError(t, pool.QueryRow(context.Background(), query, args...).Scan(&v))
	return v
}

// sqlc03fBudgetAllowance reads one allowance by natural key.
func sqlc03fBudgetAllowance(t *testing.T, pool *pgxpool.Pool, replica string, scope ScopeKind, key, period string) (id, granted, returned int64, status string) {
	t.Helper()
	require.NoError(t, pool.QueryRow(context.Background(), `
		SELECT id, granted_micro_usd, returned_micro_usd, status FROM budget_allowances
		WHERE replica_id = $1 AND scope_kind = $2 AND scope_key = $3 AND period = $4`,
		replica, string(scope), key, period).Scan(&id, &granted, &returned, &status))
	return id, granted, returned, status
}

// sqlc03fBudgetJob inserts one settlement_jobs row and returns its id.
func sqlc03fBudgetJob(t *testing.T, pool *pgxpool.Pool, org, requestID, kind string, amountMicro int64, status string, payload any, allowanceID int64) int64 {
	t.Helper()
	payloadJSON := []byte("null")
	if payload != nil {
		var err error
		payloadJSON, err = json.Marshal(payload)
		require.NoError(t, err)
	}
	var id int64
	require.NoError(t, pool.QueryRow(context.Background(), `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, amount_cents, amount_micro_usd, status, payload, allowance_id)
		VALUES ($1, $2, $3, $4::bigint / 10000, $4, $5, $6::jsonb,
		        CASE WHEN $7 > 0 THEN $7 END)
		RETURNING id`,
		org, requestID, kind, amountMicro, status, string(payloadJSON), allowanceID).Scan(&id))
	return id
}

func sqlc03fBudgetSeed(t *testing.T, pool *pgxpool.Pool) *sqlc03fBudgetFixture {
	t.Helper()
	ctx := context.Background()
	token := fmt.Sprintf("sc03f%x", time.Now().UnixNano())
	fx := &sqlc03fBudgetFixture{
		Token:           token,
		WalletOrg:       token + "-wallet",
		NoWalletOrg:     token + "-nowallet",
		TeamHard:        uuid.NewString(),
		TeamExceed:      uuid.NewString(),
		TeamSoft:        uuid.NewString(),
		AgentSpend:      uuid.NewString(),
		AgentBatch:      uuid.NewString(),
		SessionCapped:   uuid.NewString(),
		SessionUncapped: uuid.NewString(),
		Period:          time.Now().UTC().Format("2006-01"),
		Day:             time.Now().UTC().Format("2006-01-02"),
	}

	// Wallets: the money org holds 100 USD with the platform-default floor
	// (grace_floor_cents NULL, 0023 columns at rest); the batch no-wallet
	// org has deliberately no org_credits row.
	_, err := pool.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd, reserved_micro_usd, grace_floor_cents)
		VALUES ($1, 10000, 0, 0, NULL)`, fx.WalletOrg)
	require.NoError(t, err)

	// Team budgets: hard 100, hard 2, soft 1. team_budgets and
	// team_spend_monthly carry an FK to organizations_teams, so the teams
	// ride a real org → teams chain.
	var teamOrgID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		token+"-org").Scan(&teamOrgID))
	teams := map[string]*string{
		fx.TeamHard: nil, fx.TeamExceed: nil, fx.TeamSoft: nil,
	}
	for key := range teams {
		var id string
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO organizations_teams (org_id, name, slug) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
			teamOrgID, token+"-"+key, key).Scan(&id))
		teams[key] = &id
	}
	fx.TeamHard, fx.TeamExceed, fx.TeamSoft = *teams[fx.TeamHard], *teams[fx.TeamExceed], *teams[fx.TeamSoft]
	for _, tb := range []struct {
		team  string
		limit string
		hard  bool
	}{
		{fx.TeamHard, "100.00", true},
		{fx.TeamExceed, "2.00", true},
		{fx.TeamSoft, "1.00", false},
	} {
		_, err = pool.Exec(ctx, `
			INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
			VALUES ($1::uuid, $2, $3)`, tb.team, tb.limit, tb.hard)
		require.NoError(t, err, "seed team budget")
	}

	// Agent budgets: 500 cents/day.
	for _, agent := range []string{fx.AgentSpend, fx.AgentBatch} {
		_, err = pool.Exec(ctx,
			`INSERT INTO agent_budgets (agent_id, daily_limit_cents) VALUES ($1::uuid, 500)`, agent)
		require.NoError(t, err, "seed agent budget")
	}

	// Session keys ride the real FK chain org → api key → session key.
	var sessOrgID, apiKeyID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-sess-org", token+"-sess-org").Scan(&sessOrgID))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO api_keys (key_hash, org_id, name, team_id) VALUES ($1, $2::uuid, $3, $4::uuid) RETURNING id::text`,
		token+"-ak", sessOrgID, token+"-key", fx.TeamHard).Scan(&apiKeyID))
	for i, sk := range []struct {
		target  *string
		maxCost string
	}{
		{&fx.SessionCapped, "1.00"},
		{&fx.SessionUncapped, "NULL"},
	} {
		require.NoError(t, pool.QueryRow(ctx, fmt.Sprintf(`
			INSERT INTO session_keys (key_hash, org_id, parent_api_key_id, name, max_cost_usd, expires_at)
			VALUES ($1, $2::uuid, $3::uuid, $4, %s, now() + interval '24 hours') RETURNING id::text`, sk.maxCost),
			fmt.Sprintf("%s-sk-%d", token, i), sessOrgID, apiKeyID, token+"-session").Scan(sk.target))
	}

	// Settlement jobs for the reconcile branches: the settled job carries the
	// §5.4 settle-decrement key; the '{}' and '[]' payloads exercise the
	// jsonb_typeof branches of the reconcile sum (0 contribution each).
	fx.ReconcileJobID = sqlc03fBudgetJob(t, pool, fx.WalletOrg, token+"-j1", SettleKindResale,
		1_500_000, "settled", map[string]any{reconcileSettleKey: 1_500_000}, 0)
	fx.PayloadObjJobID = sqlc03fBudgetJob(t, pool, fx.WalletOrg, token+"-j2", SettleKindResale,
		100, "settled", map[string]any{}, 0)
	fx.PayloadArrJobID = sqlc03fBudgetJob(t, pool, fx.WalletOrg, token+"-j3", SettleKindResale,
		100, "settled", []any{"not-an-object"}, 0)

	// Batch jobs (org wallet): resale, team, agent, session + one poison.
	fx.BatchJobResale = sqlc03fBudgetJob(t, pool, fx.WalletOrg, token+"-br", SettleKindResale,
		1_500_000, "pending", map[string]any{"model": token + "-m", "tokens_in": 10, "tokens_out": 5}, 0)
	fx.BatchJobTeam = sqlc03fBudgetJob(t, pool, fx.WalletOrg, token+"-bt", SettleKindTeam,
		1_000_000, "pending", map[string]any{"team_id": fx.TeamExceed, "period": fx.Period}, 0)
	fx.BatchJobAgent = sqlc03fBudgetJob(t, pool, fx.WalletOrg, token+"-ba", SettleKindAgent,
		1_000_000, "pending", map[string]any{"agent_id": fx.AgentBatch, "tokens_in": 3, "tokens_out": 1}, 0)
	fx.BatchJobSession = sqlc03fBudgetJob(t, pool, fx.WalletOrg, token+"-bs", SettleKindSession,
		800_000, "pending", map[string]any{"session_key_id": fx.SessionCapped}, 0)
	fx.BatchJobPoison = sqlc03fBudgetJob(t, pool, fx.WalletOrg, "", SettleKindResale,
		100, "pending", nil, 0)
	fx.NoWalletJobID = sqlc03fBudgetJob(t, pool, fx.NoWalletOrg, token+"-nw", SettleKindResale,
		500_000, "pending", map[string]any{"model": token + "-m"}, 0)

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("budget contract cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM settlement_jobs WHERE org_id LIKE $1`, token+"%")
		cleanup(`DELETE FROM budget_allowances WHERE org_id = $1 OR replica_id LIKE $2`,
			fx.WalletOrg, "repl03f%")
		cleanup(`DELETE FROM session_spend WHERE session_key_id::text = ANY($1)`,
			[]string{fx.SessionCapped, fx.SessionUncapped})
		cleanup(`DELETE FROM session_keys WHERE key_hash LIKE $1`, token+"%")
		cleanup(`DELETE FROM api_keys WHERE key_hash LIKE $1`, token+"%")
		cleanup(`DELETE FROM agent_spend_daily WHERE agent_id::text = ANY($1)`,
			[]string{fx.AgentSpend, fx.AgentBatch})
		cleanup(`DELETE FROM agent_budgets WHERE agent_id::text = ANY($1)`,
			[]string{fx.AgentSpend, fx.AgentBatch})
		cleanup(`DELETE FROM team_spend_monthly WHERE team_id::text = ANY($1)`,
			[]string{fx.TeamHard, fx.TeamExceed, fx.TeamSoft})
		cleanup(`DELETE FROM team_budgets WHERE team_id::text = ANY($1)`,
			[]string{fx.TeamHard, fx.TeamExceed, fx.TeamSoft})
		cleanup(`DELETE FROM credit_transactions WHERE org_id LIKE $1`, token+"%")
		cleanup(`DELETE FROM org_credits WHERE org_id LIKE $1`, token+"%")
		cleanup(`DELETE FROM organizations WHERE name LIKE $1`, token+"%")
	})
	return fx
}

func TestSQLContractBudget(t *testing.T) {
	pool := testdb.Postgres(t)
	fx := sqlc03fBudgetSeed(t, pool)
	ctx := context.Background()
	grace := DefaultReservationConfig().DefaultGraceFloorCents

	// Shared-DB isolation: ReconcileRelease (and the zero-remainder branches)
	// scan every lapsed allowance in the database, not just this fixture's.
	// Sibling suites in this binary intentionally leave lapsed/expired
	// allowances behind; the historical 0023 up/down cycle used to wipe them
	// as a side effect, and the 0001_init consolidation removed that
	// accident. Park foreign candidates as released so the exact-sum
	// assertions below see only fixture state. Sibling cleanups already ran,
	// so this cannot break a live test.
	_, err := pool.Exec(ctx, `
		UPDATE budget_allowances SET status = 'released'
		WHERE org_id <> $1 AND status <> 'released'
		  AND (lease_until < now() OR status IN ('draining', 'expired'))`, fx.WalletOrg)
	require.NoError(t, err, "sweep foreign lapsed allowances")

	// --- Team enforcer: budget read, exact micro spend, hard/soft branches.
	sqlc03fBudgetContract(t, "CheckBudget[hard,zero-spend]", func(ctx context.Context) error {
		if err := NewEnforcer(pool, slog.Default()).CheckBudget(ctx, fx.TeamHard); err != nil {
			return fmt.Errorf("zero-spend hard-limit team must be admitted: %w", err)
		}
		return nil
	})
	require.ErrorIs(t, NewEnforcer(pool, slog.Default()).CheckBudget(ctx, uuid.NewString()), ErrNoBudget,
		"a team without a budget row must be denied")
	require.NoError(t, RecordTeamSpendExact(ctx, pool, fx.TeamExceed, fx.Period, 2_500_000))
	require.NoError(t, RecordTeamSpendExact(ctx, pool, fx.TeamExceed, fx.Period, 2_500_000),
		"caller-driven idempotency: a fresh request id is a legitimate second spend")
	require.ErrorIs(t, NewEnforcer(pool, slog.Default()).CheckBudget(ctx, fx.TeamExceed), ErrBudgetExceeded,
		"5 USD spend against a 2 USD hard limit must be exceeded")
	require.NoError(t, RecordTeamSpendExact(ctx, pool, fx.TeamSoft, fx.Period, 2_000_000))
	sqlc03fBudgetContract(t, "CheckBudget[soft,over]", func(ctx context.Context) error {
		return NewEnforcer(pool, slog.Default()).CheckBudget(ctx, fx.TeamSoft)
	})
	assert.Equal(t, int64(5_000_000),
		sqlc03fBudgetScalar(t, pool, `SELECT spend_micro_usd FROM team_spend_monthly WHERE team_id::text = $1 AND period = $2`, fx.TeamExceed, fx.Period),
		"the exact accumulator must carry both spends")

	// --- Agent enforcer: budget read, cents and exact micro spends.
	require.ErrorIs(t, NewAgentEnforcer(pool, slog.Default()).CheckAgentBudget(ctx, uuid.NewString()), ErrNoAgentBudget,
		"an agent without a budget row must be denied")
	require.NoError(t, NewAgentEnforcer(pool, slog.Default()).RecordAgentSpend(ctx, fx.AgentSpend, 100, 10, 5))
	require.NoError(t, NewAgentEnforcer(pool, slog.Default()).RecordAgentSpend(ctx, fx.AgentSpend, 100, 10, 5))
	sqlc03fBudgetContract(t, "CheckAgentBudget[after-spend]", func(ctx context.Context) error {
		return NewAgentEnforcer(pool, slog.Default()).CheckAgentBudget(ctx, fx.AgentSpend)
	})
	require.NoError(t, NewAgentEnforcer(pool, slog.Default()).RecordAgentSpendExact(ctx, pool, fx.AgentBatch, 6_000_000, 3, 1))
	require.ErrorIs(t, NewAgentEnforcer(pool, slog.Default()).CheckAgentBudget(ctx, fx.AgentBatch), ErrAgentBudgetExceeded,
		"600 cents spent against a 500 cent limit must exceed")
	assert.Equal(t, int64(200),
		sqlc03fBudgetScalar(t, pool, `SELECT cost_cents FROM agent_spend_daily WHERE agent_id::text = $1 AND day = $2`, fx.AgentSpend, fx.Day))

	// --- Reservation store (0023): every §4.1 scope, refusals, returns,
	// renewals, settle decrement and reconcile.
	rs := NewReservationStoreWithConfig(pool, nil, ReservationConfig{DefaultGraceFloorCents: grace})

	sqlc03fBudgetContract(t, "Grant[wallet]", func(ctx context.Context) error {
		grants, err := rs.Grant(ctx, "repl03f-w", fx.WalletOrg, []GrantRequest{
			{Scope: ScopeWallet, Key: fx.WalletOrg, Bound: 2_000_000}})
		if err != nil {
			return err
		}
		if len(grants) != 1 || grants[0].Delta < 2_000_000 {
			t.Errorf("Grant[wallet]: expected one grant >= bound, got %+v", grants)
		}
		return nil
	})
	sqlc03fBudgetContract(t, "Grant[team_month,hard]", func(ctx context.Context) error {
		_, err := rs.Grant(ctx, "repl03f-t", fx.WalletOrg, []GrantRequest{
			{Scope: ScopeTeamMonth, Key: fx.TeamHard, Period: fx.Period, Bound: 1_000_000}})
		return err
	})
	sqlc03fBudgetContract(t, "Grant[team_month,soft,advisory]", func(ctx context.Context) error {
		_, err := rs.Grant(ctx, "repl03f-t", fx.WalletOrg, []GrantRequest{
			{Scope: ScopeTeamMonth, Key: fx.TeamSoft, Period: fx.Period, Bound: 1_000_000}})
		return err
	})
	_, err = rs.Grant(ctx, "repl03f-t", fx.WalletOrg, []GrantRequest{
		{Scope: ScopeTeamMonth, Key: uuid.NewString(), Period: fx.Period, Bound: 1}})
	require.ErrorIs(t, err, ErrNoCapacitySource, "Grant[team_month,missing] must fail closed")

	sqlc03fBudgetContract(t, "Grant[agent_day]", func(ctx context.Context) error {
		_, err := rs.Grant(ctx, "repl03f-a", fx.WalletOrg, []GrantRequest{
			{Scope: ScopeAgentDay, Key: fx.AgentSpend, Period: fx.Day, Bound: 300_000}})
		return err
	})
	_, err = rs.Grant(ctx, "repl03f-a", fx.WalletOrg, []GrantRequest{
		{Scope: ScopeAgentDay, Key: uuid.NewString(), Period: fx.Day, Bound: 1}})
	require.ErrorIs(t, err, ErrNoCapacitySource, "Grant[agent_day,missing]")

	sqlc03fBudgetContract(t, "Grant[session,capped]", func(ctx context.Context) error {
		_, err := rs.Grant(ctx, "repl03f-s", fx.WalletOrg, []GrantRequest{
			{Scope: ScopeSession, Key: fx.SessionCapped, Bound: 100_000}})
		return err
	})
	// The batch's team entry links to this allowance: the §5.3 settle
	// decrement and the §5.4 payload key both ride the link. TeamHard has
	// no spend yet, so its capacity source is positive.
	sqlc03fBudgetContract(t, "Grant[team_month,batch-link]", func(ctx context.Context) error {
		_, err := rs.Grant(ctx, "repl03f-batch", fx.WalletOrg, []GrantRequest{
			{Scope: ScopeTeamMonth, Key: fx.TeamHard, Period: fx.Period, Bound: 500_000}})
		return err
	})
	_, err = rs.Grant(ctx, "repl03f-s", fx.WalletOrg, []GrantRequest{
		{Scope: ScopeSession, Key: fx.SessionUncapped, Bound: 1}})
	require.ErrorIs(t, err, ErrNoCapacitySource, "Grant[session,uncapped] is a misconfiguration")
	_, err = rs.Grant(ctx, "repl03f-s", fx.WalletOrg, []GrantRequest{
		{Scope: ScopeSession, Key: uuid.NewString(), Bound: 1}})
	require.ErrorIs(t, err, ErrNoCapacitySource, "Grant[session,missing]")

	// Multi-scope grant in one transaction, canonical scope order preserved.
	sqlc03fBudgetContract(t, "Grant[multi-scope]", func(ctx context.Context) error {
		grants, err := rs.Grant(ctx, "repl03f-multi", fx.WalletOrg, []GrantRequest{
			{Scope: ScopeSession, Key: fx.SessionCapped, Bound: 50_000},
			{Scope: ScopeAgentDay, Key: fx.AgentSpend, Period: fx.Day, Bound: 50_000},
			{Scope: ScopeTeamMonth, Key: fx.TeamHard, Period: fx.Period, Bound: 50_000},
			{Scope: ScopeWallet, Key: fx.WalletOrg, Bound: 50_000},
		})
		if err != nil {
			return err
		}
		if len(grants) != 4 {
			t.Errorf("Grant[multi]: expected 4 scope grants, got %d", len(grants))
			return nil
		}
		for i, scope := range []ScopeKind{ScopeWallet, ScopeTeamMonth, ScopeAgentDay, ScopeSession} {
			assert.Equal(t, scope, grants[i].Scope, "grants must follow the canonical lock order")
		}
		return nil
	})
	_, err = rs.Grant(ctx, "repl03f-w", fx.WalletOrg, []GrantRequest{
		{Scope: ScopeWallet, Key: fx.WalletOrg, Bound: 10_000_000_000}})
	require.ErrorIs(t, err, ErrInsufficientCapacity, "Grant[wallet,bound>free]")
	_, err = rs.Grant(ctx, "repl03f-w", fx.WalletOrg, nil)
	require.ErrorIs(t, err, ErrInvalidRequest, "Grant[empty]")

	// Return: part of the agent-day reserve flows back; zero is a no-op;
	// unknown allowances are refused.
	_, granted, _, _ := sqlc03fBudgetAllowance(t, pool, "repl03f-a", ScopeAgentDay, fx.AgentSpend, fx.Day)
	reservedBefore := sqlc03fBudgetScalar(t, pool,
		`SELECT reserved_micro_usd FROM agent_spend_daily WHERE agent_id::text = $1 AND day = $2`, fx.AgentSpend, fx.Day)
	sqlc03fBudgetContract(t, "Return[agent_day,partial]", func(ctx context.Context) error {
		return rs.Return(ctx, fx.WalletOrg, "repl03f-a", []ReturnRequest{
			{Scope: ScopeAgentDay, Key: fx.AgentSpend, Period: fx.Day, Amount: 100_000}})
	})
	assert.Equal(t, reservedBefore-100_000, sqlc03fBudgetScalar(t, pool,
		`SELECT reserved_micro_usd FROM agent_spend_daily WHERE agent_id::text = $1 AND day = $2`, fx.AgentSpend, fx.Day))
	require.NoError(t, rs.Return(ctx, fx.WalletOrg, "repl03f-a", []ReturnRequest{
		{Scope: ScopeAgentDay, Key: fx.AgentSpend, Period: fx.Day, Amount: 0}}))
	err = rs.Return(ctx, fx.WalletOrg, "repl03f-a", []ReturnRequest{
		{Scope: ScopeAgentDay, Key: fx.AgentSpend, Period: fx.Day, Amount: money.MicroUSD(granted * 2)}})
	require.ErrorIs(t, err, ErrAllowanceUnderflow, "Return[over-return]")
	err = rs.Return(ctx, fx.WalletOrg, "repl03f-none", []ReturnRequest{
		{Scope: ScopeAgentDay, Key: fx.AgentSpend, Period: fx.Day, Amount: 1}})
	require.ErrorIs(t, err, ErrAllowanceNotFound, "Return[unknown allowance]")
	_, _, returned, _ := sqlc03fBudgetAllowance(t, pool, "repl03f-a", ScopeAgentDay, fx.AgentSpend, fx.Day)
	assert.Equal(t, int64(100_000), returned)

	// Renewal extends active leases; draining stops renewing.
	renewed, err := rs.Renewal(ctx, "repl03f-multi")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, renewed, int64(1), "Renewal must extend the active allowances")
	drained, err := rs.MarkDraining(ctx, "repl03f-multi")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, drained, int64(1), "MarkDraining must flip active allowances")
	renewed, err = rs.Renewal(ctx, "repl03f-multi")
	require.NoError(t, err)
	assert.Equal(t, int64(0), renewed, "draining allowances are no longer renewable")

	// SettleDecrement: min(actual, bound) leaves the wallet reserve; the
	// allowance links the §5.4 settle jobs so reconcile can compute the
	// remainder.
	walletAllowance, walletGranted, _, _ := sqlc03fBudgetAllowance(t, pool, "repl03f-w", ScopeWallet, fx.WalletOrg, "")
	require.NoError(t, pool.QueryRow(ctx, `
		UPDATE settlement_jobs SET allowance_id = $1
		WHERE id = ANY($2) RETURNING id`,
		walletAllowance, []int64{fx.ReconcileJobID, fx.PayloadObjJobID, fx.PayloadArrJobID}).Scan(new(int64)))
	reservedWallet := sqlc03fBudgetScalar(t, pool,
		`SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, fx.WalletOrg)
	res, err := rs.SettleDecrement(ctx, fx.WalletOrg, walletAllowance, 1_500_000, 2_000_000)
	require.NoError(t, err)
	assert.True(t, res.Applied)
	assert.Equal(t, money.MicroUSD(1_500_000), res.Amount)
	assert.Equal(t, reservedWallet-1_500_000, sqlc03fBudgetScalar(t, pool,
		`SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, fx.WalletOrg))
	_, err = rs.SettleDecrement(ctx, fx.WalletOrg, 0, 1, 1)
	require.ErrorIs(t, err, ErrInvalidRequest, "SettleDecrement[zero id]")
	_, err = rs.SettleDecrement(ctx, fx.WalletOrg, 1<<40, 1, 1)
	require.ErrorIs(t, err, ErrAllowanceNotFound, "SettleDecrement[unknown]")

	// ReconcileRelease: a lapsed lease releases granted − returned − settled.
	_, err = pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - interval '1 hour' WHERE id = $1`, walletAllowance)
	require.NoError(t, err)
	summary, err := rs.ReconcileRelease(ctx, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, summary.Released, int64(1), "the lapsed wallet allowance must release")
	residual := walletGranted - 1_500_000 // returned 0, settled sum reads 1_500_000 from the §5.4 payload keys
	assert.Equal(t, residual, summary.ReturnedMicroUSD, "the released remainder is granted − settled")
	assert.Equal(t, reservedWallet-1_500_000-residual, sqlc03fBudgetScalar(t, pool,
		`SELECT reserved_micro_usd FROM org_credits WHERE org_id = $1`, fx.WalletOrg))
	_, _, _, releasedStatus := sqlc03fBudgetAllowance(t, pool, "repl03f-w", ScopeWallet, fx.WalletOrg, "")
	assert.Equal(t, AllowanceReleased, releasedStatus)
	res, err = rs.SettleDecrement(ctx, fx.WalletOrg, walletAllowance, 1, 1)
	require.NoError(t, err)
	assert.False(t, res.Applied, "a late settle after release is ledger-only")

	// --- SettleOrgBatch: wallet + team + agent + session settle in one
	// transaction; the poison entry parks requires_attention; the no-wallet
	// org parks its resale entries as durable debt.
	batchTeamAllowance, _, _, _ := sqlc03fBudgetAllowance(t, pool, "repl03f-batch", ScopeTeamMonth, fx.TeamHard, fx.Period)
	entries := []SettleEntry{
		{JobID: fx.BatchJobResale, RequestID: fx.Token + "-br", Kind: SettleKindResale,
			Amount: 1_500_000, Payload: []byte(`{"model":"` + fx.Token + `-m","tokens_in":10,"tokens_out":5}`)},
		{JobID: fx.BatchJobTeam, RequestID: fx.Token + "-bt", Kind: SettleKindTeam,
			Amount: 1_000_000, Bound: 500_000, AllowanceID: batchTeamAllowance,
			Payload: []byte(`{"team_id":"` + fx.TeamHard + `","period":"` + fx.Period + `"}`)},
		{JobID: fx.BatchJobAgent, RequestID: fx.Token + "-ba", Kind: SettleKindAgent,
			Amount: 1_000_000, Payload: []byte(`{"agent_id":"` + fx.AgentBatch + `","tokens_in":3,"tokens_out":1}`)},
		{JobID: fx.BatchJobSession, RequestID: fx.Token + "-bs", Kind: SettleKindSession,
			Amount: 800_000, Payload: []byte(`{"session_key_id":"` + fx.SessionCapped + `"}`)},
		{JobID: fx.BatchJobPoison, RequestID: "", Kind: SettleKindResale,
			Amount: 100, Payload: []byte(`null`)},
	}
	balanceBefore := sqlc03fBudgetScalar(t, pool,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, fx.WalletOrg)
	sqlc03fBudgetContract(t, "SettleOrgBatch[wallet]", func(ctx context.Context) error {
		dispositions, err := SettleOrgBatch(ctx, pool, fx.WalletOrg, grace, entries,
			BatchSpenders{Agent: NewAgentEnforcer(pool, slog.Default())})
		if err != nil {
			return err
		}
		for _, jobID := range []int64{fx.BatchJobResale, fx.BatchJobTeam, fx.BatchJobAgent, fx.BatchJobSession} {
			d := dispositions[jobID]
			if !d.Settled || !d.Applied {
				t.Errorf("SettleOrgBatch: job %d must settle applied, got %+v", jobID, d)
			}
		}
		if d := dispositions[fx.BatchJobPoison]; d.Settled || d.Reason != ReasonPoisonPayload {
			t.Errorf("SettleOrgBatch: poison entry must park requires_attention, got %+v", d)
		}
		return nil
	})
	assert.Equal(t, balanceBefore-150, sqlc03fBudgetScalar(t, pool,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, fx.WalletOrg),
		"the wallet pays exactly the resale cents")
	assert.Equal(t, int64(1),
		sqlc03fBudgetScalar(t, pool, `SELECT count(*) FROM credit_transactions WHERE org_id = $1 AND request_id = $2 AND type = 'usage'`,
			fx.WalletOrg, fx.Token+"-br"))
	assert.Equal(t, int64(1_000_000), sqlc03fBudgetScalar(t, pool,
		`SELECT spend_micro_usd FROM team_spend_monthly WHERE team_id::text = $1 AND period = $2`, fx.TeamHard, fx.Period),
		"the exact team spend lands on the batch's charge target")
	assert.Equal(t, int64(7_000_000), sqlc03fBudgetScalar(t, pool,
		`SELECT cost_micro_usd FROM agent_spend_daily WHERE agent_id::text = $1 AND day = $2`, fx.AgentBatch, fx.Day))
	assert.Equal(t, int64(800_000), sqlc03fBudgetScalar(t, pool,
		`SELECT spent_micro_usd FROM session_spend WHERE session_key_id::text = $1`, fx.SessionCapped))
	assert.Equal(t, int64(1), sqlc03fBudgetScalar(t, pool,
		`SELECT count(*) FROM settlement_jobs WHERE id = $1 AND status = 'settled' AND payload->>'`+reconcileSettleKey+`' = '500000'`, fx.BatchJobTeam),
		"the settled job records min(actual, bound) in the §5.4 payload key")
	assert.Equal(t, int64(0), sqlc03fBudgetScalar(t, pool,
		`SELECT reserved_micro_usd FROM team_spend_monthly WHERE team_id::text = $1 AND period = $2`, fx.TeamExceed, fx.Period),
		"the batch decrement releases the linked team reserve")
	assert.Equal(t, int64(1), sqlc03fBudgetScalar(t, pool,
		`SELECT count(*) FROM settlement_jobs WHERE id = $1 AND status = 'requires_attention' AND last_error = $2`,
		fx.BatchJobPoison, ReasonPoisonPayload))

	sqlc03fBudgetContract(t, "SettleOrgBatch[no-wallet]", func(ctx context.Context) error {
		dispositions, err := SettleOrgBatch(ctx, pool, fx.NoWalletOrg, grace, []SettleEntry{
			{JobID: fx.NoWalletJobID, RequestID: fx.Token + "-nw", Kind: SettleKindResale,
				Amount: 500_000, Payload: []byte(`{"model":"` + fx.Token + `-m"}`)},
		}, BatchSpenders{Agent: NewAgentEnforcer(pool, slog.Default())})
		if err != nil {
			return err
		}
		if d := dispositions[fx.NoWalletJobID]; d.Settled || d.Reason != ReasonNoWallet {
			t.Errorf("SettleOrgBatch[no-wallet]: expected durable-debt parking, got %+v", d)
		}
		return nil
	})

	// Idempotent replay of a settled batch entry is a no-op settle.
	sqlc03fBudgetContract(t, "SettleOrgBatch[replay]", func(ctx context.Context) error {
		dispositions, err := SettleOrgBatch(ctx, pool, fx.WalletOrg, grace, entries[:1],
			BatchSpenders{Agent: NewAgentEnforcer(pool, slog.Default())})
		if err != nil {
			return err
		}
		if d := dispositions[fx.BatchJobResale]; !d.Settled || d.Applied {
			t.Errorf("SettleOrgBatch[replay]: expected an idempotent no-op settle, got %+v", d)
		}
		return nil
	})
}

// TestSQLContractBudgetDelegation runs the AUDIT-P1-03 delegation paths of
// the reservation store against real Postgres: the grant-side ancestor
// bound, the ancestor clause of the ScopeAgentDay applyReserve predicate
// (parent exists, budget present), its NULL-parent root guard, the
// missing-parent-budget fail-closed refusals, and the enforcer's
// parent-chain walk against the same seeded delegation graph.
// 1 cent = 10_000 µUSD; the parent cap is 600c = 6_000_000 µUSD —
// deliberately SMALLER than the 600c+400c sum of the minted child caps.
// That overcommitted state is what the mint-time invariant now prevents
// (legacy rows, re-enabled siblings, concurrent clamps racing past the
// grant-side read), and it is exactly the state the ancestor clause must
// still enforce: the predicate, not the mint rule, is the backstop.
func TestSQLContractBudgetDelegation(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	token := fmt.Sprintf("delp03f%x", time.Now().UnixNano())
	day := time.Now().UTC().Format("2006-01-02")

	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org", token+"-org").Scan(&orgID))

	parentA, childA1, childA2 := uuid.NewString(), uuid.NewString(), uuid.NewString()
	parentB, childB1 := uuid.NewString(), uuid.NewString()
	for _, k := range []struct {
		id     string
		parent *string
	}{
		{parentA, nil}, {parentB, nil},
		{childA1, &parentA}, {childA2, &parentA}, {childB1, &parentB},
	} {
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO agent_keys (id, org_id, name, key_hash, parent_id)
			VALUES ($1::uuid, $2::uuid, $3, $3, $4)
			RETURNING id::text`,
			k.id, orgID, token+"-"+k.id[:8], k.parent).Scan(new(string)))
	}
	for _, b := range []struct {
		id    string
		limit int64
	}{
		{parentA, 600}, {childA1, 600}, {childA2, 400}, {childB1, 500},
		// parentB deliberately has NO budget row: fail-closed target.
	} {
		_, err := pool.Exec(ctx,
			`INSERT INTO agent_budgets (agent_id, daily_limit_cents) VALUES ($1::uuid, $2)`, b.id, b.limit)
		require.NoError(t, err, "seed agent budget")
	}

	// EscrowMaxFraction 1.0 keeps the arithmetic transparent: a bound at
	// or below the effective free grants exactly the bound; a bound above
	// it is refused naming that free — so every outcome below is
	// attributable to a named constraint (own cap or ancestor cap).
	rs := NewReservationStoreWithConfig(pool, nil, ReservationConfig{
		DefaultGraceFloorCents: -100, EscrowMaxFraction: 1.0})
	ae := NewAgentEnforcer(pool, slog.Default())
	grant := func(replica, key string, bound int64) ([]ScopeGrant, error) {
		return rs.Grant(ctx, replica, orgID, []GrantRequest{
			{Scope: ScopeAgentDay, Key: key, Period: day, Bound: money.MicroUSD(bound)}})
	}
	reserved := func(key string) int64 {
		return sqlc03fBudgetScalar(t, pool,
			`SELECT reserved_micro_usd FROM agent_spend_daily WHERE agent_id::text = $1 AND day = $2`,
			key, day)
	}

	// 1) Child grant within the parent headroom: the ancestor clause runs
	// live (parent exists, budget present, subtree sums visible).
	grants, err := grant(token+"-r1", childA1, 1_000_000)
	require.NoError(t, err, "Grant[child within headroom]")
	require.Len(t, grants, 1)
	assert.Equal(t, money.MicroUSD(1_000_000), grants[0].Delta,
		"bound below every cap grants exactly the bound")
	a1ID, _, _, a1Status := sqlc03fBudgetAllowance(t, pool, token+"-r1", ScopeAgentDay, childA1, day)
	assert.Equal(t, AllowanceActive, a1Status)

	// 2) Sibling grant at its own cap (400c; ancestor free 500c after step 1).
	grants, err = grant(token+"-r2", childA2, 4_000_000)
	require.NoError(t, err, "Grant[sibling at own cap]")
	assert.Equal(t, money.MicroUSD(4_000_000), grants[0].Delta)

	// 3) The ancestor bound refuses a delegated child BELOW its own cap:
	// a 400c bound fits childA1's own budget (500c still free) but the
	// parent subtree (100c+400c committed of the 600c cap) leaves only
	// 100c — the grant-side min is the ancestor-clamped free.
	_, err = grant(token+"-r3", childA1, 4_000_000)
	require.ErrorIs(t, err, ErrInsufficientCapacity, "Grant[refused by the ancestor bound under the own bound]")
	assert.Equal(t, int64(5_000_000), reserved(childA1)+reserved(childA2),
		"the refused grant leaves no reserve residue (atomicity)")

	// 3b) The bound that exactly fits the ancestor headroom is allowed
	// (100c = the remaining ancestor free): it commits the whole
	// overcommitted parent cap.
	grants, err = grant(token+"-r3", childA1, 1_000_000)
	require.NoError(t, err, "Grant[exactly the remaining ancestor headroom]")
	require.Len(t, grants, 1)
	assert.Equal(t, money.MicroUSD(1_000_000), grants[0].Delta)
	assert.Equal(t, int64(6_000_000), reserved(childA1)+reserved(childA2),
		"the whole overcommitted parent cap is escrowed")

	// 4) With the subtree fully committed, any further grant on either
	// child is refused (ancestor free 0) while the cap-sum invariant is
	// already violated — the predicate is the enforcement.
	_, err = grant(token+"-r4", childA1, 1)
	require.ErrorIs(t, err, ErrInsufficientCapacity,
		"Grant[child refused at zero ancestor headroom]")
	_, err = grant(token+"-r5", childA2, 1)
	require.ErrorIs(t, err, ErrInsufficientCapacity,
		"Grant[sibling refused at zero ancestor headroom]")
	assert.Equal(t, int64(6_000_000), reserved(childA1)+reserved(childA2),
		"refused grants leave no reserve residue (atomicity)")

	// 5) Settling child A1's first allowance releases its escrow back into
	// the parent headroom, and a fresh grant may then claim part of it.
	res, err := rs.SettleDecrement(ctx, orgID, a1ID, 1_000_000, 1_000_000)
	require.NoError(t, err, "SettleDecrement[child allowance]")
	assert.True(t, res.Applied)
	assert.Equal(t, money.MicroUSD(1_000_000), res.Amount)
	grants, err = grant(token+"-r6", childA1, 100_000)
	require.NoError(t, err, "Grant[after settle frees parent headroom]")
	assert.Equal(t, money.MicroUSD(100_000), grants[0].Delta)
	_, err = rs.SettleDecrement(ctx, orgID, grants[0].AllowanceID, 100_000, 100_000)
	require.NoError(t, err, "SettleDecrement[second allowance]")
	r3ID, _, _, _ := sqlc03fBudgetAllowance(t, pool, token+"-r3", ScopeAgentDay, childA1, day)
	_, err = rs.SettleDecrement(ctx, orgID, r3ID, 1_000_000, 1_000_000)
	require.NoError(t, err, "SettleDecrement[clamped allowance]")
	r2ID, _, _, _ := sqlc03fBudgetAllowance(t, pool, token+"-r2", ScopeAgentDay, childA2, day)
	_, err = rs.SettleDecrement(ctx, orgID, r2ID, 4_000_000, 4_000_000)
	require.NoError(t, err, "SettleDecrement[sibling allowance]")

	// 6) A parent with no budget row fails the grant closed (sentinel:
	// ErrNoCapacitySource naming the parent), never an unbounded grant.
	err = func() error { _, err := grant(token+"-r7", childB1, 100_000); return err }()
	require.ErrorIs(t, err, ErrNoCapacitySource, "Grant[parent budget missing]")
	require.ErrorContains(t, err, parentB, "the refusal must name the missing ancestor")

	// 7) Exact spends flow into both ledgers (cost_cents and cost_micro),
	// exhausting the subtree on both the enforcer's cents walk and the
	// grant/predicate micro side: 100c (parent) + 350c + 200c = 650c ≥
	// the 600c cap.
	require.NoError(t, ae.RecordAgentSpendExact(ctx, pool, parentA, 1_000_000, 1, 1))
	require.NoError(t, ae.RecordAgentSpendExact(ctx, pool, childA1, 3_500_000, 1, 1))
	require.NoError(t, ae.RecordAgentSpendExact(ctx, pool, childA2, 2_000_000, 1, 1))
	_, err = grant(token+"-r8", childA1, 1)
	require.ErrorIs(t, err, ErrInsufficientCapacity,
		"Grant[after subtree cost exhausts the parent cap]")

	// 8) The walk refuses BOTH children via the parent's subtree spend
	// while the parent itself keeps its own headroom.
	require.ErrorIs(t, ae.CheckAgentBudget(ctx, childA1), ErrAgentBudgetExceeded,
		"CheckAgentBudget[child refused by ancestor subtree]")
	require.ErrorIs(t, ae.CheckAgentBudget(ctx, childA2), ErrAgentBudgetExceeded,
		"CheckAgentBudget[sibling refused by ancestor subtree]")
	require.NoError(t, ae.CheckAgentBudget(ctx, parentA),
		"CheckAgentBudget[root judged by its own limit only]")

	// 9) childB1: the walk finds the parent row but no budget — fail closed.
	err = ae.CheckAgentBudget(ctx, childB1)
	require.ErrorIs(t, err, ErrNoAgentBudget, "CheckAgentBudget[parent budget missing]")

	// 10) Root keys keep the own-only bound end to end: the NULL-parent
	// guard keeps the ancestor predicate out of the root's UPDATE.
	_, err = grant(token+"-r9", parentA, 100_000)
	require.NoError(t, err, "Grant[root unaffected by ancestor clause]")
}
