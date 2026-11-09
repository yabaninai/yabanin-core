package adminstore

// disposable Postgres. Unit-test mocks only match query substrings, so
// types, placeholders, casts and column names were never exercised; the
// contract runs production SQL against the fully migrated stand and fails
// the test on any *pgconn.PgError (rejected types/columns/placeholders) and
// on any rows-iteration failure (rows.Err / scan) — the failure modes mocks
// cannot reproduce. Business errors (not found, empty windows, validation)
// are contract-legal and only logged.
//
// 03a lands the harness plus the cross-domain seed fixture and a smoke run
// (sqlcontract_<domain>_int_test.go on top of these helpers).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errRowsIteration marks failures surfaced by contractRows (scan or rows.Err)
// so contract can tell rows-stream breakage from ordinary business errors.
var errRowsIteration = errors.New("rows iteration failed")

// contractRows drains a rows stream: it runs scan per row, closes the result
// and propagates rows.Err — the deferred failures mocks cannot exercise —
// wrapped with errRowsIteration for contract().
func contractRows(rows pgx.Rows, scan func(pgx.Rows) error) error {
	if rows == nil {
		return fmt.Errorf("nil rows: %w", errRowsIteration)
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return errors.Join(err, errRowsIteration)
		}
	}
	if err := rows.Err(); err != nil {
		return errors.Join(err, errRowsIteration)
	}
	return nil
}

// contract runs one store call and fails the test when Postgres rejects the
// SQL (any *pgconn.PgError: bad types, casts, column names, placeholders) or
// when a rows stream broke mid-iteration (scan / rows.Err). Every other
// error is a business answer, not a contract breach, and is only logged.
func contract(t *testing.T, name string, fn func(ctx context.Context) error) {
	t.Helper()
	err := fn(context.Background())
	if err == nil {
		return
	}
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr):
		t.Errorf("%s: Postgres rejected the SQL: %s (code %s, where %s, detail %q, hint %q)",
			name, pgErr.Message, pgErr.Code, pgErr.Where, pgErr.Detail, pgErr.Hint)
	case errors.Is(err, errRowsIteration):
		t.Errorf("%s: rows iteration failed: %v", name, err)
	default:
		t.Logf("%s: non-SQL error tolerated by the contract: %v", name, err)
	}
}

// contractFixture carries the seeded identifiers contract cases need.
type contractFixture struct {
	Token string
	// OrgA carries the full 3-day log mix; OrgB exists so org-scoped SQL can
	// be caught leaking across tenants.
	OrgA, OrgB             string
	TeamA1, TeamA2, TeamB1 string
	APIKeyA, APIKeyB       string
	AgentKeyA              string
	SessionKeyA            string
	// From/To is the 3-day window that covers every seeded request_logs row.
	From, To time.Time
}

// contractLogRow is one seeded request_logs variant (day 0 = today).
type contractLogRow struct {
	day                     int
	org, team, requestID    string
	model                   string
	status                  int
	errText                 string
	tokensIn, tokensOut     int
	costUSD, counterfactual string
	cacheHit, costStatus    string
	abGroup                 string
	labels                  string
}

// seedContractFixture fills the shared, fully migrated stand with the
// minimum cross-domain data the store SQL joins against: 2 organizations,
// teams, API/agent/session keys, models with failover/tier pools, an alias,
// routing rules, request_logs over 3 days (priced, shadow mirror, cache hit,
// labels, error, unknown price), evalgate_results, an audit row, budgets,
// credits and MCP/A2A registrations. Every name carries a per-run token so
// the seed is safe alongside the other tests serialized on this stand, and
// cleanup removes every seeded row (organizations last, via CASCADE).
func seedContractFixture(t *testing.T, pool *pgxpool.Pool) *contractFixture {
	t.Helper()
	ctx := context.Background()
	token := fmt.Sprintf("sc03a%x", time.Now().UnixNano())
	fx := &contractFixture{
		Token: token,
		To:    time.Now().Add(time.Hour),
		From:  time.Now().Add(-72 * time.Hour),
	}
	// W-VER flake fix: report windows derive from the HOST clock while
	// created_at uses the DB clock; wait out VM clock drift before seeding.
	testdb.WaitClockCaughtUp(t, pool)

	// Organizations (orgB carries a spend-alert budget) — wallets are seeded
	// explicitly below because the raw INSERT bypasses store.CreateOrganization.
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug, spend_alert_threshold_usd)
		VALUES ($1, $2, 25.00) RETURNING id::text`,
		token+"-org-a", token+"-org-a").Scan(&fx.OrgA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug)
		VALUES ($1, $2) RETURNING id::text`,
		token+"-org-b", token+"-org-b").Scan(&fx.OrgB))

	// Teams: two for org A (one nested) and one for org B.
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations_teams (org_id, name, slug)
		VALUES ($1::uuid, $2, 'alpha') RETURNING id::text`,
		fx.OrgA, token+"-team-a1").Scan(&fx.TeamA1))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations_teams (org_id, name, slug, parent_team_id)
		VALUES ($1::uuid, $2, 'beta', $3::uuid) RETURNING id::text`,
		fx.OrgA, token+"-team-a2", fx.TeamA1).Scan(&fx.TeamA2))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations_teams (org_id, name, slug)
		VALUES ($1::uuid, $2, 'alpha') RETURNING id::text`,
		fx.OrgB, token+"-team-b1").Scan(&fx.TeamB1))

	// Keys: API (team-bound), agent and a session key minted from the API key.
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO api_keys (key_hash, org_id, name, team_id)
		VALUES ($1, $2::uuid, $3, $4::uuid) RETURNING id::text`,
		token+"-ak-a", fx.OrgA, token+"-key-a", fx.TeamA1).Scan(&fx.APIKeyA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO api_keys (key_hash, org_id, name, team_id)
		VALUES ($1, $2::uuid, $3, $4::uuid) RETURNING id::text`,
		token+"-ak-b", fx.OrgB, token+"-key-b", fx.TeamB1).Scan(&fx.APIKeyB))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO agent_keys (org_id, name, key_hash)
		VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		fx.OrgA, token+"-agent-a", token+"-ag-a").Scan(&fx.AgentKeyA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO session_keys (key_hash, org_id, parent_api_key_id, name, labels, expires_at)
		VALUES ($1, $2::uuid, $3::uuid, $4, '{}'::jsonb, now() + interval '24 hours') RETURNING id::text`,
		token+"-sk-a", fx.OrgA, fx.APIKeyA, token+"-session-a").Scan(&fx.SessionKeyA))

	// Models with failover_models / tier_pool (plus an unpriced model and a
	// shadow peer used by the request_logs rows below).
	models := []struct {
		name               string
		failover, tierPool []string
	}{
		{token + "-m-smart", []string{token + "-m-fast"}, nil},
		{token + "-m-fast", nil, []string{token + "-m-mini"}},
		{token + "-m-mini", nil, nil},
		{token + "-m-shadow", nil, nil},
		{token + "-m-unpriced", nil, nil},
	}
	for _, m := range models {
		if m.failover == nil {
			m.failover = []string{}
		}
		if m.tierPool == nil {
			m.tierPool = []string{}
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO models_registry (model_name, display_name, tier, provider, failover_models, tier_pool)
			VALUES ($1, $1, 'smart', 'openai-compat', $2, $3)`,
			m.name, m.failover, m.tierPool)
		require.NoError(t, err, "seed model %s", m.name)
	}

	// Alias and routing rules (one per org so priority order is exercised).
	_, err := pool.Exec(ctx, `
		INSERT INTO model_aliases (alias, target_model) VALUES ($1, $2)`,
		token+"-alias", token+"-m-smart")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO routing_rules (org_id, match_expr, target_model, priority)
		VALUES ($1::uuid, $2, $3, 10)`,
		fx.OrgA, `model == "`+token+`-m-fast"`, token+"-m-fast")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO routing_rules (org_id, match_expr, target_model, priority)
		VALUES ($1::uuid, $2, $3, 20)`,
		fx.OrgB, `model == "`+token+`-m-smart"`, token+"-m-smart")
	require.NoError(t, err)

	// request_logs over 3 days for both orgs; the org A mix carries every
	// contract variant (priced, shadow mirror, cache hit, labels, error,
	// unknown price).
	logs := []contractLogRow{
		{0, fx.OrgA, fx.TeamA1, token + "-r1", token + "-m-smart", 200, "", 120, 80,
			"0.000012", "0.000024", "", "priced", "", ""},
		// Shadow mirror of -r1: same request_id, ab_group='shadow'.
		{0, fx.OrgA, fx.TeamA1, token + "-r1", token + "-m-shadow", 200, "", 120, 80,
			"0.000015", "0.000028", "", "priced", "shadow", ""},
		{1, fx.OrgA, fx.TeamA1, token + "-r2", token + "-m-smart", 200, "", 50, 40,
			"0", "0.000006", "exact", "cache_hit", "", `{"env":"prod"}`},
		{1, fx.OrgA, fx.TeamA1, token + "-r3", token + "-m-fast", 200, "", 90, 70,
			"0.000008", "0.000016", "", "priced", "", `{"env":"dev","team":"alpha"}`},
		{2, fx.OrgA, fx.TeamA1, token + "-r4", token + "-m-smart", 500, "upstream exploded",
			10, 0, "0", "0", "", "no_usage", "", ""},
		{2, fx.OrgA, fx.TeamA1, token + "-r5", token + "-m-unpriced", 200, "", 70, 60,
			"0", "0.000018", "", "unknown_price", "", ""},
		{1, fx.OrgB, fx.TeamB1, token + "-rb1", token + "-m-smart", 200, "", 60, 50,
			"0.000009", "0.000018", "", "priced", "", `{"env":"prod"}`},
		{2, fx.OrgB, fx.TeamB1, token + "-rb2", token + "-m-smart", 502, "upstream timeout",
			10, 0, "0", "0", "", "no_usage", "", ""},
	}
	for _, r := range logs {
		usageSource := "provider"
		if r.costStatus == "no_usage" {
			usageSource = "none"
		}
		labels := r.labels
		if labels == "" {
			labels = "{}"
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO request_logs (
				org_id, team_id, model_requested, model_used, status_code, duration_ms,
				tokens_in, tokens_out, error, created_at, request_id,
				cost_in_usd, counterfactual_cost_usd, cache_hit_type, tier_used,
				ab_group, labels, cost_status, usage_source, endpoint, home_region
			) VALUES (
				$1::uuid, NULLIF($2, '')::uuid, $3, $3, $4, 100,
				$5, $6, NULLIF($7, ''), $8, NULLIF($9, ''),
				$10::numeric, $11::numeric, NULLIF($12, ''), 'smart',
				NULLIF($13, ''), $14::jsonb, $15, $16, 'chat.completions', 'GLOBAL')`,
			r.org, r.team, r.model, r.status, r.tokensIn, r.tokensOut,
			r.errText, time.Now().AddDate(0, 0, -r.day), r.requestID,
			r.costUSD, r.counterfactual, r.cacheHit, r.abGroup,
			labels, r.costStatus, usageSource)
		require.NoError(t, err, "seed request_log %s", r.requestID)
	}

	// Evalgate quality samples.
	_, err = pool.Exec(ctx, `
		INSERT INTO evalgate_results (org_id, request_id, prompt, cheap_model, premium_model,
			cheap_quality, premium_quality, should_upgrade, reason, raw_confidence)
		VALUES ($1, $2, $3, $4, $5, 0.4, 0.9, true, 'quality gap', 0.77)`,
		fx.OrgA, token+"-eg1", "summarize the quarterly report",
		token+"-m-fast", token+"-m-smart")
	require.NoError(t, err)

	// Audit journal row (seq comes from its sequence; hash chain fields are
	// inert placeholders — chain semantics belong to the 03d coverage).
	_, err = pool.Exec(ctx, `
		INSERT INTO admin_audit_logs (id, action, resource, details, admin_id, admin_name, ip_address, row_hash)
		VALUES ($1, 'seed.contract', $2, '{}', 'seed-admin', 'seed', '127.0.0.1', 'seed-hash')`,
		token+"-audit-1", "organization/"+fx.OrgA)
	require.NoError(t, err)

	// Budgets: team monthly, agent daily and the orgB spend-alert threshold.
	_, err = pool.Exec(ctx, `
		INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
		VALUES ($1::uuid, 100.00, true)`, fx.TeamA1)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO agent_budgets (agent_id, daily_limit_cents) VALUES ($1::uuid, 500)`,
		fx.AgentKeyA)
	require.NoError(t, err)

	// Credits: wallets plus a topup/usage transaction trail.
	_, err = pool.Exec(ctx, `INSERT INTO org_credits (org_id, balance_cents) VALUES ($1, 4988)`, fx.OrgA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type, request_id)
		VALUES ($1, 5000, 5000, 'topup', NULL), ($1, -12, 4988, 'usage', $2)`,
		fx.OrgA, token+"-r1")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO org_credits (org_id, balance_cents) VALUES ($1, 900)`, fx.OrgB)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type)
		VALUES ($1, 900, 900, 'topup')`, fx.OrgB)
	require.NoError(t, err)

	// MCP servers + a per-agent grant, and an A2A agent registration.
	_, err = pool.Exec(ctx, `
		INSERT INTO mcp_servers (org_id, name, display_name, url, allowed_tools, enabled)
		VALUES ($1::uuid, $2, $3, 'https://mcp.example.com', '["search"]'::jsonb, true)`,
		fx.OrgA, token+"-mcp", "Contract MCP")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO mcp_server_grants (org_id, agent_id, server_name, allowed_tools, enabled)
		VALUES ($1::uuid, $2::uuid, $3, '[]'::jsonb, true)`,
		fx.OrgA, fx.AgentKeyA, token+"-mcp")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO a2a_agents (org_id, name, display_name, url, enabled)
		VALUES ($1::uuid, $2, $3, 'https://a2a.example.com/agent', true)`,
		fx.OrgA, token+"-a2a", "Contract A2A")
	require.NoError(t, err)

	// Teardown in FK-safe order (routing_rules and api_keys have non-cascading
	// FKs to organizations); the org delete cascades teams, MCP/A2A, session
	// keys and the team budget.
	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("contract fixture cleanup: %v", err)
			}
		}
		orgs := []string{fx.OrgA, fx.OrgB}
		cleanup(`DELETE FROM request_logs WHERE org_id::text = ANY($1)`, orgs)
		cleanup(`DELETE FROM credit_transactions WHERE org_id = ANY($1)`, orgs)
		cleanup(`DELETE FROM org_credits WHERE org_id = ANY($1)`, orgs)
		cleanup(`DELETE FROM evalgate_results WHERE org_id = ANY($1)`, orgs)
		cleanup(`DELETE FROM admin_audit_logs WHERE id LIKE $1`, token+"%")
		cleanup(`DELETE FROM agent_budgets WHERE agent_id = ANY($1)`, []string{fx.AgentKeyA})
		cleanup(`DELETE FROM model_aliases WHERE alias LIKE $1`, token+"%")
		cleanup(`DELETE FROM models_registry WHERE model_name LIKE $1`, token+"%")
		cleanup(`DELETE FROM routing_rules WHERE org_id::text = ANY($1)`, orgs)
		cleanup(`DELETE FROM api_keys WHERE key_hash LIKE $1`, token+"%")
		cleanup(`DELETE FROM agent_keys WHERE key_hash LIKE $1`, token+"%")
		cleanup(`DELETE FROM session_keys WHERE key_hash LIKE $1`, token+"%")
		cleanup(`DELETE FROM organizations WHERE id::text = ANY($1)`, orgs)
	})

	return fx
}

// TestSQLContractHarness_Smoke proves the 03a harness end-to-end: the seed
// fixture lands on the migrated stand and representative SELECT methods —
// org-scoped and global — execute without Postgres rejecting the SQL.
func TestSQLContractHarness_Smoke(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)

	// Seed sanity: org A carries the 3-day log mix.
	var logsA int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM request_logs WHERE org_id::text = $1`, fx.OrgA).Scan(&logsA))
	assert.GreaterOrEqual(t, logsA, 6, "org A must carry the seeded 3-day log mix")

	// Global list (no org scoping).
	contract(t, "ListOrganizations", func(ctx context.Context) error {
		orgs, total, err := store.ListOrganizations(ctx, NewPageFilter(1, 100))
		if err != nil {
			return err
		}
		if total < 2 || len(orgs) == 0 {
			t.Errorf("ListOrganizations: expected the seeded organizations, got total=%d rows=%d", total, len(orgs))
		}
		return nil
	})

	// Org-scoped cost analytics over the seeded window.
	contract(t, "GetCostAnalytics[orgA]", func(ctx context.Context) error {
		report, err := store.GetCostAnalytics(ctx, fx.OrgA, fx.From, fx.To, "")
		if err != nil {
			return err
		}
		// 6 org-A rows minus the shadow mirror = 5 counted requests.
		if report == nil || report.RequestCount < 5 {
			t.Errorf("GetCostAnalytics: expected the seeded non-shadow rows, got %+v", report)
		}
		return nil
	})

	// Global window variant (no org).
	contract(t, "GetGlobalCostStats", func(ctx context.Context) error {
		_, err := store.GetGlobalCostStats(ctx, fx.From, fx.To)
		return err
	})

	// Org-scoped request list. The list excludes shadow rows by design
	// (requestListWhere), so 5 of the 6 seeded org-A rows are visible.
	contract(t, "ListRequests[orgA]", func(ctx context.Context) error {
		rows, _, err := store.ListRequests(ctx, RequestListFilters{OrgID: fx.OrgA, Page: 1})
		if err != nil {
			return err
		}
		if len(rows) < 5 {
			t.Errorf("ListRequests: expected the 5 non-shadow seeded org-A rows, got %d", len(rows))
		}
		return nil
	})

	// Shadow comparison joins the primary/shadow mirror pair on request_id.
	// The org-scoped variant was excluded while the placeholder defect was
	// so the org variant is a standing regression contract now.
	contract(t, "GetShadowComparison[global]", func(ctx context.Context) error {
		_, err := store.GetShadowComparison(ctx, "", 3)
		return err
	})
	// the org-scoped variant must execute the same join without a SQL type
	// error and see at most the org-A seeded pair (deep isolation lives in
	// shadow_compare_int_test.go).
	contract(t, "GetShadowComparison[orgA]", func(ctx context.Context) error {
		scoped, err := store.GetShadowComparison(ctx, fx.OrgA, 3)
		if err != nil {
			return err
		}
		global, err := store.GetShadowComparison(ctx, "", 3)
		if err != nil {
			return err
		}
		if scoped.Overlap > global.Overlap {
			t.Errorf("GetShadowComparison[orgA]: scoped overlap %d exceeds global %d", scoped.Overlap, global.Overlap)
		}
		return nil
	})

	// The contractRows drain over a real rows stream — the rows.Err path
	// mocks cannot exercise.
	contract(t, "fixture.request_logs[orgA]", func(ctx context.Context) error {
		rows, err := pool.Query(ctx,
			`SELECT org_id::text, cost_status FROM request_logs WHERE org_id::text = $1`, fx.OrgA)
		if err != nil {
			return err
		}
		seen := 0
		err = contractRows(rows, func(rows pgx.Rows) error {
			var org, status string
			if scanErr := rows.Scan(&org, &status); scanErr != nil {
				return scanErr
			}
			seen++
			return nil
		})
		if err == nil && seen < 6 {
			t.Errorf("fixture.request_logs: expected >=6 seeded rows, got %d", seen)
		}
		return err
	})
}
