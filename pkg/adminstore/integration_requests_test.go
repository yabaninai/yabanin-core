//go:build integration

package adminstore

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/budget"
	migrate "github.com/reireirei/yabanin/pkg/migrate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// Integration coverage on a REAL Postgres (the previously Docker-gated half):
//   - the squashed baseline applies via the real migration runner;
//   - ListRequests filters (model / error-only / time / pagination + total);
//   - RecentErrors returns request_id (the error -> lineage join key);
//   - GetTaskAnalytics buckets task-tagged rows.

func startStoreDB(t *testing.T) (*Store, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err, "docker/testcontainers required")
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)
	parts := strings.Split(port.Port(), "/")
	connStr := fmt.Sprintf("postgres://postgres:postgres@%s:%s/yabanin?sslmode=disable", host, parts[0])

	waitPool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(waitPool.Close)
	waitForStoreDBReady(t, ctx, waitPool)

	_, err = migrate.Run(ctx, connStr, "sg")
	require.NoError(t, err, "squashed baseline must apply via the real runner")

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return New(pool, slog.Default(), nil), connStr
}

// waitForStoreDBReady polls the pool until Postgres accepts connections or
// the deadline expires — container healthcheck by deadline, not a fixed
// retry-count sleep loop.
func waitForStoreDBReady(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var err error
	for {
		if err = pool.Ping(ctx); err == nil {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("test postgres did not become reachable within 15s: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func seedRequestLogs(t *testing.T, db *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	var orgID string
	require.NoError(t, db.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('Itest', 'itest') RETURNING id::text").Scan(&orgID))
	now := time.Now().UTC()
	for _, r := range []struct {
		req, model string
		status     int
		cost       float64
		task       string
		err        string
	}{
		{"req-a", "gpt-4o-mini", 200, 0.001, "task-1", ""},
		{"req-b", "gpt-4o-mini", 500, 0, "", "boom"},
		{"req-c", "claude-3", 200, 0.002, "", ""},
	} {
		errArg := interface{}(nil)
		if r.err != "" {
			errArg = r.err
		}
		_, err := db.Exec(ctx,
			`INSERT INTO request_logs (org_id, home_region, model_requested, model_used, status_code,
			   duration_ms, tokens_in, tokens_out, request_id, cost_in_usd, task_id, error, created_at)
			 VALUES ($1,'sg',$2,$2,$3, 10, 1, 1, $4, $5, $6, $7, $8)`,
			orgID, r.model, r.status, r.req, r.cost, r.task, errArg, now)
		require.NoError(t, err)
	}
	return orgID
}

// The per-request tool-call column of the LIST (the table view), as opposed
// to the detail endpoint covered above: distinct names, org-scoped, and a
// foreign org shadowing the same request_id must never leak its names.
func TestIntegration_ListRequests_ToolCallsPerRow(t *testing.T) {
	store, _ := startStoreDB(t)
	pool := store.pool
	ctx := context.Background()
	orgID := seedRequestLogs(t, pool)

	// Recorded calls: req-a (bash + read, inserted out of order to prove
	// the DISTINCT/ORDER), req-c (grep). req-b has none.
	for _, ins := range []struct{ req, tool string }{
		{"req-a", "read"}, {"req-a", "bash"}, {"req-c", "grep"},
	} {
		_, err := pool.Exec(ctx,
			`INSERT INTO tool_calls (request_id, org_id, model_used, tool_name) VALUES ($1, $2::uuid, 'm', $3)`,
			ins.req, orgID, ins.tool)
		require.NoError(t, err)
	}

	// Foreign org shadows req-a with its own tool_calls row: 'evil' must
	// stay invisible in this org's list (org-scoped subquery).
	var otherOrg string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('Other', 'other-"+fmt.Sprint(time.Now().UnixNano())+"') RETURNING id::text").Scan(&otherOrg))
	_, err := pool.Exec(ctx,
		`INSERT INTO tool_calls (request_id, org_id, model_used, tool_name) VALUES ('req-a', $1::uuid, 'm', 'evil')`, otherOrg)
	require.NoError(t, err)

	rows, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: orgID})
	require.NoError(t, err)
	require.Equal(t, 3, total)

	byReq := map[string]RequestListRow{}
	for _, r := range rows {
		byReq[r.RequestID] = r
	}
	assert.Equal(t, []string{"bash", "read"}, byReq["req-a"].ToolCalls, "distinct names, sorted, no foreign-org leakage")
	assert.Equal(t, []string{"grep"}, byReq["req-c"].ToolCalls)
	assert.Empty(t, byReq["req-b"].ToolCalls, "plain chat request: none recorded")
}

func TestIntegration_ListRequests_FiltersAndPagination(t *testing.T) {
	store, _ := startStoreDB(t)
	pool := store.pool
	orgID := seedRequestLogs(t, pool)

	// All: 3 rows, newest first, total honest.
	rows, total, err := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID})
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	require.Len(t, rows, 3)

	// Model filter.
	rows, total, err = store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, Model: "claude-3"})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, rows, 1)
	assert.Equal(t, "req-c", rows[0].RequestID)
	assert.InDelta(t, 0.002, rows[0].CostUSD, 1e-9)

	// Error-only.
	rows, total, err = store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, ErrorOnly: true})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, rows, 1)
	assert.Equal(t, "req-b", rows[0].RequestID)
	assert.Equal(t, "boom", rows[0].ErrorMsg)

	// Task filter (G2 tagging).
	rows, total, err = store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, TaskID: "task-1"})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Equal(t, "req-a", rows[0].RequestID)
	assert.Equal(t, "task-1", rows[0].TaskID)

	// Pagination + total beyond the page.
	rows, total, err = store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID, Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	require.Len(t, rows, 2)
}

// YQL must filter and order the explorer list on a real database with the
// same semantics the unit tests assert textually: org scoping holds for the
// tool EXISTS (a foreign org shadowing the request_id must not leak), list
// and stats share one filter surface, and order by is whitelisted columns
// only.
func TestIntegration_ListRequests_YQL(t *testing.T) {
	store, _ := startStoreDB(t)
	pool := store.pool
	ctx := context.Background()
	orgID := seedRequestLogs(t, pool)

	// req-a made tool calls (bash + read) and one retry; a foreign org
	// shadows req-a's request_id with an "evil" tool row.
	_, err := pool.Exec(ctx,
		"UPDATE request_logs SET retry_count = 2, first_token_ms = 300 WHERE request_id = 'req-a' AND org_id = $1::uuid", orgID)
	require.NoError(t, err)
	for _, tool := range []string{"bash", "read"} {
		_, err = pool.Exec(ctx,
			`INSERT INTO tool_calls (request_id, org_id, model_used, tool_name) VALUES ('req-a', $1::uuid, 'm', $2)`,
			orgID, tool)
		require.NoError(t, err)
	}
	var otherOrg string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('OtherYQL', 'other-yql') RETURNING id::text").Scan(&otherOrg))
	_, err = pool.Exec(ctx,
		`INSERT INTO tool_calls (request_id, org_id, model_used, tool_name) VALUES ('req-a', $1::uuid, 'm', 'evil')`, otherOrg)
	require.NoError(t, err)

	yql := func(t *testing.T, query string) ([]RequestListRow, int) {
		t.Helper()
		rq, err := ParseYQL(query)
		require.NoError(t, err)
		rows, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: orgID, Query: rq})
		require.NoError(t, err)
		return rows, total
	}
	ids := func(rows []RequestListRow) []string {
		out := make([]string, len(rows))
		for i, r := range rows {
			out[i] = r.RequestID
		}
		return out
	}

	// Errors only.
	rows, total := yql(t, "status >= 400")
	assert.Equal(t, []string{"req-b"}, ids(rows))
	assert.Equal(t, 1, total)

	// AND + range + model.
	rows, total = yql(t, "model = gpt-4o-mini and status < 400")
	assert.Equal(t, []string{"req-a"}, ids(rows))
	assert.Equal(t, 1, total)

	// Tool EXISTS: req-a only; the foreign "evil" row must not leak.
	rows, total = yql(t, "tool = bash")
	assert.Equal(t, []string{"req-a"}, ids(rows))
	assert.Equal(t, 1, total)

	// NOT EXISTS includes tool-less requests.
	rows, total = yql(t, "tool != bash")
	assert.Equal(t, []string{"req-b", "req-c"}, ids(rows))
	assert.Equal(t, 2, total)

	// Nullable observability column.
	rows, total = yql(t, "retries >= 1")
	assert.Equal(t, []string{"req-a"}, ids(rows))
	assert.Equal(t, 1, total)

	// Cache miss (NULL cache_hit_type) + in-list + NOT group.
	rows, total = yql(t, "cache = miss and status in (200, 500) and not (model = claude-3)")
	assert.Equal(t, []string{"req-a", "req-b"}, ids(rows))
	assert.Equal(t, 2, total)

	// Content search.
	rows, total = yql(t, `text ~ boom`)
	assert.Equal(t, []string{"req-b"}, ids(rows))
	assert.Equal(t, 1, total)

	// Task emptiness.
	rows, total = yql(t, "task is not empty")
	assert.Equal(t, []string{"req-a"}, ids(rows))
	assert.Equal(t, 1, total)

	// Relative time window covers the seeded rows.
	rows, total = yql(t, "created >= -24h")
	assert.Equal(t, 3, total)
	require.Len(t, rows, 3)

	// ORDER BY cost desc (0.002, 0.001, 0), tiebreak deterministic.
	rows, _ = yql(t, "order by cost desc")
	assert.Equal(t, []string{"req-c", "req-a", "req-b"}, ids(rows))

	// Stats share the same filter surface.
	rq, err := ParseYQL("tool = bash")
	require.NoError(t, err)
	stats, err := store.RequestStats(ctx, RequestListFilters{OrgID: orgID, Query: rq})
	require.NoError(t, err)
	assert.Equal(t, int64(1), stats.TotalRequests)
}

func TestIntegration_RecentErrors_ExposesRequestID(t *testing.T) {
	store, _ := startStoreDB(t)
	orgID := seedRequestLogs(t, store.pool)
	errs, err := store.RecentErrors(context.Background(), &orgID, 10)
	require.NoError(t, err)
	require.Len(t, errs, 1)
	assert.Equal(t, "req-b", errs[0].RequestID, "request_id is the error -> lineage join key")
}

// The tool_calls recorded for a request must reach the detail view even when
// the stored upstream_response sample is truncated past the tool fragments
// (loggerd extracts names pre-truncation). Org scoping applies to the calls
// exactly like to the row itself; a request without calls yields a stable
// empty list, never null (client contract).
func TestIntegration_GetRequestDetail_ToolCalls(t *testing.T) {
	store, _ := startStoreDB(t)
	pool := store.pool
	ctx := context.Background()
	orgID := seedRequestLogs(t, pool)

	// A second org with a tool_calls row shadowing req-a's request_id: it
	// must never leak into org-1's detail (org-scoped join).
	var otherOrg string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('Other', 'other') RETURNING id::text").Scan(&otherOrg))
	seedCalls := []struct{ org, req, tool string }{
		{orgID, "req-a", "bash"},
		{orgID, "req-a", "read"},
		{otherOrg, "req-a", "foreign_tool"},
	}
	for _, c := range seedCalls {
		_, err := pool.Exec(ctx,
			`INSERT INTO tool_calls (request_id, org_id, model_used, tool_name) VALUES ($1, $2::uuid, 'm', $3)`,
			c.req, c.org, c.tool)
		require.NoError(t, err)
	}
	// Per-occurrence invocations (0014): two occurrences for req-a —
	// including a same-name repeat with its own arguments — plus a foreign
	// row that must stay invisible to org-1.
	seedInvocations := []struct {
		org, req, callID, tool, args string
		seq                          int
	}{
		{orgID, "req-a", "call_b1", "bash", `{"cmd":"git status"}`, 0},
		{orgID, "req-a", "call_b2", "bash", `{"cmd":"git diff"}`, 1},
		{orgID, "req-a", "", "read", `{"path":"Makefile"}`, 2},
		{otherOrg, "req-a", "call_x", "foreign_tool", `{"x":1}`, 0},
	}
	for _, inv := range seedInvocations {
		_, err := pool.Exec(ctx,
			`INSERT INTO tool_call_invocations (request_id, org_id, seq, call_id, tool_name, arguments)
			 VALUES ($1, $2::uuid, $3, NULLIF($4, ''), $5, NULLIF($6, ''))`,
			inv.req, inv.org, inv.seq, inv.callID, inv.tool, inv.args)
		require.NoError(t, err)
	}

	contentCtx := WithRequestPayloadAccess(ctx, RequestPayloadAccess{Grant: true})
	d, err := store.GetRequestDetail(contentCtx, orgID, "req-a")
	require.NoError(t, err)
	assert.Equal(t, []RequestToolCall{{ToolName: "bash"}, {ToolName: "read"}}, d.ToolCalls)

	// Invocations: per-occurrence, ordered by seq, args and call ids intact,
	// foreign row filtered by org. A missing call id is an honest null.
	require.Len(t, d.ToolCallInvocations, 3)
	callID2 := "call_b2"
	noCallID := (*string)(nil)
	assert.Equal(t, "call_b1", *d.ToolCallInvocations[0].CallID)
	assert.Equal(t, "bash", d.ToolCallInvocations[0].ToolName)
	assert.Equal(t, `{"cmd":"git status"}`, *d.ToolCallInvocations[0].Arguments)
	assert.Equal(t, callID2, *d.ToolCallInvocations[1].CallID)
	assert.Equal(t, `{"cmd":"git diff"}`, *d.ToolCallInvocations[1].Arguments, "same-name repeat keeps its own args")
	assert.Equal(t, noCallID, d.ToolCallInvocations[2].CallID)
	assert.Equal(t, `{"path":"Makefile"}`, *d.ToolCallInvocations[2].Arguments)

	// No recorded calls -> empty list (stable JSON contract), not an error.
	d, err = store.GetRequestDetail(contentCtx, orgID, "req-c")
	require.NoError(t, err)
	assert.Equal(t, []RequestToolCall{}, d.ToolCalls)
	assert.Equal(t, []RequestToolCallInvocation{}, d.ToolCallInvocations)

	// The other org has no request_logs row for req-a -> 404 contract.
	_, err = store.GetRequestDetail(contentCtx, otherOrg, "req-a")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestIntegration_TaskAnalytics_OnRealDB(t *testing.T) {
	store, _ := startStoreDB(t)
	orgID := seedRequestLogs(t, store.pool)
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)
	rep, err := store.GetTaskAnalytics(context.Background(), orgID, from, to, "task", 100)
	require.NoError(t, err)
	require.NotNil(t, rep)
	// task-1 bucket (priced) + (untagged) bucket with req-b and req-c.
	require.Len(t, rep.Groups, 2)
	var found bool
	for _, g := range rep.Groups {
		if g.Group == "task-1" {
			found = true
			assert.InDelta(t, 0.001, g.CostUSD, 1e-9)
		}
	}
	assert.True(t, found, "task-1 bucket must exist")
}

func TestIntegration_AgentBudgetCrudAndEnforcement(t *testing.T) {
	store, _ := startStoreDB(t)
	pool := store.pool
	ctx := context.Background()

	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('AgTest', 'agtest') RETURNING id::text").Scan(&orgID))
	var agentID string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, 'ci-agent', 'hash-ci') RETURNING id::text",
		orgID).Scan(&agentID))

	// No budget row -> ErrNoAgentBudget (deny) via the gateway enforcer.
	enf := budget.NewAgentEnforcer(pool, slog.Default())
	err := enf.CheckAgentBudget(ctx, agentID)
	assert.ErrorIs(t, err, budget.ErrNoAgentBudget)

	// Upsert authorizes the agent. The enforcer caches budget rows for ~1m
	// (in production admin and gateway are separate processes; here in one
	// process the cache is cleared explicitly to observe the update).
	b, err := store.UpsertAgentBudget(ctx, agentID, 5000)
	require.NoError(t, err)
	assert.Equal(t, int64(5000), b.DailyLimitCents)
	enf.ClearCache(agentID)

	// Within limit -> allowed.
	assert.NoError(t, enf.CheckAgentBudget(ctx, agentID))

	// Record spend up to the cap -> exceeded (G2 consumer wiring path).
	require.NoError(t, enf.RecordAgentSpend(ctx, agentID, 5000, 10, 20))
	err = enf.CheckAgentBudget(ctx, agentID)
	assert.ErrorIs(t, err, budget.ErrAgentBudgetExceeded)

	// Get + Delete round-trip.
	got, err := store.GetAgentBudget(ctx, agentID)
	require.NoError(t, err)
	assert.Equal(t, int64(5000), got.DailyLimitCents)
	require.NoError(t, store.DeleteAgentBudget(ctx, agentID))
	enf.ClearCache(agentID)
	err = enf.CheckAgentBudget(ctx, agentID)
	assert.ErrorIs(t, err, budget.ErrNoAgentBudget, "budget removal returns the agent to denied")
}

func TestIntegration_ListRequests_LabelFilter(t *testing.T) {
	store, _ := startStoreDB(t)
	pool := store.pool
	ctx := context.Background()
	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('Labels', 'labels') RETURNING id::text").Scan(&orgID))
	now := time.Now().UTC()
	_, err := pool.Exec(ctx,
		`INSERT INTO request_logs (org_id, home_region, model_requested, model_used, status_code,
		   duration_ms, tokens_in, tokens_out, request_id, cost_in_usd, created_at, labels)
		 VALUES ($1,'sg','m','m',200, 10, 1, 1, 'pay', 0, $2, '{"issue":"PAY-1"}'),
		        ($1,'sg','m','m',200, 10, 1, 1, 'other', 0, $2, '{"issue":"OTHER"}')`,
		orgID, now)
	require.NoError(t, err)
	q, err := ParseYQL(`label.issue = "PAY-1"`)
	require.NoError(t, err)
	rows, total, err := store.ListRequests(ctx, RequestListFilters{OrgID: orgID, Query: q})
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Len(t, rows, 1)
	require.Equal(t, "pay", rows[0].RequestID)
	require.Equal(t, "PAY-1", rows[0].Labels["issue"])
}

func TestIntegration_RequestPayloadGrantCycleAndRootHasNoBypass(t *testing.T) {
	store, _ := startStoreDB(t)
	pool := store.pool
	ctx := context.Background()
	var orgID, rootID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('Payload grants', 'payload-grants') RETURNING id::text`).Scan(&orgID))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, is_root) VALUES ('payload-root@example.test', 'x', true) RETURNING id::text`).Scan(&rootID))
	_, err := pool.Exec(ctx, `INSERT INTO request_logs
		(org_id, home_region, model_requested, model_used, status_code, duration_ms, tokens_in, tokens_out,
		 request_id, cost_in_usd, response, upstream_request, upstream_response, created_at)
		VALUES ($1::uuid, 'sg', 'model', 'model', 200, 3, 1, 1, 'foreign-payload', 0,
		'{"response":"private-response"}', '{"request":"private-request"}', '{"response":"private-upstream"}', now())`, orgID)
	require.NoError(t, err)

	// A root without an explicit self-grant can fetch metadata but never the
	// processed or upstream payload fields.
	detail, err := store.GetRequestDetail(WithRequestPayloadAccess(ctx, RequestPayloadAccess{
		UserID: rootID, SubjectType: RequestPayloadHuman, OrgWideMetadata: true,
	}), orgID, "foreign-payload")
	require.NoError(t, err)
	assert.NotContains(t, string(detail.Response), "private-response")
	assert.NotContains(t, string(detail.UpstreamRequest), "private-request")
	assert.NotContains(t, string(detail.UpstreamResponse), "private-upstream")

	now := time.Now().UTC()
	expired, err := store.CreateRequestPayloadGrant(orgID, "foreign-payload", rootID, time.Second, now)
	require.NoError(t, err)
	assert.False(t, store.ConsumeRequestPayloadGrant(expired.Token, orgID, "foreign-payload", rootID, now.Add(2*time.Second)), "expired grant must fail")

	revoked, err := store.CreateRequestPayloadGrant(orgID, "foreign-payload", rootID, time.Minute, now)
	require.NoError(t, err)
	require.NoError(t, store.RevokeRequestPayloadGrant(revoked.Token, rootID))
	assert.False(t, store.ConsumeRequestPayloadGrant(revoked.Token, orgID, "foreign-payload", rootID, time.Now().UTC()), "revoked grant must fail")

	active, err := store.CreateRequestPayloadGrant(orgID, "foreign-payload", rootID, time.Minute, now)
	require.NoError(t, err)
	assert.False(t, store.ConsumeRequestPayloadGrant(active.Token, orgID, "another-request", rootID, time.Now().UTC()), "wrong request must fail")
	assert.False(t, store.ConsumeRequestPayloadGrant(active.Token, "00000000-0000-0000-0000-000000000001", "foreign-payload", rootID, time.Now().UTC()), "wrong organization must fail")
	assert.False(t, store.ConsumeRequestPayloadGrant(active.Token, orgID, "foreign-payload", "00000000-0000-0000-0000-000000000002", time.Now().UTC()), "wrong grantee must fail")
	assert.True(t, store.ConsumeRequestPayloadGrant(active.Token, orgID, "foreign-payload", rootID, time.Now().UTC()), "matching durable grant must be consumed")
	assert.False(t, store.ConsumeRequestPayloadGrant(active.Token, orgID, "foreign-payload", rootID, time.Now().UTC()), "grant is single-use")

	listed, err := store.ListRequestPayloadGrants(ctx, rootID)
	require.NoError(t, err)
	require.NotEmpty(t, listed)
	for _, grant := range listed {
		assert.Empty(t, grant.Token, "list must never return bearer tokens")
	}
}
