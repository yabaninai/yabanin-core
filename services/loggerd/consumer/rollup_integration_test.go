//go:build integration

package consumer

import (
	"context"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

func TestIntegration_RollupRefresh(t *testing.T) {
	pool := testdb.Postgres(t)
	store := adminstore.New(pool, slog.Default(), nil)
	ctx := context.Background()
	var orgID, other string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('Rollup', 'rollup-org') RETURNING id::text").Scan(&orgID))
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('Other region', 'rollup-eu') RETURNING id::text").Scan(&other))
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	at := from.Add(30 * time.Minute)
	_, err := pool.Exec(ctx, `
		INSERT INTO request_logs (org_id, home_region, model_requested, model_used, status_code,
		  duration_ms, tokens_in, tokens_out, request_id, cost_in_usd, cost_status, created_at, labels, ab_group, endpoint)
		VALUES
		  ($1::uuid,'sg','m','gpt',200, 10, 4, 2, 'r1', 1.5, 'priced', $2, '{"issue":"PAY-1","not_a_rollup_key":"x"}', '', 'chat.completions'),
		  ($1::uuid,'sg','m','gpt',500, 10, 1, 1, 'r2', 0.5, 'priced', $2, '{"issue":"PAY-1"}', '', 'chat.completions'),
		  ($1::uuid,'sg','m','gpt',200, 10, 9, 1, 'r3', 9, 'priced', $2, '{"issue":"PAY-1"}', 'shadow', 'chat.completions'),
		  ($3::uuid,'eu','m','gpt',200, 10, 8, 1, 'r4', 8, 'priced', $2, '{"issue":"PAY-1"}', '', 'chat.completions')`,
		orgID, at, other)
	require.NoError(t, err)

	rawQ, err := adminstore.ParseAnalyticsQuery(url.Values{
		"org_id": {orgID}, "from": {from.Format(time.RFC3339)}, "to": {from.Add(24 * time.Hour).Format(time.RFC3339)},
		"metrics": {"requests,cost_usd,errors,tokens_in"}, "granularity": {"day"}, "filter": {"status >= 100"},
	}, "UTC", from)
	require.NoError(t, err)
	rawRes, err := store.RunAnalyticsQuery(ctx, rawQ)
	require.NoError(t, err)
	require.Equal(t, "raw", rawRes.Source)

	ref := &RollupRefresher{DB: NewRollupDB(pool), Now: func() time.Time { return from.Add(time.Hour) }, Log: slog.Default(), Region: "sg"}
	skipped, err := ref.RefreshWindow(ctx, from, from.Add(24*time.Hour))
	require.NoError(t, err)
	require.False(t, skipped)
	var n1 int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM analytics_rollup_hourly").Scan(&n1))
	require.Greater(t, n1, 0)
	skipped, err = ref.RefreshWindow(ctx, from, from.Add(24*time.Hour))
	require.NoError(t, err)
	require.False(t, skipped)
	var n2 int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM analytics_rollup_hourly").Scan(&n2))
	require.Equal(t, n1, n2)

	var extraKey int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM label_rollup_hourly WHERE key = 'not_a_rollup_key'").Scan(&extraKey))
	require.Equal(t, 0, extraKey)
	var issueRows int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM label_rollup_hourly WHERE key = 'issue' AND value = 'PAY-1'").Scan(&issueRows))
	require.Equal(t, 1, issueRows)
	var otherRegion int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM analytics_rollup_hourly WHERE home_region <> 'sg'").Scan(&otherRegion))
	require.Equal(t, 0, otherRegion)

	rollQ, err := adminstore.ParseAnalyticsQuery(url.Values{
		"org_id": {orgID}, "from": {from.Format(time.RFC3339)}, "to": {from.Add(24 * time.Hour).Format(time.RFC3339)},
		"metrics": {"requests,cost_usd,errors,tokens_in"}, "granularity": {"day"}, "group_by": {"model"},
	}, "UTC", from)
	require.NoError(t, err)
	rollRes, err := store.RunAnalyticsQuery(ctx, rollQ)
	require.NoError(t, err)
	require.Equal(t, "rollup", rollRes.Source)
	require.Equal(t, rawRes.Totals["requests"], rollRes.Totals["requests"])
	require.InDelta(t, rawRes.Totals["cost_usd"].(float64), rollRes.Totals["cost_usd"].(float64), 0.001)
	require.Equal(t, rawRes.Totals["errors"], rollRes.Totals["errors"])
	require.Equal(t, rawRes.Totals["tokens_in"], rollRes.Totals["tokens_in"])

	hold, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = hold.Rollback(ctx) }()
	var got bool
	require.NoError(t, hold.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", int64(18018)).Scan(&got))
	require.True(t, got)
	skipped, err = ref.RefreshWindow(ctx, from, from.Add(24*time.Hour))
	require.NoError(t, err)
	require.True(t, skipped)
}
