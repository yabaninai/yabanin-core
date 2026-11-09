//go:build integration

package adminstore

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIntegration_AnalyticsQuery(t *testing.T) {
	store, _ := startStoreDB(t)
	pool := store.pool
	ctx := context.Background()
	insertOrg := func(name, slug string) string {
		t.Helper()
		var id string
		require.NoError(t, pool.QueryRow(ctx,
			"INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text", name, slug).Scan(&id))
		return id
	}
	orgA := insertOrg("A", "an-a")
	orgB := insertOrg("B", "an-b")
	var teamID string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations_teams (org_id, name, slug) VALUES ($1::uuid, 'payments', 'payments') RETURNING id::text",
		orgA).Scan(&teamID))
	var agentID string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, 'review-bot', 'hash-analytics-a') RETURNING id::text",
		orgA).Scan(&agentID))

	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	at := from.Add(time.Hour)
	type row struct {
		org, issue string
		cost       float64
		status     int
		shadow     bool
		team       bool
	}
	rows := []row{
		{orgA, "PAY-1", 1, 200, false, true},
		{orgA, "PAY-1", 2, 200, false, false},
		{orgA, "PAY-2", 0.5, 500, false, false},
		{orgA, "PAY-1", 9, 200, true, false},
		{orgB, "PAY-1", 8, 200, false, false},
	}
	for i, r := range rows {
		ab := ""
		if r.shadow {
			ab = "shadow"
		}
		var team any
		if r.team {
			team = teamID
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO request_logs (org_id, home_region, model_requested, model_used, status_code,
			  duration_ms, tokens_in, tokens_out, request_id, cost_in_usd, created_at, labels, ab_group, team_id, agent_id)
			VALUES ($1::uuid, 'sg', 'm', 'm', $2, 10, 1, 1, $3, $4, $5, $6::jsonb, $7, $8::uuid, $9::uuid)`,
			r.org, r.status, "aq-"+string(rune('a'+i)), r.cost, at,
			`{"issue":"`+r.issue+`"}`, ab, team, agentID)
		require.NoError(t, err)
	}

	v := url.Values{
		"org_id":      {orgA},
		"from":        {from.Format(time.RFC3339)},
		"to":          {from.Add(24 * time.Hour).Format(time.RFC3339)},
		"metrics":     {"requests,cost_usd,errors"},
		"group_by":    {"label:issue"},
		"granularity": {"day"},
		"top":         {"1"},
		"filter":      {"status >= 100"},
	}
	q, err := ParseAnalyticsQuery(v, "UTC", from)
	require.NoError(t, err)
	res, err := store.RunAnalyticsQuery(ctx, q)
	require.NoError(t, err)
	require.Equal(t, "raw", res.Source)
	require.Equal(t, float64(3), res.Totals["requests"])
	require.InDelta(t, 3.5, res.Totals["cost_usd"], 0.001)
	require.Equal(t, float64(1), res.Totals["errors"])
	require.True(t, res.Truncated)
	var sawOther, sawPay bool
	for _, row := range res.Rows {
		switch row[1] {
		case "(other)":
			sawOther = true
			require.Equal(t, float64(1), row[2])
		case "PAY-1":
			sawPay = true
			require.Equal(t, float64(2), row[2])
		default:
			t.Fatalf("unexpected group %v", row[1])
		}
	}
	require.True(t, sawOther && sawPay)

	keys, err := store.ListLabelKeys(ctx, orgA, from, from.Add(24*time.Hour))
	require.NoError(t, err)
	require.NotEmpty(t, keys)
	require.Equal(t, "issue", keys[0].Key)

	v.Set("group_by", "team")
	v.Set("top", "20")
	v.Del("granularity")
	q, err = ParseAnalyticsQuery(v, "UTC", from)
	require.NoError(t, err)
	res, err = store.RunAnalyticsQuery(ctx, q)
	require.NoError(t, err)
	require.Equal(t, "payments", res.DisplayNames["team"][teamID])

	oldTimeout, oldSleep := analyticsTimeout, analyticsForceSleep
	analyticsTimeout = "1ms"
	analyticsForceSleep = true
	t.Cleanup(func() {
		analyticsTimeout = oldTimeout
		analyticsForceSleep = oldSleep
	})
	_, err = store.RunAnalyticsQuery(ctx, q)
	require.ErrorIs(t, err, ErrAnalyticsTimeout)
}
