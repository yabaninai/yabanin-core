package adminstore

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseAnalyticsQuery_Errors(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	from := now.Add(-24 * time.Hour).Format(time.RFC3339)
	to := now.Format(time.RFC3339)
	cases := []struct {
		name string
		q    string
		code string
	}{
		{"org", "from=" + from + "&to=" + to + "&metrics=requests", "org_required"},
		{"range", "org_id=o&from=" + to + "&to=" + from + "&metrics=requests", "invalid_range"},
		{"span", "org_id=o&from=" + now.Add(-94*24*time.Hour).Format(time.RFC3339) + "&to=" + to + "&metrics=requests&granularity=none", "range_too_large"},
		{"metric", "org_id=o&from=" + from + "&to=" + to + "&metrics=cost_usd%3Bdrop", "invalid_metric"},
		{"dim", "org_id=o&from=" + from + "&to=" + to + "&metrics=requests&group_by=label:a'b", "invalid_dimension"},
		{"hour", "org_id=o&from=" + now.Add(-15*24*time.Hour).Format(time.RFC3339) + "&to=" + to + "&metrics=requests&granularity=hour", "invalid_granularity"},
		{"top", "org_id=o&from=" + from + "&to=" + to + "&metrics=requests&top=0", "invalid_top"},
		{"tz", "org_id=o&from=" + from + "&to=" + to + "&metrics=requests&tz=Not/AZone", "invalid_tz"},
		{"filter", "org_id=o&from=" + from + "&to=" + to + "&metrics=requests&filter=nope+%3D+1", "invalid_filter"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := url.ParseQuery(tc.q)
			require.NoError(t, err)
			_, err = ParseAnalyticsQuery(v, "UTC", now)
			var ae *AnalyticsQueryError
			require.ErrorAs(t, err, &ae)
			require.Equal(t, tc.code, ae.Code)
			if tc.code == "invalid_filter" {
				require.True(t, ae.HasPos)
				require.Contains(t, ae.Error(), "label.<key>")
			}
			if tc.code == "range_too_large" {
				require.Contains(t, ae.Msg, "granularity=day")
			}
		})
	}
	old := analyticsPointLimit
	analyticsPointLimit = 10
	t.Cleanup(func() { analyticsPointLimit = old })
	v, err := url.ParseQuery("org_id=o&from=" + from + "&to=" + to + "&metrics=requests&granularity=hour&top=20")
	require.NoError(t, err)
	_, err = ParseAnalyticsQuery(v, "UTC", now)
	var ae *AnalyticsQueryError
	require.ErrorAs(t, err, &ae)
	require.Equal(t, "too_many_points", ae.Code)
}

func TestBuildAnalyticsSQL_Golden(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Moscow")
	require.NoError(t, err)
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	base := func(metrics, group, gran string) *AnalyticsQuery {
		v := url.Values{
			"org_id":  {"11111111-1111-1111-1111-111111111111"},
			"from":    {from.Format(time.RFC3339)},
			"to":      {to.Format(time.RFC3339)},
			"metrics": {metrics},
		}
		if group != "" {
			v.Set("group_by", group)
		}
		if gran != "" {
			v.Set("granularity", gran)
		}
		q, err := ParseAnalyticsQuery(v, "UTC", to)
		require.NoError(t, err)
		q.TZ = loc
		return q
	}

	t.Run("no group", func(t *testing.T) {
		q := base("requests", "", "none")
		built, err := buildAnalyticsSQL(q)
		require.NoError(t, err)
		require.Empty(t, built.TopSQL)
		require.Equal(t, "SELECT COUNT(*)::float8 FROM request_logs rl WHERE rl.org_id = $1::uuid AND rl.created_at >= $2 AND rl.created_at < $3 AND COALESCE(rl.ab_group, '') <> 'shadow' AND $4::text IS NOT NULL AND $5::text IS NOT NULL", built.MainSQL)
		require.Equal(t, q.OrgID, built.MainArgs[0])
		require.Equal(t, "none", built.MainArgs[3])
		require.Equal(t, "Europe/Moscow", built.MainArgs[4])
	})

	t.Run("label", func(t *testing.T) {
		q := base("cost_usd", "label:Issue", "day")
		built, err := buildAnalyticsSQL(q)
		require.NoError(t, err)
		require.Contains(t, built.TopSQL, "label_rollup_hourly ru")
		require.Contains(t, built.TopSQL, "ru.key = $6::text")
		require.Contains(t, built.TopSQL, "LIMIT 20")
		require.NotContains(t, built.TopSQL, "Issue")
		require.Equal(t, "issue", built.TopArgs[5])
		require.Contains(t, built.MainSQL, "ANY($7::text[])")
		require.Contains(t, built.MainSQL, "date_trunc($4::text")
		require.Len(t, built.MainArgs, 6)
	})

	t.Run("two dims", func(t *testing.T) {
		q := base("requests,errors", "model,team", "none")
		built, err := buildAnalyticsSQL(q)
		require.NoError(t, err)
		require.Contains(t, built.TopSQL, "AS g")
		require.Contains(t, built.TopSQL, "rl.model_used")
		require.Contains(t, built.TopSQL, "rl.team_id::text")
		require.Contains(t, built.MainSQL, "GROUP BY 1, 2")
		require.Contains(t, built.MainSQL, "ANY($6::text[])")
	})

	t.Run("yql filter numbering", func(t *testing.T) {
		v := url.Values{
			"org_id":  {"11111111-1111-1111-1111-111111111111"},
			"from":    {from.Format(time.RFC3339)},
			"to":      {to.Format(time.RFC3339)},
			"metrics": {"requests"},
			"filter":  {`label.issue = "PAY'1"`},
		}
		q, err := ParseAnalyticsQuery(v, "UTC", to)
		require.NoError(t, err)
		built, err := buildAnalyticsSQL(q)
		require.NoError(t, err)
		require.NotContains(t, built.MainSQL, "PAY")
		require.Contains(t, built.MainSQL, "$6::text")
		require.Equal(t, []any{"issue", "PAY'1"}, built.MainArgs[5:])
	})

	t.Run("rollup day range is allowed", func(t *testing.T) {
		now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
		v, err := url.ParseQuery("org_id=o&from=" + now.Add(-120*24*time.Hour).Format(time.RFC3339) + "&to=" + now.Format(time.RFC3339) + "&metrics=requests,cost_usd&granularity=day&group_by=model")
		require.NoError(t, err)
		q, err := ParseAnalyticsQuery(v, "UTC", now)
		require.NoError(t, err)
		require.Equal(t, "rollup", analyticsPublicSource(q))
		built, err := buildAnalyticsSQL(q)
		require.NoError(t, err)
		require.Contains(t, built.MainSQL, "analytics_rollup_hourly ru")
		require.Contains(t, built.MainSQL, "ru.model_used")
		_, err = ParseAnalyticsQuery(url.Values{
			"org_id": {"o"}, "from": {now.Add(-401 * 24 * time.Hour).Format(time.RFC3339)},
			"to": {now.Format(time.RFC3339)}, "metrics": {"requests"}, "granularity": {"day"},
		}, "UTC", now)
		var ae *AnalyticsQueryError
		require.ErrorAs(t, err, &ae)
		require.Equal(t, "range_too_large", ae.Code)
	})

	t.Run("compare shifts the window", func(t *testing.T) {
		v := url.Values{
			"org_id":  {"11111111-1111-1111-1111-111111111111"},
			"from":    {from.Format(time.RFC3339)},
			"to":      {to.Format(time.RFC3339)},
			"metrics": {"cost_usd"},
			"compare": {"previous"},
		}
		q, err := ParseAnalyticsQuery(v, "UTC", to)
		require.NoError(t, err)
		require.True(t, q.Compare)
		built, err := buildAnalyticsSQL(q)
		require.NoError(t, err)
		args := append([]any{}, built.TotalsArgs...)
		span := q.To.Sub(q.From)
		args[1] = q.From.Add(-span)
		args[2] = q.From
		require.Equal(t, from.Add(-24*time.Hour), args[1])
		require.Equal(t, from, args[2])
		require.Contains(t, built.TotalsSQL, "AND $4::text IS NOT NULL AND $5::text IS NOT NULL")
	})
}

func TestCSVSafe(t *testing.T) {
	require.Equal(t, "'=cmd", csvSafe("=cmd"))
	require.Equal(t, "'+1", csvSafe("+1"))
	require.Equal(t, "'-1", csvSafe("-1"))
	require.Equal(t, "'@a", csvSafe("@a"))
	require.Equal(t, "'\tok", csvSafe("\tok"))
	require.Equal(t, "hello", csvSafe("hello"))
	res := &AnalyticsResult{
		Columns: []AnalyticsColumn{{Name: "team", Type: "string"}, {Name: "cost_usd", Type: "number", Unit: "usd"}},
		Rows:    [][]any{{"11111111-1111-1111-1111-111111111111", 1.5}, {"=evil", nil}},
		DisplayNames: map[string]map[string]string{
			"team": {"11111111-1111-1111-1111-111111111111": "payments"},
		},
	}
	var b strings.Builder
	require.NoError(t, res.WriteCSV(&b))
	text := b.String()
	require.Contains(t, text, "team,team_name,cost_usd")
	require.Contains(t, text, "payments")
	require.Contains(t, text, "'=evil")
}
