package adminstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestGetRequestLogStats_CoalescesEmptyErrorCount(t *testing.T) {
	var sql string
	store := newForTest(&mockDB{
		queryRowFn: func(_ context.Context, q string, _ ...interface{}) pgx.Row {
			sql = q
			return &mockPGXRow{data: [][]interface{}{{int64(0), int64(0), int64(0), float64(0), int64(0)}}}
		},
	}, newTestLogger(), nil)

	stats, err := store.GetRequestLogStats(t.Context(), nil, time.Time{})
	require.NoError(t, err)
	require.Equal(t, int64(0), stats.ErrorCount)
	require.Contains(t, sql, "COALESCE(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0)")
	require.Equal(t, 1, strings.Count(sql, " WHERE "))
}

func TestGetRequestLogStats_AppendsSinceWithAND(t *testing.T) {
	var sql string
	store := newForTest(&mockDB{
		queryRowFn: func(_ context.Context, q string, _ ...interface{}) pgx.Row {
			sql = q
			return &mockPGXRow{data: [][]interface{}{{int64(0), int64(0), int64(0), float64(0), int64(0)}}}
		},
	}, newTestLogger(), nil)

	_, err := store.GetRequestLogStats(t.Context(), nil, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.Contains(t, sql, " AND created_at >=")
	require.NotContains(t, sql, "WHERE created_at")
	require.Equal(t, 1, strings.Count(sql, " WHERE "))
}

// The explorer filter builder must emit one placeholder per filter and keep
// every branch org-scoped + shadow-excluded (mirrors the Bifrost log
// explorer's slicing surface).
func TestRequestListWhere_Filters(t *testing.T) {
	base := "org_id = $1"
	f := RequestListFilters{
		OrgID:         "org-1",
		RequestID:     "req-9",
		Model:         "gpt-4o",
		MinLatencyMs:  100,
		MaxLatencyMs:  5000,
		MinTokens:     10,
		MaxTokens:     1000,
		MinCostUSD:    0.001,
		MaxCostUSD:    1,
		CacheHit:      "exact",
		ContentSearch: "timeout",
	}
	w, args := requestListWhere(f)
	require.Contains(t, w, base)
	require.Contains(t, w, "COALESCE(ab_group, '') <> 'shadow'")
	require.Contains(t, w, "request_id = $2")
	require.Contains(t, w, "model_used = $3")
	require.Contains(t, w, "COALESCE(duration_ms, 0) >= $4")
	require.Contains(t, w, "COALESCE(duration_ms, 0) <= $5")
	require.Contains(t, w, "COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) >= $6")
	require.Contains(t, w, "COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) <= $7")
	require.Contains(t, w, "COALESCE(cost_in_usd, 0) >= $8")
	require.Contains(t, w, "COALESCE(cost_in_usd, 0) <= $9")
	require.Contains(t, w, "cache_hit_type = $10")
	require.Contains(t, w, "ILIKE $11")
	require.Len(t, args, 11)
	require.Equal(t, "%timeout%", args[10])
}

func TestRequestListWhere_CacheHitMissAndDefaults(t *testing.T) {
	w, args := requestListWhere(RequestListFilters{OrgID: "org-1"})
	require.Contains(t, w, "org_id = $1")
	require.Len(t, args, 1)
	require.NotContains(t, w, "cache_hit_type")

	w, args = requestListWhere(RequestListFilters{OrgID: "org-1", CacheHit: "miss"})
	require.Contains(t, w, "COALESCE(cache_hit_type, '') = ''")
	require.Len(t, args, 1)

	// Unknown cache_hit values must not silently filter (defensive).
	w, _ = requestListWhere(RequestListFilters{OrgID: "org-1", CacheHit: "bogus"})
	require.NotContains(t, w, "cache_hit_type")
}

func TestRequestStats_SuccessRateAndScan(t *testing.T) {
	var sql string
	var callArgs []interface{}
	store := newForTest(&mockDB{
		queryRowFn: func(_ context.Context, q string, a ...interface{}) pgx.Row {
			sql = q
			callArgs = a
			// total, success, avg, p95, in, out, cost
			return &mockPGXRow{data: [][]interface{}{{int64(4), int64(3), 150.5, 950.0, int64(400), int64(800), 0.02}}}
		},
	}, newTestLogger(), nil)

	stats, err := store.RequestStats(t.Context(), RequestListFilters{OrgID: "org-1", Model: "gpt-4o"})
	require.NoError(t, err)
	require.Equal(t, int64(4), stats.TotalRequests)
	require.InDelta(t, 0.75, stats.SuccessRate, 1e-9)
	require.InDelta(t, 150.5, stats.AvgLatencyMs, 1e-9)
	require.InDelta(t, 950.0, stats.P95LatencyMs, 1e-9)
	require.Equal(t, int64(400), stats.TotalTokensIn)
	require.Equal(t, int64(800), stats.TotalTokensOut)
	require.InDelta(t, 0.02, stats.TotalCostUSD, 1e-9)
	require.Contains(t, sql, "COUNT(*) FILTER (WHERE status_code < 400)")
	require.Contains(t, sql, "percentile_cont(0.95)")
	require.Equal(t, "org-1", callArgs[0])
}

func TestRequestStats_ZeroTotal_NoDivision(t *testing.T) {
	store := newForTest(&mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{int64(0), int64(0), float64(0), float64(0), int64(0), int64(0), float64(0)}}}
		},
	}, newTestLogger(), nil)

	stats, err := store.RequestStats(t.Context(), RequestListFilters{OrgID: "org-1"})
	require.NoError(t, err)
	require.Equal(t, int64(0), stats.TotalRequests)
	require.Zero(t, stats.SuccessRate)
}

// The explorer list must pass the observability-parity columns through with
// NULL honesty: legacy rows read as nil (absent from JSON), measured rows
// keep their values.
func TestListRequests_ObservabilityColumnsScan(t *testing.T) {
	store := newForTest(&mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{{int64(2)}}}
		},
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			require.Contains(t, sql, "rl.first_token_ms, rl.attempt_count, rl.retry_count")
			now := time.Now()
			return &mockPGXRows{data: [][]interface{}{
				// measured row: session + ttft + attempts + retries present
				{"req-1", "org-1", "gpt-4", "gpt-4", 200, 0.002, int64(100), int64(50),
					"", "sess-1", int64(1500), "exact", int64(412), int64(2), int64(1), "", now, nil, []byte(`{"issue":"PAY-1"}`)},
				// legacy row: all three NULL, no session, no labels
				{"req-2", "org-1", "", "gpt-3.5", 200, 0.0, int64(10), int64(5),
					"", "", int64(300), "", nil, nil, nil, "", now, nil, []byte(`{}`)},
			}}, nil
		},
	}, newTestLogger(), nil)

	rows, total, err := store.ListRequests(t.Context(), RequestListFilters{OrgID: "org-1"})
	require.NoError(t, err)
	require.Equal(t, 2, total)
	require.Len(t, rows, 2)

	require.NotNil(t, rows[0].FirstTokenMs)
	require.Equal(t, int64(412), *rows[0].FirstTokenMs)
	require.Equal(t, "sess-1", rows[0].SessionID)
	require.NotNil(t, rows[0].AttemptCount)
	require.Equal(t, int64(2), *rows[0].AttemptCount)
	require.NotNil(t, rows[0].RetryCount)
	require.Equal(t, int64(1), *rows[0].RetryCount)
	require.Equal(t, "exact", rows[0].CacheHitType)
	require.Equal(t, "PAY-1", rows[0].Labels["issue"])

	require.Nil(t, rows[1].FirstTokenMs)
	require.Nil(t, rows[1].AttemptCount)
	require.Nil(t, rows[1].RetryCount)
	require.Empty(t, rows[1].SessionID)
}
