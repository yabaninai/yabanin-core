package adminstore

import (
	"context"
	"fmt"
	"time"
)

// GetRequestLogStats returns aggregated request log statistics.
func (s *Store) GetRequestLogStats(ctx context.Context, orgID *string, since time.Time) (*RequestLogStats, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	query := `SELECT COUNT(*), COALESCE(SUM(tokens_in), 0), COALESCE(SUM(tokens_out), 0),
                        COALESCE(AVG(duration_ms), 0),
                        COALESCE(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0)
                 FROM request_logs WHERE COALESCE(ab_group, '') <> 'shadow'`
	var args []interface{}
	where := make([]string, 0)
	if !since.IsZero() {
		where = append(where, "created_at >= $"+fmt.Sprintf("%d", len(args)+1))
		args = append(args, since)
	}
	if orgID != nil {
		where = append(where, "org_id = $"+fmt.Sprintf("%d", len(args)+1))
		args = append(args, *orgID)
	}
	query = appendSQLAnd(query, where)

	var stats RequestLogStats
	err := s.db.QueryRow(ctx, query, args...).Scan(
		&stats.TotalRequests, &stats.TotalTokensIn, &stats.TotalTokensOut,
		&stats.AvgDurationMs, &stats.ErrorCount,
	)
	if err != nil {
		return nil, fmt.Errorf("get request log stats: %w", err)
	}
	if stats.TotalRequests > 0 {
		stats.SuccessRate = float64(stats.TotalRequests-stats.ErrorCount) / float64(stats.TotalRequests) * 100
	}
	return &stats, nil
}

// TopModels returns the top N most-used models with request counts.
func (s *Store) TopModels(ctx context.Context, orgID *string, limit int) ([]TopModelCount, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	query := `SELECT model_used, COUNT(*) FROM request_logs WHERE COALESCE(ab_group, '') <> 'shadow'`
	var args []interface{}
	where := make([]string, 0)
	if orgID != nil {
		where = append(where, "org_id = $"+fmt.Sprintf("%d", len(args)+1))
		args = append(args, *orgID)
	}
	if len(where) > 0 {
		query = appendSQLAnd(query, where)
	}
	query += " GROUP BY model_used ORDER BY COUNT(*) DESC"
	if limit > 0 {
		query += " LIMIT $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, limit)
	}

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("top models: %w", err)
	}
	defer rows.Close()

	var result []TopModelCount
	for rows.Next() {
		var r TopModelCount
		if err := rows.Scan(&r.ModelName, &r.Count); err != nil {
			return nil, fmt.Errorf("scan top model: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// TopOrgs returns the top N organizations by request volume with tokens consumed.
func (s *Store) TopOrgs(ctx context.Context, limit int) ([]TopOrgCount, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	query := `SELECT o.id::text, o.slug, COUNT(*) AS count, COALESCE(SUM(rl.tokens_in), 0) AS tokens_in
	          FROM request_logs rl
	          JOIN organizations o ON o.id = rl.org_id
	          WHERE COALESCE(rl.ab_group, '') <> 'shadow'
	          GROUP BY o.id, o.slug ORDER BY count DESC`
	var args []interface{}
	if limit > 0 {
		query += " LIMIT $1"
		args = append(args, limit)
	}

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("top orgs: %w", err)
	}
	defer rows.Close()

	var result []TopOrgCount
	for rows.Next() {
		var r TopOrgCount
		if err := rows.Scan(&r.OrgID, &r.Slug, &r.Count, &r.TokensIn); err != nil {
			return nil, fmt.Errorf("scan top org: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// RequestTimeSeries returns request counts over time buckets.
func (s *Store) RequestTimeSeries(ctx context.Context, orgID *string, since time.Time, interval string) ([]TimeSeriesPoint, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var intervalCol string
	switch interval {
	case "day":
		intervalCol = "date_trunc('day', created_at)"
	case "minute":
		intervalCol = "date_trunc('minute', created_at)"
	case "week":
		intervalCol = "date_trunc('week', created_at)"
	default:
		intervalCol = "date_trunc('hour', created_at)"
	}

	query := fmt.Sprintf(`SELECT %s AS bucket, COUNT(*) FROM request_logs WHERE COALESCE(ab_group, '') <> 'shadow'`, intervalCol)
	var args []interface{}
	where := make([]string, 0)
	if !since.IsZero() {
		where = append(where, "created_at >= $"+fmt.Sprintf("%d", len(args)+1))
		args = append(args, since)
	}
	if orgID != nil {
		where = append(where, "org_id = $"+fmt.Sprintf("%d", len(args)+1))
		args = append(args, *orgID)
	}
	query = appendSQLAnd(query, where)
	query += " GROUP BY bucket ORDER BY bucket"

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("request time series: %w", err)
	}
	defer rows.Close()

	var result []TimeSeriesPoint
	for rows.Next() {
		var r TimeSeriesPoint
		var bucket time.Time
		if err := rows.Scan(&bucket, &r.Value); err != nil {
			return nil, fmt.Errorf("scan time series point: %w", err)
		}
		r.Time = bucket.Format(time.RFC3339)
		result = append(result, r)
	}
	return result, rows.Err()
}

// ErrorBreakdown returns error counts by category.
func (s *Store) ErrorBreakdown(ctx context.Context, orgID *string, since time.Time) ([]ErrorBreakdownEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	query := `SELECT 
		          CASE 
		              WHEN status_code >= 500 THEN 'server_error'
		              WHEN status_code >= 400 THEN 'client_error'
		              ELSE 'other'
		          END AS category,
		          COUNT(*) AS count
	          FROM request_logs`
	var args []interface{}
	where := make([]string, 0)
	if !since.IsZero() {
		where = append(where, "created_at >= $"+fmt.Sprintf("%d", len(args)+1))
		args = append(args, since)
	}
	if orgID != nil {
		where = append(where, "org_id = $"+fmt.Sprintf("%d", len(args)+1))
		args = append(args, *orgID)
	}
	if len(where) > 0 {
		query += " WHERE " + joinConditions(where)
	}
	query += " GROUP BY category ORDER BY count DESC"

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("error breakdown: %w", err)
	}
	defer rows.Close()

	var result []ErrorBreakdownEntry
	for rows.Next() {
		var r ErrorBreakdownEntry
		if err := rows.Scan(&r.Category, &r.Count); err != nil {
			return nil, fmt.Errorf("scan error breakdown: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// LatencyPercentiles returns p50/p90/p95/p99 latency percentiles in ms.
func (s *Store) LatencyPercentiles(ctx context.Context, orgID *string, since time.Time) (*LatencyPercentile, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	query := `SELECT
		          COALESCE(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY duration_ms), 0) AS p50,
		          COALESCE(PERCENTILE_CONT(0.90) WITHIN GROUP (ORDER BY duration_ms), 0) AS p90,
		          COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms), 0) AS p95,
		          COALESCE(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms), 0) AS p99
	          FROM request_logs WHERE COALESCE(ab_group, '') <> 'shadow'`
	var args []interface{}
	where := make([]string, 0)
	if !since.IsZero() {
		where = append(where, "created_at >= $"+fmt.Sprintf("%d", len(args)+1))
		args = append(args, since)
	}
	if orgID != nil {
		where = append(where, "org_id = $"+fmt.Sprintf("%d", len(args)+1))
		args = append(args, *orgID)
	}
	query = appendSQLAnd(query, where)

	var p LatencyPercentile
	err := s.db.QueryRow(ctx, query, args...).Scan(&p.P50, &p.P90, &p.P95, &p.P99)
	if err != nil {
		return nil, fmt.Errorf("latency percentiles: %w", err)
	}
	return &p, nil
}

// RecentErrors returns the most recent failed requests for debugging.
func (s *Store) RecentErrors(ctx context.Context, orgID *string, limit int) ([]RecentErrorLog, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	query := `SELECT id::bigint, COALESCE(request_id, ''), COALESCE(org_id::text, ''), COALESCE(model_used, ''), status_code,
	                 COALESCE(duration_ms, 0), COALESCE(error, ''), created_at
	          FROM request_logs WHERE status_code >= 400 AND COALESCE(ab_group, '') <> 'shadow'`
	var args []interface{}
	where := make([]string, 0)
	if orgID != nil {
		where = append(where, "org_id = $"+fmt.Sprintf("%d", len(args)+1))
		args = append(args, *orgID)
	}
	if len(where) > 0 {
		query += " AND " + joinConditions(where)
	}
	query += " ORDER BY created_at DESC"
	if limit > 0 {
		query += " LIMIT $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, limit)
	}

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("recent errors: %w", err)
	}
	defer rows.Close()

	var result []RecentErrorLog
	for rows.Next() {
		var r RecentErrorLog
		if err := rows.Scan(&r.ID, &r.RequestID, &r.OrgID, &r.ModelUsed, &r.StatusCode, &r.DurationMs, &r.Error, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan recent error: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
