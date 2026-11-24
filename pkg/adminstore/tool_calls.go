package adminstore

import (
	"context"
	"fmt"
	"time"
)

// ToolCallsReport aggregates the tool/function calls models requested across
// requests: the cross-request view the explorer inspector cannot give. Rows
// exist only for parsed calls — untracked/truncated samples read as absence,
// never as zero-usage.
type ToolCallsReport struct {
	TotalCalls    int            `json:"total_calls"`
	DistinctTools int            `json:"distinct_tools"`
	Top           []ToolCallsRow `json:"top_tools"`
	ByModel       []ToolModelRow `json:"by_model"`
	RequestsUsing int            `json:"requests_using_tools"`
}

// ToolCallsRow is one tool's aggregate inside the report window.
type ToolCallsRow struct {
	Tool       string    `json:"tool_name"`
	Calls      int       `json:"calls"`
	Share      float64   `json:"share"` // 0..100 of total calls
	LastUsedAt time.Time `json:"last_used_at"`
}

// ToolModelRow groups tool calls by the model that issued them.
type ToolModelRow struct {
	Model string `json:"model"`
	Calls int    `json:"calls"`
}

// GetToolCallsReport aggregates tool_calls for one org over the window.
func (s *Store) GetToolCallsReport(ctx context.Context, orgID string, days int) (*ToolCallsReport, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if days <= 0 || days > 366 {
		days = 30
	}
	to := time.Now()
	from := to.AddDate(0, 0, -days)

	total, distinct, requests, err := s.toolReportTotals(ctx, orgID, from, to)
	if err != nil {
		return nil, err
	}
	rep := &ToolCallsReport{TotalCalls: total, DistinctTools: distinct, RequestsUsing: requests}
	if err := s.appendToolReportTop(ctx, rep, orgID, from, to, total); err != nil {
		return nil, err
	}
	if err := s.appendToolReportByModel(ctx, rep, orgID, from, to); err != nil {
		return nil, err
	}
	return rep, nil
}

// toolReportTotals returns the fact-domain totals (calls, distinct tool
// names) and the request-identity count. RequestsUsing counts physical
// request identities (0028/0030), not client correlations, using the single
// association rule of this package (toolFactMatchesRow): invocation-bearing
// facts count their exact rl row, and NULL-invocation facts (legacy, or
// pre-0030 writer mode) count the org's unique carrier — ambiguous
// multi-carrier correlations count no row. Facts retained past their
// request_logs rows (retention keeps facts longer than rows) still count:
// once per minted invocation when invocation identity survives, else once
// under the correlation key, so pruning parents never silently drops usage.
func (s *Store) toolReportTotals(ctx context.Context, orgID string, from, to time.Time) (total, distinct, requests int, err error) {
	err = s.db.QueryRow(ctx, `
		SELECT (SELECT COUNT(*) FROM tool_calls
		        WHERE org_id = $1 AND created_at BETWEEN $2 AND $3),
		       (SELECT COUNT(DISTINCT tool_name) FROM tool_calls
		        WHERE org_id = $1 AND created_at BETWEEN $2 AND $3),
		       (SELECT COUNT(DISTINCT k) FROM (
		          SELECT rl.id::text AS k
		          FROM tool_calls tc
		          JOIN request_logs rl
		            ON rl.org_id = tc.org_id AND rl.request_id = tc.request_id
		           AND `+toolFactMatchesRow+`
		          WHERE tc.org_id = $1 AND tc.created_at BETWEEN $2 AND $3
		          UNION
		          SELECT 'i:' || tc.invocation_id
		          FROM tool_calls tc
		          WHERE tc.org_id = $1 AND tc.created_at BETWEEN $2 AND $3
		            AND tc.invocation_id IS NOT NULL
		            AND NOT EXISTS (SELECT 1 FROM request_logs rl
		            WHERE rl.org_id = tc.org_id AND rl.request_id = tc.request_id
		              AND rl.invocation_id = tc.invocation_id)
		          UNION
		          SELECT 'r:' || tc.request_id
		          FROM tool_calls tc
		          WHERE tc.org_id = $1 AND tc.created_at BETWEEN $2 AND $3
		            AND tc.invocation_id IS NULL
		            AND NOT EXISTS (SELECT 1 FROM request_logs rl
		            WHERE rl.org_id = tc.org_id AND rl.request_id = tc.request_id)
		       ) keys)`,
		orgID, from, to).Scan(&total, &distinct, &requests)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("tool_calls totals: %w", err)
	}
	return total, distinct, requests, nil
}

// appendToolReportTop fills the per-tool leaderboard (top 25 by calls) with
// each tool's share of the org's total calls in the window.
func (s *Store) appendToolReportTop(ctx context.Context, rep *ToolCallsReport, orgID string, from, to time.Time, total int) error {
	rows, err := s.db.Query(ctx, `
		SELECT tool_name, COUNT(*), MAX(created_at)
		FROM tool_calls
		WHERE org_id = $1 AND created_at BETWEEN $2 AND $3
		GROUP BY tool_name
		ORDER BY COUNT(*) DESC, tool_name ASC
		LIMIT 25`, orgID, from, to)
	if err != nil {
		return fmt.Errorf("tool_calls top: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r ToolCallsRow
		if err := rows.Scan(&r.Tool, &r.Calls, &r.LastUsedAt); err != nil {
			return fmt.Errorf("tool_calls top scan: %w", err)
		}
		if total > 0 {
			r.Share = float64(r.Calls) / float64(total) * 100
		}
		rep.Top = append(rep.Top, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("tool_calls top rows: %w", err)
	}
	return nil
}

// appendToolReportByModel fills the per-model call counts for the window.
func (s *Store) appendToolReportByModel(ctx context.Context, rep *ToolCallsReport, orgID string, from, to time.Time) error {
	mrows, err := s.db.Query(ctx, `
		SELECT COALESCE(model_used, ''), COUNT(*)
		FROM tool_calls
		WHERE org_id = $1 AND created_at BETWEEN $2 AND $3
		GROUP BY COALESCE(model_used, '')
		ORDER BY COUNT(*) DESC`, orgID, from, to)
	if err != nil {
		return fmt.Errorf("tool_calls by model: %w", err)
	}
	defer mrows.Close()
	for mrows.Next() {
		var r ToolModelRow
		if err := mrows.Scan(&r.Model, &r.Calls); err != nil {
			return fmt.Errorf("tool_calls by model scan: %w", err)
		}
		rep.ByModel = append(rep.ByModel, r)
	}
	if err := mrows.Err(); err != nil {
		return fmt.Errorf("tool_calls by model rows: %w", err)
	}
	return nil
}
