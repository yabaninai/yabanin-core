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

	var total, distinct, requests int
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*),
		       COUNT(DISTINCT tool_name),
		       COUNT(DISTINCT request_id)
		FROM tool_calls
		WHERE org_id = $1 AND created_at BETWEEN $2 AND $3`,
		orgID, from, to).Scan(&total, &distinct, &requests)
	if err != nil {
		return nil, fmt.Errorf("tool_calls totals: %w", err)
	}

	rep := &ToolCallsReport{TotalCalls: total, DistinctTools: distinct, RequestsUsing: requests}

	rows, err := s.db.Query(ctx, `
		SELECT tool_name, COUNT(*), MAX(created_at)
		FROM tool_calls
		WHERE org_id = $1 AND created_at BETWEEN $2 AND $3
		GROUP BY tool_name
		ORDER BY COUNT(*) DESC, tool_name ASC
		LIMIT 25`, orgID, from, to)
	if err != nil {
		return nil, fmt.Errorf("tool_calls top: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r ToolCallsRow
		if err := rows.Scan(&r.Tool, &r.Calls, &r.LastUsedAt); err != nil {
			return nil, fmt.Errorf("tool_calls top scan: %w", err)
		}
		if total > 0 {
			r.Share = float64(r.Calls) / float64(total) * 100
		}
		rep.Top = append(rep.Top, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tool_calls top rows: %w", err)
	}

	mrows, err := s.db.Query(ctx, `
		SELECT COALESCE(model_used, ''), COUNT(*)
		FROM tool_calls
		WHERE org_id = $1 AND created_at BETWEEN $2 AND $3
		GROUP BY COALESCE(model_used, '')
		ORDER BY COUNT(*) DESC`, orgID, from, to)
	if err != nil {
		return nil, fmt.Errorf("tool_calls by model: %w", err)
	}
	defer mrows.Close()
	for mrows.Next() {
		var r ToolModelRow
		if err := mrows.Scan(&r.Model, &r.Calls); err != nil {
			return nil, fmt.Errorf("tool_calls by model scan: %w", err)
		}
		rep.ByModel = append(rep.ByModel, r)
	}
	if err := mrows.Err(); err != nil {
		return nil, fmt.Errorf("tool_calls by model rows: %w", err)
	}

	return rep, nil
}
