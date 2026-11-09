package adminstore

import (
	"context"
	"fmt"
	"time"
)

// UntaggedBucket is the label for requests with no value in the grouping
// column (task_id / agent_id / session_id).
const UntaggedBucket = "(untagged)"

// TaskAnalyticsGroup is one row of the CTOR/task analytics report: a group
// (task, session, or agent) with its cost, counterfactual (what the same work
// would have cost at the premium tier), the resulting savings, and cache hits.
type TaskAnalyticsGroup struct {
	Group             string  `json:"group"`
	CostUSD           float64 `json:"cost_usd"`
	CounterfactualUSD float64 `json:"counterfactual_usd"`
	SavingsUSD        float64 `json:"savings_usd"`
	CacheHits         int64   `json:"cache_hits"`
	RequestCount      int64   `json:"request_count"`
}

// TaskAnalyticsReport is the result of GetTaskAnalytics.
type TaskAnalyticsReport struct {
	OrgID        string               `json:"org_id"`
	From         time.Time            `json:"from"`
	To           time.Time            `json:"to"`
	GroupBy      string               `json:"group_by"` // task | session | agent | user
	Groups       []TaskAnalyticsGroup `json:"groups"`
	TotalCostUSD float64              `json:"total_cost_usd"`
}

// taskAnalyticsColumn maps a group_by value to the request_logs column used
// for grouping (and the bucket expression for NULLs).
func taskAnalyticsColumn(groupBy string) (string, error) {
	switch groupBy {
	case "task":
		return "task_id", nil
	case "session":
		return "session_id", nil
	case "agent":
		return "agent_id", nil
	case "user":
		return "user_id", nil
	default:
		return "", fmt.Errorf("group_by must be one of: task, session, agent, user (got %q)", groupBy)
	}
}

// GetTaskAnalytics returns per-group cost / counterfactual / savings /
// cache-hits for an org within [from, to]. Shadow rows are excluded (they are
// mirrors, not real spend). group_by is task | session | agent | user; a NULL group
// value is reported under "(untagged)". limit (capped at 500) bounds the number
// of groups returned, ordered by cost descending.
func (s *Store) GetTaskAnalytics(ctx context.Context, orgID string, from, to time.Time, groupBy string, limit int) (*TaskAnalyticsReport, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	column, err := taskAnalyticsColumn(groupBy)
	if err != nil {
		return nil, err
	}

	// bucket is the grouping key: COALESCE the column to the untagged label
	// (UUIDs are cast to text for the session/agent groups).
	bucketExpr := fmt.Sprintf("COALESCE(%s::text, %s)", column, "'"+UntaggedBucket+"'")

	rows, err := s.db.Query(ctx,
		`SELECT `+bucketExpr+`,
		       COALESCE(SUM(cost_in_usd), 0),
		       COALESCE(SUM(counterfactual_cost_usd), 0),
		       COALESCE(SUM(CASE WHEN cache_hit_type IS NOT NULL AND cache_hit_type <> '' THEN 1 ELSE 0 END), 0),
		       COUNT(*)
		 FROM request_logs
		 WHERE org_id = $1 AND created_at BETWEEN $2 AND $3 AND COALESCE(ab_group, '') <> 'shadow'
		 GROUP BY 1
		 ORDER BY SUM(cost_in_usd) DESC NULLS LAST, 1 ASC
		 LIMIT $4`,
		orgID, from, to, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("task analytics query: %w", err)
	}
	defer rows.Close()

	var groups []TaskAnalyticsGroup
	var totalCost float64
	for rows.Next() {
		var g TaskAnalyticsGroup
		if err := rows.Scan(&g.Group, &g.CostUSD, &g.CounterfactualUSD, &g.CacheHits, &g.RequestCount); err != nil {
			return nil, fmt.Errorf("task analytics scan: %w", err)
		}
		g.SavingsUSD = g.CounterfactualUSD - g.CostUSD
		groups = append(groups, g)
		totalCost += g.CostUSD
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("task analytics rows: %w", err)
	}
	if groups == nil {
		groups = []TaskAnalyticsGroup{}
	}
	return &TaskAnalyticsReport{
		OrgID:        orgID,
		From:         from,
		To:           to,
		GroupBy:      groupBy,
		Groups:       groups,
		TotalCostUSD: totalCost,
	}, nil
}
