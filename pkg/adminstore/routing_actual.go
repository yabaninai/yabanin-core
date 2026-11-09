package adminstore

import (
	"context"
	"fmt"
	"time"
)

// requested→used transition that request_logs actually recorded over a
// bounded window: which model the caller asked for, which model served the
// request (after alias resolution, rule overrides, tier fallback and
// failover), how often, and how much of the window's traffic the edges
// explain. Nothing here writes.

// RoutingActualEdge is one requested→used pair as SQL returns it, with the
// share filled in by groupActualRouting. From is model_requested (the
// caller's ask); To is model_used (what actually served).
type RoutingActualEdge struct {
	From     string  `json:"from"`
	To       string  `json:"to"`
	Requests int64   `json:"requests"`
	Share    float64 `json:"share"`
}

// RoutingActualCoverage says how much of the window's non-shadow traffic
// the edges explain. Some request_logs rows carry no requested model
// (model_requested is empty); those rows cannot form a from-edge and are
// counted as unattributed instead of being silently dropped, so the UI can
// render the recorded paths together with an honest coverage number.
// Share = attributed / total (1 means the edges cover the whole window).
type RoutingActualCoverage struct {
	TotalRequests        int64   `json:"total_requests"`
	AttributedRequests   int64   `json:"attributed_requests"`
	UnattributedRequests int64   `json:"unattributed_requests"`
	Share                float64 `json:"share"`
}

// RoutingActual is the recorded-paths aggregate for one organization over
// one window. Edges is always non-nil so an empty window serializes as []
// (honest empty), not null. The handler owns the org/window envelope; this
// type carries only the data the store derives.
type RoutingActual struct {
	Edges    []RoutingActualEdge   `json:"edges"`
	Coverage RoutingActualCoverage `json:"coverage"`
}

// routingActualRow is one flat requested×used aggregate as SQL returns it.
type routingActualRow struct {
	Requested string
	Used      string
	Requests  int64
}

// GetActualRouting aggregates request_logs for orgID between from
// (inclusive) and to (exclusive) into requested→used edges plus window
// coverage. Shadow traffic is excluded (the same convention as every other
// request_logs consumer); edges are ordered by request volume (then names,
// deterministically).
func (s *Store) GetActualRouting(ctx context.Context, orgID string, from, to time.Time) (*RoutingActual, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx, `
		SELECT COALESCE(rl.model_requested, '') AS requested,
		       rl.model_used,
		       COUNT(*) AS requests
		FROM request_logs rl
		WHERE rl.org_id = $1::uuid
		  AND rl.created_at >= $2
		  AND rl.created_at < $3
		  AND COALESCE(rl.ab_group, '') <> 'shadow'
		GROUP BY rl.model_requested, rl.model_used
		ORDER BY requests DESC, requested, rl.model_used`, orgID, from, to)
	if err != nil {
		return nil, fmt.Errorf("routing actual: %w", err)
	}
	records := []routingActualRow{}
	for rows.Next() {
		var r routingActualRow
		if err := rows.Scan(&r.Requested, &r.Used, &r.Requests); err != nil {
			return nil, fmt.Errorf("scan routing actual: %w", err)
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("routing actual: %w", err)
	}
	return groupActualRouting(records), nil
}

// groupActualRouting folds the flat requested×used rows into edges with
// shares plus the window coverage. It is a pure function so the share
// rules stay unit-testable without a DB:
//
//   - rows with an empty requested model cannot form a from-edge; they
//     count as unattributed traffic, never silently dropped;
//   - edge shares are fractions of the ATTRIBUTED total (the edges' shares
//     sum to 1 whenever anything was attributed), so a partially-covered
//     window still renders sane path weights;
//   - coverage.share is the attributed fraction of the whole window.
func groupActualRouting(rows []routingActualRow) *RoutingActual {
	edges := []RoutingActualEdge{}
	coverage := RoutingActualCoverage{}
	attributed := int64(0)
	for _, r := range rows {
		coverage.TotalRequests += r.Requests
		if r.Requested == "" {
			coverage.UnattributedRequests += r.Requests
			continue
		}
		attributed += r.Requests
		edges = append(edges, RoutingActualEdge{From: r.Requested, To: r.Used, Requests: r.Requests})
	}
	coverage.AttributedRequests = attributed
	coverage.Share = safeRate(attributed, coverage.TotalRequests)
	for i := range edges {
		edges[i].Share = safeRate(edges[i].Requests, attributed)
	}
	return &RoutingActual{Edges: edges, Coverage: coverage}
}
