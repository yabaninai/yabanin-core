package adminstore

import (
	"context"
	"fmt"
	"time"
)

// CacheAnalytics holds cache performance data for an organization.
type CacheAnalytics struct {
	TotalRequests      int64   `json:"total_requests"`
	HitsExact          int64   `json:"hits_exact"`
	HitsSemantic       int64   `json:"hits_semantic"`
	Misses             int64   `json:"misses"`
	CacheHitRate       float64 `json:"cache_hit_rate"`
	SavingsUSD         float64 `json:"savings_usd"`
	CounterfactualCost float64 `json:"counterfactual_cost_usd"`
	AvgSimilarity      float64 `json:"avg_similarity"`
}

// GetCacheAnalytics returns cache hit-rate and savings analytics for an org.
func (s *Store) GetCacheAnalytics(ctx context.Context, orgID string, from, to time.Time) (*CacheAnalytics, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	var totalRequests, hitsExact, hitsSemantic, misses int64
	var savingsUSD, counterfactualCost, avgSimilarity float64

	err := s.db.QueryRow(ctx, `
		SELECT
			COUNT(*) AS total_requests,
			COUNT(*) FILTER (WHERE cache_hit_type = 'exact') AS hits_exact,
			COUNT(*) FILTER (WHERE cache_hit_type = 'semantic') AS hits_semantic,
			COUNT(*) FILTER (WHERE cache_hit_type IS NULL) AS misses,
			COALESCE(SUM(counterfactual_cost_usd), 0) AS counterfactual_cost,
			COALESCE(AVG(cache_similarity), 0) AS avg_similarity
		FROM request_logs
		WHERE org_id = $1 AND created_at BETWEEN $2 AND $3
		  AND COALESCE(ab_group, '') <> 'shadow'
	`, orgID, from, to).Scan(
		&totalRequests, &hitsExact, &hitsSemantic, &misses,
		&counterfactualCost, &avgSimilarity,
	)
	if err != nil {
		return nil, fmt.Errorf("cache analytics query: %w", err)
	}

	hits := hitsExact + hitsSemantic
	hitRate := 0.0
	if totalRequests > 0 {
		hitRate = float64(hits) / float64(totalRequests)
	}

	// Savings = counterfactual cost minus actual cost (sum of estimated_cost_usd for cache-hit requests).
	// For simplicity, we estimate savings as the full counterfactual cost for cache-hits.
	savingsUSD = counterfactualCost * hitRate

	return &CacheAnalytics{
		TotalRequests:      totalRequests,
		HitsExact:          hitsExact,
		HitsSemantic:       hitsSemantic,
		Misses:             misses,
		CacheHitRate:       hitRate,
		SavingsUSD:         savingsUSD,
		CounterfactualCost: counterfactualCost,
		AvgSimilarity:      avgSimilarity,
	}, nil
}
