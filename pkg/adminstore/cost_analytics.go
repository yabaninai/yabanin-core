package adminstore

import (
	"context"
	"fmt"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// CostReport holds aggregated cost analytics for one org or globally.
type CostReport struct {
	TotalCostUSD       float64              `json:"total_cost_usd"`
	CounterfactualCost float64              `json:"counterfactual_cost"`
	SavingsUSD         float64              `json:"savings_usd"`
	SavingsPercent     float64              `json:"savings_percent"`
	RequestCount       int                  `json:"request_count"`
	AvgCostPerRequest  float64              `json:"avg_cost_per_request"`
	ByModel            []ModelCostBreakdown `json:"by_model"`
	ByDay              []DailyCost          `json:"by_day"`
	// Pricing carries the as-of / completeness context of the USD figures
	// above (A01): zero cost is not necessarily free. Additive — old
	// consumers ignore it.
	Pricing PricingMetadata `json:"pricing"`
}

// ModelCostBreakdown holds cost breakdown for a single model.
type ModelCostBreakdown struct {
	ModelName    string  `json:"model_name"`
	TotalCost    float64 `json:"total_cost"`
	RequestCount int     `json:"request_count"`
	TokensIn     int64   `json:"tokens_in"`
	TokensOut    int64   `json:"tokens_out"`
}

// DailyCost holds cost data for a single day.
type DailyCost struct {
	Date         string  `json:"date"`
	TotalCost    float64 `json:"total_cost"`
	RequestCount int     `json:"request_count"`
}

// GetCostAnalytics retrieves cost breakdown for an org within a time window.
// A non-empty provider narrows to that provider's models via models_registry
// (the U03 scope bar's provider dimension).
func (s *Store) GetCostAnalytics(ctx context.Context, orgID string, from, to time.Time, provider string) (*CostReport, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	whereClause := "org_id = $1 AND created_at BETWEEN $2 AND $3 AND COALESCE(ab_group, '') <> 'shadow'"
	args := []interface{}{orgID, from, to}
	if provider != "" {
		args = append(args, provider)
		whereClause += fmt.Sprintf(" AND model_used IN (SELECT model_name FROM models_registry WHERE provider = $%d)", len(args))
	}

	// Total cost stats
	var totalCost, counterfactual float64
	var reqCount int
	err := s.db.QueryRow(ctx, `
		SELECT COALESCE(SUM(cost_in_usd), 0), COALESCE(SUM(counterfactual_cost_usd), 0), COUNT(*)
		FROM request_logs WHERE `+whereClause, args...).Scan(&totalCost, &counterfactual, &reqCount)
	if err != nil {
		return nil, fmt.Errorf("cost analytics total: %w", err)
	}

	savings := counterfactual - totalCost
	savingsPct := 0.0
	if counterfactual > 0 {
		savingsPct = (savings / counterfactual) * 100
	}

	avgCost := 0.0
	if reqCount > 0 {
		avgCost = totalCost / float64(reqCount)
	}

	// A02: all-or-error — a partial cost report (missing by-model or by-day
	// rows) would misstate the aggregates, so every Query/Scan/rows.Err below
	// is propagated instead of swallowed.
	// By-model breakdown
	var byModel []ModelCostBreakdown
	rows, err := s.db.Query(ctx, `
		SELECT model_used,
		       COALESCE(SUM(cost_in_usd), 0), COUNT(*),
		       COALESCE(SUM(tokens_in), 0), COALESCE(SUM(tokens_out), 0)
		FROM request_logs WHERE `+whereClause+`
		GROUP BY model_used
		ORDER BY SUM(cost_in_usd) DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("cost analytics by-model query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var m ModelCostBreakdown
		if err := rows.Scan(&m.ModelName, &m.TotalCost, &m.RequestCount, &m.TokensIn, &m.TokensOut); err != nil {
			return nil, fmt.Errorf("cost analytics by-model scan: %w", err)
		}
		byModel = append(byModel, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cost analytics by-model rows: %w", err)
	}

	// By-day breakdown
	var byDay []DailyCost
	dayRows, err := s.db.Query(ctx, `
		SELECT DATE(created_at),
		       COALESCE(SUM(cost_in_usd), 0), COUNT(*)
		FROM request_logs WHERE `+whereClause+`
		GROUP BY DATE(created_at)
		ORDER BY DATE(created_at)`, args...)
	if err != nil {
		return nil, fmt.Errorf("cost analytics by-day query: %w", err)
	}
	defer dayRows.Close()
	for dayRows.Next() {
		var d DailyCost
		var date time.Time
		if err := dayRows.Scan(&date, &d.TotalCost, &d.RequestCount); err != nil {
			return nil, fmt.Errorf("cost analytics by-day scan: %w", err)
		}
		d.Date = date.Format("2006-01-02")
		byDay = append(byDay, d)
	}
	if err := dayRows.Err(); err != nil {
		return nil, fmt.Errorf("cost analytics by-day rows: %w", err)
	}

	return &CostReport{
		TotalCostUSD:       totalCost,
		CounterfactualCost: counterfactual,
		SavingsUSD:         savings,
		SavingsPercent:     savingsPct,
		RequestCount:       reqCount,
		AvgCostPerRequest:  avgCost,
		ByModel:            byModel,
		ByDay:              byDay,
		Pricing:            buildPricingMetadata(s.db, ctx, whereClause, reqCount, args...),
	}, nil
}

// buildPricingMetadata computes the as-of / completeness context (A01) shared
// by the per-org and global cost reports. The provider is recovered via
// models_registry (request_logs has no provider column); 'openai-compat' is
// the registry default for legacy rows. Zero cost is not free: coverage
// status + unpriced share + top unpriced models let surfaces say "unknown".
//
// AF-07 contract: coverage is measured against the price sources in effect
// now (file pricer snapshot + models_pricing/models_registry); it never
// claims that the whole window was priced as-of that snapshot. Provenance
// (PricingAsOf) and failures (CoverageStatus/CoverageError) are reported
// separately; a failed Query/Scan/rows.Err degrades to unknown/partial and
// never serializes as an unmarked fully-priced report.
func buildPricingMetadata(db pgxdb, ctx context.Context, whereClause string, reqCount int, args ...interface{}) PricingMetadata {
	// AF-14: the pricing predicate rewritten from the correlated
	// NOT EXISTS (... provider IN (SELECT ... UNION ALL ...)) form to the
	// equivalent uncorrelated NOT IN over the set of priced models —
	// a model is priced iff some models_pricing row matches its registry
	// provider or the 'openai-compat' default. Identical result set (the
	// AF-07 contract is untouched: same coverage counts, same top list),
	// but PostgreSQL can hash the catalog side once instead of re-resolving
	// the registry per candidate row (measured, baseline EXPLAIN: the
	// SubPlan re-scanned models_registry per row).
	pricingWhere := whereClause + `
		AND model_used NOT IN (
		    SELECT p.model FROM models_pricing p
		    WHERE p.provider = 'openai-compat'
		    UNION
		    SELECT p.model FROM models_pricing p
		    JOIN models_registry r
		      ON r.model_name = p.model AND r.provider = p.provider
		)`
	// A03: cite the ACTUAL price snapshot the report was computed against —
	// the file-backed pricer's provenance (source, date, SHA256), not a
	// generic "bundled table" label. CORE-REF-04: when the pricer serves the
	// reference catalog, also carry the structured citation (version,
	// generation date, digest) so surfaces render `catalog:<version>
	// digest:<prefix>` without parsing the PricingAsOf line.
	prov := pricing.DefaultFilePricer().Provenance()
	meta := PricingMetadata{
		PricingAsOf:    prov.Source + " " + prov.Date + " " + prov.SHA256,
		UnpricedModels: []string{},
	}
	if info, ok := pricing.DefaultFilePricer().CatalogProvenance(); ok {
		meta.PricingCatalog = &PricingCatalogInfo{
			Version:     info.Version,
			GeneratedAt: info.GeneratedAt,
			Digest:      info.Digest,
		}
	}
	if reqCount == 0 {
		// Empty window: a distinct state, not "fully priced" and not an
		// unknown-cost measurement. Share stays 0 by convention (no
		// division by zero), null would read as a failed measurement.
		zero := 0.0
		meta.UnpricedShare = &zero
		meta.CoverageStatus = CoverageEmpty
		return meta
	}
	var unpricedReqs int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM request_logs WHERE `+pricingWhere, args...).Scan(&unpricedReqs); err != nil {
		// Pricing context is advisory: on failure the report degrades to
		// "unknown coverage" rather than failing the whole cost report —
		// and never to share=0, which would read as fully priced.
		meta.CoverageStatus = CoverageUnknown
		meta.CoverageError = "coverage query failed"
		return meta
	}
	share := float64(unpricedReqs) / float64(reqCount)
	meta.UnpricedShare = &share
	switch unpricedReqs {
	case 0:
		meta.CoverageStatus = CoverageComplete
	case reqCount:
		// 100% unpriced: the measurement succeeded, but the cost of the
		// window is unknown (nothing in the price table).
		meta.CoverageStatus = CoverageUnknown
	default:
		meta.CoverageStatus = CoveragePartial
	}
	// markListFailure: the share itself was measured, but the top-unpriced
	// models list failed. Coverage information is incomplete — never leave
	// the report looking like an unmarked success; a failed "complete"
	// degrades to "partial" (a truncated check must not claim completeness).
	markListFailure := func(reason string) {
		meta.CoverageError = reason
		if meta.CoverageStatus == CoverageComplete {
			meta.CoverageStatus = CoveragePartial
		}
	}
	rows, err := db.Query(ctx, `
		SELECT model_used, COUNT(*) AS n
		FROM request_logs WHERE `+pricingWhere+`
		GROUP BY model_used
		ORDER BY n DESC
		LIMIT 5`, args...)
	if err != nil {
		markListFailure("unpriced model list query failed")
		return meta
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			markListFailure("unpriced model list scan failed")
			return meta
		}
		meta.UnpricedModels = append(meta.UnpricedModels, name)
	}
	if err := rows.Err(); err != nil {
		markListFailure("unpriced model list incomplete")
		return meta
	}
	return meta
}

// GetGlobalCostStats returns cost stats across all orgs.
func (s *Store) GetGlobalCostStats(ctx context.Context, from, to time.Time) (*CostReport, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	whereClause := "created_at BETWEEN $1 AND $2 AND COALESCE(ab_group, '') <> 'shadow'"
	args := []interface{}{from, to}

	var totalCost, counterfactual float64
	var reqCount int
	err := s.db.QueryRow(ctx, `
		SELECT COALESCE(SUM(cost_in_usd), 0), COALESCE(SUM(counterfactual_cost_usd), 0), COUNT(*)
		FROM request_logs WHERE `+whereClause, args...).Scan(&totalCost, &counterfactual, &reqCount)
	if err != nil {
		return nil, fmt.Errorf("global cost stats: %w", err)
	}

	savings := counterfactual - totalCost
	savingsPct := 0.0
	if counterfactual > 0 {
		savingsPct = (savings / counterfactual) * 100
	}

	avgCost := 0.0
	if reqCount > 0 {
		avgCost = totalCost / float64(reqCount)
	}

	// By-model breakdown (no org_id filter)
	var byModel []ModelCostBreakdown
	rows, err := s.db.Query(ctx, `
		SELECT model_used,
		       COALESCE(SUM(cost_in_usd), 0), COUNT(*),
		       COALESCE(SUM(tokens_in), 0), COALESCE(SUM(tokens_out), 0)
		FROM request_logs WHERE `+whereClause+`
		GROUP BY model_used
		ORDER BY SUM(cost_in_usd) DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("cost analytics by-model query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var m ModelCostBreakdown
		if err := rows.Scan(&m.ModelName, &m.TotalCost, &m.RequestCount, &m.TokensIn, &m.TokensOut); err != nil {
			return nil, fmt.Errorf("cost analytics by-model scan: %w", err)
		}
		byModel = append(byModel, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cost analytics by-model rows: %w", err)
	}

	// By-day breakdown (no org_id filter)
	var byDay []DailyCost
	dayRows, err := s.db.Query(ctx, `
		SELECT DATE(created_at),
		       COALESCE(SUM(cost_in_usd), 0), COUNT(*)
		FROM request_logs WHERE `+whereClause+`
		GROUP BY DATE(created_at)
		ORDER BY DATE(created_at)`, args...)
	if err != nil {
		return nil, fmt.Errorf("cost analytics by-day query: %w", err)
	}
	defer dayRows.Close()
	for dayRows.Next() {
		var d DailyCost
		var date time.Time
		if err := dayRows.Scan(&date, &d.TotalCost, &d.RequestCount); err != nil {
			return nil, fmt.Errorf("cost analytics by-day scan: %w", err)
		}
		d.Date = date.Format("2006-01-02")
		byDay = append(byDay, d)
	}
	if err := dayRows.Err(); err != nil {
		return nil, fmt.Errorf("cost analytics by-day rows: %w", err)
	}

	return &CostReport{
		TotalCostUSD:       totalCost,
		CounterfactualCost: counterfactual,
		SavingsUSD:         savings,
		SavingsPercent:     savingsPct,
		RequestCount:       reqCount,
		AvgCostPerRequest:  avgCost,
		ByModel:            byModel,
		ByDay:              byDay,
		Pricing:            buildPricingMetadata(s.db, ctx, whereClause, reqCount, args...),
	}, nil
}
