package adminstore

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Pricing coverage statuses (AF-07). Coverage is measured against the price
// sources in effect when the report is built — the file-backed pricer
// snapshot plus models_pricing/models_registry — and says nothing about the
// historical prices that actually priced each row at request time.
const (
	// CoverageComplete: every request in the window is priced
	// (unpriced_share = 0).
	CoverageComplete = "complete"
	// CoveragePartial: measured, some requests unpriced (0 < share < 1).
	CoveragePartial = "partial"
	// CoverageUnknown: the cost of the window cannot be quantified — either
	// the coverage measurement failed (unpriced_share = null) or every
	// request is unpriced (unpriced_share = 1).
	CoverageUnknown = "unknown"
	// CoverageEmpty: no requests in the window; not a coverage measurement.
	CoverageEmpty = "empty"
)

// PricingMetadata carries the as-of / completeness context of the price table
// behind the USD figures in this report (A01). Downstream surfaces MUST NOT
// present an unpriced share as free: actual_cost_usd = 0 can mean "the model
// is not in the price table" — use coverage_status, unpriced_share and
// unpriced_models to distinguish zero-cost from unknown-cost (AF-07).
type PricingMetadata struct {
	// PricingAsOf is the provenance label of the price source used to build
	// this report (file-backed snapshot: source + date + SHA256). Since
	// CORE-REF-04 the default source is the reference catalog, so the line
	// reads `yabanin-catalog@<version> <date> sha256:<digest>`. It is NOT a
	// freshness claim and NOT an as-of guarantee over the whole window: rows
	// were priced with the prices current at request time, which may differ
	// from this snapshot. It never carries failure markers — failures are
	// reported via CoverageStatus/CoverageError.
	PricingAsOf string `json:"pricing_as_of"`
	// PricingCatalog is the structured citation of the reference catalog
	// behind PricingAsOf when the report was computed against the catalog
	// projection (CORE-REF-04); nil for legacy snapshot-backed reports.
	// Structured fields let surfaces render `catalog:<version>
	// digest:<prefix>` without parsing the PricingAsOf line.
	PricingCatalog *PricingCatalogInfo `json:"pricing_catalog,omitempty"`
	// CoverageStatus classifies pricing coverage of the window; see the
	// Coverage* constants. Empty on responses produced before AF-07 — an
	// absent status must not be read as proven full coverage. Any
	// Query/Scan/rows.Err failure degrades to "unknown" or "partial", never
	// to an unmarked "complete".
	CoverageStatus string `json:"coverage_status,omitempty"`
	// UnpricedShare is the measured fraction (0..1) of window requests whose
	// model is not in the price table. nil means "not measured" (coverage
	// query failed, or an empty window) — it is NOT zero coverage.
	UnpricedShare *float64 `json:"unpriced_share"`
	// UnpricedModels lists the top unpriced model names by request count.
	// Best-effort: with a non-empty CoverageError it may be truncated.
	UnpricedModels []string `json:"unpriced_models,omitempty"`
	// CoverageError is a stable reason marker set when part of the coverage
	// measurement failed. Kept separate from PricingAsOf: provenance and
	// failure are reported independently (AF-07).
	CoverageError string `json:"coverage_error,omitempty"`
}

// PricingCatalogInfo is the structured citation of the served reference
// catalog (CORE-REF-04): the sealed catalog version, its generation date,
// and its digest. Reports computed against the legacy bundled snapshot carry
// no such citation.
type PricingCatalogInfo struct {
	Version     string `json:"version"`
	GeneratedAt string `json:"generated_at"`
	Digest      string `json:"digest"`
}

// SavingsReport holds combined cache + routing savings analytics.
// This is the Go equivalent of scripts/measure_savings.py output.
type SavingsReport struct {
	Period             string              `json:"period"`
	TotalRequests      int                 `json:"total_requests"`
	ActualCostUSD      float64             `json:"actual_cost_usd"`
	CounterfactualCost float64             `json:"counterfactual_cost_usd"`
	CombinedSavingsPct float64             `json:"combined_savings_pct"`
	KillCriterionMet   bool                `json:"kill_criterion_met"`
	CacheHits          int                 `json:"cache_hits"`
	CacheSavingsPct    float64             `json:"cache_savings_pct"`
	RoutedRequests     int                 `json:"routed_requests"`
	RoutingSavingsPct  float64             `json:"routing_savings_pct"`
	TopModelsByCost    []SavingsModelRow   `json:"top_models_by_cost"`
	DailyBreakdown     []SavingsDayRow     `json:"daily_breakdown"`
	ClassifierDist     []ClassifierDistRow `json:"classifier_distribution"`
	// Pricing carries the as-of / completeness context of the USD figures
	// above (A01). Additive — old consumers ignore it.
	Pricing PricingMetadata `json:"pricing"`
}

// SavingsModelRow is a per-model breakdown for savings analytics.
type SavingsModelRow struct {
	Model                 string  `json:"model"`
	Requests              int     `json:"requests"`
	ActualCostUSD         float64 `json:"actual_cost_usd"`
	CounterfactualCostUSD float64 `json:"counterfactual_cost_usd"`
	SavingsPct            float64 `json:"savings_pct"`
}

// SavingsDayRow is a per-day breakdown for savings analytics.
type SavingsDayRow struct {
	Date                  string  `json:"date"`
	Requests              int     `json:"requests"`
	ActualCostUSD         float64 `json:"actual_cost_usd"`
	CounterfactualCostUSD float64 `json:"counterfactual_cost_usd"`
	SavingsPct            float64 `json:"savings_pct"`
}

// ClassifierDistRow holds classifier class distribution counts.
type ClassifierDistRow struct {
	Class         string  `json:"class"`
	Count         int     `json:"count"`
	Pct           float64 `json:"pct"`
	AvgConfidence float64 `json:"avg_confidence"`
}

// emptySavingsReport is the all-zeros report for a window with no matching
// rows — also the legacy result for a non-UUID org filter (the previous
// org_id::text comparison never matched one), now returned without hitting
// the database. The pricing metadata is the AF-07 empty-window state: an
// empty report must not read as a coverage measurement.
func emptySavingsReport(db pgxdb, ctx context.Context, days int) *SavingsReport {
	return &SavingsReport{
		Period:          fmt.Sprintf("last_%d_days", days),
		TopModelsByCost: []SavingsModelRow{},
		DailyBreakdown:  []SavingsDayRow{},
		ClassifierDist:  []ClassifierDistRow{},
		Pricing:         buildPricingMetadata(db, ctx, "", 0),
	}
}

// GetSavingsReport retrieves combined cache + routing savings analytics.
// If orgID is empty, queries across all orgs (global). A non-empty provider
// narrows to models of that provider via models_registry (request_logs has no
// provider column) — the U03 scope bar's provider dimension.
func (s *Store) GetSavingsReport(ctx context.Context, orgID string, days int, provider string) (*SavingsReport, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	to := time.Now()
	from := to.AddDate(0, 0, -days)

	var whereClause string
	var args []interface{}
	if orgID != "" {
		// AF-14: typed UUID predicate. org_id is uuid; the legacy
		// org_id::text = $3 comparison prevented PostgreSQL from using
		// idx_request_logs_org_created (org_id, created_at DESC) and forced a
		// whole-window scan filtered per row (measured, baseline EXPLAIN).
		// A non-UUID filter never matched any row before — keep that legacy
		// empty-report behavior instead of a cast error.
		orgUUID, parseErr := uuid.Parse(orgID)
		if parseErr != nil {
			return emptySavingsReport(s.db, ctx, days), nil
		}
		whereClause = "created_at BETWEEN $1 AND $2 AND org_id = $3"
		args = []interface{}{from, to, orgUUID}
	} else {
		whereClause = "created_at BETWEEN $1 AND $2"
		args = []interface{}{from, to}
	}
	// V9: shadow-mode rows (ab_group='shadow') are real spend at the shadow
	// provider, NOT client spend. They must be excluded from every
	// client-visible aggregate; the cache/routing sub-queries below are
	// additionally isolated by cache_hit_type/tier_used (NULL on shadow rows).
	whereClause += " AND COALESCE(ab_group, '') <> 'shadow'"
	if provider != "" {
		args = append(args, provider)
		whereClause += fmt.Sprintf(" AND model_used IN (SELECT model_name FROM models_registry WHERE provider = $%d)", len(args))
	}

	// Pricing metadata (A01): how much of the window is NOT covered by the
	// price table. Zero cost must not be presented as "free" — the share and
	// the top unpriced models let the UI say "unknown" instead. The provider
	// is recovered via models_registry (request_logs has no provider column);
	// 'openai-compat' is the registry default for legacy rows.

	// AF-14: one consistent aggregate for total + cache + routing instead of
	// three sequential full-window passes. FILTER keeps the exact per-bucket
	// predicates of the legacy queries (cache_hit_type IS NOT NULL;
	// tier_used/classifier_class both NOT NULL), so every sum, count and
	// denominator is unchanged — they are now computed in a single scan.
	var totalReqs, cacheHits, routedReqs int
	var actualCost, counterfactual float64
	var cacheCounterfactual, cacheActual float64
	var routingCounterfactual, routingActual float64
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*),
		       COALESCE(SUM(cost_in_usd), 0),
		       COALESCE(SUM(counterfactual_cost_usd), 0),
		       COUNT(*) FILTER (WHERE cache_hit_type IS NOT NULL),
		       COALESCE(SUM(counterfactual_cost_usd) FILTER (WHERE cache_hit_type IS NOT NULL), 0),
		       COALESCE(SUM(cost_in_usd) FILTER (WHERE cache_hit_type IS NOT NULL), 0),
		       COUNT(*) FILTER (WHERE tier_used IS NOT NULL AND classifier_class IS NOT NULL),
		       COALESCE(SUM(counterfactual_cost_usd) FILTER (WHERE tier_used IS NOT NULL AND classifier_class IS NOT NULL), 0),
		       COALESCE(SUM(cost_in_usd) FILTER (WHERE tier_used IS NOT NULL AND classifier_class IS NOT NULL), 0)
		FROM request_logs WHERE `+whereClause, args...).Scan(
		&totalReqs, &actualCost, &counterfactual,
		&cacheHits, &cacheCounterfactual, &cacheActual,
		&routedReqs, &routingCounterfactual, &routingActual)
	if err != nil {
		return nil, fmt.Errorf("savings aggregate query: %w", err)
	}

	// Pricing metadata (A01): as-of provenance + unpriced coverage, shared
	// with the cost reports (buildPricingMetadata in cost_analytics.go).
	pricingMeta := buildPricingMetadata(s.db, ctx, whereClause, totalReqs, args...)

	combinedPct := 0.0
	if counterfactual > 0 {
		combinedPct = ((counterfactual - actualCost) / counterfactual) * 100
	}

	cachePct := 0.0
	if cacheCounterfactual > 0 {
		cachePct = ((cacheCounterfactual - cacheActual) / cacheCounterfactual) * 100
	}

	routingPct := 0.0
	if routingCounterfactual > 0 {
		routingPct = ((routingCounterfactual - routingActual) / routingCounterfactual) * 100
	}

	// A02: all-or-error — a partial savings report (missing top models or
	// daily rows) would misstate the savings figures, so every Query/Scan/
	// rows.Err below is propagated instead of swallowed.

	// Top models by counterfactual cost
	topModels := []SavingsModelRow{}
	modelRows, err := s.db.Query(ctx, `
		SELECT model_requested, COUNT(*),
		       COALESCE(SUM(cost_in_usd), 0), COALESCE(SUM(counterfactual_cost_usd), 0)
		FROM request_logs WHERE `+whereClause+`
		GROUP BY model_requested
		ORDER BY SUM(counterfactual_cost_usd) DESC NULLS LAST
		LIMIT 10`, args...)
	if err != nil {
		return nil, fmt.Errorf("savings top-models query: %w", err)
	}
	defer modelRows.Close()
	for modelRows.Next() {
		var m SavingsModelRow
		if err := modelRows.Scan(&m.Model, &m.Requests, &m.ActualCostUSD, &m.CounterfactualCostUSD); err != nil {
			return nil, fmt.Errorf("savings top-models scan: %w", err)
		}
		if m.CounterfactualCostUSD > 0 {
			m.SavingsPct = ((m.CounterfactualCostUSD - m.ActualCostUSD) / m.CounterfactualCostUSD) * 100
		}
		topModels = append(topModels, m)
	}
	if err := modelRows.Err(); err != nil {
		return nil, fmt.Errorf("savings top-models rows: %w", err)
	}

	// Daily breakdown
	daily := []SavingsDayRow{}
	dayRows, err := s.db.Query(ctx, `
		SELECT DATE(created_at), COUNT(*),
		       COALESCE(SUM(cost_in_usd), 0), COALESCE(SUM(counterfactual_cost_usd), 0)
		FROM request_logs WHERE `+whereClause+`
		GROUP BY DATE(created_at)
		ORDER BY DATE(created_at) DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("savings daily query: %w", err)
	}
	defer dayRows.Close()
	for dayRows.Next() {
		var d SavingsDayRow
		var date time.Time
		if err := dayRows.Scan(&date, &d.Requests, &d.ActualCostUSD, &d.CounterfactualCostUSD); err != nil {
			return nil, fmt.Errorf("savings daily scan: %w", err)
		}
		d.Date = date.Format("2006-01-02")
		if d.CounterfactualCostUSD > 0 {
			d.SavingsPct = ((d.CounterfactualCostUSD - d.ActualCostUSD) / d.CounterfactualCostUSD) * 100
		}
		daily = append(daily, d)
	}
	if err := dayRows.Err(); err != nil {
		return nil, fmt.Errorf("savings daily rows: %w", err)
	}

	// Classifier distribution
	classDist := []ClassifierDistRow{}
	classRows, err := s.db.Query(ctx, `
		SELECT COALESCE(classifier_class, 'unknown'), COUNT(*),
		       COALESCE(AVG(classifier_confidence), 0)
		FROM request_logs WHERE `+whereClause+`
		GROUP BY classifier_class
		ORDER BY COUNT(*) DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("savings classifier query: %w", err)
	}
	defer classRows.Close()
	totalClassified := 0
	tempDist := []ClassifierDistRow{}
	for classRows.Next() {
		var d ClassifierDistRow
		if err := classRows.Scan(&d.Class, &d.Count, &d.AvgConfidence); err != nil {
			return nil, fmt.Errorf("savings classifier scan: %w", err)
		}
		tempDist = append(tempDist, d)
		totalClassified += d.Count
	}
	if err := classRows.Err(); err != nil {
		return nil, fmt.Errorf("savings classifier rows: %w", err)
	}
	for _, d := range tempDist {
		if totalClassified > 0 {
			d.Pct = (float64(d.Count) / float64(totalClassified)) * 100
		}
		classDist = append(classDist, d)
	}

	return &SavingsReport{
		Pricing:            pricingMeta,
		Period:             fmt.Sprintf("last_%d_days", days),
		TotalRequests:      totalReqs,
		ActualCostUSD:      actualCost,
		CounterfactualCost: counterfactual,
		CombinedSavingsPct: combinedPct,
		KillCriterionMet:   combinedPct >= 45.0,
		CacheHits:          cacheHits,
		CacheSavingsPct:    cachePct,
		RoutedRequests:     routedReqs,
		RoutingSavingsPct:  routingPct,
		TopModelsByCost:    topModels,
		DailyBreakdown:     daily,
		ClassifierDist:     classDist,
	}, nil
}
