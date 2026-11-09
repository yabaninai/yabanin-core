package adminstore

// GET /api/units/spend: the per-unit spend
// rollup. One measured quantity per line, each carrying unit × fidelity ×
// provenance (the design contract "Measure = amount × unit × fidelity ×
// provenance"):
//
//	USD actual        — from the existing cost-analytics snapshot machinery
//	                    (GetCostAnalytics), fidelity gated by its coverage
//	                    metadata (A01/AF-07);
//	USD counterfactual— the same window's what-if cost, fidelity simulated;
//	credits           — wallet-currency spend from credit_transactions
//	                    (1 credit = 0.01 USD, wallet cents);
//	tokens            — usage-bearing rows, fidelity gated by usage_source;
//	gCO2e             — carbon_factors × tokens/1M, fidelity gated by factor
//	                    coverage (unknown ≠ 0: an unmodeled fleet is not a
//	                    zero-emission fleet).
//
// Unknowns are explicit: every line is present in the response even when its
// amount is null, with a note explaining why. The rollup refuses to emit any
// measure that fails the vocabulary contract (Validate) — a collapsed
// unknown→0 is a build failure, not a wire format.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// SpendWindow is the measured window (RFC 3339).
type SpendWindow struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// UnitSpendLine is one measured quantity plus an optional human note for
// unknown/partial states.
type UnitSpendLine struct {
	Measure
	Note string `json:"note,omitempty"`
}

// UnitSpendRollup is the GET /api/units/spend payload.
type UnitSpendRollup struct {
	OrgID  string      `json:"org_id"`
	Window SpendWindow `json:"window"`
	// Requests is the org's request count in the window (shadow excluded).
	Requests int64           `json:"requests"`
	Lines    []UnitSpendLine `json:"lines"`
	// Pricing is the cost-analytics coverage metadata behind the USD lines
	// (A01/AF-07): zero cost is not necessarily free.
	Pricing PricingMetadata `json:"pricing"`
	// CreditsScale states the wallet-currency definition for the credits
	// line (no surface has to guess the scale).
	CreditsScale string `json:"credits_scale"`
	// UnknownUsageRows counts window rows whose usage was never recorded
	// (usage_source none) — the rows the tokens line cannot see.
	UnknownUsageRows int64 `json:"unknown_usage_rows"`
	// UnmodeledCarbonRows counts usage-bearing rows with no carbon factor —
	// the rows the gCO2e line cannot see.
	UnmodeledCarbonRows int64 `json:"unmodeled_carbon_rows"`
	// LegacyCostRows counts rows priced by the pre-exact-accounting
	// estimator; their presence degrades the USD fidelity to estimated.
	LegacyCostRows int64 `json:"legacy_cost_rows"`
}

// spendProvenance renders the price-source citation for the USD lines: the
// structured REF-04 catalog citation when present, the composed PricingAsOf
// line otherwise.
func spendProvenance(meta PricingMetadata) string {
	if meta.PricingCatalog != nil {
		return CatalogProvenanceLabel(meta.PricingCatalog.Version, meta.PricingCatalog.Digest)
	}
	if meta.PricingAsOf != "" {
		return meta.PricingAsOf
	}
	return "unknown"
}

// usdFidelity maps cost-analytics coverage metadata onto the measure
// vocabulary. An absent status is NOT proven coverage (AF-07) — it maps to
// estimated, never exact. Returns (fidelity, provenance).
func usdFidelity(meta PricingMetadata, legacyRows int64) (string, string) {
	prov := spendProvenance(meta)
	switch meta.CoverageStatus {
	case CoverageUnknown:
		return FidelityUnknown, prov
	case CoverageEmpty:
		return FidelityExact, prov // caller supplies the zero amount
	case CoveragePartial:
		return FidelityEstimated, prov
	case CoverageComplete:
		if legacyRows > 0 {
			return FidelityEstimated, prov // legacy estimator rows are estimates
		}
		return FidelityExact, prov
	default:
		// Old reports without a status: measured but unproven (AF-07).
		return FidelityEstimated, prov
	}
}

// GetUnitSpendRollup builds the slice-1 per-unit rollup for one org window.
func (s *Store) GetUnitSpendRollup(ctx context.Context, orgID string, from, to time.Time) (*UnitSpendRollup, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if orgID == "" {
		return nil, fmt.Errorf("org id is required")
	}

	report, err := s.GetCostAnalytics(ctx, orgID, from, to, "")
	if err != nil {
		return nil, fmt.Errorf("unit spend: cost analytics: %w", err)
	}

	// Tokens + row accounting over the same window (shadow excluded, same
	// predicate as the cost analytics). usage_source NULL reads as provider
	// (historical rows); 'none' rows are the unknown-usage remainder.
	var exactTokens, estTokens int64
	var unknownUsageRows, legacyRows, requests int64
	err = s.db.QueryRow(ctx, `
		SELECT
			COALESCE(SUM(l.tokens_in + l.tokens_out) FILTER (WHERE COALESCE(l.usage_source, 'provider') = 'provider'), 0),
			COALESCE(SUM(l.tokens_in + l.tokens_out) FILTER (WHERE COALESCE(l.usage_source, 'provider') = 'estimated'), 0),
			COUNT(*) FILTER (WHERE COALESCE(l.usage_source, 'provider') NOT IN ('provider', 'estimated')),
			COUNT(*) FILTER (WHERE l.cost_status = 'legacy'),
			COUNT(*)
		FROM request_logs l
		WHERE l.org_id = $1 AND l.created_at BETWEEN $2 AND $3
		  AND COALESCE(l.ab_group, '') <> 'shadow'`,
		orgID, from, to).Scan(&exactTokens, &estTokens, &unknownUsageRows, &legacyRows, &requests)
	if err != nil {
		return nil, fmt.Errorf("unit spend: tokens: %w", err)
	}

	// Carbon: grams = factor(g per 1M tokens) × tokens / 1M over
	// usage-bearing rows (shared with the budgets caps).
	grams, gramsUnverified, unmodeledRows, unverifiedRows, usageRows, err := s.carbonWindowAggregates(ctx, orgID, from, to)
	if err != nil {
		return nil, err
	}

	// Credits spend: usage settlements in the window (wallet cents).
	var spentCents, usageCount int64
	err = s.db.QueryRow(ctx, `
		SELECT COALESCE(SUM(-amount_cents) FILTER (WHERE type = 'usage'), 0),
		       COUNT(*) FILTER (WHERE type = 'usage')
		FROM credit_transactions
		WHERE org_id = $1 AND created_at BETWEEN $2 AND $3`,
		orgID, from, to).Scan(&spentCents, &usageCount)
	if err != nil {
		return nil, fmt.Errorf("unit spend: credits: %w", err)
	}

	// Wallet presence gates the credits line: no wallet row means credits
	// accounting is not configured for this org — unknown, not zero.
	hasWallet, err := s.hasWalletRow(ctx, orgID)
	if err != nil {
		return nil, err
	}

	rollup := &UnitSpendRollup{
		OrgID: orgID,
		Window: SpendWindow{
			From: from.UTC().Format(time.RFC3339),
			To:   to.UTC().Format(time.RFC3339),
		},
		Requests:            requests,
		Pricing:             report.Pricing,
		CreditsScale:        WalletUnitScale,
		UnknownUsageRows:    unknownUsageRows,
		UnmodeledCarbonRows: unmodeledRows,
		LegacyCostRows:      legacyRows,
		Lines:               make([]UnitSpendLine, 0, 5),
	}

	// USD actual — fidelity from coverage metadata + legacy rows. The
	// empty/unknown coverage branches stay explicit: an empty window is an
	// exact zero, an unmeasurable window is an unknown (never a zero).
	fid, prov := usdFidelity(report.Pricing, legacyRows)
	var usdLine UnitSpendLine
	switch report.Pricing.CoverageStatus {
	case CoverageEmpty:
		usdLine = mustLine(ZeroMeasure(UnitUSD, prov), "")
	case CoverageUnknown:
		usdLine = UnitSpendLine{Measure: UnknownMeasure(UnitUSD, prov), Note: "coverage measurement unavailable or fully unpriced window"}
	default:
		usdLine = buildUSDLine(fid, report.TotalCostUSD, prov)
	}
	rollup.Lines = append(rollup.Lines, usdLine)

	// USD counterfactual — the what-if projection of the same window.
	switch report.Pricing.CoverageStatus {
	case CoverageEmpty:
		rollup.Lines = append(rollup.Lines, mustLine(ZeroMeasure(UnitUSD, prov), ""))
	case CoverageUnknown:
		rollup.Lines = append(rollup.Lines, UnitSpendLine{Measure: UnknownMeasure(UnitUSD, prov), Note: "counterfactual undefined while coverage is unknown"})
	default:
		rollup.Lines = append(rollup.Lines, buildUSDLine(FidelitySimulated, report.CounterfactualCost, prov))
	}

	// Credits spend (wallet cents).
	if !hasWallet {
		rollup.Lines = append(rollup.Lines, UnitSpendLine{Measure: UnknownMeasure(UnitCredits, ProvenanceCreditsLedger), Note: "no wallet for org"})
	} else if usageCount == 0 {
		rollup.Lines = append(rollup.Lines, mustLine(ZeroMeasure(UnitCredits, ProvenanceCreditsLedger), ""))
	} else {
		m, err := KnownMeasure(UnitCredits, float64(spentCents), FidelityExact, ProvenanceCreditsLedger)
		if err != nil {
			return nil, fmt.Errorf("unit spend: credits measure: %w", err)
		}
		rollup.Lines = append(rollup.Lines, UnitSpendLine{Measure: m})
	}

	// Tokens.
	tokProv := "internal:request_logs"
	switch {
	case requests == 0:
		rollup.Lines = append(rollup.Lines, mustLine(ZeroMeasure(UnitTokens, tokProv), ""))
	case unknownUsageRows > 0 && exactTokens+estTokens > 0:
		m, err := KnownMeasure(UnitTokens, float64(exactTokens+estTokens), FidelityEstimated, tokProv)
		if err != nil {
			return nil, fmt.Errorf("unit spend: tokens measure: %w", err)
		}
		rollup.Lines = append(rollup.Lines, UnitSpendLine{Measure: m, Note: fmt.Sprintf("%d rows without recorded usage excluded from the sum", unknownUsageRows)})
	case unknownUsageRows > 0:
		rollup.Lines = append(rollup.Lines, UnitSpendLine{Measure: UnknownMeasure(UnitTokens, tokProv), Note: "no usage recorded for any request in the window"})
	case estTokens > 0:
		m, err := KnownMeasure(UnitTokens, float64(exactTokens+estTokens), FidelityEstimated, tokProv)
		if err != nil {
			return nil, fmt.Errorf("unit spend: tokens measure: %w", err)
		}
		rollup.Lines = append(rollup.Lines, UnitSpendLine{Measure: m})
	case exactTokens > 0:
		m, err := KnownMeasure(UnitTokens, float64(exactTokens), FidelityExact, tokProv)
		if err != nil {
			return nil, fmt.Errorf("unit spend: tokens measure: %w", err)
		}
		rollup.Lines = append(rollup.Lines, UnitSpendLine{Measure: m})
	default:
		// Requests exist and usage was recorded, but every token count is
		// zero — an honestly measured zero.
		rollup.Lines = append(rollup.Lines, mustLine(ZeroMeasure(UnitTokens, tokProv), ""))
	}

	// gCO2e — unknown ≠ 0: an unmodeled fleet is not a zero-emission fleet
	// (fidelity mapping shared with the budgets caps).
	rollup.Lines = append(rollup.Lines, carbonSpendLine(grams, gramsUnverified, unmodeledRows, unverifiedRows, usageRows))

	// Builder contract: no measure leaves the store in a shape that breaks
	// the vocabulary (this is where an unknown→0 collapse would be caught).
	for i, line := range rollup.Lines {
		if err := line.Validate(); err != nil {
			return nil, fmt.Errorf("unit spend: line %d: %w", i, err)
		}
	}
	return rollup, nil
}

// mustLine wraps a builder-known-good measure.
func mustLine(m Measure, note string) UnitSpendLine {
	return UnitSpendLine{Measure: m, Note: note}
}

// carbonWindowAggregates measures the org's carbon over a window: grams =
// factor(g per 1M tokens) × tokens / 1M over usage-bearing rows.
// carbon_factors is keyed (model_name, provider); request_logs has no
// provider column, so one deterministic factor per model name is joined
// (verified preferred, then provider order).
func (s *Store) carbonWindowAggregates(ctx context.Context, orgID string, from, to time.Time) (grams, gramsUnverified float64, unmodeledRows, unverifiedRows, usageRows int64, err error) {
	if s.db == nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("database not available")
	}
	err = s.db.QueryRow(ctx, `
		SELECT
			COALESCE(SUM(cf.gco2e_per_1m * (l.tokens_in + l.tokens_out) / 1000000.0), 0),
			COALESCE(SUM(cf.gco2e_per_1m * (l.tokens_in + l.tokens_out) / 1000000.0) FILTER (WHERE NOT cf.verified), 0),
			COUNT(*) FILTER (WHERE cf.model_name IS NULL),
			COUNT(*) FILTER (WHERE cf.model_name IS NOT NULL AND NOT cf.verified),
			COUNT(*)
		FROM request_logs l
		LEFT JOIN (
			SELECT DISTINCT ON (model_name) model_name, gco2e_per_1m, verified
			FROM carbon_factors
			ORDER BY model_name, verified DESC, provider ASC
		) cf ON cf.model_name = l.model_used
		WHERE l.org_id = $1 AND l.created_at BETWEEN $2 AND $3
		  AND COALESCE(l.ab_group, '') <> 'shadow'
		  AND COALESCE(l.usage_source, 'provider') IN ('provider', 'estimated')`,
		orgID, from, to).Scan(&grams, &gramsUnverified, &unmodeledRows, &unverifiedRows, &usageRows)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("carbon window: %w", err)
	}
	return grams, gramsUnverified, unmodeledRows, unverifiedRows, usageRows, nil
}

// carbonSpendLine maps the carbon aggregates onto the measure vocabulary.
// unknown ≠ 0: an unmodeled fleet is not a zero-emission fleet.
func carbonSpendLine(grams, gramsUnverified float64, unmodeledRows, unverifiedRows, usageRows int64) UnitSpendLine {
	modeledRows := usageRows - unmodeledRows
	switch {
	case usageRows == 0:
		return mustLine(ZeroMeasure(UnitGCO2e, ProvenanceCarbonFactors), "no usage-bearing requests in the window")
	case modeledRows <= 0:
		return UnitSpendLine{Measure: UnknownMeasure(UnitGCO2e, ProvenanceCarbonFactors), Note: "no carbon factor available for any model used in the window"}
	case gramsUnverified > 0 || unmodeledRows > 0:
		m, err := KnownMeasure(UnitGCO2e, grams, FidelityEstimated, ProvenanceCarbonFactors)
		if err != nil {
			return UnitSpendLine{Measure: UnknownMeasure(UnitGCO2e, ProvenanceCarbonFactors), Note: "measure build refused: " + err.Error()}
		}
		note := ""
		switch {
		case unmodeledRows > 0 && unverifiedRows > 0:
			note = fmt.Sprintf("%d rows without a factor and %d rows with unverified factors excluded from the exact sum", unmodeledRows, unverifiedRows)
		case unmodeledRows > 0:
			note = fmt.Sprintf("%d rows without a carbon factor excluded from the sum", unmodeledRows)
		default:
			note = "includes rows priced with unverified factors"
		}
		return UnitSpendLine{Measure: m, Note: note}
	default:
		m, err := KnownMeasure(UnitGCO2e, grams, FidelityExact, ProvenanceCarbonFactors)
		if err != nil {
			return UnitSpendLine{Measure: UnknownMeasure(UnitGCO2e, ProvenanceCarbonFactors), Note: "measure build refused: " + err.Error()}
		}
		return UnitSpendLine{Measure: m}
	}
}

// walletBalance reads the org wallet's balance; hasWallet=false when the
// wallet row is missing (created lazily by the first top-up).
func (s *Store) walletBalance(ctx context.Context, orgID string) (balanceCents int64, updatedAt time.Time, hasWallet bool, err error) {
	if s.db == nil {
		return 0, time.Time{}, false, fmt.Errorf("database not available")
	}
	err = s.db.QueryRow(ctx, `
		SELECT balance_cents, updated_at FROM org_credits WHERE org_id = $1`,
		orgID).Scan(&balanceCents, &updatedAt)
	if errorsIsNoRows(err) {
		return 0, time.Time{}, false, nil
	}
	if err != nil {
		return 0, time.Time{}, false, fmt.Errorf("wallet balance: %w", err)
	}
	return balanceCents, updatedAt, true, nil
}

// hasWalletRow reports whether the org has a wallet row.
func (s *Store) hasWalletRow(ctx context.Context, orgID string) (bool, error) {
	_, _, has, err := s.walletBalance(ctx, orgID)
	return has, err
}

// buildUSDLine builds a USD line from an explicit fidelity. Kept as a helper
// so the actual/counterfactual branches stay uniform at the call site.
func buildUSDLine(fidelity string, amount float64, prov string) UnitSpendLine {
	m, err := KnownMeasure(UnitUSD, amount, fidelity, prov)
	if err != nil {
		return UnitSpendLine{Measure: UnknownMeasure(UnitUSD, prov), Note: "measure build refused: " + err.Error()}
	}
	return UnitSpendLine{Measure: m}
}

// errorsIsNoRows reports whether err is pgx's no-rows condition.
func errorsIsNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
