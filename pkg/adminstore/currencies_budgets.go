package adminstore

// GET /api/budgets: the Policies workspace
// caps status. Three caps in fixed order, each with a used-side Measure
// (slice-1 vocabulary), an optional limit and a status:
//
//	usd_monthly_budget   — EffectiveOrgCaps limit vs OrgMonthSpendCents used
//	                       (the same enforcement accounting the spend alerts
//	                       and admission caps act on);
//	carbon_monthly_grams — optional handler-provided limit (CarbonLimitSource
//	                       seam; nil → status unknown, never silently
//	                       unlimited) vs the carbon_factors measurement;
//	credits_floor        — the org's effective grace floor vs the wallet
//	                       balance (inverted: OVER means balance at/below
//	                       floor).
//
// Status mapping: over = used ≥ limit, near = used ≥ 80% of limit; the
// credits floor inverts (balance ≤ floor → over, balance < 0 → near). An
// unmeasurable used side or missing limit is status unknown — a cap whose
// state cannot be compared is unknown, never ok.

import (
	"context"
	"fmt"
	"time"
)

// defaultGraceFloorCents mirrors budget.DefaultReservationConfig's §14
// default (-$1.00, credits.DefaultConfig). This package must NOT import
// pkg/budget: pkg/budget's integration tests import adminstore, so a
// product-level edge here is an import cycle. currencies_budgets_lockstep_test.go
// guards the mirror against drift.
const defaultGraceFloorCents int64 = -100

// Cap IDs — the stable keys the UI renders.
const (
	CapIDUSDMonthlyBudget = "usd_monthly_budget"
	CapIDCarbonMonthly    = "carbon_monthly_grams"
	CapIDCreditsFloor     = "credits_floor"
)

// Cap status thresholds.
const (
	capNearFraction = 0.8
)

// BudgetCapLine is one cap: what it is, how much is used (a Measure), what
// the limit is (nil = unknown) and the status.
type BudgetCapLine struct {
	// ID is the stable cap key (CapID* constants).
	ID string `json:"id"`
	// Used is the measured side (slice-1 measure vocabulary).
	Used Measure `json:"used"`
	// Limit is the configured cap in the same unit, nil when unknown.
	Limit *float64 `json:"limit"`
	// Status is CapStatusOK / Near / Over / Unknown.
	Status string `json:"status"`
	// Note explains unknown states or floor semantics.
	Note string `json:"note,omitempty"`
}

// BudgetCapsStatus is the GET /api/budgets payload.
type BudgetCapsStatus struct {
	OrgID string `json:"org_id"`
	// Window is the month-to-date window the used sides cover.
	Window SpendWindow     `json:"window"`
	Caps   []BudgetCapLine `json:"caps"`
	// CreditsScale states the wallet-currency definition (credits cap).
	CreditsScale string `json:"credits_scale"`
}

// capStatus compares used against limit with the near threshold.
func capStatus(used, limit float64) string {
	switch {
	case used >= limit:
		return CapStatusOver
	case used >= limit*capNearFraction:
		return CapStatusNear
	default:
		return CapStatusOK
	}
}

// GetBudgetCapsStatus builds the Policies workspace caps payload. The
// carbon limit is injected by the caller (handler seam) because no org-side
// carbon budget row exists yet; nil → carbon cap status unknown.
func (s *Store) GetBudgetCapsStatus(ctx context.Context, orgID string, carbonLimitGrams *float64) (*BudgetCapsStatus, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if orgID == "" {
		return nil, fmt.Errorf("org id is required")
	}
	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)

	out := &BudgetCapsStatus{
		OrgID: orgID,
		Window: SpendWindow{
			From: monthStart.UTC().Format(time.RFC3339),
			To:   monthEnd.UTC().Format(time.RFC3339),
		},
		CreditsScale: WalletUnitScale,
		Caps:         make([]BudgetCapLine, 0, 3),
	}

	// USD monthly budget — the enforcement-side accounting (exact integer
	// cents, same source the caps enforcement and spend alerts act on).
	caps, err := s.EffectiveOrgCaps(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("budget caps: %w", err)
	}
	spentCents, err := s.OrgMonthSpendCents(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("budget caps: %w", err)
	}
	limitUSD := float64(caps.MonthlyBudgetCents) / 100
	usedUSD := float64(spentCents) / 100
	usedMeasure, err := KnownMeasure(UnitUSD, usedUSD, FidelityExact, ProvenanceOrgCaps)
	if err != nil {
		return nil, fmt.Errorf("budget caps: usd measure: %w", err)
	}
	out.Caps = append(out.Caps, BudgetCapLine{
		ID:     CapIDUSDMonthlyBudget,
		Used:   usedMeasure,
		Limit:  &limitUSD,
		Status: capStatus(usedUSD, limitUSD),
	})

	// Carbon monthly grams — usage measured via carbon_factors; the limit
	// comes from the caller. Unknown on either side → status unknown.
	grams, gramsUnv, unmodeled, unverified, usageRows, err := s.carbonWindowAggregates(ctx, orgID, monthStart, monthEnd)
	if err != nil {
		return nil, fmt.Errorf("budget caps: carbon: %w", err)
	}
	carbonLine := carbonSpendLine(grams, gramsUnv, unmodeled, unverified, usageRows)
	carbonCap := BudgetCapLine{
		ID:    CapIDCarbonMonthly,
		Used:  carbonLine.Measure,
		Limit: carbonLimitGrams,
	}
	switch {
	case carbonLimitGrams == nil:
		carbonCap.Status = CapStatusUnknown
		carbonCap.Note = "no carbon budget configured"
	case carbonLine.Amount == nil:
		carbonCap.Status = CapStatusUnknown
		carbonCap.Note = carbonLine.Note
	default:
		carbonCap.Status = capStatus(*carbonLine.Amount, *carbonLimitGrams)
		if carbonLine.Note != "" {
			carbonCap.Note = carbonLine.Note
		}
	}
	out.Caps = append(out.Caps, carbonCap)

	// Credits floor — inverted comparison: OVER is balance at/below the
	// effective floor, NEAR is any overdraft above the floor.
	settings, err := s.GetOrgBudgetSettings(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("budget caps: %w", err)
	}
	effectiveFloor := defaultGraceFloorCents
	floorSource := "platform default floor"
	if settings.GraceFloorCents != nil {
		effectiveFloor = *settings.GraceFloorCents
		floorSource = "org override floor"
	}
	balanceCents, _, hasWallet, err := s.walletBalance(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("budget caps: %w", err)
	}
	floorUSD := float64(effectiveFloor) / 100
	floorCap := BudgetCapLine{
		ID:     CapIDCreditsFloor,
		Used:   UnknownMeasure(UnitCredits, ProvenanceCreditsLedger),
		Limit:  &floorUSD,
		Status: CapStatusUnknown,
		Note:   "no wallet for org (" + floorSource + ": " + fmt.Sprintf("%.2f", floorUSD) + " credits)",
	}
	if hasWallet {
		m, err := KnownMeasure(UnitCredits, float64(balanceCents), FidelityExact, ProvenanceCreditsLedger)
		if err != nil {
			return nil, fmt.Errorf("budget caps: credits measure: %w", err)
		}
		floorCap.Used = m
		floorCap.Note = floorSource
		switch {
		case float64(balanceCents) <= floorUSD*100:
			floorCap.Status = CapStatusOver
		case balanceCents < 0:
			floorCap.Status = CapStatusNear
		default:
			floorCap.Status = CapStatusOK
		}
	}
	out.Caps = append(out.Caps, floorCap)

	// Builder contract: same refusal as the spend rollup.
	for i, cap := range out.Caps {
		if err := cap.Used.Validate(); err != nil {
			return nil, fmt.Errorf("budget caps: cap %d: %w", i, err)
		}
	}
	return out, nil
}
