package consumer

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/budget"
)

// Spend reconciliation core (N06-P06-T02 "Свести UI aggregate с ledger и
// provider invoices"). Inventory and exact boundary:
// artifacts/internal-delivery-program/N06-P06/T01-scope-20261025.md.
//
// N06-P06-T04 adds the reporting dimension: UNRESOLVED usage (late /
// unknown-priced events) and ESTIMATED usage (in-flight reservations yet
// to settle) are reported as separate, clearly labelled lines and columns
// — never folded into the settled totals, never hidden.
//
// Read-only over canonical money facts; it writes nothing. The three
// surfaces it ties together:
//
//   - UI aggregate — pkg/adminstore GetCostAnalytics parity:
//     SUM(cost_in_usd) over ALL cost_status values, excluding shadow rows
//     (COALESCE(ab_group,'') <> 'shadow'). It relies on the invariant
//     "unpriced ⇒ $0"; this report verifies that invariant instead of
//     assuming it.
//   - Wallet ledger — credit_transactions rows of type='usage'. The wallet
//     is billed the RESALE charge (scopeChargePlan: "Wallet: resale price
//     wins over base") while request_logs.cost_in_usd is the BASE provider
//     cost, so usage↔wallet is a named gap (resale markup + unsettled
//     settlement tail + cent rounding), never an equality invariant.
//   - Provider invoice — per-day invoice micro amounts (the invoice fact
//     itself is imported by pkg/trcli `yb spend-reconcile`; this core
//     consumes the parsed per-day values). Captured spend for the invoice
//     side includes shadow rows: shadow requests hit the provider and do
//     appear on the invoice, unlike the UI aggregate.
//
// Semantics honored (negative card requirements):
//   - Late events only append facts; recomputing the report never rewrites
//     previously computed day rows (the core is pure — inputs are values
//     and are never mutated).
//   - Prices are taken as captured (as-of write); a price provenance change
//     must not change any dollar figure of the report — provenance labels
//     are echoed, never used in arithmetic.
//
// History: request_logs has no resale column, so the wallet gap cannot be
// attributed per row; it is reported as a whole with its named components.

const (
	// SpendReconStatusOK — all hard invariants hold (soft gaps are reported
	// with their named components and are not violations).
	SpendReconStatusOK = "ok"
	// SpendReconStatusViolation — at least one hard invariant failed.
	SpendReconStatusViolation = "violation"

	// spendReconUSDMicro is one USD in micro-USD (cost_in_usd scale ×1e6).
	spendReconUSDMicro = int64(1_000_000)
	// spendReconCentMicro is one cent in micro-USD (amount_cents scale).
	spendReconCentMicro = int64(10_000)

	// ViolationUITotalMismatch — the UI-parity total differs from the
	// confirmed+unpriced breakdown (status-class cost leakage or a period
	// boundary disagreement between the two queries).
	ViolationUITotalMismatch = "ui_total_mismatch"
	// ViolationUnpricedNonzero — unpriced rows (unknown_price/no_usage)
	// carry non-zero cost, breaking the unpriced⇒$0 invariant the UI
	// aggregate relies on.
	ViolationUnpricedNonzero = "unpriced_nonzero_cost"
	// ViolationLedgerRounding — the wallet cent-vs-micro delta exceeds the
	// declared carry bound (possible ledger corruption or a cents/micro
	// writer inconsistency).
	ViolationLedgerRounding = "ledger_rounding_exceeded"
	// ViolationLedgerLegacyNoMicro — pre-AF-05 wallet rows without an exact
	// micro amount; the rounding bound is not verifiable for the window.
	ViolationLedgerLegacyNoMicro = "ledger_legacy_rows_without_micro"
	// ViolationInvoiceGapExceeded — |captured − invoice| exceeds the
	// configured invoice tolerance (period total or a single day; a
	// period-level check alone would let offsetting day deltas cancel).
	ViolationInvoiceGapExceeded = "invoice_gap_exceeded"
	// ViolationDayOutsidePeriod — a usage/ledger day row (or an unparseable
	// invoice day) lies outside the report window [From, To): the queries or
	// the caller disagree on the period boundary. The row is excluded from
	// every total and the report is a violation.
	ViolationDayOutsidePeriod = "day_outside_period"
	// ViolationDuplicateDayRows — the same UTC day appears more than once in
	// the usage or ledger facts. The SQL producers GROUP BY day, so this
	// means a caller/SQL bug; the report keeps the last occurrence but is a
	// violation (invoice day rows accumulate by design and are not flagged).
	ViolationDuplicateDayRows = "duplicate_day_rows"
	// ViolationUnresolvedPriceNonzero — unknown-cost settlement visibility
	// rows (charge_kind='pending_price', status pending_price/unknown)
	// carry a non-zero amount. Those rows are never billed: refundless
	// semantics release the reserved bound uncharged and keep the unknown
	// cost visible as a pending_price row, so their amount must be
	// exactly 0 — mirroring ViolationUnpricedNonzero on the request_logs
	// side. The report keeps the amount visible but never folds it into any
	// settled or estimated total.
	ViolationUnresolvedPriceNonzero = "unresolved_price_nonzero_micro"
)

// SpendReconUsageDay is one UTC day of request_logs usage facts, split by
// cost_status exactly like the rollup aggregates (rollupAgg status classes).
// Every class below covers non-shadow rows only (COALESCE(ab_group,”) <>
// 'shadow') — the GetCostAnalytics predicate — so the UI-parity detail is
// comparable with the UI total; shadow spend is reported once, separately,
// in ShadowMicro (never inside the class sums, never double-counted).
type SpendReconUsageDay struct {
	Day              string // YYYY-MM-DD (local day bucket in the report zone, see SpendReconInput.Zone)
	ConfirmedMicro   int64  // SUM(cost_in_usd) FILTER (priced, cache_hit, legacy), shadow excluded
	UnpricedMicro    int64  // SUM(cost_in_usd) FILTER (unknown_price, no_usage), shadow excluded — invariant: 0
	UnpricedRequests int64  // COUNT FILTER (unknown_price, no_usage), shadow excluded
	LegacyRows       int64  // COUNT FILTER (cost_status = 'legacy'), shadow excluded
	Requests         int64  // COUNT(*) excluding shadow rows
	ShadowMicro      int64  // SUM(cost_in_usd) WHERE ab_group='shadow' (excluded from UI parity, included in invoice capture)
}

// SpendReconLedgerDay is one UTC day of wallet usage facts from
// credit_transactions (type='usage'; amounts are negative).
type SpendReconLedgerDay struct {
	// Day is the local calendar day bucket in the report timezone (see
	// SpendReconInput.Zone; SQL binds it explicitly so the bucket never
	// depends on the session TimeZone).
	Day                     string // YYYY-MM-DD
	WalletMicro             int64  // SUM(amount_micro_usd) over rows where it is set (exact, AF-05)
	WalletCentsAppliedMicro int64  // SUM(amount_cents)*1e4 (the applied cent charge)
	WalletTxns              int64  // usage rows of the day
	WalletRowsWithoutMicro  int64  // legacy rows with NULL amount_micro_usd (pre-AF-05)
}

// SpendReconSettlementDay is one local day of settlement_jobs facts
// (N06-P06-T04): the ESTIMATED and UNRESOLVED dimensions of usage, bucketed
// by the day the charge intent was created. Amounts are micro-USD (the
// as-captured intent amount; never re-priced).
type SpendReconSettlementDay struct {
	// Day is the local calendar day bucket in the report timezone (see
	// SpendReconInput.Zone; SQL binds it explicitly so the bucket never
	// depends on the session TimeZone).
	Day string // YYYY-MM-DD
	// EstimatedMicro is Σ amount_micro_usd over charge intents not yet
	// settled (status pending, processing, retry, requires_attention):
	// the in-flight reservations that will still become charges. It is
	// reported separately and is NEVER added to confirmed, captured,
	// invoice-comparable or wallet totals.
	EstimatedMicro int64
	// EstimatedRequests is the count of unsettled charge intents of the day.
	EstimatedRequests int64
	// UnresolvedPriceRows is the count of unknown-cost visibility rows
	// (charge_kind='pending_price', status pending_price or terminal
	// 'unknown'): events whose price was never resolved. They are never
	// billed, so they stay visible here as counts instead of disappearing.
	UnresolvedPriceRows int64
	// UnresolvedPriceMicro is Σ amount_micro_usd over those same rows —
	// invariant 0 (never billed); a non-zero value is a violation.
	UnresolvedPriceMicro int64
}

// SpendReconInvoiceDay is one provider-invoice line aggregated to a day in
// the report timezone (invoice CSV day labels are interpreted as days of
// the org's reporting timezone), already converted to micro-USD
// (ParseInvoiceUSDMicro for CSV values).
type SpendReconInvoiceDay struct {
	Day          string // YYYY-MM-DD
	InvoiceMicro int64
}

// SpendReconInput carries the independently queried facts. The core never
// mutates the slices.
type SpendReconInput struct {
	OrgID string
	From  time.Time // half-open [From, To), absolute instants (any location)
	To    time.Time

	// Zone is the IANA timezone of the day buckets — the organization's
	// reporting timezone (organizations.timezone, DEFAULT 'UTC'). nil means
	// UTC (the legacy default). Day labels "YYYY-MM-DD" are LOCAL calendar
	// days in this zone: day "2026-03-08" spans [local midnight, next
	// local midnight), 23 or 25 hours around a DST transition, so all
	// three fact slices and the report window must use the same zone. The
	// reader queries bind the zone explicitly (created_at AT TIME ZONE)
	// and never depend on the database session TimeZone.
	Zone *time.Location

	// UITotalMicro is the UI-parity total: SUM(cost_in_usd) over all cost
	// statuses, shadow excluded — the GetCostAnalytics predicate. It is
	// deliberately queried independently from the by-day breakdown so the
	// equality check below is a real reconciliation, not a tautology.
	UITotalMicro int64

	Usage   []SpendReconUsageDay
	Ledger  []SpendReconLedgerDay
	Invoice []SpendReconInvoiceDay

	// Settlements carries the per-day settlement_jobs facts (estimated /
	// unresolved usage). Optional: nil keeps both dimensions zero and the
	// report unchanged (a caller without the settlement feed still gets the
	// T02/T03 surfaces; the report cannot invent visibility it was not
	// given, which is why the reader exists).
	Settlements []SpendReconSettlementDay

	// ReservedOutstandingMicro is a POINT-IN-TIME snapshot at To: the
	// outstanding reservation holds of the org (Σ granted−returned over
	// budget_allowances in statuses active/expired/draining). Snapshot
	// money is not a per-day fact (holds live across days), so it never
	// enters any day row or column total; it is echoed once, clearly
	// labelled, next to the per-day estimated columns.
	ReservedOutstandingMicro int64
	// ReservedAllowances is the number of holds behind the snapshot.
	ReservedAllowances int64

	// UsagePricingAsOf / InvoiceLabel are informational provenance labels
	// (e.g. pricing snapshot source+date; invoice identity). They are echoed
	// into the report and never influence any dollar computation.
	UsagePricingAsOf string
	InvoiceLabel     string

	// InvoiceToleranceMicro is the largest |captured − invoice| delta that
	// is not flagged (invoice-side rounding/timing tolerance; 0 = exact).
	InvoiceToleranceMicro int64
}

// SpendReconViolation is one failed invariant.
type SpendReconViolation struct {
	Code   string // Violation* constant
	Day    string // "" for period-level violations
	Detail string
}

// SpendReconDayReport is the reconciled view of one UTC day. All amounts are
// micro-USD; wallet amounts are negative.
type SpendReconDayReport struct {
	Day              string
	ConfirmedMicro   int64
	UnpricedMicro    int64
	UnpricedRequests int64
	LegacyRows       int64
	Requests         int64
	ShadowMicro      int64
	WalletMicro      int64
	WalletGapMicro   int64 // ConfirmedMicro + WalletMicro (≤0 wallet): base vs resale charge, unsettled tail, rounding
	InvoiceMicro     int64
	InvoiceDelta     int64 // Confirmed + Shadow − Invoice (captured upstream spend vs billed)
	Flags            []string

	// EstimatedMicro/EstimatedRequests are the unsettled charge intents
	// created this day (N06-P06-T04): usage that is reserved but not yet
	// settled. Reported SEPARATELY from ConfirmedMicro — never added to it,
	// to CapturedMicro, to the wallet gap or to the invoice comparison.
	EstimatedMicro    int64
	EstimatedRequests int64
	// UnresolvedPriceRows/UnresolvedPriceMicro are the unknown-cost
	// visibility rows created this day: usage whose price never resolved
	// and which will never be billed. UnresolvedPriceMicro is invariant 0
	// (ViolationUnresolvedPriceNonzero otherwise).
	UnresolvedPriceRows  int64
	UnresolvedPriceMicro int64
}

// SpendReconReport is the reconciled period report. It is a plain DTO
// (json-tagged) so a caller can persist the exact example result alongside
// the named limitations.
type SpendReconReport struct {
	OrgID string    `json:"org_id"`
	From  time.Time `json:"from"`
	To    time.Time `json:"to"`
	// Zone is the resolved report timezone actually used ("UTC" when the
	// input carried no zone). Day labels in Days and in every fact slice
	// are local calendar days of this zone.
	Zone         string `json:"zone"`
	Status       string `json:"status"`
	UITotalMicro int64  `json:"ui_total_micro_usd"`

	// ConfirmedTotalMicro is Σ day ConfirmedMicro (the rollup-class total).
	ConfirmedTotalMicro int64 `json:"confirmed_total_micro_usd"`
	// UI parity invariant: UITotalMicro == ConfirmedTotalMicro +
	// UnpricedTotalMicro exactly, or the report is a violation.
	UnpricedTotalMicro int64   `json:"unpriced_total_micro_usd"`
	UnpricedRequests   int64   `json:"unpriced_requests"`
	LegacyRows         int64   `json:"legacy_rows"`
	Requests           int64   `json:"requests"`
	ShadowTotalMicro   int64   `json:"shadow_total_micro_usd"`
	CapturedMicro      int64   `json:"captured_micro_usd"` // confirmed + shadow (invoice-comparable capture)
	InvoiceTotalMicro  int64   `json:"invoice_total_micro_usd"`
	InvoiceDeltaMicro  int64   `json:"invoice_delta_micro_usd"` // captured − invoice
	CaptureRatePct     float64 `json:"capture_rate_pct"`
	// InvoiceDaysOutsidePeriod counts invoice day rows whose day bucket does
	// not intersect [From, To). Mirroring `yb spend-reconcile`, they are
	// excluded from every total (a late invoice for a former period must not
	// distort this period's delta) and remain visible through this counter.
	InvoiceDaysOutsidePeriod int64 `json:"invoice_days_outside_period"`

	WalletMicro              int64 `json:"wallet_micro_usd"`                // negative; resale charges
	WalletGapMicro           int64 `json:"wallet_gap_micro_usd"`            // confirmed + wallet (named components, not an error)
	WalletRoundingDeltaMicro int64 `json:"wallet_rounding_delta_micro_usd"` // Σcents×1e4 − Σexact
	LedgerRoundingBoundMicro int64 `json:"ledger_rounding_bound_micro_usd"` // −1 when not verifiable

	// Estimated / unresolved dimension (N06-P06-T04). Estimated totals are
	// the exact Σ of the per-day estimated columns; they are never part of
	// Confirmed/Unpriced/Captured totals or of the UI parity identity.
	EstimatedTotalMicro       int64 `json:"estimated_total_micro_usd"`
	EstimatedRequests         int64 `json:"estimated_requests"`
	UnresolvedPriceRows       int64 `json:"unresolved_price_rows"`
	UnresolvedPriceTotalMicro int64 `json:"unresolved_price_total_micro_usd"` // invariant 0

	// ReservedOutstandingMicro/ReservedAllowances echo the point-in-time
	// reservation snapshot from the input (see SpendReconInput); they are
	// never summed into day rows or column totals.
	ReservedOutstandingMicro int64 `json:"reserved_outstanding_micro_usd"`
	ReservedAllowances       int64 `json:"reserved_allowances"`

	Days       []SpendReconDayReport `json:"days"`
	Violations []SpendReconViolation `json:"violations,omitempty"`

	UsagePricingAsOf string   `json:"usage_pricing_as_of,omitempty"`
	InvoiceLabel     string   `json:"invoice_label,omitempty"`
	Limitations      []string `json:"limitations"`
}

// spendReconLimitations are the named non-invariants every report carries so
// a reader cannot mistake soft gaps for broken equality.
func spendReconLimitations() []string {
	return []string{
		"wallet_gap = resale markup + unsettled settlement tail + cent rounding; request_logs carries no resale column, so the gap is not per-row attributable (scopeChargePlan bills the wallet the resale charge, request_logs.cost_in_usd is the base cost)",
		"invoice deltas include provider-side rounding, late-arriving usage and partial boundary days; only deltas beyond InvoiceToleranceMicro are violations — on the period total and on each single day, so offsetting day deltas cannot cancel silently",
		"invoice day rows outside [from,to) are excluded from every total and counted in invoice_days_outside_period (late invoices for former periods stay visible without distorting this period)",
		"price provenance is echoed, never applied: captured costs are as-of write and are not re-priced by this report",
		"estimated = settlement charge intents opened in the window and not yet settled (pending/processing/retry/requires_attention); a job opened day N and settled day N+k counts as estimated on day N only, so Σestimated is an in-flight measure of the window, never added to confirmed/captured/wallet totals, and the same request's base cost may independently appear in confirmed (request_logs) — the two ledgers are named and kept separate",
		"unresolved = unknown-cost visibility rows (charge_kind='pending_price', status pending_price or terminal 'unknown'); they are never billed (refundless semantics), carry an invariant-zero amount, and stay visible as row counts so unknown-priced usage can never read as zero settled spend",
		"reserved_outstanding_micro_usd is a point-in-time snapshot at 'to' (Σ granted−returned over active/expired/draining budget_allowances); holds live across days, so it is echoed once and never spread over day rows",
		"day buckets are local calendar days in the report zone (the org's reporting timezone; DST-aware): the SQL day buckets bind the zone explicitly (created_at AT TIME ZONE) and never depend on the session TimeZone, and invoice CSV day labels are compared in the same zone",
	}
}

// ReconcileSpend computes the period report from independently queried
// facts. Pure: it never mutates its inputs and derives every total by
// summation, so recomputation after a late event changes only the affected
// day rows and the re-derived totals.
func ReconcileSpend(in SpendReconInput) SpendReconReport {
	// nil zone keeps the legacy default (UTC); the name is echoed so a
	// reader can tell which local days the buckets are.
	zone := in.Zone
	if zone == nil {
		zone = time.UTC
	}
	rep := SpendReconReport{
		OrgID:            in.OrgID,
		From:             in.From,
		To:               in.To,
		Zone:             zone.String(),
		UITotalMicro:     in.UITotalMicro,
		UsagePricingAsOf: in.UsagePricingAsOf,
		InvoiceLabel:     in.InvoiceLabel,
		Limitations:      spendReconLimitations(),
		// Point-in-time snapshot echo (never a day fact).
		ReservedOutstandingMicro: in.ReservedOutstandingMicro,
		ReservedAllowances:       in.ReservedAllowances,
	}
	// A negative tolerance is a degenerate configuration: clamped to exact
	// (0) so a perfect tie cannot be flagged.
	invoiceTolerance := in.InvoiceToleranceMicro
	if invoiceTolerance < 0 {
		invoiceTolerance = 0
	}

	usageByDay := make(map[string]SpendReconUsageDay, len(in.Usage))
	ledgerByDay := make(map[string]SpendReconLedgerDay, len(in.Ledger))
	invoiceByDay := make(map[string]int64, len(in.Invoice))

	// Classify every input row against the report window before it may
	// influence any total: usage/ledger rows are produced by the paired
	// queries over the same [From, To), so a row outside the window is a
	// boundary disagreement (violation, excluded); invoice day rows come
	// from an external CSV that may cover a wider window, so they are
	// excluded and counted (trcli OutsidePeriod parity), never summed here.
	for _, d := range in.Usage {
		if ok, err := spendReconDayInWindow(d.Day, in.From, in.To, zone); err != nil || !ok {
			rep.Violations = append(rep.Violations, SpendReconViolation{
				Code: ViolationDayOutsidePeriod,
				Day:  d.Day,
				Detail: fmt.Sprintf("usage day row %q outside report window [%s .. %s): %v",
					d.Day, in.From.UTC().Format("2006-01-02"), in.To.UTC().Format("2006-01-02"), err),
			})
			continue
		}
		if _, dup := usageByDay[d.Day]; dup {
			rep.Violations = append(rep.Violations, SpendReconViolation{
				Code:   ViolationDuplicateDayRows,
				Day:    d.Day,
				Detail: "duplicate usage day row (producer must GROUP BY day); last occurrence wins",
			})
		}
		usageByDay[d.Day] = d
	}
	for _, d := range in.Ledger {
		if ok, err := spendReconDayInWindow(d.Day, in.From, in.To, zone); err != nil || !ok {
			rep.Violations = append(rep.Violations, SpendReconViolation{
				Code: ViolationDayOutsidePeriod,
				Day:  d.Day,
				Detail: fmt.Sprintf("ledger day row %q outside report window [%s .. %s): %v",
					d.Day, in.From.UTC().Format("2006-01-02"), in.To.UTC().Format("2006-01-02"), err),
			})
			continue
		}
		if _, dup := ledgerByDay[d.Day]; dup {
			rep.Violations = append(rep.Violations, SpendReconViolation{
				Code:   ViolationDuplicateDayRows,
				Day:    d.Day,
				Detail: "duplicate ledger day row (producer must GROUP BY day); last occurrence wins",
			})
		}
		ledgerByDay[d.Day] = d
	}
	// Settlement facts follow the same window/duplicate discipline as
	// usage/ledger: a day row outside [From, To) is a boundary disagreement
	// (violation, excluded from every total), a duplicate is a producer bug.
	settlementByDay := make(map[string]SpendReconSettlementDay, len(in.Settlements))
	for _, d := range in.Settlements {
		if ok, err := spendReconDayInWindow(d.Day, in.From, in.To, zone); err != nil || !ok {
			rep.Violations = append(rep.Violations, SpendReconViolation{
				Code: ViolationDayOutsidePeriod,
				Day:  d.Day,
				Detail: fmt.Sprintf("settlement day row %q outside report window [%s .. %s): %v",
					d.Day, in.From.UTC().Format("2006-01-02"), in.To.UTC().Format("2006-01-02"), err),
			})
			continue
		}
		if _, dup := settlementByDay[d.Day]; dup {
			rep.Violations = append(rep.Violations, SpendReconViolation{
				Code:   ViolationDuplicateDayRows,
				Day:    d.Day,
				Detail: "duplicate settlement day row (producer must GROUP BY day); last occurrence wins",
			})
		}
		settlementByDay[d.Day] = d
	}
	for _, d := range in.Invoice {
		ok, err := spendReconDayInWindow(d.Day, in.From, in.To, zone)
		switch {
		case err != nil:
			rep.Violations = append(rep.Violations, SpendReconViolation{
				Code: ViolationDayOutsidePeriod,
				Day:  d.Day,
				Detail: fmt.Sprintf("invoice day %q is not a YYYY-MM-DD day bucket in the report zone: %v",
					d.Day, err),
			})
			// The line cannot be bucketed, so its amount must not enter
			// invoiceByDay/InvoiceTotalMicro — same discipline as the
			// malformed usage/ledger rows: the violation makes the error
			// visible, the totals stay trustworthy.
			continue
		case !ok:
			rep.InvoiceDaysOutsidePeriod++
			continue
		}
		invoiceByDay[d.Day] += d.InvoiceMicro
	}

	seen := make(map[string]bool, len(usageByDay)+len(ledgerByDay)+len(invoiceByDay)+len(settlementByDay))
	days := make([]string, 0, len(usageByDay)+len(ledgerByDay)+len(invoiceByDay)+len(settlementByDay))
	appendDay := func(day string) {
		if day != "" && !seen[day] {
			seen[day] = true
			days = append(days, day)
		}
	}
	for day := range usageByDay {
		appendDay(day)
	}
	for day := range ledgerByDay {
		appendDay(day)
	}
	for day := range invoiceByDay {
		appendDay(day)
	}
	// Settlement-only days still produce a day row (estimated usage must
	// never be hidden just because the day has no settled facts yet).
	for day := range settlementByDay {
		appendDay(day)
	}
	sort.Strings(days)

	legacyNoMicro := int64(0)
	allTxns := int64(0)
	for _, d := range ledgerByDay {
		legacyNoMicro += d.WalletRowsWithoutMicro
		allTxns += d.WalletTxns
	}

	for _, day := range days {
		u := usageByDay[day]
		l := ledgerByDay[day]
		s := settlementByDay[day]
		inv := invoiceByDay[day]

		dr := SpendReconDayReport{
			Day:                  day,
			ConfirmedMicro:       u.ConfirmedMicro,
			UnpricedMicro:        u.UnpricedMicro,
			UnpricedRequests:     u.UnpricedRequests,
			LegacyRows:           u.LegacyRows,
			Requests:             u.Requests,
			ShadowMicro:          u.ShadowMicro,
			WalletMicro:          l.WalletMicro,
			WalletGapMicro:       u.ConfirmedMicro + l.WalletMicro,
			InvoiceMicro:         inv,
			InvoiceDelta:         u.ConfirmedMicro + u.ShadowMicro - inv,
			EstimatedMicro:       s.EstimatedMicro,
			EstimatedRequests:    s.EstimatedRequests,
			UnresolvedPriceRows:  s.UnresolvedPriceRows,
			UnresolvedPriceMicro: s.UnresolvedPriceMicro,
		}

		if u.UnpricedMicro != 0 {
			dr.Flags = append(dr.Flags, ViolationUnpricedNonzero)
			rep.Violations = append(rep.Violations, SpendReconViolation{
				Code: ViolationUnpricedNonzero,
				Day:  day,
				Detail: fmt.Sprintf("unpriced rows carry non-zero cost %d micro-USD (invariant unpriced⇒$0 broken)",
					u.UnpricedMicro),
			})
		}

		// The unknown-cost settlement rows are never billed: their amount
		// must be exactly 0 (the request_logs-side twin of this invariant
		// is ViolationUnpricedNonzero above). The amount stays visible in
		// the day row but is never folded into any total discipline.
		if s.UnresolvedPriceMicro != 0 {
			dr.Flags = append(dr.Flags, ViolationUnresolvedPriceNonzero)
			rep.Violations = append(rep.Violations, SpendReconViolation{
				Code: ViolationUnresolvedPriceNonzero,
				Day:  day,
				Detail: fmt.Sprintf("unknown-cost settlement rows carry non-zero amount %d micro-USD (they are never billed; invariant pending_price⇒$0 broken)",
					s.UnresolvedPriceMicro),
			})
		}

		// Per-day invoice capture tolerance: a period-level check alone
		// would let offsetting day deltas (e.g. a shifted provider day
		// boundary) cancel and mask two real single-day capture failures.
		if d := spendReconAbs(dr.InvoiceDelta); d > invoiceTolerance {
			dr.Flags = append(dr.Flags, ViolationInvoiceGapExceeded)
			rep.Violations = append(rep.Violations, SpendReconViolation{
				Code: ViolationInvoiceGapExceeded,
				Day:  day,
				Detail: fmt.Sprintf("day captured−invoice = %d exceeds tolerance %d micro-USD",
					dr.InvoiceDelta, invoiceTolerance),
			})
		}

		rep.Days = append(rep.Days, dr)

		rep.ConfirmedTotalMicro += u.ConfirmedMicro
		rep.UnpricedTotalMicro += u.UnpricedMicro
		rep.UnpricedRequests += u.UnpricedRequests
		rep.LegacyRows += u.LegacyRows
		rep.Requests += u.Requests
		rep.ShadowTotalMicro += u.ShadowMicro
		rep.WalletMicro += l.WalletMicro
		rep.WalletRoundingDeltaMicro += l.WalletCentsAppliedMicro - l.WalletMicro
		rep.InvoiceTotalMicro += inv
		// The estimated/unresolved columns sum exactly like every other
		// column (TOTAL = Σ detail rows) but feed NO settled total.
		rep.EstimatedTotalMicro += s.EstimatedMicro
		rep.EstimatedRequests += s.EstimatedRequests
		rep.UnresolvedPriceRows += s.UnresolvedPriceRows
		rep.UnresolvedPriceTotalMicro += s.UnresolvedPriceMicro
	}

	rep.CapturedMicro = rep.ConfirmedTotalMicro + rep.ShadowTotalMicro
	rep.InvoiceDeltaMicro = rep.CapturedMicro - rep.InvoiceTotalMicro
	rep.WalletGapMicro = rep.ConfirmedTotalMicro + rep.WalletMicro
	rep.CaptureRatePct = spendReconCaptureRatePct(rep.CapturedMicro, rep.InvoiceTotalMicro)

	// Hard invariant 1: the UI-parity total must equal the filtered
	// breakdown exactly. A mismatch means a cost_status class carries cost
	// outside {confirmed, unpriced} or the two queries disagree on the
	// period boundary — exactly the silent-drift class this report exists
	// to surface.
	if rep.UITotalMicro != rep.ConfirmedTotalMicro+rep.UnpricedTotalMicro {
		rep.Violations = append(rep.Violations, SpendReconViolation{
			Code: ViolationUITotalMismatch,
			Detail: fmt.Sprintf("UI-parity total %d != confirmed %d + unpriced %d micro-USD",
				rep.UITotalMicro, rep.ConfirmedTotalMicro, rep.UnpricedTotalMicro),
		})
	}

	// Hard invariant 2: wallet cent rounding. Every wallet ledger row is an
	// applied carry step (settleWalletEntries writes rows only when
	// carryWalletCharge applied) satisfying
	//   amount_cents×1e4 = rem_prev + amount_micro − rem_next
	// with remainder CHECK < 1 cent, so each row's cent-vs-micro delta is
	// strictly inside one cent and the window delta is bounded by
	// (txns + 1) cents regardless of interleaving with other writers.
	// Verifiable only when every usage row carries the exact micro amount
	// (AF-05); legacy NULL-micro rows downgrade the check to a notice.
	if legacyNoMicro > 0 {
		rep.LedgerRoundingBoundMicro = -1 // not verifiable
		rep.Violations = append(rep.Violations, SpendReconViolation{
			Code: ViolationLedgerLegacyNoMicro,
			Detail: fmt.Sprintf("%d wallet usage rows without exact micro amount (pre-AF-05); rounding bound not verifiable",
				legacyNoMicro),
		})
	} else {
		rep.LedgerRoundingBoundMicro = spendReconLedgerRoundingBound(allTxns)
		if d := spendReconAbs(rep.WalletRoundingDeltaMicro); d > rep.LedgerRoundingBoundMicro {
			rep.Violations = append(rep.Violations, SpendReconViolation{
				Code: ViolationLedgerRounding,
				Detail: fmt.Sprintf("|Σcents×1e4 − Σmicro| = %d exceeds rounding bound %d micro-USD (%d txns)",
					rep.WalletRoundingDeltaMicro, rep.LedgerRoundingBoundMicro, allTxns),
			})
		}
	}

	// Hard invariant 3: invoice capture within tolerance (period total; a
	// single day beyond tolerance is flagged in the day loop above).
	if d := spendReconAbs(rep.InvoiceDeltaMicro); d > invoiceTolerance {
		rep.Violations = append(rep.Violations, SpendReconViolation{
			Code: ViolationInvoiceGapExceeded,
			Detail: fmt.Sprintf("captured %d − invoice %d = %d exceeds tolerance %d micro-USD",
				rep.CapturedMicro, rep.InvoiceTotalMicro, rep.InvoiceDeltaMicro, invoiceTolerance),
		})
	}

	rep.Status = SpendReconStatusOK
	if len(rep.Violations) > 0 {
		rep.Status = SpendReconStatusViolation
	}
	return rep
}

// spendReconAbs returns |v|.
func spendReconAbs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// spendReconDayInWindow reports whether the local calendar day bucket named
// by the YYYY-MM-DD day string — [local midnight in zone, next local
// midnight) in loc, nil = UTC — intersects the half-open report window
// [from, to). Both bounds are absolute instants and compare exactly, so a
// DST-shortened or -lengthened day is handled by the calendar-field
// addition (AddDate), not by fixed 24h math. A zero From or To disables
// that side's bound (the report never clips when the caller declared no
// window edge). An unparseable day string is an error, not an
// out-of-window answer: the row cannot be bucketed at all.
func spendReconDayInWindow(day string, from, to time.Time, loc *time.Location) (bool, error) {
	if loc == nil {
		loc = time.UTC
	}
	dayStart, err := time.ParseInLocation("2006-01-02", day, loc)
	if err != nil {
		return false, err
	}
	if !to.IsZero() && !dayStart.Before(to) {
		return false, nil
	}
	if !from.IsZero() && !from.Before(dayStart.AddDate(0, 0, 1)) {
		return false, nil
	}
	return true, nil
}

// spendReconLedgerRoundingBound returns the declared tolerance for
// |Σcents×1e4 − Σmicro| over a window: each applied wallet row satisfies
// amount_cents×1e4 = rem_prev + amount_micro − rem_next with remainders
// strictly inside one cent (org_credits CHECK), so the per-row delta is
// < 1 cent and the window bound is (txns + 1) cents. Only meaningful when
// no usage row is missing its exact micro amount.
func spendReconLedgerRoundingBound(txns int64) int64 {
	if txns < 0 {
		txns = 0
	}
	return spendReconCentMicro * (txns + 1)
}

// spendReconCaptureRatePct mirrors the trcli capture-rate convention:
// 100% when both sides are zero, 0% when nothing was captured against a
// non-zero invoice, and captured/invoice otherwise.
func spendReconCaptureRatePct(captured, invoice int64) float64 {
	if invoice == 0 {
		if captured == 0 {
			return 100
		}
		return 0
	}
	return float64(captured) / float64(invoice) * 100
}

// ParseInvoiceUSDMicro parses an invoice decimal amount ("12.34", "-0.05")
// into exact micro-USD without float rounding. More than six fractional
// digits is an error (numeric(12,6) captured costs never need more), as is
// an amount whose micro-USD value does not fit int64 on either sign — the
// negative side admits exactly one more magnitude than the positive one
// (MinInt64 = -9223372036854.775808). The multiplication is bounds-checked
// so a malformed invoice line can never wrap into a silently wrong amount.
func ParseInvoiceUSDMicro(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty amount")
	}
	neg := false
	switch s[0] {
	case '-':
		neg = true
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if s == "" || s == "." {
		return 0, fmt.Errorf("amount %q has no digits", s)
	}
	intPart, fracPart := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, fracPart = s[:i], s[i+1:]
	}
	if intPart == "" {
		intPart = "0"
	}
	if len(fracPart) > 6 {
		return 0, fmt.Errorf("amount %q has more than 6 fractional digits", s)
	}
	for len(fracPart) < 6 {
		fracPart += "0"
	}
	intMicro, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("integer part of %q: %w", s, err)
	}
	fracMicro, err := strconv.ParseInt(fracPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("fractional part of %q: %w", s, err)
	}
	bound := (math.MaxInt64 - fracMicro) / spendReconUSDMicro
	if neg && fracMicro == math.MaxInt64%spendReconUSDMicro+1 {
		// int64's negative side holds exactly one more magnitude than its
		// positive side (MinInt64 = -2^63 µUSD = -9223372036854.775808):
		// 775808 = MaxInt64%1e6+1 is the only fractional part where the
		// positive-side bound understates the admissible integer part by
		// one. Every other fraction keeps the two bounds identical.
		bound++
	}
	if intMicro > bound {
		return 0, fmt.Errorf("amount %q exceeds int64 micro-USD range", s)
	}
	out := intMicro * spendReconUSDMicro
	if neg {
		// Assemble the magnitude on the negative side by subtracting the
		// fractional part, so even the exact MinInt64 boundary is built
		// without any signed overflow (the no-silent-wrap pin above).
		out = -out - fracMicro
	} else {
		out += fracMicro
	}
	return out, nil
}

// RenderText renders the operator-facing summary (report-only output, in
// the spirit of `yb spend-reconcile`).
func (r SpendReconReport) RenderText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "spend reconciliation %s [%s .. %s) %s — %s\n",
		r.OrgID, r.From.UTC().Format("2006-01-02"), r.To.UTC().Format("2006-01-02"), r.Zone, r.Status)
	fmt.Fprintf(&b, "  ui total        %12d micro (parity vs detail)\n", r.UITotalMicro)
	fmt.Fprintf(&b, "  confirmed       %12d micro (+unpriced %d, %d req; legacy %d rows)\n",
		r.ConfirmedTotalMicro, r.UnpricedTotalMicro, r.UnpricedRequests, r.LegacyRows)
	fmt.Fprintf(&b, "  shadow          %12d micro (ui-excluded, invoice-included)\n", r.ShadowTotalMicro)
	fmt.Fprintf(&b, "  captured        %12d micro\n", r.CapturedMicro)
	fmt.Fprintf(&b, "  invoice         %12d micro (delta %d, capture %.2f%%)\n",
		r.InvoiceTotalMicro, r.InvoiceDeltaMicro, r.CaptureRatePct)
	if r.InvoiceDaysOutsidePeriod > 0 {
		fmt.Fprintf(&b, "  invoice days outside period: %d (excluded from totals)\n", r.InvoiceDaysOutsidePeriod)
	}
	fmt.Fprintf(&b, "  wallet          %12d micro (gap %d, rounding |%d| <= %d)\n",
		r.WalletMicro, r.WalletGapMicro, r.WalletRoundingDeltaMicro, r.LedgerRoundingBoundMicro)
	// N06-P06-T04: the estimated and unresolved dimensions, clearly
	// labelled and never folded into the settled lines above.
	fmt.Fprintf(&b, "  estimated       %12d micro (%d req unsettled; NOT added to confirmed/captured)\n",
		r.EstimatedTotalMicro, r.EstimatedRequests)
	fmt.Fprintf(&b, "  unresolved      %12d micro (%d unknown-price rows, never billed)\n",
		r.UnresolvedPriceTotalMicro, r.UnresolvedPriceRows)
	if r.ReservedOutstandingMicro != 0 || r.ReservedAllowances != 0 {
		fmt.Fprintf(&b, "  reserved        %12d micro outstanding at period end (%d holds; snapshot, not a day fact)\n",
			r.ReservedOutstandingMicro, r.ReservedAllowances)
	}
	if r.UsagePricingAsOf != "" {
		fmt.Fprintf(&b, "  usage pricing as-of: %s\n", r.UsagePricingAsOf)
	}
	if r.InvoiceLabel != "" {
		fmt.Fprintf(&b, "  invoice: %s\n", r.InvoiceLabel)
	}
	for _, v := range r.Violations {
		fmt.Fprintf(&b, "  VIOLATION %s day=%s: %s\n", v.Code, v.Day, v.Detail)
	}
	for _, d := range r.Days {
		fmt.Fprintf(&b, "  day %s confirmed %d unpriced %d/%d req wallet %d invoice %d delta %d estimated %d/%d unresolved %d/%d flags=%v\n",
			d.Day, d.ConfirmedMicro, d.UnpricedMicro, d.UnpricedRequests, d.WalletMicro, d.InvoiceMicro, d.InvoiceDelta,
			d.EstimatedMicro, d.EstimatedRequests, d.UnresolvedPriceRows, d.UnresolvedPriceMicro, d.Flags)
	}
	for _, l := range r.Limitations {
		fmt.Fprintf(&b, "  limitation: %s\n", l)
	}
	return b.String()
}

// SpendReconReader is the read-only seam over the canonical tables. Queries
// never write; period windows are half-open [from, to) (absolute instants,
// independent of any timezone) and the by-day buckets are local calendar
// days in the caller's report timezone:
// to_char(date_trunc('day', created_at AT TIME ZONE zone), 'YYYY-MM-DD')
// with the zone bound as a query parameter, so the bucketing never depends
// on the database session TimeZone.
type SpendReconReader interface {
	// UsageTotal returns the UI-parity total (all cost statuses, shadow
	// excluded — the GetCostAnalytics predicate), scaled exactly to
	// micro-USD.
	UsageTotal(ctx context.Context, orgID string, from, to time.Time) (int64, error)
	// UsageByDay returns per-day cost facts split by rollup status classes.
	// zone is the IANA report timezone of the day buckets ("" = UTC); an
	// unknown zone is an error, never a silent UTC fallback.
	UsageByDay(ctx context.Context, orgID string, from, to time.Time, zone string) ([]SpendReconUsageDay, error)
	// LedgerByDay returns per-day wallet usage facts from
	// credit_transactions (type='usage'); zone as in UsageByDay.
	LedgerByDay(ctx context.Context, orgID string, from, to time.Time, zone string) ([]SpendReconLedgerDay, error)
	// SettlementsByDay returns per-day settlement_jobs facts: the
	// ESTIMATED usage (unsettled charge intents) and UNRESOLVED usage
	// (unknown-cost visibility rows) of each day, in the same zoned day
	// buckets as UsageByDay. Read-only; zone as in UsageByDay.
	SettlementsByDay(ctx context.Context, orgID string, from, to time.Time, zone string) ([]SpendReconSettlementDay, error)
	// ReservedOutstanding returns the point-in-time reservation snapshot:
	// Σ(granted−returned) over the org's budget_allowances that still hold
	// money (statuses active, expired, draining; released holds nothing)
	// and the number of holds. It is a snapshot at call time, never a
	// per-day fact.
	ReservedOutstanding(ctx context.Context, orgID string) (micro int64, holds int64, err error)
}

// spendReconUSDToMicro is the exact numeric(12,6)→micro scale for
// cost_in_usd (USD, 6 decimals ⇒ ×1e6 integral).
const spendReconUSDToMicro = "1000000"

// spendReconCentsToMicro is the exact amount_cents→micro scale
// (1 cent = 10 000 micro).
const spendReconCentsToMicro = "10000"

// spendReconUIExcludeShadow is the shadow-exclusion predicate of the
// GetCostAnalytics UI aggregate. The UI-parity total and EVERY cost-class
// expression of the by-day breakdown must carry it: shadow rows carry both
// cost_in_usd and cost_status (shadowRequestLogRow), so without the
// predicate the class sums would double-count shadow spend (it is also
// reported once as ShadowMicro and added back for invoice capture) and the
// parity invariant would fail on any period with shadow usage.
const spendReconUIExcludeShadow = "COALESCE(ab_group, '') <> 'shadow'"

// spendReconConfirmedExpr is the confirmed-class cost sum (rollup status
// classes; shadow excluded so it sums to the UI aggregate, never to
// UI+shadow).
const spendReconConfirmedExpr = `SUM(cost_in_usd) FILTER (WHERE cost_status IN ('priced', 'cache_hit', 'legacy') AND ` + spendReconUIExcludeShadow + `)`

// spendReconUnpricedCostExpr is the unpriced-class cost sum (invariant: 0).
const spendReconUnpricedCostExpr = `SUM(cost_in_usd) FILTER (WHERE cost_status IN ('unknown_price', 'no_usage') AND ` + spendReconUIExcludeShadow + `)`

// spendReconUnpricedCountExpr is the unpriced request count (shadow excluded
// so the counts describe the same rows as the UI aggregate).
const spendReconUnpricedCountExpr = `COUNT(*) FILTER (WHERE cost_status IN ('unknown_price', 'no_usage') AND ` + spendReconUIExcludeShadow + `)`

// spendReconLegacyCountExpr is the legacy row count (shadow excluded).
const spendReconLegacyCountExpr = `COUNT(*) FILTER (WHERE cost_status = 'legacy' AND ` + spendReconUIExcludeShadow + `)`

// spendReconShadowExpr is the ONLY place the by-day query sums shadow rows
// (deliberately without the exclusion predicate).
const spendReconShadowExpr = `SUM(cost_in_usd) FILTER (WHERE COALESCE(ab_group, '') = 'shadow')`

// spendReconOpenSettlementStatuses are the settlement_jobs statuses whose
// charge intent is still in flight (N06-P06-T04): pending = not yet leased,
// processing = leased by an executor, retry = failed, re-enters after
// backoff, requires_attention = durable debt (the cost was incurred, the
// charge is still owed). All of them are ESTIMATED usage: reserved, not
// yet settled. 'settled' is the wallet ledger's business and is excluded;
// 'pending_price'/'unknown' are the unresolved class below, never billed.
const spendReconOpenSettlementStatuses = `('pending', 'processing', 'retry', 'requires_attention')`

// spendReconUnresolvedPricePredicate is the unknown-cost visibility class:
// pending_price rows (created with amount literals 0,0 — never a charge)
// and their terminal 'unknown' expiry state (refundless semantics: the
// bound is released uncharged, the unknown cost stays visible).
const spendReconUnresolvedPricePredicate = `charge_kind = 'pending_price' AND status IN ('pending_price', 'unknown')`

// spendReconZonedDayBucket is the day-bucket expression of the by-day
// queries: created_at is converted to the report timezone ($4, bound by the
// reader — never the session TimeZone) BEFORE date_trunc, so a bucket is
// one local calendar day of the org's reporting timezone (23/25 hours
// around a DST transition) and the SQL grouping matches the window
// semantics of ReconcileSpend exactly. The window bounds stay absolute
// comparisons (timestamptz >= $2 AND < $3) — only the LABELS are zoned.
const spendReconZonedDayBucket = `to_char(date_trunc('day', created_at AT TIME ZONE $4::text), 'YYYY-MM-DD')`

// spendReconUsageTotalQuery is the UI-parity total: all cost statuses,
// shadow excluded (GetCostAnalytics predicate), scaled exactly to micro.
// It is window-only and deliberately day-free: no date_trunc at all, so no
// timezone parameter can affect it.
const spendReconUsageTotalQuery = `
		SELECT COALESCE((SUM(cost_in_usd) * ` + spendReconUSDToMicro + `)::bigint, 0)
		FROM request_logs
		WHERE org_id = $1 AND created_at >= $2 AND created_at < $3
		  AND ` + spendReconUIExcludeShadow

// spendReconUsageByDayQuery is the per-day cost breakdown, grouped by
// local calendar day in the report zone ($4). The class expressions
// exclude shadow rows (UI parity) while the GROUP BY keeps shadow-only
// days on the list, so invoice comparisons still see them via ShadowMicro.
const spendReconUsageByDayQuery = `
		SELECT ` + spendReconZonedDayBucket + `,
		       COALESCE((` + spendReconConfirmedExpr + ` * ` + spendReconUSDToMicro + `)::bigint, 0),
		       COALESCE((` + spendReconUnpricedCostExpr + ` * ` + spendReconUSDToMicro + `)::bigint, 0),
		       ` + spendReconUnpricedCountExpr + `,
		       ` + spendReconLegacyCountExpr + `,
		       COUNT(*) FILTER (WHERE ` + spendReconUIExcludeShadow + `),
		       COALESCE((` + spendReconShadowExpr + ` * ` + spendReconUSDToMicro + `)::bigint, 0)
		FROM request_logs
		WHERE org_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY 1 ORDER BY 1`

// spendReconLedgerByDayQuery is the per-day wallet usage breakdown,
// grouped by local calendar day in the report zone ($4) like the usage
// query — both sides of the wallet gap must bucket identically.
const spendReconLedgerByDayQuery = `
		SELECT ` + spendReconZonedDayBucket + `,
		       COALESCE(SUM(amount_micro_usd), 0)::bigint,
		       COALESCE(SUM(amount_cents), 0)::bigint * ` + spendReconCentsToMicro + `,
		       COUNT(*),
		       COUNT(*) FILTER (WHERE amount_micro_usd IS NULL)
		FROM credit_transactions
		WHERE org_id = $1 AND created_at >= $2 AND created_at < $3
		  AND type = 'usage'
		GROUP BY 1 ORDER BY 1`

// spendReconSettlementsByDayQuery is the per-day settlement_jobs breakdown
// (N06-P06-T04), grouped by the intent's creation day in the report zone
// ($4) like the other fact queries. Every day group carries the estimated
// (open) amount/count and the unresolved unknown-price rows/count — the
// FILTER classes are disjoint (open statuses vs pending_price/unknown), so
// a row feeds at most one class and the two columns can never double-count.
const spendReconSettlementsByDayQuery = `
		SELECT ` + spendReconZonedDayBucket + `,
		       COALESCE(SUM(amount_micro_usd) FILTER (WHERE status IN ` + spendReconOpenSettlementStatuses + `), 0)::bigint,
		       COUNT(*) FILTER (WHERE status IN ` + spendReconOpenSettlementStatuses + `),
		       COUNT(*) FILTER (WHERE ` + spendReconUnresolvedPricePredicate + `),
		       COALESCE(SUM(amount_micro_usd) FILTER (WHERE ` + spendReconUnresolvedPricePredicate + `), 0)::bigint
		FROM settlement_jobs
		WHERE org_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY 1 ORDER BY 1`

// spendReconReservedOutstandingQuery is the point-in-time reservation
// snapshot: residual holds (granted−returned) over allowances that still
// hold money. Released allowances are excluded (they returned everything
// by construction); expired/draining holds still reserve real money until
// the reconcile pass returns them, so they count. Read-only, no day
// bucket — the snapshot is echoed once per report, never spread over days.
const spendReconReservedOutstandingQuery = `
		SELECT COALESCE(SUM(granted_micro_usd - returned_micro_usd), 0)::bigint,
		       COUNT(*)
		FROM budget_allowances
		WHERE org_id = $1
		  AND status IN ('active', 'expired', 'draining')`

// spendReconReportZone resolves the report timezone name for reader
// queries: "" (and UTC variants) resolves to "UTC"; anything else must be a
// valid tzdb zone via budget.ResolveReportZone — the same resolver the
// reporting-period helpers use, so reader buckets can never silently
// diverge from the caller's zoned window (no implicit UTC fallback).
func spendReconReportZone(zone string) (string, error) {
	loc, err := budget.ResolveReportZone(zone)
	if err != nil {
		return "", fmt.Errorf("spend recon report zone: %w", err)
	}
	return loc.String(), nil
}

// PgxSpendReconReader is the pgx implementation of SpendReconReader.
type PgxSpendReconReader struct {
	pool *pgxpool.Pool
}

var _ SpendReconReader = (*PgxSpendReconReader)(nil)

// NewPgxSpendReconReader returns a reader over the given pool.
func NewPgxSpendReconReader(pool *pgxpool.Pool) *PgxSpendReconReader {
	return &PgxSpendReconReader{pool: pool}
}

// UsageTotal implements SpendReconReader.
func (r *PgxSpendReconReader) UsageTotal(ctx context.Context, orgID string, from, to time.Time) (int64, error) {
	if r.pool == nil {
		return 0, fmt.Errorf("spend recon reader: pool not configured")
	}
	var total int64
	err := r.pool.QueryRow(ctx, spendReconUsageTotalQuery, orgID, from, to).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("spend recon usage total: %w", err)
	}
	return total, nil
}

// UsageByDay implements SpendReconReader.
func (r *PgxSpendReconReader) UsageByDay(ctx context.Context, orgID string, from, to time.Time, zone string) ([]SpendReconUsageDay, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("spend recon reader: pool not configured")
	}
	z, err := spendReconReportZone(zone)
	if err != nil {
		return nil, err
	}
	rows, err := r.pool.Query(ctx, spendReconUsageByDayQuery, orgID, from, to, z)
	if err != nil {
		return nil, fmt.Errorf("spend recon usage by-day query: %w", err)
	}
	defer rows.Close()

	out := make([]SpendReconUsageDay, 0, 32)
	for rows.Next() {
		var d SpendReconUsageDay
		if err := rows.Scan(&d.Day, &d.ConfirmedMicro, &d.UnpricedMicro,
			&d.UnpricedRequests, &d.LegacyRows, &d.Requests, &d.ShadowMicro); err != nil {
			return nil, fmt.Errorf("spend recon usage by-day scan: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("spend recon usage by-day rows: %w", err)
	}
	return out, nil
}

// LedgerByDay implements SpendReconReader.
func (r *PgxSpendReconReader) LedgerByDay(ctx context.Context, orgID string, from, to time.Time, zone string) ([]SpendReconLedgerDay, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("spend recon reader: pool not configured")
	}
	z, err := spendReconReportZone(zone)
	if err != nil {
		return nil, err
	}
	rows, err := r.pool.Query(ctx, spendReconLedgerByDayQuery, orgID, from, to, z)
	if err != nil {
		return nil, fmt.Errorf("spend recon ledger by-day query: %w", err)
	}
	defer rows.Close()

	out := make([]SpendReconLedgerDay, 0, 32)
	for rows.Next() {
		var d SpendReconLedgerDay
		if err := rows.Scan(&d.Day, &d.WalletMicro, &d.WalletCentsAppliedMicro,
			&d.WalletTxns, &d.WalletRowsWithoutMicro); err != nil {
			return nil, fmt.Errorf("spend recon ledger by-day scan: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("spend recon ledger by-day rows: %w", err)
	}
	return out, nil
}

// SettlementsByDay implements SpendReconReader.
func (r *PgxSpendReconReader) SettlementsByDay(ctx context.Context, orgID string, from, to time.Time, zone string) ([]SpendReconSettlementDay, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("spend recon reader: pool not configured")
	}
	z, err := spendReconReportZone(zone)
	if err != nil {
		return nil, err
	}
	rows, err := r.pool.Query(ctx, spendReconSettlementsByDayQuery, orgID, from, to, z)
	if err != nil {
		return nil, fmt.Errorf("spend recon settlements by-day query: %w", err)
	}
	defer rows.Close()

	out := make([]SpendReconSettlementDay, 0, 32)
	for rows.Next() {
		var d SpendReconSettlementDay
		if err := rows.Scan(&d.Day, &d.EstimatedMicro, &d.EstimatedRequests,
			&d.UnresolvedPriceRows, &d.UnresolvedPriceMicro); err != nil {
			return nil, fmt.Errorf("spend recon settlements by-day scan: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("spend recon settlements by-day rows: %w", err)
	}
	return out, nil
}

// ReservedOutstanding implements SpendReconReader.
func (r *PgxSpendReconReader) ReservedOutstanding(ctx context.Context, orgID string) (int64, int64, error) {
	if r.pool == nil {
		return 0, 0, fmt.Errorf("spend recon reader: pool not configured")
	}
	var micro, holds int64
	err := r.pool.QueryRow(ctx, spendReconReservedOutstandingQuery, orgID).Scan(&micro, &holds)
	if err != nil {
		return 0, 0, fmt.Errorf("spend recon reserved outstanding: %w", err)
	}
	return micro, holds, nil
}
