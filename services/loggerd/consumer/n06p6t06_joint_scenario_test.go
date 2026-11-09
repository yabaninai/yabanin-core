package consumer

// Joint end-to-end user scenario for packet N06-P06 (card T06): the accepted
// seams of this packet — the reconciliation core (T02), the reporting-period
// zone helpers (T03), the estimated/unresolved settlement dimension (T04)
// and the negative corpus (T05) — exercised TOGETHER by one operator journey
// ("report September for an org, reconcile wallet + invoice, export CSV"),
// plus the documented failure edges of the packet.
//
// The card requires real and mock checks to be EXPLICITLY DISTINGUISHED.
// The two stands used here are:
//
//   - REAL stand (TestN06P6T06RealPG_*): a disposable testcontainers Postgres
//     (pkg/testdb, the established stand of this package, Docker required
//     outside -short). The FULL user path runs against live SQL: the org's
//     reporting timezone is read back from organizations.timezone, resolved
//     with budget.ResolveReportZone, the period is built with
//     budget.MonthReportPeriod, every fact slice is read with
//     PgxSpendReconReader (the five real queries — this closes the T02/T03
//     handoff note that the reader was only contract-pinned by string tests),
//     the invoice side is parsed with ParseInvoiceUSDMicro exactly like the
//     `yb spend-reconcile` CSV import, and the report is exported with
//     WriteCSV. Seeded rows follow the established live-test seeding style
//     (pkg/trcli/spend_reconcile_test.go): explicit created_at instants,
//     org-scoped, cleaned up after the test.
//
//   - MOCK stand (TestN06P6T06Mock_*): pure in-memory facts into
//     ReconcileSpend, no Docker. It covers ONLY the composition edges that
//     are unreachable on the real stand by construction: the reader's SQL
//     windows and day-buckets every fact (proven on the real stand), so
//     out-of-window or malformed day rows can only be injected by a caller
//     bug — the core's fail-closed defense for hand-assembled facts is a
//     caller-contract property, pinned here on mock input (the T05 corpus
//     already covers each slice separately; the joint case has all five
//     fact slices populated at once).
//
// Card acceptance: "сумма детализации совпадает с итогами и округлением"
// — the TOTAL row is the exact sum of the emitted detail rows in every
// numeric column, including the once-per-row cents projection — asserted on
// all three stands via the accepted n06p6t05AssertDetailSumsToTotals helper.

import (
	"bytes"
	"context"
	"encoding/csv"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// Distinct org UUIDs per test: the testcontainers Postgres is a shared,
// migrated container (one cached pool per region), so every seed is
// org-scoped and cleaned up.
const (
	n06p6t06HappyOrgID = "3a6f1c2e-9b4d-4e8a-b7c1-5d2e8f9a0b31"
	n06p6t06LateOrgID  = "4b7e2d3f-0c5e-4f9b-8a2d-6e3f9a0b1c42"
	n06p6t06Zone       = "Europe/Berlin"
)

// n06p6t06SeedRealScenario seeds the joint REAL-stand scenario for one org:
// a Berlin-reporting org with September-2026 usage (priced, unknown-price,
// shadow, cross-midnight and out-of-window rows), wallet usage transactions
// (exact micro + applied cents), settlement charge intents (estimated,
// settled, unresolved-price, out-of-window) and reservation holds (active
// residual + released). Rows carry explicit created_at instants so the zoned
// day buckets are deterministic; cleanup removes the org's rows.
func n06p6t06SeedRealScenario(t *testing.T, pool *pgxpool.Pool, orgID string) {
	t.Helper()
	ctx := context.Background()

	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug, timezone)
		VALUES ($1, 'n06p6-t06 recon org', 'n06p6-t06-' || $2, $3)
		ON CONFLICT (id) DO NOTHING`,
		orgID, orgID[:8], n06p6t06Zone)
	require.NoError(t, err)
	t.Cleanup(func() {
		// Children first (request_logs.org_id carries a real FK), then the
		// org; the text-keyed fact tables have no FK but are org-scoped.
		_, _ = pool.Exec(ctx, `DELETE FROM request_logs WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM settlement_jobs WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM budget_allowances WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	seedLog := func(reqID, createdAt, cost, costStatus, abGroup string) {
		t.Helper()
		_, err := pool.Exec(ctx, `
			INSERT INTO request_logs (org_id, request_id, model_requested, model_used, status_code,
				duration_ms, cost_in_usd, cost_status, ab_group, created_at, updated_at)
			VALUES ($1, $2, 'gpt-x', 'gpt-x', 200, 5, $3::numeric, $4,
				NULLIF($5, ''), $6::timestamptz, $6::timestamptz)`,
			orgID, reqID, cost, costStatus, abGroup, createdAt)
		require.NoError(t, err)
	}
	// Berlin September 2026: [2026-08-31T22:00Z .. 2026-09-30T22:00Z).
	seedLog("n06p6t06-r1", "2026-08-31T22:30:00Z", "0.5", "priced", "")       // Berlin 09-01 00:30 — cross-midnight
	seedLog("n06p6t06-r2", "2026-09-01T10:00:00Z", "0.25", "priced", "")      // Berlin 09-01
	seedLog("n06p6t06-r3", "2026-09-01T11:00:00Z", "0", "unknown_price", "")  // unpriced ⇒ $0
	seedLog("n06p6t06-r4", "2026-09-01T21:30:00Z", "0.1", "priced", "shadow") // Berlin 09-01 23:30, UI-excluded
	seedLog("n06p6t06-r5", "2026-09-02T12:00:00Z", "3.75", "priced", "")      // Berlin 09-02
	seedLog("n06p6t06-r6", "2026-09-30T23:30:00Z", "0.777", "priced", "")     // Berlin 10-01 01:30 — outside window

	seedTxn := func(createdAt string, cents, balanceAfter, micro int64, reqID string) {
		t.Helper()
		_, err := pool.Exec(ctx, `
			INSERT INTO credit_transactions (org_id, amount_cents, balance_after, type,
				request_id, amount_micro_usd, created_at)
			VALUES ($1, $2, $3, 'usage', $4, $5, $6::timestamptz)`,
			orgID, cents, balanceAfter, reqID, micro, createdAt)
		require.NoError(t, err)
	}
	// Wallet usage exactly like the AF-05 writer: negative applied cents
	// (half-away projection) plus the exact micro amount. Day 09-01 carries
	// a sub-cent carry (|−123×1e4 − (−1_234_567)| = 4_567 < 1 cent).
	seedTxn("2026-08-31T22:30:05Z", -123, 9_999_877, -1_234_567, "n06p6t06-r1")
	seedTxn("2026-09-02T12:00:05Z", -380, 9_999_497, -3_800_000, "n06p6t06-r5")

	seedJob := func(reqID, chargeKind, status, createdAt string, micro int64) {
		t.Helper()
		_, err := pool.Exec(ctx, `
			INSERT INTO settlement_jobs (org_id, request_id, charge_kind, status,
				amount_micro_usd, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $6::timestamptz)`,
			orgID, reqID, chargeKind, status, micro, createdAt)
		require.NoError(t, err)
	}
	seedJob("n06p6t06-j1", "resale_deduction", "pending", "2026-09-01T09:00:00Z", 300_000)            // estimated 09-01
	seedJob("n06p6t06-j2", "resale_deduction", "settled", "2026-09-01T09:30:00Z", 800_000)            // settled ⇒ wallet's business, excluded
	seedJob("n06p6t06-j3", "pending_price", "pending_price", "2026-09-01T10:30:00Z", 0)               // unresolved ⇒ visible count, $0
	seedJob("n06p6t06-j4", "resale_deduction", "requires_attention", "2026-09-02T08:00:00Z", 150_000) // estimated 09-02 (durable debt)
	seedJob("n06p6t06-j5", "resale_deduction", "pending", "2026-09-30T23:30:00Z", 555_000)            // Berlin 10-01 — outside window

	seedHold := func(replica, status string, granted, returned int64, leaseUntil time.Time) {
		t.Helper()
		_, err := pool.Exec(ctx, `
			INSERT INTO budget_allowances (replica_id, scope_kind, scope_key, org_id,
				granted_micro_usd, returned_micro_usd, status, lease_until)
			VALUES ($1, 'wallet', $2, $2, $3, $4, $5, $6::timestamptz)`,
			replica, orgID, granted, returned, status, leaseUntil)
		require.NoError(t, err)
	}
	seedHold("n06p6t06-h1", "active", 5_000_000, 1_200_000, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) // residual 3_800_000
	seedHold("n06p6t06-h2", "released", 900_000, 900_000, time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))   // holds nothing ⇒ excluded
}

// n06p6t06InvoiceLines is the provider invoice CSV (one line per row, day
// label = org-local day like the `yb spend-reconcile` import): three lines
// accumulate on Berlin 09-01, one on 09-02, plus a late line for the former
// period (August 31) that must stay out of every total.
func n06p6t06InvoiceLines() []struct{ day, amount string } {
	return []struct{ day, amount string }{
		{"2026-09-01", "0.50"},
		{"2026-09-01", "0.25"},
		{"2026-09-01", "0.10"},
		{"2026-09-02", "3.75"},
		{"2026-08-31", "1.00"}, // late invoice line for the former period
	}
}

// n06p6t06ReadFacts runs the REAL-stand joint read path: org timezone from
// the DB → budget.ResolveReportZone → budget.MonthReportPeriod → all five
// PgxSpendReconReader methods → invoice CSV parsed with
// ParseInvoiceUSDMicro. Returns the period (for window assertions) and the
// fully populated reconciliation input.
func n06p6t06ReadFacts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID string) (budget.ReportPeriod, SpendReconInput) {
	t.Helper()

	var tz string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT timezone FROM organizations WHERE id = $1`, orgID).Scan(&tz))
	loc, err := budget.ResolveReportZone(tz)
	require.NoError(t, err)
	require.Equal(t, n06p6t06Zone, loc.String())

	period, err := budget.MonthReportPeriod("2026-09", tz)
	require.NoError(t, err)

	reader := NewPgxSpendReconReader(pool)
	usageTotal, err := reader.UsageTotal(ctx, orgID, period.From, period.To)
	require.NoError(t, err)
	usage, err := reader.UsageByDay(ctx, orgID, period.From, period.To, tz)
	require.NoError(t, err)
	ledger, err := reader.LedgerByDay(ctx, orgID, period.From, period.To, tz)
	require.NoError(t, err)
	settlements, err := reader.SettlementsByDay(ctx, orgID, period.From, period.To, tz)
	require.NoError(t, err)
	reservedMicro, reservedHolds, err := reader.ReservedOutstanding(ctx, orgID)
	require.NoError(t, err)

	// Invoice import exactly like the CLI: parse each CSV amount, accumulate
	// per day, deterministic day order.
	invoiceByDay := make(map[string]int64)
	for _, line := range n06p6t06InvoiceLines() {
		micro, err := ParseInvoiceUSDMicro(line.amount)
		require.NoError(t, err)
		invoiceByDay[line.day] += micro
	}
	var invoice []SpendReconInvoiceDay
	for _, day := range []string{"2026-08-31", "2026-09-01", "2026-09-02"} {
		invoice = append(invoice, SpendReconInvoiceDay{Day: day, InvoiceMicro: invoiceByDay[day]})
	}

	return period, SpendReconInput{
		OrgID:        orgID,
		From:         period.From,
		To:           period.To,
		Zone:         loc,
		UITotalMicro: usageTotal,
		Usage:        usage,
		Ledger:       ledger,
		Invoice:      invoice,
		Settlements:  settlements,

		ReservedOutstandingMicro: reservedMicro,
		ReservedAllowances:       reservedHolds,

		UsagePricingAsOf: "bundled.json@2026-09-01",
		InvoiceLabel:     "provider-invoice-2026-09",
	}
}

// TestN06P6T06RealPG_JointReportingScenario — REAL stand. One operator
// journey end-to-end on live SQL: report September 2026 for a Berlin org,
// reconcile usage × wallet × invoice × settlements × reservations, export
// CSV, and verify every accepted invariant of the packet on the composed
// state.
func TestN06P6T06RealPG_JointReportingScenario(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	creditsIntegrationMu.Lock()
	t.Cleanup(creditsIntegrationMu.Unlock)

	ctx := context.Background()
	n06p6t06SeedRealScenario(t, pool, n06p6t06HappyOrgID)

	period, in := n06p6t06ReadFacts(t, ctx, pool, n06p6t06HappyOrgID)

	// The T03 period contract on the real org setting: the September window
	// is local midnight to local midnight (30 Berlin days), NOT flat UTC.
	require.Equal(t, "2026-09", period.Label)
	require.Equal(t, n06p6t06Zone, period.Zone)
	require.True(t, period.From.Equal(time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)),
		"Berlin local midnight 2026-09-01 = %s", period.From)
	require.True(t, period.To.Equal(time.Date(2026, 9, 30, 22, 0, 0, 0, time.UTC)),
		"Berlin local midnight 2026-10-01 = %s", period.To)
	buckets := period.DayBuckets()
	require.Len(t, buckets, 30)
	require.Equal(t, "2026-09-01", buckets[0])
	require.Equal(t, "2026-09-30", buckets[len(buckets)-1])

	rep := ReconcileSpend(in)

	// Happy path: every hard invariant holds on the composed state.
	if rep.Status != SpendReconStatusOK {
		t.Fatalf("status = %q, want ok (violations: %+v)", rep.Status, rep.Violations)
	}
	if rep.Zone != n06p6t06Zone {
		t.Errorf("zone = %q, want %q", rep.Zone, n06p6t06Zone)
	}

	// UI parity: the independently queried total equals the class breakdown
	// exactly ($4.50 confirmed + $0 unpriced; shadow and out-of-window rows
	// excluded from the UI side).
	if rep.UITotalMicro != 4_500_000 || rep.ConfirmedTotalMicro != 4_500_000 || rep.UnpricedTotalMicro != 0 {
		t.Errorf("ui/confirmed/unpriced = %d/%d/%d, want 4500000/4500000/0",
			rep.UITotalMicro, rep.ConfirmedTotalMicro, rep.UnpricedTotalMicro)
	}
	if rep.UnpricedRequests != 1 || rep.Requests != 4 {
		t.Errorf("unpriced req / requests = %d/%d, want 1/4", rep.UnpricedRequests, rep.Requests)
	}

	// Shadow is reported once, invoice-comparable, never inside the UI side.
	if rep.ShadowTotalMicro != 100_000 {
		t.Errorf("shadow = %d, want 100000", rep.ShadowTotalMicro)
	}
	if rep.CapturedMicro != 4_600_000 {
		t.Errorf("captured = %d, want 4600000", rep.CapturedMicro)
	}

	// Invoice side: the late 2026-08-31 line ($1.00) is excluded from every
	// total but stays visible through the counter.
	if rep.InvoiceTotalMicro != 4_600_000 || rep.InvoiceDeltaMicro != 0 {
		t.Errorf("invoice/delta = %d/%d, want 4600000/0", rep.InvoiceTotalMicro, rep.InvoiceDeltaMicro)
	}
	if rep.InvoiceDaysOutsidePeriod != 1 {
		t.Errorf("invoice days outside period = %d, want 1 (the late 2026-08-31 line)", rep.InvoiceDaysOutsidePeriod)
	}
	if rep.CaptureRatePct != 100 {
		t.Errorf("capture rate = %v, want 100", rep.CaptureRatePct)
	}

	// Wallet: exact micro total, the sub-cent carry of day 09-01 inside the
	// declared (txns + 1)-cent bound.
	if rep.WalletMicro != -5_034_567 {
		t.Errorf("wallet = %d, want -5034567", rep.WalletMicro)
	}
	if rep.WalletGapMicro != -534_567 { // 4_500_000 + (−5_034_567), named components
		t.Errorf("wallet gap = %d, want -534567", rep.WalletGapMicro)
	}
	if rep.WalletRoundingDeltaMicro != 4_567 {
		t.Errorf("wallet rounding delta = %d, want 4567", rep.WalletRoundingDeltaMicro)
	}
	if rep.LedgerRoundingBoundMicro != 30_000 { // (2 txns + 1) cents
		t.Errorf("ledger rounding bound = %d, want 30000", rep.LedgerRoundingBoundMicro)
	}

	// T04 dimension on live SQL: estimated in-flight usage and the
	// unresolved-price visibility rows stay separate from every settled
	// total; the reservation snapshot is echoed once.
	if rep.EstimatedTotalMicro != 450_000 || rep.EstimatedRequests != 2 {
		t.Errorf("estimated = %d/%d, want 450000/2", rep.EstimatedTotalMicro, rep.EstimatedRequests)
	}
	if rep.UnresolvedPriceRows != 1 || rep.UnresolvedPriceTotalMicro != 0 {
		t.Errorf("unresolved = %d/%d, want 1/0", rep.UnresolvedPriceRows, rep.UnresolvedPriceTotalMicro)
	}
	if rep.ReservedOutstandingMicro != 3_800_000 || rep.ReservedAllowances != 1 {
		t.Errorf("reserved snapshot = %d/%d, want 3800000/1 (released hold excluded)",
			rep.ReservedOutstandingMicro, rep.ReservedAllowances)
	}

	// Day rows: exactly the two Berlin September days with usage facts.
	// The cross-midnight row (2026-08-31T22:30Z = Berlin 09-01 00:30) lands
	// on the org-local day, and both out-of-window rows (Berlin 10-01) are
	// invisible: the reader's SQL windows them out by construction.
	if len(rep.Days) != 2 || rep.Days[0].Day != "2026-09-01" || rep.Days[1].Day != "2026-09-02" {
		t.Fatalf("days = %+v, want [2026-09-01 2026-09-02]", rep.Days)
	}
	d1, d2 := rep.Days[0], rep.Days[1]
	if d1.ConfirmedMicro != 750_000 || d1.Requests != 3 || d1.UnpricedRequests != 1 ||
		d1.ShadowMicro != 100_000 || d1.WalletMicro != -1_234_567 ||
		d1.InvoiceMicro != 850_000 || d1.InvoiceDelta != 0 ||
		d1.EstimatedMicro != 300_000 || d1.EstimatedRequests != 1 || d1.UnresolvedPriceRows != 1 {
		t.Errorf("day 09-01 = %+v", d1)
	}
	if d2.ConfirmedMicro != 3_750_000 || d2.Requests != 1 || d2.WalletMicro != -3_800_000 ||
		d2.InvoiceMicro != 3_750_000 || d2.InvoiceDelta != 0 ||
		d2.EstimatedMicro != 150_000 || d2.EstimatedRequests != 1 || d2.UnresolvedPriceRows != 0 {
		t.Errorf("day 09-02 = %+v", d2)
	}

	// Third-path parity check: a separately written aggregate (plain
	// shadow exclusion, no class FILTERs) over the seeded rows must agree
	// with the report's UI total — the parity identity holds against an
	// independently computed number, not just reader-vs-core.
	var parity int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COALESCE((SUM(cost_in_usd) * 1000000)::bigint, 0)
		FROM request_logs
		WHERE org_id = $1 AND created_at >= $2 AND created_at < $3
		  AND COALESCE(ab_group, '') <> 'shadow'`,
		n06p6t06HappyOrgID, period.From, period.To).Scan(&parity))
	if parity != rep.UITotalMicro {
		t.Errorf("independent aggregate %d != report UI total %d", parity, rep.UITotalMicro)
	}

	// CSV export: fixed column order, TOTAL = Σ detail rows in every
	// numeric column (the accepted packet pin), and the once-per-row cents
	// projection lands exactly on the canonical totals here.
	var buf bytes.Buffer
	require.NoError(t, rep.WriteCSV(&buf))
	recs, err := csv.NewReader(&buf).ReadAll()
	require.NoError(t, err)
	if len(recs[0]) != len(spendReconCSVColumns) || recs[0][0] != "day" || recs[0][len(recs[0])-1] != "flags" {
		t.Fatalf("csv header = %v, want the fixed %v", recs[0], spendReconCSVColumns)
	}
	n06p6t05AssertDetailSumsToTotals(t, rep)
	if recs[len(recs)-1][0] != "TOTAL" {
		t.Errorf("last row day = %q, want TOTAL", recs[len(recs)-1][0])
	}
	// confirmed_cents_usd (idx 12): 75 + 375 = 450 = cents($4.50).
	if got := recs[1][12] + "/" + recs[2][12] + "/" + recs[3][12]; got != "75/375/450" {
		t.Errorf("confirmed cents rows = %s, want 75/375/450", got)
	}
	// captured_cents_usd (idx 13): 85 + 375 = 460 = cents($4.60).
	if got := recs[1][13] + "/" + recs[2][13] + "/" + recs[3][13]; got != "85/375/460" {
		t.Errorf("captured cents rows = %s, want 85/375/460", got)
	}

	// The core is pure: recomputing from the same facts is deterministic.
	rep2 := ReconcileSpend(in)
	if !reflect.DeepEqual(rep, rep2) {
		t.Error("recomputation from identical facts produced a different report")
	}

	// REAL-stand property (the real/mock asymmetry this card documents):
	// every day label the reader produced is a parseable local day whose
	// bucket intersects the window — the reader cannot emit out-of-window
	// or malformed rows, so day_outside_period violations defend only
	// against caller-assembled facts (pinned on the mock stand below).
	for _, label := range []string{rep.Days[0].Day, rep.Days[1].Day} {
		day, err := budget.DayReportPeriod(label, n06p6t06Zone)
		require.NoError(t, err)
		if day.From.Before(period.To) && day.To.After(period.From) {
			continue
		}
		t.Errorf("day %q does not intersect the report window", label)
	}
}

// TestN06P6T06RealPG_LateUnknownCostFailsClosed — REAL stand, documented
// failure edge of the packet: after a clean report, a late unknown-cost
// settlement row carrying a non-zero amount (the invariant
// pending_price ⇒ $0 broken on live data) appends one visible day row,
// fails the report closed, and never rewrites the previously emitted rows.
func TestN06P6T06RealPG_LateUnknownCostFailsClosed(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	creditsIntegrationMu.Lock()
	t.Cleanup(creditsIntegrationMu.Unlock)

	ctx := context.Background()
	n06p6t06SeedRealScenario(t, pool, n06p6t06LateOrgID)

	_, in := n06p6t06ReadFacts(t, ctx, pool, n06p6t06LateOrgID)
	base := ReconcileSpend(in)
	if base.Status != SpendReconStatusOK {
		t.Fatalf("baseline status = %q, want ok (violations: %+v)", base.Status, base.Violations)
	}
	var baseBuf bytes.Buffer
	require.NoError(t, base.WriteCSV(&baseBuf))
	baseRecs, err := csv.NewReader(&baseBuf).ReadAll()
	require.NoError(t, err)

	// The bad late fact: an unknown-cost row with a non-zero amount, created
	// on Berlin 2026-09-03 (11:00 local).
	_, err = pool.Exec(ctx, `
		INSERT INTO settlement_jobs (org_id, request_id, charge_kind, status,
			amount_micro_usd, created_at, updated_at)
		VALUES ($1, 'n06p6t06-j6', 'pending_price', 'pending_price', 42_000,
			'2026-09-03T09:00:00Z'::timestamptz, '2026-09-03T09:00:00Z'::timestamptz)`,
		n06p6t06LateOrgID)
	require.NoError(t, err)

	_, inLate := n06p6t06ReadFacts(t, ctx, pool, n06p6t06LateOrgID)
	rep := ReconcileSpend(inLate)
	if rep.Status != SpendReconStatusViolation {
		t.Fatalf("status = %q, want violation (violations: %+v)", rep.Status, rep.Violations)
	}
	v := spendReconFindViolation(rep, ViolationUnresolvedPriceNonzero, "2026-09-03")
	if v == nil {
		t.Fatalf("missing %s violation for 2026-09-03 in %+v", ViolationUnresolvedPriceNonzero, rep.Violations)
	}

	// The new fact APPENDS: exactly one new day row, prior rows untouched,
	// settled surfaces unchanged.
	if len(rep.Days) != 3 {
		t.Fatalf("days = %d rows, want 3 (append-only)", len(rep.Days))
	}
	last := rep.Days[2]
	if last.Day != "2026-09-03" || last.ConfirmedMicro != 0 ||
		last.UnresolvedPriceRows != 1 || last.UnresolvedPriceMicro != 42_000 {
		t.Errorf("appended day = %+v, want 2026-09-03 with 0 confirmed and 1 unresolved row of 42000", last)
	}
	if rep.ConfirmedTotalMicro != base.ConfirmedTotalMicro ||
		rep.CapturedMicro != base.CapturedMicro ||
		rep.EstimatedTotalMicro != base.EstimatedTotalMicro ||
		rep.WalletMicro != base.WalletMicro {
		t.Error("settled/estimated totals changed after the late unresolved fact")
	}

	// CSV: prior detail rows byte-identical, the amount visible in its own
	// column, TOTAL still the exact sum of detail rows (identity preserved
	// in the violation state).
	var buf bytes.Buffer
	require.NoError(t, rep.WriteCSV(&buf))
	recs, err := csv.NewReader(&buf).ReadAll()
	require.NoError(t, err)
	for i, rec := range baseRecs[1 : len(baseRecs)-1] { // baseline detail rows
		if got := strings.Join(recs[1+i], ","); got != strings.Join(rec, ",") {
			t.Errorf("history rewritten: detail row %d = %q, want %q", i, got, strings.Join(rec, ","))
		}
	}
	if got := recs[len(recs)-1][17]; got != "42000" {
		t.Errorf("TOTAL unresolved_price_micro_usd = %q, want 42000", got)
	}
	n06p6t05AssertDetailSumsToTotals(t, rep)
}

// TestN06P6T06Mock_JointComposition — MOCK stand (no Docker): the joint
// composition edges that the real reader cannot produce, documented as the
// real/mock split of this card.
func TestN06P6T06Mock_JointComposition(t *testing.T) {
	t.Run("dst_month_full_packet", func(t *testing.T) {
		// T03×T02×T04 composed across a DST boundary: America/New_York
		// November 2026 contains the fall-back night (2026-11-01 is a 25-hour
		// local day), so the month is 721 hours — not a flat 30×24. Facts on
		// the DST day from all five slices reconcile with the CSV TOTAL
		// identity intact.
		period, err := budget.MonthReportPeriod("2026-11", "America/New_York")
		require.NoError(t, err)
		if got := period.To.Sub(period.From); got != 721*time.Hour {
			t.Errorf("DST month length = %v, want 721h (30×24 + fall-back hour)", got)
		}
		if buckets := period.DayBuckets(); len(buckets) != 30 || buckets[0] != "2026-11-01" {
			t.Errorf("day buckets = %d entries, first %q", len(buckets), buckets[0])
		}

		loc, err := budget.ResolveReportZone("America/New_York")
		require.NoError(t, err)
		rep := ReconcileSpend(SpendReconInput{
			OrgID:        "n06p6-t06-mock-dst",
			From:         period.From,
			To:           period.To,
			Zone:         loc,
			UITotalMicro: 2_000_000,
			Usage: []SpendReconUsageDay{
				{Day: "2026-11-01", ConfirmedMicro: 2_000_000, Requests: 2},
			},
			Ledger: []SpendReconLedgerDay{
				{Day: "2026-11-01", WalletMicro: -2_200_000, WalletCentsAppliedMicro: -2_200_000, WalletTxns: 1},
			},
			Invoice: []SpendReconInvoiceDay{
				{Day: "2026-11-01", InvoiceMicro: 2_000_000},
			},
			Settlements: []SpendReconSettlementDay{
				{Day: "2026-11-01", EstimatedMicro: 100_000, EstimatedRequests: 1},
			},
			ReservedOutstandingMicro: 250_000,
			ReservedAllowances:       1,
		})

		if rep.Status != SpendReconStatusOK {
			t.Fatalf("status = %q, want ok (violations: %+v)", rep.Status, rep.Violations)
		}
		if rep.Zone != "America/New_York" || len(rep.Days) != 1 || rep.Days[0].Day != "2026-11-01" {
			t.Fatalf("zone/days = %s/%+v, want America/New_York/[2026-11-01]", rep.Zone, rep.Days)
		}
		if rep.WalletGapMicro != -200_000 {
			t.Errorf("wallet gap = %d, want -200000 (named components)", rep.WalletGapMicro)
		}
		// The estimated dimension never leaks into the settled surfaces.
		if rep.CapturedMicro != 2_000_000 || rep.EstimatedTotalMicro != 100_000 {
			t.Errorf("captured/estimated = %d/%d, want 2000000/100000", rep.CapturedMicro, rep.EstimatedTotalMicro)
		}
		n06p6t05AssertDetailSumsToTotals(t, rep)
	})

	t.Run("caller_bug_out_of_window_rows_fail_closed", func(t *testing.T) {
		// MOCK-only edge (documented real/mock split): the real reader windows
		// every fact in SQL, so an out-of-window day row can only come from a
		// caller bug. With ALL five fact slices populated, the core fails
		// closed: both rows are violations, excluded from every total and
		// from the day rows, and the CSV TOTAL identity still holds.
		in := n06p6t04SettlementInput()
		in.Usage = append(in.Usage, SpendReconUsageDay{Day: "2026-08-15", ConfirmedMicro: 999_999, Requests: 1})
		in.Ledger = append(in.Ledger, SpendReconLedgerDay{
			Day: "2026-08-20", WalletMicro: -500_000, WalletCentsAppliedMicro: -500_000, WalletTxns: 1,
		})

		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation", rep.Status)
		}
		if spendReconFindViolation(rep, ViolationDayOutsidePeriod, "2026-08-15") == nil ||
			spendReconFindViolation(rep, ViolationDayOutsidePeriod, "2026-08-20") == nil {
			t.Fatalf("missing day_outside_period violations in %+v", rep.Violations)
		}
		base := ReconcileSpend(n06p6t04SettlementInput())
		if rep.ConfirmedTotalMicro != base.ConfirmedTotalMicro ||
			rep.WalletMicro != base.WalletMicro ||
			rep.EstimatedTotalMicro != base.EstimatedTotalMicro {
			t.Error("out-of-window rows leaked into totals")
		}
		for _, d := range rep.Days {
			if d.Day == "2026-08-15" || d.Day == "2026-08-20" {
				t.Errorf("out-of-window day %q produced a day row", d.Day)
			}
		}
		n06p6t05AssertDetailSumsToTotals(t, rep)
	})

	t.Run("joint_cents_rounding_once_per_row", func(t *testing.T) {
		// The acceptance's "итоги и округлением" on one composed state: odd
		// confirmed, captured and wallet amounts in the SAME report. Each
		// detail row's cents are the half-away projection rounded ONCE PER
		// ROW; the TOTAL cents column is the sum of the row cents (1002),
		// which here deliberately differs from the cents of the summed
		// micro (1001) — the export never re-rounds the period.
		in := SpendReconInput{
			OrgID:        "n06p6-t06-mock-rounding",
			From:         timeUTC(2026, time.September, 1),
			To:           timeUTC(2026, time.September, 3),
			UITotalMicro: 10_010_000,
			Usage: []SpendReconUsageDay{
				{Day: "2026-09-01", ConfirmedMicro: 5_005_000, Requests: 1, ShadowMicro: 55_000},
				{Day: "2026-09-02", ConfirmedMicro: 5_005_000, Requests: 1, ShadowMicro: 55_000},
			},
			Ledger: []SpendReconLedgerDay{
				{Day: "2026-09-01", WalletMicro: -5_005_000, WalletCentsAppliedMicro: -5_010_000, WalletTxns: 1},
				{Day: "2026-09-02", WalletMicro: -5_005_000, WalletCentsAppliedMicro: -5_010_000, WalletTxns: 1},
			},
			Invoice: []SpendReconInvoiceDay{
				{Day: "2026-09-01", InvoiceMicro: 5_060_000},
				{Day: "2026-09-02", InvoiceMicro: 5_060_000},
			},
		}

		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusOK {
			t.Fatalf("status = %q, want ok (violations: %+v)", rep.Status, rep.Violations)
		}
		if money.MicroUSD(5_005_000).Cents() != 501 || money.MicroUSD(10_010_000).Cents() != 1001 {
			t.Fatalf("cents projection precondition broke: %d/%d, want 501/1001",
				money.MicroUSD(5_005_000).Cents(), money.MicroUSD(10_010_000).Cents())
		}
		// Wallet: the sub-cent carry of both days inside the declared bound.
		if rep.WalletRoundingDeltaMicro != -10_000 || rep.LedgerRoundingBoundMicro != 30_000 {
			t.Errorf("wallet rounding delta/bound = %d/%d, want -10000/30000",
				rep.WalletRoundingDeltaMicro, rep.LedgerRoundingBoundMicro)
		}

		recs := spendReconExportRecords(t, rep)
		if got := recs[1][12] + "/" + recs[2][12] + "/" + recs[3][12]; got != "501/501/1002" {
			t.Errorf("confirmed cents rows = %s, want 501/501/1002 (Σ rows, NOT cents(Σ micro)=1001)", got)
		}
		// Captured ($5.06/day): 506 + 506 = 1012 cents, Σ rows again.
		if got := recs[1][13] + "/" + recs[2][13] + "/" + recs[3][13]; got != "506/506/1012" {
			t.Errorf("captured cents rows = %s, want 506/506/1012", got)
		}
		n06p6t05AssertDetailSumsToTotals(t, rep)
	})
}
