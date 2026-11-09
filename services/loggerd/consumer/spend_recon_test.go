package consumer

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func spendReconTestPeriod() (time.Time, time.Time) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return from, from.AddDate(0, 0, 2)
}

func spendReconHappyInput() SpendReconInput {
	from, to := spendReconTestPeriod()
	// Day 1: $1.50 confirmed; Day 2: $2.25 confirmed + $0.10 shadow.
	// Wallet: −$3.00 across two days (exact micro, in-bound rounding).
	// Invoice: $3.85 = captured (1.50 + 2.25 + 0.10) exactly.
	return SpendReconInput{
		OrgID:        "11111111-1111-1111-1111-111111111111",
		From:         from,
		To:           to,
		UITotalMicro: 3_750_000,
		Usage: []SpendReconUsageDay{
			{Day: "2026-09-01", ConfirmedMicro: 1_500_000, Requests: 3},
			{Day: "2026-09-02", ConfirmedMicro: 2_250_000, Requests: 4, ShadowMicro: 100_000},
		},
		Ledger: []SpendReconLedgerDay{
			{Day: "2026-09-01", WalletMicro: -1_200_000, WalletCentsAppliedMicro: -1_200_000, WalletTxns: 1},
			{Day: "2026-09-02", WalletMicro: -1_800_000, WalletCentsAppliedMicro: -1_800_000, WalletTxns: 1},
		},
		Invoice: []SpendReconInvoiceDay{
			{Day: "2026-09-01", InvoiceMicro: 1_500_000},
			{Day: "2026-09-02", InvoiceMicro: 2_350_000},
		},
		UsagePricingAsOf: "openrouter@2026-09-01",
		InvoiceLabel:     "provider-invoice-2026-09",
		// Provider-side rounding/timing tolerance; late-arriving usage under
		// half a cent-dollar stays a reportable non-violation.
		InvoiceToleranceMicro: 500_000,
	}
}

func TestReconcileSpendDetailMatchesUITotal(t *testing.T) {
	rep := ReconcileSpend(spendReconHappyInput())

	if rep.Status != SpendReconStatusOK {
		t.Fatalf("status = %q, want ok (violations: %+v)", rep.Status, rep.Violations)
	}
	if rep.ConfirmedTotalMicro != 3_750_000 {
		t.Errorf("confirmed total = %d, want 3750000", rep.ConfirmedTotalMicro)
	}
	if rep.UITotalMicro != rep.ConfirmedTotalMicro+rep.UnpricedTotalMicro {
		t.Errorf("ui parity broken: %d != %d + %d", rep.UITotalMicro, rep.ConfirmedTotalMicro, rep.UnpricedTotalMicro)
	}
	if rep.CapturedMicro != 3_850_000 {
		t.Errorf("captured = %d, want 3850000 (shadow included)", rep.CapturedMicro)
	}
	if rep.InvoiceDeltaMicro != 0 || rep.CaptureRatePct != 100 {
		t.Errorf("invoice tie: delta=%d capture=%.2f, want 0/100", rep.InvoiceDeltaMicro, rep.CaptureRatePct)
	}
	if rep.WalletMicro != -3_000_000 {
		t.Errorf("wallet = %d, want -3000000", rep.WalletMicro)
	}
	if rep.WalletGapMicro != 750_000 {
		t.Errorf("wallet gap = %d, want 750000 (resale > base by design)", rep.WalletGapMicro)
	}
	if len(rep.Days) != 2 {
		t.Fatalf("days = %d, want 2", len(rep.Days))
	}
	if len(rep.Violations) != 0 {
		t.Errorf("violations = %+v, want none", rep.Violations)
	}
	if len(rep.Limitations) == 0 {
		t.Error("limitations must always be present")
	}
}

func TestReconcileSpendUITotalMismatchFlagged(t *testing.T) {
	in := spendReconHappyInput()
	in.UITotalMicro = 3_750_001 // boundary/status drift

	rep := ReconcileSpend(in)
	if rep.Status != SpendReconStatusViolation {
		t.Fatalf("status = %q, want violation", rep.Status)
	}
	found := false
	for _, v := range rep.Violations {
		if v.Code == ViolationUITotalMismatch {
			found = true
		}
	}
	if !found {
		t.Errorf("violations %+v missing %s", rep.Violations, ViolationUITotalMismatch)
	}
}

func TestReconcileSpendUnpricedNonzeroNotMixedIntoConfirmed(t *testing.T) {
	in := spendReconHappyInput()
	// A future cost_status regression: unknown_price rows carrying cost.
	in.Usage[1].UnpricedMicro = 42_000
	in.Usage[1].UnpricedRequests = 2
	in.UITotalMicro = 3_750_000 + 42_000 // parity total includes it

	rep := ReconcileSpend(in)
	if rep.Status != SpendReconStatusViolation {
		t.Fatalf("status = %q, want violation", rep.Status)
	}
	if rep.ConfirmedTotalMicro != 3_750_000 {
		t.Errorf("confirmed = %d, want 3750000 (unpriced cost must not mix into confirmed)", rep.ConfirmedTotalMicro)
	}
	if rep.UnpricedTotalMicro != 42_000 || rep.UnpricedRequests != 2 {
		t.Errorf("unpriced = %d/%d, want 42000/2 (visible, never dollars-zeroed)", rep.UnpricedTotalMicro, rep.UnpricedRequests)
	}
	day2 := rep.Days[1]
	if len(day2.Flags) == 0 {
		t.Fatalf("day2 flags empty, want %s", ViolationUnpricedNonzero)
	}
	if day2.Flags[0] != ViolationUnpricedNonzero {
		t.Errorf("day2 flag = %q, want %s", day2.Flags[0], ViolationUnpricedNonzero)
	}
}

func TestReconcileSpendLateEventAppendsWithoutRewritingHistory(t *testing.T) {
	in := spendReconHappyInput()
	snapshotUsage := append([]SpendReconUsageDay(nil), in.Usage...)
	snapshotLedger := append([]SpendReconLedgerDay(nil), in.Ledger...)
	snapshotInvoice := append([]SpendReconInvoiceDay(nil), in.Invoice...)

	r1 := ReconcileSpend(in)

	// The core must never mutate its inputs.
	if !reflect.DeepEqual(in.Usage, snapshotUsage) || !reflect.DeepEqual(in.Ledger, snapshotLedger) ||
		!reflect.DeepEqual(in.Invoice, snapshotInvoice) {
		t.Fatal("ReconcileSpend mutated its input slices")
	}

	// A late-arriving event appends a NEW day of facts (refundless
	// semantics: nothing is ever subtracted from or rewritten in the
	// already-computed history). The recompute covers the old window plus
	// the late day.
	in.To = in.To.AddDate(0, 0, 1)
	in.Usage = append(in.Usage, SpendReconUsageDay{Day: "2026-09-03", ConfirmedMicro: 250_000, Requests: 1})
	in.UITotalMicro += 250_000

	r2 := ReconcileSpend(in)

	// The previously computed day rows must be byte-identical after the
	// recompute; only the appended day and the re-derived totals move.
	if len(r2.Days) != len(r1.Days)+1 {
		t.Fatalf("days = %d, want %d (late event appends a day)", len(r2.Days), len(r1.Days)+1)
	}
	for i := range r1.Days {
		if !reflect.DeepEqual(r2.Days[i], r1.Days[i]) {
			t.Errorf("history rewritten at day %d: %+v vs %+v", i, r2.Days[i], r1.Days[i])
		}
	}
	if r2.Days[len(r1.Days)].ConfirmedMicro != 250_000 {
		t.Errorf("appended day = %d, want 250000", r2.Days[len(r1.Days)].ConfirmedMicro)
	}
	if r2.ConfirmedTotalMicro != r1.ConfirmedTotalMicro+250_000 {
		t.Errorf("total = %d, want r1+250000 (append-only)", r2.ConfirmedTotalMicro)
	}
	if r2.ConfirmedTotalMicro < r1.ConfirmedTotalMicro {
		t.Error("refundless late event must never decrease the confirmed total")
	}
	for _, v := range r2.Violations {
		if v.Code == ViolationUITotalMismatch {
			t.Errorf("late append flagged %s: %+v", v.Code, r2.Violations)
		}
	}
	if r2.Status != SpendReconStatusOK {
		t.Fatalf("status = %q, want ok; violations %+v", r2.Status, r2.Violations)
	}
}

func TestReconcileSpendPriceProvenanceChangeKeepsDollars(t *testing.T) {
	in := spendReconHappyInput()
	r1 := ReconcileSpend(in)

	// The price catalog is later re-published (new provenance). Captured
	// facts are as-of write: dollars must not move, only the label.
	in2 := in
	in2.UsagePricingAsOf = "openrouter@2026-10-20"
	r2 := ReconcileSpend(in2)

	if r2.UsagePricingAsOf != "openrouter@2026-10-20" {
		t.Fatalf("provenance not echoed: %q", r2.UsagePricingAsOf)
	}
	// Compare with labels equalized so any difference is a dollar-field
	// difference (provenance must never enter the arithmetic).
	r1Shifted := r1
	r1Shifted.UsagePricingAsOf = "same"
	r2Shifted := r2
	r2Shifted.UsagePricingAsOf = "same"
	if !reflect.DeepEqual(r1Shifted, r2Shifted) {
		t.Error("price provenance change altered dollar fields")
	}
}

func TestReconcileSpendLedgerRoundingBound(t *testing.T) {
	t.Run("exact", func(t *testing.T) {
		in := spendReconHappyInput()
		rep := ReconcileSpend(in)
		if rep.WalletRoundingDeltaMicro != 0 {
			t.Errorf("rounding delta = %d, want 0", rep.WalletRoundingDeltaMicro)
		}
		// 2 txns → (2+1) cents = 30_000 micro (1 cent = 10 000 micro).
		if rep.LedgerRoundingBoundMicro != 30_000 {
			t.Errorf("bound = %d, want 30000", rep.LedgerRoundingBoundMicro)
		}
	})

	t.Run("within bound", func(t *testing.T) {
		in := spendReconHappyInput()
		// Half a cent of carried remainder across the window.
		in.Ledger[0].WalletCentsAppliedMicro -= 5_000
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusOK {
			t.Errorf("status = %q, want ok; violations %+v", rep.Status, rep.Violations)
		}
		if rep.WalletRoundingDeltaMicro != -5_000 {
			t.Errorf("rounding delta = %d, want -5000", rep.WalletRoundingDeltaMicro)
		}
	})

	t.Run("beyond bound flagged", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Ledger[0].WalletCentsAppliedMicro -= 50_000 // 5 cents off
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation", rep.Status)
		}
		found := false
		for _, v := range rep.Violations {
			if v.Code == ViolationLedgerRounding {
				found = true
			}
		}
		if !found {
			t.Errorf("violations %+v missing %s", rep.Violations, ViolationLedgerRounding)
		}
	})

	t.Run("legacy rows without micro downgrade", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Ledger[0].WalletRowsWithoutMicro = 1
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation", rep.Status)
		}
		if rep.LedgerRoundingBoundMicro != -1 {
			t.Errorf("bound = %d, want -1 (not verifiable)", rep.LedgerRoundingBoundMicro)
		}
		found := false
		for _, v := range rep.Violations {
			if v.Code == ViolationLedgerLegacyNoMicro {
				found = true
			}
		}
		if !found {
			t.Errorf("violations %+v missing %s", rep.Violations, ViolationLedgerLegacyNoMicro)
		}
	})
}

func TestReconcileSpendInvoiceCaptureAndShadow(t *testing.T) {
	t.Run("shadow excluded from ui, included in capture", func(t *testing.T) {
		in := spendReconHappyInput()
		rep := ReconcileSpend(in)
		if rep.UITotalMicro != 3_750_000 {
			t.Errorf("ui total = %d, want 3750000 (shadow never in it)", rep.UITotalMicro)
		}
		if rep.ShadowTotalMicro != 100_000 || rep.CapturedMicro != 3_850_000 {
			t.Errorf("shadow/captured = %d/%d, want 100000/3850000", rep.ShadowTotalMicro, rep.CapturedMicro)
		}
	})

	t.Run("gap beyond tolerance flagged", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Invoice = nil
		in.InvoiceToleranceMicro = 0
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation", rep.Status)
		}
		if rep.InvoiceDeltaMicro != 3_850_000 {
			t.Errorf("delta = %d, want 3850000", rep.InvoiceDeltaMicro)
		}
		if rep.CaptureRatePct != 0 {
			t.Errorf("capture = %.2f, want 0 (nothing invoiced)", rep.CaptureRatePct)
		}
	})

	t.Run("gap within tolerance ok", func(t *testing.T) {
		in := spendReconHappyInput()
		in.InvoiceToleranceMicro = 500_000
		in.Invoice[1].InvoiceMicro -= 400_000 // provider-side rounding/timing
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusOK {
			t.Errorf("status = %q, want ok; violations %+v", rep.Status, rep.Violations)
		}
		if rep.InvoiceDeltaMicro != 400_000 {
			t.Errorf("delta = %d, want 400000", rep.InvoiceDeltaMicro)
		}
	})

	t.Run("empty period capture rate is 100", func(t *testing.T) {
		from, to := spendReconTestPeriod()
		rep := ReconcileSpend(SpendReconInput{From: from, To: to})
		if rep.Status != SpendReconStatusOK {
			t.Fatalf("status = %q, want ok; violations %+v", rep.Status, rep.Violations)
		}
		if rep.CaptureRatePct != 100 {
			t.Errorf("capture = %.2f, want 100 (0/0)", rep.CaptureRatePct)
		}
	})
}

func TestParseInvoiceUSDMicro(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"12.34", 12_340_000, false},
		{"-0.05", -50_000, false},
		{"+3", 3_000_000, false},
		{"0.000001", 1, false},
		{"0.5", 500_000, false},
		{" 7.89 ", 7_890_000, false},
		{"9223372036854.775807", 9_223_372_036_854_775_807, false}, // exact int64 max
		{"", 0, true},
		{"-", 0, true},
		{"+", 0, true},
		{".", 0, true},
		{"1.2345671", 0, true},
		{"abc", 0, true},
		{"1e5", 0, true},
		{"..5", 0, true},
		{"9223372036854.775808", 0, true}, // int64 max + 1 micro: must error, never wrap
		{"9223372036855.0", 0, true},      // integer part alone overflows
		{"-9223372036855.0", 0, true},     // same, negative
	}
	for _, tc := range cases {
		got, err := ParseInvoiceUSDMicro(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseInvoiceUSDMicro(%q) = %d, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseInvoiceUSDMicro(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseInvoiceUSDMicro(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestPgxSpendReconReaderNilPool(t *testing.T) {
	r := NewPgxSpendReconReader(nil)
	ctx := context.Background()
	from, to := spendReconTestPeriod()
	if _, err := r.UsageTotal(ctx, "org", from, to); err == nil {
		t.Error("UsageTotal with nil pool must error")
	}
	if _, err := r.UsageByDay(ctx, "org", from, to, ""); err == nil {
		t.Error("UsageByDay with nil pool must error")
	}
	if _, err := r.LedgerByDay(ctx, "org", from, to, ""); err == nil {
		t.Error("LedgerByDay with nil pool must error")
	}
}

func TestSpendReconRenderTextContainsFacts(t *testing.T) {
	rep := ReconcileSpend(spendReconHappyInput())
	out := rep.RenderText()
	for _, want := range []string{"spend reconciliation", "ok", "captured", "limitation:"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q in:\n%s", want, out)
		}
	}
}

// spendReconFindViolation returns the first violation with exactly the given
// code and day (day "" matches only period-level violations).
func spendReconFindViolation(rep SpendReconReport, code, day string) *SpendReconViolation {
	for i := range rep.Violations {
		v := &rep.Violations[i]
		if v.Code == code && v.Day == day {
			return v
		}
	}
	return nil
}

// TestSpendReconSQLShadowParityContract pins the SQL-level half of the UI
// parity invariant: shadow rows carry cost_in_usd AND cost_status
// (shadowRequestLogRow), so every cost-class expression of the by-day query
// must exclude them exactly like the UI-parity total (GetCostAnalytics
// predicate) — otherwise class sums double-count shadow spend and parity
// fails on any period with shadow usage. The shadow column is the only
// place without the predicate.
func TestSpendReconSQLShadowParityContract(t *testing.T) {
	for name, expr := range map[string]string{
		"confirmed_cost":    spendReconConfirmedExpr,
		"unpriced_cost":     spendReconUnpricedCostExpr,
		"unpriced_requests": spendReconUnpricedCountExpr,
		"legacy_rows":       spendReconLegacyCountExpr,
	} {
		if !strings.Contains(expr, spendReconUIExcludeShadow) {
			t.Errorf("%s class expression lacks the shadow exclusion: %s", name, expr)
		}
		if !strings.Contains(spendReconUsageByDayQuery, expr) {
			t.Errorf("%s class expression missing from the by-day query", name)
		}
	}
	if strings.Contains(spendReconShadowExpr, spendReconUIExcludeShadow) {
		t.Error("shadow expression must count shadow rows (no exclusion predicate)")
	}
	if !strings.Contains(spendReconUsageByDayQuery, spendReconShadowExpr) {
		t.Error("shadow expression missing from the by-day query")
	}
	if !strings.Contains(spendReconUsageTotalQuery, spendReconUIExcludeShadow) {
		t.Errorf("UI-parity total query lacks the shadow exclusion: %s", spendReconUsageTotalQuery)
	}
}

func TestSpendReconDayInWindow(t *testing.T) {
	from := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) // mid-day start
	to := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)    // midnight end (half-open)
	cases := []struct {
		day  string
		want bool
	}{
		{"2026-08-31", false}, // ends exactly at From's midnight — before the window
		{"2026-09-01", true},  // bucket [09-01 00:00, 09-02 00:00) intersects [09-01 12:00, ...)
		{"2026-09-02", true},  // last full day inside
		{"2026-09-03", false}, // starts at To (half-open: excluded)
		{"2026-09-04", false},
	}
	for _, tc := range cases {
		got, err := spendReconDayInWindow(tc.day, from, to, time.UTC)
		if err != nil || got != tc.want {
			t.Errorf("spendReconDayInWindow(%q) = %v, %v; want %v, nil", tc.day, got, err, tc.want)
		}
	}
	if _, err := spendReconDayInWindow("2026-09-31", from, to, time.UTC); err == nil {
		t.Error("unparseable day must error")
	}
	// Zero bounds disable the window clipping entirely.
	for _, day := range []string{"1999-01-01", "2999-12-31"} {
		if got, err := spendReconDayInWindow(day, time.Time{}, time.Time{}, time.UTC); err != nil || !got {
			t.Errorf("zero window must accept %q, got %v, %v", day, got, err)
		}
	}
}

func TestReconcileSpendInvoiceDayOutsidePeriodExcluded(t *testing.T) {
	in := spendReconHappyInput()
	// A late invoice line for a day before the window and one after it:
	// visible as counts, never summed into this period's totals.
	in.Invoice = append(in.Invoice,
		SpendReconInvoiceDay{Day: "2026-08-31", InvoiceMicro: 777_000_000},
		SpendReconInvoiceDay{Day: "2026-09-03", InvoiceMicro: 888_000_000},
	)
	rep := ReconcileSpend(in)
	if rep.InvoiceTotalMicro != 3_850_000 {
		t.Errorf("invoice total = %d, want 3850000 (out-of-period lines excluded)", rep.InvoiceTotalMicro)
	}
	if rep.InvoiceDeltaMicro != 0 {
		t.Errorf("invoice delta = %d, want 0 (out-of-period lines must not distort it)", rep.InvoiceDeltaMicro)
	}
	if rep.InvoiceDaysOutsidePeriod != 2 {
		t.Errorf("outside-period count = %d, want 2 (late invoices stay visible)", rep.InvoiceDaysOutsidePeriod)
	}
	if len(rep.Days) != 2 {
		t.Errorf("days = %d, want 2 (out-of-period days must not appear)", len(rep.Days))
	}
	if rep.Status != SpendReconStatusOK {
		t.Errorf("status = %q, want ok; violations %+v", rep.Status, rep.Violations)
	}
}

func TestReconcileSpendUsageAndLedgerDayOutsidePeriodViolation(t *testing.T) {
	t.Run("usage day beyond To", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Usage = append(in.Usage, SpendReconUsageDay{Day: "2026-09-09", ConfirmedMicro: 1_000_000, Requests: 1})
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation", rep.Status)
		}
		if spendReconFindViolation(rep, ViolationDayOutsidePeriod, "2026-09-09") == nil {
			t.Errorf("violations %+v missing %s for 2026-09-09", rep.Violations, ViolationDayOutsidePeriod)
		}
		if rep.ConfirmedTotalMicro != 3_750_000 {
			t.Errorf("confirmed = %d, want 3850000−1000000=3750000 (out-of-window row excluded)", rep.ConfirmedTotalMicro)
		}
		if rep.UITotalMicro != rep.ConfirmedTotalMicro+rep.UnpricedTotalMicro {
			t.Error("parity must hold over the in-window rows only")
		}
	})
	t.Run("ledger day before From", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Ledger = append(in.Ledger, SpendReconLedgerDay{Day: "2026-08-30", WalletMicro: -5_000_000, WalletCentsAppliedMicro: -5_000_000, WalletTxns: 1})
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation", rep.Status)
		}
		if spendReconFindViolation(rep, ViolationDayOutsidePeriod, "2026-08-30") == nil {
			t.Errorf("violations %+v missing %s for 2026-08-30", rep.Violations, ViolationDayOutsidePeriod)
		}
		if rep.WalletMicro != -3_000_000 {
			t.Errorf("wallet = %d, want -3000000 (out-of-window row excluded)", rep.WalletMicro)
		}
	})
	t.Run("unparseable invoice day", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Invoice = append(in.Invoice, SpendReconInvoiceDay{Day: "09/09/2026", InvoiceMicro: 1})
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation", rep.Status)
		}
		if spendReconFindViolation(rep, ViolationDayOutsidePeriod, "09/09/2026") == nil {
			t.Errorf("violations %+v missing %s for unparseable day", rep.Violations, ViolationDayOutsidePeriod)
		}
		if rep.InvoiceDaysOutsidePeriod != 0 {
			t.Errorf("outside-period count = %d, want 0 (unparseable is a violation, not a count)", rep.InvoiceDaysOutsidePeriod)
		}
	})
}

func TestReconcileSpendDuplicateDayRowsFlagged(t *testing.T) {
	t.Run("usage duplicate flagged, last wins", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Usage = append(in.Usage, SpendReconUsageDay{Day: "2026-09-01", ConfirmedMicro: 9_999_999, Requests: 1})
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation", rep.Status)
		}
		if spendReconFindViolation(rep, ViolationDuplicateDayRows, "2026-09-01") == nil {
			t.Errorf("violations %+v missing %s", rep.Violations, ViolationDuplicateDayRows)
		}
		if len(rep.Days) != 2 {
			t.Errorf("days = %d, want 2 (duplicate collapses, never double-counts)", len(rep.Days))
		}
	})
	t.Run("ledger duplicate flagged", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Ledger = append(in.Ledger, in.Ledger[0])
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation", rep.Status)
		}
		if spendReconFindViolation(rep, ViolationDuplicateDayRows, "2026-09-01") == nil {
			t.Errorf("violations %+v missing %s", rep.Violations, ViolationDuplicateDayRows)
		}
	})
	t.Run("invoice lines same day accumulate without violation", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Invoice = append(in.Invoice, SpendReconInvoiceDay{Day: "2026-09-01", InvoiceMicro: 500_000})
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusOK {
			t.Fatalf("status = %q, want ok (multiple invoice lines per day are the CSV shape); violations %+v", rep.Status, rep.Violations)
		}
		if rep.InvoiceTotalMicro != 4_350_000 {
			t.Errorf("invoice total = %d, want 4350000 (lines accumulated)", rep.InvoiceTotalMicro)
		}
	})
}

// TestReconcileSpendDayInvoiceGapNotMaskedByCancellation pins the day-level
// tolerance: two single-day capture failures with offsetting signs cancel in
// the period total, and only the day-level check keeps the report a
// violation.
func TestReconcileSpendDayInvoiceGapNotMaskedByCancellation(t *testing.T) {
	in := spendReconHappyInput()
	in.InvoiceToleranceMicro = 500_000
	in.Invoice[0].InvoiceMicro -= 600_000 // day 1 under-billed
	in.Invoice[1].InvoiceMicro += 600_000 // day 2 over-billed; period nets to 0
	rep := ReconcileSpend(in)
	if rep.InvoiceDeltaMicro != 0 {
		t.Fatalf("period delta = %d, want 0 (offsets cancel)", rep.InvoiceDeltaMicro)
	}
	if rep.Status != SpendReconStatusViolation {
		t.Fatalf("status = %q, want violation (cancellation must not mask day gaps)", rep.Status)
	}
	if spendReconFindViolation(rep, ViolationInvoiceGapExceeded, "2026-09-01") == nil ||
		spendReconFindViolation(rep, ViolationInvoiceGapExceeded, "2026-09-02") == nil {
		t.Errorf("violations %+v missing day-level %s", rep.Violations, ViolationInvoiceGapExceeded)
	}
	if v := spendReconFindViolation(rep, ViolationInvoiceGapExceeded, ""); v != nil {
		t.Errorf("period-level %s must not fire when the total is within tolerance: %+v", ViolationInvoiceGapExceeded, rep.Violations)
	}
	if rep.Days[0].Flags == nil || rep.Days[0].Flags[0] != ViolationInvoiceGapExceeded {
		t.Errorf("day1 flags = %v, want %s", rep.Days[0].Flags, ViolationInvoiceGapExceeded)
	}
}

func TestReconcileSpendInvoiceToleranceBoundary(t *testing.T) {
	t.Run("period delta exactly at tolerance is ok", func(t *testing.T) {
		in := spendReconHappyInput()
		in.InvoiceToleranceMicro = 500_000
		in.Invoice[1].InvoiceMicro -= 500_000
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusOK {
			t.Errorf("status = %q, want ok (delta == tolerance); violations %+v", rep.Status, rep.Violations)
		}
	})
	t.Run("period delta tolerance+1 is violation", func(t *testing.T) {
		in := spendReconHappyInput()
		in.InvoiceToleranceMicro = 500_000
		in.Invoice[1].InvoiceMicro -= 500_001
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Errorf("status = %q, want violation (delta == tolerance+1)", rep.Status)
		}
	})
	t.Run("day delta exactly at tolerance is ok", func(t *testing.T) {
		in := spendReconHappyInput()
		in.InvoiceToleranceMicro = 500_000
		in.Invoice[0].InvoiceMicro -= 500_000
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusOK {
			t.Errorf("status = %q, want ok (day delta == tolerance); violations %+v", rep.Status, rep.Violations)
		}
	})
	t.Run("day delta tolerance+1 is violation", func(t *testing.T) {
		in := spendReconHappyInput()
		in.InvoiceToleranceMicro = 500_000
		in.Invoice[0].InvoiceMicro -= 500_001
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Errorf("status = %q, want violation (day delta == tolerance+1)", rep.Status)
		}
	})
	t.Run("negative tolerance clamped, perfect tie stays ok", func(t *testing.T) {
		in := spendReconHappyInput()
		in.InvoiceToleranceMicro = -1
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusOK {
			t.Errorf("status = %q, want ok (negative tolerance clamped to exact); violations %+v", rep.Status, rep.Violations)
		}
	})
}

func TestReconcileSpendRoundingBoundBoundary(t *testing.T) {
	cases := []struct {
		name  string
		delta int64 // WalletRoundingDeltaMicro induced on day 1 (2 txns ⇒ bound 30 000)
		want  string
	}{
		{"at positive bound", 30_000, SpendReconStatusOK},
		{"positive bound+1", 30_001, SpendReconStatusViolation},
		{"at negative bound", -30_000, SpendReconStatusOK},
		{"negative bound−1", -30_001, SpendReconStatusViolation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := spendReconHappyInput()
			in.Ledger[0].WalletCentsAppliedMicro += tc.delta
			rep := ReconcileSpend(in)
			if rep.Status != tc.want {
				t.Errorf("status = %q, want %q (rounding delta %d, bound %d); violations %+v",
					rep.Status, tc.want, rep.WalletRoundingDeltaMicro, rep.LedgerRoundingBoundMicro, rep.Violations)
			}
		})
	}
}
