package consumer

// N06-P06-T05 — negative-path proof for the spend reporting area (packet
// N06-P06 "Расходы отчётность и сверка"). Card negative: "Late event
// refundless semantics и смена цены не переписывают историю"; acceptance:
// "Сумма детализации совпадает с итогами и округлением"; stage acceptance:
// the negative scenario has an observable outcome and a regression, and the
// error is not hidden.
//
// The battery pins FAIL-CLOSED behavior of ReconcileSpend and its export:
//
//   - empty inputs invent nothing (no fabricated day rows, no fake money);
//   - malformed fact day labels, degenerate (inverted/empty) windows and
//     out-of-window rows raise violations, are excluded from every total,
//     and never break the Σ detail == TOTAL identity;
//   - a late event appends without rewriting any previously emitted day row
//     or exported byte — even when the same recompute carries violations
//     (refundless semantics: history is never compensated or restated);
//   - a price-provenance change rewrites nothing, not even in a violation
//     state (dollars, CSV bytes and the violation set stay put);
//   - the unreleased-allowance reservation snapshot is echoed exactly and
//     never folds into any settled total, day row or exported column
//     (settled-but-not-released overlaps stay visible on both surfaces, no
//     silent netting).
//
// Companion of T04 (positives, n06p6t04_*); T02/T03 own the settled
// surfaces and the timezone contract.

import (
	"bytes"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// n06p6t05AssertDetailSumsToTotals pins the acceptance criterion in ANY
// state (clean or violation): the exported TOTAL row is the exact Σ of the
// emitted detail rows in every numeric column. Excluded/malformed rows must
// disappear from BOTH sides of that identity — an error surfaced as a
// violation must never leave the arithmetic inconsistent.
func n06p6t05AssertDetailSumsToTotals(t *testing.T, rep SpendReconReport) {
	t.Helper()
	recs := spendReconExportRecords(t, rep)
	details := recs[1 : len(recs)-1]
	total := recs[len(recs)-1]
	for j := 1; j < len(spendReconCSVColumns)-1; j++ {
		var sum int64
		for _, d := range details {
			v, err := strconv.ParseInt(d[j], 10, 64)
			if err != nil {
				t.Fatalf("detail col %s = %q: %v", spendReconCSVColumns[j], d[j], err)
			}
			sum += v
		}
		got, err := strconv.ParseInt(total[j], 10, 64)
		if err != nil {
			t.Fatalf("TOTAL col %s = %q: %v", spendReconCSVColumns[j], total[j], err)
		}
		if sum != got {
			t.Errorf("TOTAL %s = %d, want Σ details %d (detail/total identity broken in state %q)",
				spendReconCSVColumns[j], got, sum, rep.Status)
		}
	}
}

// n06p6t05AssertNoDayRow asserts the report carries no day row (and no day
// whose label is not a strict YYYY-MM-DD calendar day): malformed or
// out-of-window facts must never be re-bucketed into a fabricated row.
func n06p6t05AssertNoDayRow(t *testing.T, rep SpendReconReport, forbidden string) {
	t.Helper()
	for _, d := range rep.Days {
		if d.Day == forbidden {
			t.Errorf("report fabricated day row %q from a rejected fact", forbidden)
		}
		if _, err := time.Parse("2006-01-02", d.Day); err != nil {
			t.Errorf("day label %q is not a calendar day bucket: %v", d.Day, err)
		}
	}
}

// TestN06P6T05EmptyInputsInventNothing: a report over no facts at all is a
// valid zero report — status ok, zero totals, no day rows, no violations,
// a renderable summary — and a nil vs empty settlement feed yields exactly
// the same report (the optional T04 dimension cannot fork the surface).
func TestN06P6T05EmptyInputsInventNothing(t *testing.T) {
	rep := ReconcileSpend(SpendReconInput{})
	if rep.Status != SpendReconStatusOK {
		t.Fatalf("status = %q, want ok; violations %+v", rep.Status, rep.Violations)
	}
	if len(rep.Days) != 0 {
		t.Errorf("empty input produced day rows %+v (invented facts)", rep.Days)
	}
	if len(rep.Violations) != 0 {
		t.Errorf("empty input produced violations %+v", rep.Violations)
	}
	for name, v := range map[string]int64{
		"confirmed":        rep.ConfirmedTotalMicro,
		"unpriced":         rep.UnpricedTotalMicro,
		"captured":         rep.CapturedMicro,
		"invoice":          rep.InvoiceTotalMicro,
		"wallet":           rep.WalletMicro,
		"estimated":        rep.EstimatedTotalMicro,
		"unresolved micro": rep.UnresolvedPriceTotalMicro,
		"unresolved rows":  rep.UnresolvedPriceRows,
		"reserved":         rep.ReservedOutstandingMicro,
	} {
		if v != 0 {
			t.Errorf("empty input invented %s = %d", name, v)
		}
	}
	if rep.CaptureRatePct != 100 {
		t.Errorf("capture rate = %.2f, want 100 (0/0)", rep.CaptureRatePct)
	}
	out := rep.RenderText()
	if !strings.Contains(out, "ok") || !strings.Contains(out, "limitation:") {
		t.Errorf("empty report render must stay operator-readable:\n%s", out)
	}
	if strings.Contains(out, "\n  reserved ") {
		t.Errorf("zero snapshot must not render a reserved line:\n%s", out)
	}
	n06p6t05AssertDetailSumsToTotals(t, rep) // header + zero TOTAL

	// nil vs empty settlement feed: identical reports, field for field
	// (checked on an input that carries no settlement facts, so the nil
	// slice is the only difference).
	nilFeed := ReconcileSpend(spendReconHappyInput())
	emptyFeed := spendReconHappyInput()
	emptyFeed.Settlements = []SpendReconSettlementDay{}
	if diff := cmp.Diff(nilFeed, ReconcileSpend(emptyFeed)); diff != "" {
		t.Errorf("nil vs empty settlement feed changed the report (-nil +empty):\n%s", diff)
	}
}

// TestN06P6T05MalformedFactDayLabelsFailClosed: a fact row whose day label
// cannot be parsed as a calendar day of the report zone is a violation and
// its amounts are excluded from every total — for ALL FOUR fact slices. The
// error stays visible (status violation, per-row violation carrying the raw
// label), no day row is fabricated from the malformed label, and the
// detail/total identity survives (fail-closed: the report is wrong-ish and
// says so, but its numbers stay trustworthy). Regression for the invoice
// path, which used to flag the malformed line AND still sum it into
// InvoiceTotalMicro under the bogus label.
func TestN06P6T05MalformedFactDayLabelsFailClosed(t *testing.T) {
	t.Run("usage", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Usage = append(in.Usage,
			SpendReconUsageDay{Day: "2026-9-1", ConfirmedMicro: 5_000_000, Requests: 9}, // not zero-padded
			SpendReconUsageDay{Day: "", ConfirmedMicro: 6_000_000, Requests: 9},         // empty label
		)
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation; violations %+v", rep.Status, rep.Violations)
		}
		if spendReconFindViolation(rep, ViolationDayOutsidePeriod, "2026-9-1") == nil ||
			spendReconFindViolation(rep, ViolationDayOutsidePeriod, "") == nil {
			t.Errorf("violations %+v missing day_outside_period for both malformed labels", rep.Violations)
		}
		if rep.ConfirmedTotalMicro != 3_750_000 {
			t.Errorf("confirmed = %d, want 3750000 (malformed rows excluded)", rep.ConfirmedTotalMicro)
		}
		if rep.UITotalMicro != rep.ConfirmedTotalMicro+rep.UnpricedTotalMicro {
			t.Error("parity must hold over the in-window rows only")
		}
		n06p6t05AssertNoDayRow(t, rep, "2026-9-1")
		n06p6t05AssertDetailSumsToTotals(t, rep)
	})

	t.Run("ledger", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Ledger = append(in.Ledger,
			SpendReconLedgerDay{Day: "2026-13-01", WalletMicro: -7_000_000, WalletCentsAppliedMicro: -7_000_000, WalletTxns: 1},
		)
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation; violations %+v", rep.Status, rep.Violations)
		}
		if spendReconFindViolation(rep, ViolationDayOutsidePeriod, "2026-13-01") == nil {
			t.Errorf("violations %+v missing day_outside_period for 2026-13-01", rep.Violations)
		}
		if rep.WalletMicro != -3_000_000 {
			t.Errorf("wallet = %d, want -3000000 (malformed row excluded)", rep.WalletMicro)
		}
		n06p6t05AssertNoDayRow(t, rep, "2026-13-01")
		n06p6t05AssertDetailSumsToTotals(t, rep)
	})

	t.Run("settlements", func(t *testing.T) {
		in := n06p6t04SettlementInput()
		in.Settlements = append(in.Settlements,
			SpendReconSettlementDay{Day: "2026/09/01", EstimatedMicro: 8_000_000, EstimatedRequests: 7},
		)
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation; violations %+v", rep.Status, rep.Violations)
		}
		if spendReconFindViolation(rep, ViolationDayOutsidePeriod, "2026/09/01") == nil {
			t.Errorf("violations %+v missing day_outside_period for 2026/09/01", rep.Violations)
		}
		if rep.EstimatedTotalMicro != 650_000 || rep.EstimatedRequests != 3 {
			t.Errorf("estimated = %d/%d, want 650000/3 (malformed row excluded)",
				rep.EstimatedTotalMicro, rep.EstimatedRequests)
		}
		n06p6t05AssertNoDayRow(t, rep, "2026/09/01")
		n06p6t05AssertDetailSumsToTotals(t, rep)
	})

	t.Run("invoice excluded from totals, not summed under the bogus label", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Invoice = append(in.Invoice,
			SpendReconInvoiceDay{Day: "07/04/2026", InvoiceMicro: 123_000_000},
			SpendReconInvoiceDay{Day: "2026-02-30", InvoiceMicro: 321_000_000},
		)
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation; violations %+v", rep.Status, rep.Violations)
		}
		if spendReconFindViolation(rep, ViolationDayOutsidePeriod, "07/04/2026") == nil ||
			spendReconFindViolation(rep, ViolationDayOutsidePeriod, "2026-02-30") == nil {
			t.Errorf("violations %+v missing day_outside_period for the malformed invoice labels", rep.Violations)
		}
		if rep.InvoiceTotalMicro != 3_850_000 {
			t.Errorf("invoice total = %d, want 3850000 (malformed lines must not be summed)", rep.InvoiceTotalMicro)
		}
		if rep.InvoiceDeltaMicro != 0 || rep.CaptureRatePct != 100 {
			t.Errorf("invoice delta/capture = %d/%.2f, want 0/100 (malformed lines must not distort the delta)",
				rep.InvoiceDeltaMicro, rep.CaptureRatePct)
		}
		if rep.InvoiceDaysOutsidePeriod != 0 {
			t.Errorf("outside-period count = %d, want 0 (unparseable is a violation, never a count)", rep.InvoiceDaysOutsidePeriod)
		}
		if len(rep.Days) != 2 {
			t.Errorf("days = %d, want 2 (no fabricated rows from malformed labels)", len(rep.Days))
		}
		n06p6t05AssertNoDayRow(t, rep, "07/04/2026")
		n06p6t05AssertDetailSumsToTotals(t, rep)
	})
}

// TestN06P6T05DegenerateWindowsFailClosed: an inverted (from > to) or empty
// (from == to) window is a caller/producer disagreement, not a quiet empty
// period — every fact row is rejected with a violation, totals stay zero,
// and no row is silently absorbed.
func TestN06P6T05DegenerateWindowsFailClosed(t *testing.T) {
	t.Run("inverted window", func(t *testing.T) {
		in := spendReconHappyInput()
		in.From = timeUTC(2026, 9, 3) // after To: every row is outside
		in.To = timeUTC(2026, 9, 1)
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation; violations %+v", rep.Status, rep.Violations)
		}
		if spendReconFindViolation(rep, ViolationDayOutsidePeriod, "2026-09-01") == nil ||
			spendReconFindViolation(rep, ViolationDayOutsidePeriod, "2026-09-02") == nil {
			t.Errorf("violations %+v missing day_outside_period for the in-input days", rep.Violations)
		}
		if rep.ConfirmedTotalMicro != 0 || rep.WalletMicro != 0 || rep.InvoiceTotalMicro != 0 {
			t.Errorf("totals confirmed/wallet/invoice = %d/%d/%d, want 0/0/0 (nothing fits the window)",
				rep.ConfirmedTotalMicro, rep.WalletMicro, rep.InvoiceTotalMicro)
		}
		if rep.InvoiceDaysOutsidePeriod != 2 {
			t.Errorf("invoice outside-period count = %d, want 2", rep.InvoiceDaysOutsidePeriod)
		}
		if len(rep.Days) != 0 {
			t.Errorf("days = %+v, want none", rep.Days)
		}
		n06p6t05AssertDetailSumsToTotals(t, rep)
	})

	t.Run("empty window", func(t *testing.T) {
		in := spendReconHappyInput()
		in.From = timeUTC(2026, 9, 2)
		in.To = timeUTC(2026, 9, 2) // zero-length: nothing can be inside
		rep := ReconcileSpend(in)
		if rep.Status != SpendReconStatusViolation {
			t.Fatalf("status = %q, want violation (empty window is a disagreement, not an ok period); violations %+v",
				rep.Status, rep.Violations)
		}
		if rep.ConfirmedTotalMicro != 0 || len(rep.Days) != 0 {
			t.Errorf("confirmed/days = %d/%d, want 0/0", rep.ConfirmedTotalMicro, len(rep.Days))
		}
		n06p6t05AssertDetailSumsToTotals(t, rep)
	})
}

// TestN06P6T05LateEventWithViolationsNeverRewritesHistory: the card's
// negative, in its hardest form — one recompute that BOTH appends valid
// late facts AND carries rejected facts (an out-of-window settlement day, a
// malformed invoice line). The valid late day appends (refundless: nothing
// anywhere is subtracted or restated), every previously emitted day row and
// exported byte stays identical, totals grow by exactly the valid late
// amounts, and the rejected facts are visible as violations without leaking
// into any number.
func TestN06P6T05LateEventWithViolationsNeverRewritesHistory(t *testing.T) {
	in1 := n06p6t04SettlementInput()
	r1 := ReconcileSpend(in1)
	if r1.Status != SpendReconStatusOK {
		t.Fatalf("r1 status = %q, want ok; violations %+v", r1.Status, r1.Violations)
	}

	in2 := n06p6t04SettlementInput()
	in2.To = in2.To.AddDate(0, 0, 1) // operator widens the period by one day
	in2.Usage = append(in2.Usage, SpendReconUsageDay{Day: "2026-09-03", ConfirmedMicro: 250_000, Requests: 1})
	in2.UITotalMicro += 250_000
	in2.Settlements = append(in2.Settlements,
		SpendReconSettlementDay{Day: "2026-09-03", EstimatedMicro: 125_000, EstimatedRequests: 1}, // valid late event
		SpendReconSettlementDay{Day: "2026-09-15", EstimatedMicro: 9_000, EstimatedRequests: 1},   // still outside
	)
	in2.Invoice = append(in2.Invoice, SpendReconInvoiceDay{Day: "07/04/2026", InvoiceMicro: 123_000_000}) // malformed
	r2 := ReconcileSpend(in2)

	if r2.Status != SpendReconStatusViolation {
		t.Fatalf("r2 status = %q, want violation (both rejected facts must surface)", r2.Status)
	}
	if spendReconFindViolation(r2, ViolationDayOutsidePeriod, "2026-09-15") == nil ||
		spendReconFindViolation(r2, ViolationDayOutsidePeriod, "07/04/2026") == nil {
		t.Errorf("r2 violations %+v missing the two rejected-fact violations", r2.Violations)
	}

	// History: every prior day row byte-identical; exactly one new row.
	if len(r2.Days) != len(r1.Days)+1 {
		t.Fatalf("days %d -> %d, want +1", len(r1.Days), len(r2.Days))
	}
	for i := range r1.Days {
		if !reflect.DeepEqual(r2.Days[i], r1.Days[i]) {
			t.Errorf("history rewritten at day %d:\nold %+v\nnew %+v", i, r1.Days[i], r2.Days[i])
		}
	}
	appended := r2.Days[len(r1.Days)]
	if appended.Day != "2026-09-03" || appended.ConfirmedMicro != 250_000 || appended.EstimatedMicro != 125_000 {
		t.Errorf("appended day = %+v, want 2026-09-03 confirmed 250000 estimated 125000", appended)
	}

	// Refundless: totals grow exactly by the valid late amounts; rejected
	// amounts appear nowhere.
	if r2.ConfirmedTotalMicro != r1.ConfirmedTotalMicro+250_000 {
		t.Errorf("confirmed %d -> %d, want +250000", r1.ConfirmedTotalMicro, r2.ConfirmedTotalMicro)
	}
	if r2.EstimatedTotalMicro != r1.EstimatedTotalMicro+125_000 || r2.EstimatedRequests != r1.EstimatedRequests+1 {
		t.Errorf("estimated %d/%d -> %d/%d, want +125000/+1 (2026-09-15 excluded)",
			r1.EstimatedTotalMicro, r1.EstimatedRequests, r2.EstimatedTotalMicro, r2.EstimatedRequests)
	}
	if r2.InvoiceTotalMicro != r1.InvoiceTotalMicro {
		t.Errorf("invoice total %d -> %d, want unchanged (malformed line must not leak in)",
			r1.InvoiceTotalMicro, r2.InvoiceTotalMicro)
	}
	if r2.InvoiceDaysOutsidePeriod != 0 {
		t.Errorf("invoice outside count = %d, want 0 (malformed is a violation, not a count)", r2.InvoiceDaysOutsidePeriod)
	}
	if r2.UITotalMicro != r2.ConfirmedTotalMicro+r2.UnpricedTotalMicro {
		t.Error("parity must keep holding over the in-window rows")
	}
	n06p6t05AssertNoDayRow(t, r2, "07/04/2026")
	n06p6t05AssertDetailSumsToTotals(t, r2)

	// Export: prior rows byte-identical, one row appended, TOTAL only moves
	// by the valid late amounts.
	recs1 := spendReconExportRecords(t, r1)
	recs2 := spendReconExportRecords(t, r2)
	if len(recs2) != len(recs1)+1 {
		t.Fatalf("records %d -> %d, want +1", len(recs1), len(recs2))
	}
	for i := range recs1[:len(recs1)-1] {
		if diff := cmp.Diff(recs1[i], recs2[i]); diff != "" {
			t.Errorf("export row %d rewritten after late event with violations (-old +new):\n%s", i, diff)
		}
	}
	if day := recs2[len(recs2)-2][0]; day != "2026-09-03" {
		t.Errorf("appended detail day = %q, want 2026-09-03", day)
	}
}

// TestN06P6T05PriceChangeKeepsViolationsAndBytes: a price-provenance change
// rewrites nothing even in a violation state — the dollar fields, the
// exported bytes and the violation set are identical; only the provenance
// label moves. (T04 pinned the clean state; this pins the fail-closed
// state, where a rewriter would be most tempted to "fix" the numbers.)
func TestN06P6T05PriceChangeKeepsViolationsAndBytes(t *testing.T) {
	mk := func(provenance string) SpendReconInput {
		in := spendReconHappyInput()
		in.Usage[1].UnpricedMicro = 42_000 // violation state (never-billed cost visible)
		in.Usage[1].UnpricedRequests = 2
		in.UITotalMicro = 3_750_000 + 42_000
		in.UsagePricingAsOf = provenance
		return in
	}
	r1 := ReconcileSpend(mk("openrouter@2026-09-01"))
	r2 := ReconcileSpend(mk("openrouter@2026-12-15"))

	if r1.Status != SpendReconStatusViolation || r2.Status != SpendReconStatusViolation {
		t.Fatalf("statuses = %q/%q, want violation/violation", r1.Status, r2.Status)
	}
	if diff := cmp.Diff(r1.Violations, r2.Violations); diff != "" {
		t.Errorf("price change altered the violation set (-before +after):\n%s", diff)
	}
	// Dollar fields and everything else identical once the label is
	// equalized (provenance must never enter any arithmetic).
	r1.UsagePricingAsOf = "same"
	r2.UsagePricingAsOf = "same"
	if diff := cmp.Diff(r1, r2); diff != "" {
		t.Errorf("price change rewrote the report (-before +after):\n%s", diff)
	}

	var buf1, buf2 bytes.Buffer
	if err := ReconcileSpend(mk("openrouter@2026-09-01")).WriteCSV(&buf1); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileSpend(mk("openrouter@2026-12-15")).WriteCSV(&buf2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Errorf("price change rewrote exported bytes in violation state:\nA=%q\nB=%q",
			buf1.String(), buf2.String())
	}
	n06p6t05AssertDetailSumsToTotals(t, r2)
}

// TestN06P6T05ReservedSnapshotEchoNeverFolds: the unreleased-allowance
// reservation snapshot (Σ granted−returned over active/expired/draining
// holds) is echoed exactly and never folds into any settled total, day row
// or exported column. A settled-but-not-released allowance (its charge is
// already in the wallet, its hold not yet returned) therefore stays visible
// on BOTH surfaces — the report never nets the snapshot against settled
// money silently; the caller reconciles via the documented remainder.
func TestN06P6T05ReservedSnapshotEchoNeverFolds(t *testing.T) {
	base := ReconcileSpend(n06p6t04SettlementInput())

	// An odd, deliberately unrealistic snapshot value must pass through
	// untouched and change NOTHING else in the report.
	in := n06p6t04SettlementInput()
	in.ReservedOutstandingMicro = 987_654_321
	in.ReservedAllowances = 12_345
	big := ReconcileSpend(in)
	if big.ReservedOutstandingMicro != 987_654_321 || big.ReservedAllowances != 12_345 {
		t.Fatalf("snapshot echo = %d/%d, want exact passthrough 987654321/12345",
			big.ReservedOutstandingMicro, big.ReservedAllowances)
	}
	baseShifted, bigShifted := base, big
	baseShifted.ReservedOutstandingMicro, baseShifted.ReservedAllowances = 0, 0
	bigShifted.ReservedOutstandingMicro, bigShifted.ReservedAllowances = 0, 0
	if diff := cmp.Diff(baseShifted, bigShifted); diff != "" {
		t.Errorf("snapshot size changed non-snapshot report fields (-base +big):\n%s", diff)
	}

	// The echo is honest even for a value the SQL could not produce
	// (negative residual): echoed as-is, never clamped, never applied.
	inNeg := n06p6t04SettlementInput()
	inNeg.ReservedOutstandingMicro = -5
	neg := ReconcileSpend(inNeg)
	if neg.ReservedOutstandingMicro != -5 {
		t.Errorf("negative snapshot echo = %d, want -5 (echo, never clamped)", neg.ReservedOutstandingMicro)
	}

	// Export: no reserved column exists (the snapshot is not a day fact and
	// must not be summable as one) and the bytes are identical either way.
	for _, h := range spendReconCSVColumns {
		if strings.Contains(h, "reserved") {
			t.Errorf("export column %q must not exist: the snapshot is not a day fact", h)
		}
	}
	var bufBase, bufBig bytes.Buffer
	if err := base.WriteCSV(&bufBase); err != nil {
		t.Fatal(err)
	}
	if err := big.WriteCSV(&bufBig); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bufBase.Bytes(), bufBig.Bytes()) {
		t.Error("snapshot value changed exported bytes (it must not be exportable per day)")
	}

	// Render + limitations: the snapshot is labelled once, with the
	// point-in-time note, and the named limitation documents the
	// settled-not-yet-released overlap instead of hiding it.
	text := big.RenderText()
	if !strings.Contains(text, "reserved") ||
		!strings.Contains(text, "987654321") ||
		!strings.Contains(text, "snapshot, not a day fact") {
		t.Errorf("render missing the labelled snapshot line:\n%s", text)
	}
	foundLimitation := false
	for _, l := range big.Limitations {
		if strings.Contains(l, "reserved_outstanding_micro_usd is a point-in-time snapshot") &&
			strings.Contains(l, "granted−returned") {
			foundLimitation = true
		}
	}
	if !foundLimitation {
		t.Errorf("limitations must document the snapshot semantics (incl. the unreleased-allowance overlap):\n%v",
			big.Limitations)
	}

	// The settled-but-not-released edge: the wallet already carries the
	// charge AND the snapshot still counts the unreleased residual — both
	// stay visible, neither is subtracted from the other.
	inOverlap := spendReconHappyInput()
	inOverlap.ReservedOutstandingMicro = 700_000
	inOverlap.ReservedAllowances = 1
	overlap := ReconcileSpend(inOverlap)
	if overlap.WalletMicro != -3_000_000 || overlap.CapturedMicro != 3_850_000 {
		t.Errorf("settled surfaces moved by the snapshot: wallet=%d captured=%d",
			overlap.WalletMicro, overlap.CapturedMicro)
	}
	if overlap.ReservedOutstandingMicro != 700_000 {
		t.Errorf("overlap echo = %d, want 700000 (raw residual stays visible)", overlap.ReservedOutstandingMicro)
	}
	if !strings.Contains(overlap.RenderText(), "700000") {
		t.Error("render must show the unreleased residual alongside the settled money")
	}
}
