package consumer

// N06-P06-T04 — the reporting dimension of unresolved and estimated usage:
// UNRESOLVED usage (late / unknown-priced events: settlement_jobs
// pending_price/unknown visibility rows plus the request_logs unpriced
// class already reported) and ESTIMATED usage (in-flight charge intents
// not yet settled, and the point-in-time reservation holds) appear as
// separate, clearly labelled columns/lines — never folded into settled
// totals, never hidden — under the T03 detail/total discipline:
//
//   - detail rows sum EXACTLY to totals per column, including the new
//     columns (the T03 TOTAL pin, extended);
//   - rounding stays once per row (the new columns are exact passthrough
//     and introduce no new rounding surface);
//   - negative: a late event appends without rewriting history, and a
//     price change never rewrites already-reported rows (byte stability;
//     new rows reflect the price at event time, refundless semantics).

import (
	"bytes"
	"context"
	"encoding/csv"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// n06p6t04SettlementInput extends the T02/T03 happy input with settlement
// facts: day 1 holds two unsettled charge intents ($0.40) and one
// unknown-price visibility row (amount 0 by construction); day 2 holds one
// unsettled intent ($0.25). The reservation snapshot echoes $1.20 across
// three holds.
func n06p6t04SettlementInput() SpendReconInput {
	in := spendReconHappyInput()
	in.Settlements = []SpendReconSettlementDay{
		{Day: "2026-09-01", EstimatedMicro: 400_000, EstimatedRequests: 2, UnresolvedPriceRows: 1},
		{Day: "2026-09-02", EstimatedMicro: 250_000, EstimatedRequests: 1},
	}
	in.ReservedOutstandingMicro = 1_200_000
	in.ReservedAllowances = 3
	return in
}

// TestN06P6T04EstimatedAndUnresolvedSeparateFromSettled: the new dimensions
// appear with their own day fields and totals, status stays ok, and the
// settled surfaces (UI parity, confirmed, captured, wallet, invoice) are
// byte-for-byte the values the settlement-free computation produced.
func TestN06P6T04EstimatedAndUnresolvedSeparateFromSettled(t *testing.T) {
	rep := ReconcileSpend(n06p6t04SettlementInput())

	if rep.Status != SpendReconStatusOK {
		t.Fatalf("status = %q, want ok (violations: %+v)", rep.Status, rep.Violations)
	}
	if rep.EstimatedTotalMicro != 650_000 || rep.EstimatedRequests != 3 {
		t.Errorf("estimated totals = %d/%d, want 650000/3", rep.EstimatedTotalMicro, rep.EstimatedRequests)
	}
	if rep.UnresolvedPriceRows != 1 || rep.UnresolvedPriceTotalMicro != 0 {
		t.Errorf("unresolved totals = %d rows / %d micro, want 1 row / 0 micro (never billed)", rep.UnresolvedPriceRows, rep.UnresolvedPriceTotalMicro)
	}
	if rep.ReservedOutstandingMicro != 1_200_000 || rep.ReservedAllowances != 3 {
		t.Errorf("snapshot echo = %d/%d, want 1200000/3", rep.ReservedOutstandingMicro, rep.ReservedAllowances)
	}
	d1 := rep.Days[0]
	if d1.EstimatedMicro != 400_000 || d1.EstimatedRequests != 2 || d1.UnresolvedPriceRows != 1 {
		t.Errorf("day1 estimated/unresolved = %d/%d/%d, want 400000/2/1",
			d1.EstimatedMicro, d1.EstimatedRequests, d1.UnresolvedPriceRows)
	}
	if d1.EstimatedMicro+d1.ConfirmedMicro != d1.ConfirmedMicro+400_000 {
		t.Error("estimated leaked into the confirmed column arithmetic")
	}

	// The settled surfaces are exactly the settlement-free values.
	base := ReconcileSpend(spendReconHappyInput())
	if rep.ConfirmedTotalMicro != base.ConfirmedTotalMicro ||
		rep.UITotalMicro != base.UITotalMicro ||
		rep.CapturedMicro != base.CapturedMicro ||
		rep.InvoiceTotalMicro != base.InvoiceTotalMicro ||
		rep.InvoiceDeltaMicro != base.InvoiceDeltaMicro ||
		rep.WalletMicro != base.WalletMicro ||
		rep.WalletGapMicro != base.WalletGapMicro ||
		rep.CaptureRatePct != base.CaptureRatePct {
		t.Errorf("estimated/unresolved facts moved a settled total:\nbase %+v\nwith %+v", base, rep)
	}
	// UI parity identity keeps holding without the estimated columns.
	if rep.UITotalMicro != rep.ConfirmedTotalMicro+rep.UnpricedTotalMicro {
		t.Errorf("ui parity broken by estimated facts: %d != %d + %d",
			rep.UITotalMicro, rep.ConfirmedTotalMicro, rep.UnpricedTotalMicro)
	}
	for i := range base.Days {
		b, w := base.Days[i], rep.Days[i]
		if b.ConfirmedMicro != w.ConfirmedMicro || b.WalletMicro != w.WalletMicro ||
			b.InvoiceMicro != w.InvoiceMicro || b.InvoiceDelta != w.InvoiceDelta ||
			b.WalletGapMicro != w.WalletGapMicro {
			t.Errorf("day %d settled columns changed: base %+v with %+v", i, b, w)
		}
	}
}

// TestN06P6T04SettlementOnlyDayVisible: a day whose only facts are
// settlement intents still produces its own day row — estimated usage is
// never hidden because the day has no settled facts yet. The period here
// has no usage, ledger or invoice facts at all; the report is still ok and
// must not invent settled dollars.
func TestN06P6T04SettlementOnlyDayVisible(t *testing.T) {
	from, to := spendReconTestPeriod()
	in := SpendReconInput{
		OrgID:            "11111111-1111-1111-1111-111111111111",
		From:             from,
		To:               to,
		UsagePricingAsOf: "openrouter@2026-09-01",
		Settlements: []SpendReconSettlementDay{
			{Day: "2026-09-01", EstimatedMicro: 90_000, EstimatedRequests: 1},
		},
	}

	rep := ReconcileSpend(in)
	if rep.Status != SpendReconStatusOK {
		t.Fatalf("status = %q, want ok (violations: %+v)", rep.Status, rep.Violations)
	}
	found := false
	for _, d := range rep.Days {
		if d.Day == "2026-09-01" {
			found = true
			if d.EstimatedMicro != 90_000 || d.EstimatedRequests != 1 {
				t.Errorf("settlement day row = %d/%d, want 90000/1", d.EstimatedMicro, d.EstimatedRequests)
			}
			if d.ConfirmedMicro != 0 || d.WalletMicro != 0 || d.InvoiceMicro != 0 {
				t.Errorf("settlement-only day must not invent settled facts: %+v", d)
			}
		}
	}
	if !found {
		t.Fatalf("settlement-only day 2026-09-01 missing from days %+v", rep.Days)
	}
	if rep.EstimatedTotalMicro != 90_000 {
		t.Errorf("estimated total = %d, want 90000", rep.EstimatedTotalMicro)
	}

	// The exported CSV carries the day with its estimated columns and no
	// invented settled dollars.
	recs := spendReconExportRecords(t, rep)
	if len(recs) != 3 { // header + 1 detail + TOTAL
		t.Fatalf("records = %d, want 3", len(recs))
	}
	if day := recs[1][0]; day != "2026-09-01" {
		t.Errorf("detail day = %q, want 2026-09-01", day)
	}
	idx := map[string]int{}
	for i, h := range recs[0] {
		idx[h] = i
	}
	if got := recs[1][idx["estimated_micro_usd"]]; got != "90000" {
		t.Errorf("detail estimated micro = %s, want 90000", got)
	}
	if got := recs[1][idx["captured_micro_usd"]]; got != "0" {
		t.Errorf("detail captured micro = %s, want 0 (estimated is never folded in)", got)
	}
}

// TestN06P6T04UnresolvedPriceNonzeroViolation: unknown-cost rows are never
// billed; a non-zero amount is a violation, stays visible in the day row,
// and never folds into any total.
func TestN06P6T04UnresolvedPriceNonzeroViolation(t *testing.T) {
	in := n06p6t04SettlementInput()
	in.Settlements[1].UnresolvedPriceRows = 2
	in.Settlements[1].UnresolvedPriceMicro = 42_000 // would-be charge on a never-billed row

	rep := ReconcileSpend(in)
	if rep.Status != SpendReconStatusViolation {
		t.Fatalf("status = %q, want violation", rep.Status)
	}
	found := false
	for _, v := range rep.Violations {
		if v.Code == ViolationUnresolvedPriceNonzero && v.Day == "2026-09-02" {
			found = true
		}
	}
	if !found {
		t.Errorf("violations %+v missing %s on 2026-09-02", rep.Violations, ViolationUnresolvedPriceNonzero)
	}
	day2 := rep.Days[1]
	if day2.UnresolvedPriceMicro != 42_000 {
		t.Errorf("unresolved amount = %d, want 42000 (visible, never dollars-zeroed)", day2.UnresolvedPriceMicro)
	}
	flagged := false
	for _, f := range day2.Flags {
		if f == ViolationUnresolvedPriceNonzero {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("day2 flags %v missing %s", day2.Flags, ViolationUnresolvedPriceNonzero)
	}
	// Not folded: confirmed/captured/estimated keep their settled values.
	if rep.ConfirmedTotalMicro != 3_750_000 || rep.CapturedMicro != 3_850_000 {
		t.Errorf("unresolved cost leaked into settled totals: confirmed=%d captured=%d",
			rep.ConfirmedTotalMicro, rep.CapturedMicro)
	}
	if rep.EstimatedTotalMicro != 650_000 {
		t.Errorf("estimated total = %d, want 650000 (unresolved is its own class)", rep.EstimatedTotalMicro)
	}
}

// TestN06P6T04ExportTotalsEqualDetailRowsAllColumns extends the T03 TOTAL
// pin to the new columns: the TOTAL row is the exact Σ of the detail rows
// in every numeric column, the new columns are exact passthrough of the
// report's day fields, and the header labels them clearly.
func TestN06P6T04ExportTotalsEqualDetailRowsAllColumns(t *testing.T) {
	rep := ReconcileSpend(n06p6t04SettlementInput())
	if rep.Status != SpendReconStatusOK {
		t.Fatalf("status = %q, want ok (violations: %+v)", rep.Status, rep.Violations)
	}
	recs := spendReconExportRecords(t, rep)

	// The new columns exist under their own names (clearly labelled).
	for _, col := range []string{"estimated_micro_usd", "estimated_requests", "unresolved_price_rows", "unresolved_price_micro_usd"} {
		found := false
		for _, h := range recs[0] {
			if h == col {
				found = true
			}
		}
		if !found {
			t.Errorf("header %v missing column %q", recs[0], col)
		}
	}

	idx := map[string]int{}
	for i, h := range recs[0] {
		idx[h] = i
	}
	details := recs[1 : len(recs)-1]
	total := recs[len(recs)-1]
	for i, d := range rep.Days {
		row := details[i]
		if got, want := row[idx["estimated_micro_usd"]], strconv.FormatInt(d.EstimatedMicro, 10); got != want {
			t.Errorf("detail %s estimated_micro = %s, want %s", d.Day, got, want)
		}
		if got, want := row[idx["estimated_requests"]], strconv.FormatInt(d.EstimatedRequests, 10); got != want {
			t.Errorf("detail %s estimated_requests = %s, want %s", d.Day, got, want)
		}
		if got, want := row[idx["unresolved_price_rows"]], strconv.FormatInt(d.UnresolvedPriceRows, 10); got != want {
			t.Errorf("detail %s unresolved_price_rows = %s, want %s", d.Day, got, want)
		}
		if got, want := row[idx["unresolved_price_micro_usd"]], strconv.FormatInt(d.UnresolvedPriceMicro, 10); got != want {
			t.Errorf("detail %s unresolved_price_micro = %s, want %s", d.Day, got, want)
		}
	}
	// TOTAL = Σ detail rows for EVERY numeric column (the T03 pin, now
	// covering the appended columns by construction).
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
			t.Errorf("TOTAL %s = %d, want Σ details %d", spendReconCSVColumns[j], got, sum)
		}
	}
	// The period totals the report exposes match the exported TOTAL row.
	if got, want := total[idx["estimated_micro_usd"]], strconv.FormatInt(rep.EstimatedTotalMicro, 10); got != want {
		t.Errorf("TOTAL estimated_micro = %s, want report total %s", got, want)
	}
	if got, want := total[idx["estimated_requests"]], strconv.FormatInt(rep.EstimatedRequests, 10); got != want {
		t.Errorf("TOTAL estimated_requests = %s, want report total %s", got, want)
	}
	if got, want := total[idx["unresolved_price_rows"]], strconv.FormatInt(rep.UnresolvedPriceRows, 10); got != want {
		t.Errorf("TOTAL unresolved_price_rows = %s, want report total %s", got, want)
	}
}

// TestN06P6T04RoundingOncePerRowUnaffectedByEstimated: the new columns are
// exact integers with no cents projection (estimated usage is not
// invoice-comparable; unresolved rows are never billed), so the export's
// rounding placement is unchanged — cents stay rounded once per detail row
// and TOTAL cents stays Σ per-row cents while estimated facts are present.
func TestN06P6T04RoundingOncePerRowUnaffectedByEstimated(t *testing.T) {
	for _, h := range spendReconCSVColumns {
		if strings.Contains(h, "cent") && (strings.Contains(h, "estimated") || strings.Contains(h, "unresolved")) {
			t.Errorf("column %q must not exist: estimated/unresolved are not invoice-comparable dollars", h)
		}
	}

	// Two $0.005 confirmed days would re-round to $0.01 if the period were
	// projected once; the contract keeps 1+1. Estimated amounts riding
	// along must not change that discipline, and the estimated column
	// itself must be an exact Σ with no rounding anywhere.
	in := spendReconHappyInput()
	in.Usage[0].ConfirmedMicro = 5_000
	in.Usage[1].ConfirmedMicro = 5_000
	in.UITotalMicro = 10_000
	in.Invoice = nil
	in.Settlements = []SpendReconSettlementDay{
		{Day: "2026-09-01", EstimatedMicro: 5_000, EstimatedRequests: 1, UnresolvedPriceRows: 1},
		{Day: "2026-09-02", EstimatedMicro: 5_000, EstimatedRequests: 1},
	}
	rep := ReconcileSpend(in)
	if rep.Status != SpendReconStatusOK {
		t.Fatalf("status = %q, want ok (violations: %+v)", rep.Status, rep.Violations)
	}
	recs := spendReconExportRecords(t, rep)
	idx := map[string]int{}
	for i, h := range recs[0] {
		idx[h] = i
	}
	if got := recs[len(recs)-1][idx["confirmed_cents_usd"]]; got != "2" {
		t.Errorf("TOTAL confirmed cents = %s, want 2 (Σ per-row, rounding once per row)", got)
	}
	if got := recs[len(recs)-1][idx["estimated_micro_usd"]]; got != "10000" {
		t.Errorf("TOTAL estimated micro = %s, want 10000 (exact Σ, no rounding)", got)
	}
	if got := recs[len(recs)-1][idx["unresolved_price_rows"]]; got != "1" {
		t.Errorf("TOTAL unresolved rows = %s, want 1", got)
	}
	// Unchanged rounding placement: the detail rows still round once each.
	if got, want := recs[1][idx["confirmed_cents_usd"]], "1"; got != want {
		t.Errorf("detail[0] confirmed cents = %s, want %s", got, want)
	}
	if got, want := recs[2][idx["confirmed_cents_usd"]], "1"; got != want {
		t.Errorf("detail[1] confirmed cents = %s, want %s", got, want)
	}
}

// TestN06P6T04LateSettlementEventAppendsWithoutRewriting: a late event
// (refundless semantics) appends one day of facts; every previously
// computed day row and every previously exported CSV row stays
// byte-identical, and the totals grow by exactly the late amounts.
func TestN06P6T04LateSettlementEventAppendsWithoutRewriting(t *testing.T) {
	in := n06p6t04SettlementInput()
	snapshotSettlements := append([]SpendReconSettlementDay(nil), in.Settlements...)
	r1 := ReconcileSpend(in)

	if !reflect.DeepEqual(in.Settlements, snapshotSettlements) {
		t.Fatal("ReconcileSpend mutated its settlement input")
	}

	// The late event: a settled-late request whose charge intent was
	// created on the day that just closed (window widened by one local
	// day) and a late unknown-price visibility row. Nothing is subtracted
	// anywhere — refundless semantics.
	late := n06p6t04SettlementInput()
	late.To = late.To.AddDate(0, 0, 1)
	late.Settlements = append(late.Settlements, SpendReconSettlementDay{
		Day: "2026-09-03", EstimatedMicro: 125_000, EstimatedRequests: 1, UnresolvedPriceRows: 1,
	})
	r2 := ReconcileSpend(late)

	if len(r2.Days) != len(r1.Days)+1 {
		t.Fatalf("days %d -> %d, want +1", len(r1.Days), len(r2.Days))
	}
	for i := range r1.Days {
		if !reflect.DeepEqual(r2.Days[i], r1.Days[i]) {
			t.Errorf("history rewritten at day %d:\nold %+v\nnew %+v", i, r1.Days[i], r2.Days[i])
		}
	}
	appended := r2.Days[len(r1.Days)]
	if appended.Day != "2026-09-03" || appended.EstimatedMicro != 125_000 || appended.EstimatedRequests != 1 || appended.UnresolvedPriceRows != 1 {
		t.Errorf("appended day = %+v, want 2026-09-03 125000/1 with 1 unresolved row", appended)
	}
	if r2.EstimatedTotalMicro != r1.EstimatedTotalMicro+125_000 {
		t.Errorf("estimated total %d -> %d, want +125000 (append-only)", r1.EstimatedTotalMicro, r2.EstimatedTotalMicro)
	}
	if r2.EstimatedRequests != r1.EstimatedRequests+1 || r2.UnresolvedPriceRows != r1.UnresolvedPriceRows+1 {
		t.Errorf("estimated/unresolved counts %d/%d -> %d/%d, want +1/+1",
			r1.EstimatedRequests, r1.UnresolvedPriceRows, r2.EstimatedRequests, r2.UnresolvedPriceRows)
	}

	// Export bytes: prior rows (header + previously exported detail rows)
	// byte-identical; the new row appends at the end of the table.
	var buf1, buf2 bytes.Buffer
	if err := r1.WriteCSV(&buf1); err != nil {
		t.Fatal(err)
	}
	if err := r2.WriteCSV(&buf2); err != nil {
		t.Fatal(err)
	}
	recs1, err := csv.NewReader(&buf1).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	recs2, err := csv.NewReader(&buf2).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs2) != len(recs1)+1 {
		t.Fatalf("records %d -> %d, want +1", len(recs1), len(recs2))
	}
	for i := range recs1[:len(recs1)-1] {
		if diff := cmp.Diff(recs1[i], recs2[i]); diff != "" {
			t.Errorf("row %d changed after late event (-old +new):\n%s", i, diff)
		}
	}
	if day := recs2[len(recs2)-2][0]; day != "2026-09-03" {
		t.Errorf("appended detail day = %q, want 2026-09-03", day)
	}
}

// TestN06P6T04PriceChangeKeepsReportedRowsBytes: a re-published price
// catalog (new provenance) never rewrites already-reported rows — the CSV
// stays byte-identical — and a NEW late row still carries the amount
// captured at event time (as-of write; the report echoes provenance,
// applies no price).
func TestN06P6T04PriceChangeKeepsReportedRowsBytes(t *testing.T) {
	before := n06p6t04SettlementInput()
	r1 := ReconcileSpend(before)

	after := n06p6t04SettlementInput()
	after.UsagePricingAsOf = "openrouter@2026-12-15" // prices changed meanwhile
	r2 := ReconcileSpend(after)

	var buf1, buf2 bytes.Buffer
	if err := r1.WriteCSV(&buf1); err != nil {
		t.Fatal(err)
	}
	if err := r2.WriteCSV(&buf2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Errorf("price provenance changed exported rows:\nA=%q\nB=%q", buf1.String(), buf2.String())
	}

	// A late event after the price change: its row carries the event-time
	// captured amount, prior rows stay byte-identical.
	late := after
	late.To = late.To.AddDate(0, 0, 1)
	late.Settlements = append(late.Settlements, SpendReconSettlementDay{
		Day: "2026-09-03", EstimatedMicro: 777_000, EstimatedRequests: 1,
	})
	r3 := ReconcileSpend(late)
	recs1 := spendReconExportRecords(t, r2)
	recs3 := spendReconExportRecords(t, r3)
	for i := range recs1[:len(recs1)-1] {
		if diff := cmp.Diff(recs1[i], recs3[i]); diff != "" {
			t.Errorf("row %d rewritten after price change + late event (-old +new):\n%s", i, diff)
		}
	}
	if got := recs3[len(recs3)-2][14]; got != "777000" { // estimated_micro_usd
		t.Errorf("late row estimated micro = %s, want 777000 (event-time capture)", got)
	}
	if r3.EstimatedTotalMicro != r2.EstimatedTotalMicro+777_000 {
		t.Errorf("estimated total %d -> %d, want +777000", r2.EstimatedTotalMicro, r3.EstimatedTotalMicro)
	}
}

// TestN06P6T04SettlementDayOutsideWindowViolationExcluded: settlement day
// rows follow the same window discipline as usage/ledger rows — outside
// rows are violations, excluded from every total.
func TestN06P6T04SettlementDayOutsideWindowViolationExcluded(t *testing.T) {
	in := n06p6t04SettlementInput()
	in.Settlements = append(in.Settlements, SpendReconSettlementDay{Day: "2026-09-15", EstimatedMicro: 9_000, EstimatedRequests: 1})

	rep := ReconcileSpend(in)
	if rep.Status != SpendReconStatusViolation {
		t.Fatalf("status = %q, want violation", rep.Status)
	}
	found := false
	for _, v := range rep.Violations {
		if v.Code == ViolationDayOutsidePeriod && v.Day == "2026-09-15" {
			found = true
		}
	}
	if !found {
		t.Errorf("violations %+v missing day_outside_period for 2026-09-15", rep.Violations)
	}
	if rep.EstimatedTotalMicro != 650_000 || rep.EstimatedRequests != 3 {
		t.Errorf("estimated totals = %d/%d, want 650000/3 (outside row excluded)", rep.EstimatedTotalMicro, rep.EstimatedRequests)
	}
}

// TestN06P6T04RenderTextLabelSeparately: the operator-facing summary names
// the estimated and unresolved dimensions on their own lines, with the
// never-added note, and echoes the reservation snapshot once.
func TestN06P6T04RenderTextLabelSeparately(t *testing.T) {
	text := ReconcileSpend(n06p6t04SettlementInput()).RenderText()
	for _, want := range []string{
		"estimated", "650000", "3 req unsettled", "NOT added to confirmed/captured",
		"unresolved", "1 unknown-price rows, never billed",
		"reserved", "1200000", "snapshot, not a day fact",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered text missing %q:\n%s", want, text)
		}
	}
	// The day lines carry both dimensions too.
	if !strings.Contains(text, "estimated 400000/2 unresolved 1/0") {
		t.Errorf("day line missing estimated/unresolved fields:\n%s", text)
	}
}

// TestN06P6T04ReaderQueriesPinEstimatedUnresolved pins the reader SQL
// contract: the settlement query buckets by the zoned report day and
// splits open (estimated) from unknown-price (unresolved) classes; the
// snapshot sums residual holds over still-holding statuses only.
func TestN06P6T04ReaderQueriesPinEstimatedUnresolved(t *testing.T) {
	if !strings.Contains(spendReconSettlementsByDayQuery, "FROM settlement_jobs") {
		t.Error("settlement query must read settlement_jobs")
	}
	if !strings.Contains(spendReconSettlementsByDayQuery, spendReconZonedDayBucket) {
		t.Error("settlement query must bucket days exactly like the other fact queries (zoned, bound $4)")
	}
	if !strings.Contains(spendReconSettlementsByDayQuery, "created_at >= $2 AND created_at < $3") {
		t.Error("settlement query must use the half-open window bounds $2/$3")
	}
	if !strings.Contains(spendReconSettlementsByDayQuery, "GROUP BY 1 ORDER BY 1") {
		t.Error("settlement query must GROUP BY day (duplicate rows are a producer violation)")
	}
	if !strings.Contains(spendReconOpenSettlementStatuses, "'requires_attention'") {
		t.Error("estimated class must include requires_attention (durable debt is still owed)")
	}
	if !strings.Contains(spendReconOpenSettlementStatuses, "'pending'") ||
		!strings.Contains(spendReconOpenSettlementStatuses, "'processing'") ||
		!strings.Contains(spendReconOpenSettlementStatuses, "'retry'") {
		t.Error("estimated class must include pending/processing/retry")
	}
	if !strings.Contains(spendReconUnresolvedPricePredicate, "charge_kind = 'pending_price'") ||
		!strings.Contains(spendReconUnresolvedPricePredicate, "'pending_price', 'unknown'") {
		t.Error("unresolved class must key on pending_price rows and their terminal 'unknown' state")
	}
	if strings.Contains(spendReconOpenSettlementStatuses, "'settled'") {
		t.Error("settled jobs belong to the wallet ledger, not the estimated class")
	}

	if !strings.Contains(spendReconReservedOutstandingQuery, "SUM(granted_micro_usd - returned_micro_usd)") {
		t.Error("snapshot must sum granted−returned residual holds")
	}
	if !strings.Contains(spendReconReservedOutstandingQuery, "'active', 'expired', 'draining'") {
		t.Error("snapshot must cover active/expired/draining holds (released holds nothing)")
	}
	if strings.Contains(spendReconReservedOutstandingQuery, "date_trunc") {
		t.Error("snapshot is a point-in-time value, never a day bucket")
	}

	// Nil pool fails loudly on the new seams, like the existing ones.
	r := NewPgxSpendReconReader(nil)
	ctx := context.Background()
	if _, err := r.SettlementsByDay(ctx, "org", timeUTC(2026, 9, 1), timeUTC(2026, 9, 2), "UTC"); err == nil {
		t.Error("SettlementsByDay on nil pool: expected error")
	}
	if _, _, err := r.ReservedOutstanding(ctx, "org"); err == nil {
		t.Error("ReservedOutstanding on nil pool: expected error")
	}
}
