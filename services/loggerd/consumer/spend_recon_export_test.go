package consumer

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/reireirei/yabanin/pkg/money"
)

func spendReconExportRecords(t *testing.T, rep SpendReconReport) [][]string {
	t.Helper()
	var buf bytes.Buffer
	if err := rep.WriteCSV(&buf); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse export: %v", buf.String())
	}
	for _, r := range recs {
		if len(r) != len(spendReconCSVColumns) {
			t.Fatalf("record %v has %d fields, want %d", r, len(r), len(spendReconCSVColumns))
		}
	}
	return recs
}

// TestSpendReconExportTotalsEqualDetailRows pins the export's core
// formatting contract: the TOTAL row is the exact int64 sum of the emitted
// detail rows in every numeric column, and every row is arithmetically
// self-contained (captured/gap/delta/cents recompute from the row itself).
func TestSpendReconExportTotalsEqualDetailRows(t *testing.T) {
	rep := ReconcileSpend(spendReconHappyInput())
	if rep.Status != SpendReconStatusOK {
		t.Fatalf("status = %q, want ok (violations: %+v)", rep.Status, rep.Violations)
	}
	recs := spendReconExportRecords(t, rep)

	if want := len(rep.Days) + 2; len(recs) != want {
		t.Fatalf("records = %d, want %d (header + days + TOTAL)", len(recs), want)
	}
	if diff := cmp.Diff(spendReconCSVColumns, recs[0]); diff != "" {
		t.Errorf("header mismatch (-want +got):\n%s", diff)
	}
	if last := recs[len(recs)-1][0]; last != "TOTAL" {
		t.Errorf("last row day = %q, want TOTAL", last)
	}
	if flags := recs[len(recs)-1][len(spendReconCSVColumns)-1]; flags != "" {
		t.Errorf("TOTAL flags = %q, want empty", flags)
	}

	details := recs[1 : len(recs)-1]
	for i, d := range details {
		if d[0] != rep.Days[i].Day {
			t.Errorf("detail[%d].day = %q, want %q (Days order)", i, d[0], rep.Days[i].Day)
		}
		num := make([]int64, len(d)-2)
		for j := 1; j < len(d)-1; j++ {
			v, err := strconv.ParseInt(d[j], 10, 64)
			if err != nil {
				t.Fatalf("detail[%d] col %s = %q: %v", i, spendReconCSVColumns[j], d[j], err)
			}
			num[j-1] = v
		}
		const (
			cConfirmed = iota
			cUnpriced
			cUnpricedReq
			cLegacy
			cRequests
			cShadow
			cCaptured
			cWallet
			cGap
			cInvoice
			cDelta
			cConfirmedCents
			cCapturedCents
		)
		day := rep.Days[i]
		if num[cConfirmed] != day.ConfirmedMicro || num[cShadow] != day.ShadowMicro ||
			num[cWallet] != day.WalletMicro || num[cInvoice] != day.InvoiceMicro {
			t.Errorf("detail[%d] raw columns diverge from report day: %+v", i, d)
		}
		// Self-contained derivations from the row's own numbers.
		if num[cCaptured] != num[cConfirmed]+num[cShadow] {
			t.Errorf("detail[%d] captured %d != confirmed+shadow %d", i, num[cCaptured], num[cConfirmed]+num[cShadow])
		}
		if num[cGap] != num[cConfirmed]+num[cWallet] {
			t.Errorf("detail[%d] gap %d != confirmed+wallet %d", i, num[cGap], num[cConfirmed]+num[cWallet])
		}
		if num[cDelta] != num[cCaptured]-num[cInvoice] {
			t.Errorf("detail[%d] delta %d != captured−invoice %d", i, num[cDelta], num[cCaptured]-num[cInvoice])
		}
		if num[cConfirmedCents] != money.MicroUSD(day.ConfirmedMicro).Cents() {
			t.Errorf("detail[%d] confirmed cents %d != canonical %d",
				i, num[cConfirmedCents], money.MicroUSD(day.ConfirmedMicro).Cents())
		}
		if num[cCapturedCents] != money.MicroUSD(num[cCaptured]).Cents() {
			t.Errorf("detail[%d] captured cents %d != canonical %d",
				i, num[cCapturedCents], money.MicroUSD(num[cCaptured]).Cents())
		}
	}

	// TOTAL = Σ detail rows for EVERY numeric column.
	for j := 1; j < len(spendReconCSVColumns)-1; j++ {
		var sum int64
		for _, d := range details {
			v, err := strconv.ParseInt(d[j], 10, 64)
			if err != nil {
				t.Fatalf("detail col %s = %q: %v", spendReconCSVColumns[j], d[j], err)
			}
			sum += v
		}
		total, err := strconv.ParseInt(recs[len(recs)-1][j], 10, 64)
		if err != nil {
			t.Fatalf("TOTAL col %s = %q: %v", spendReconCSVColumns[j], recs[len(recs)-1][j], err)
		}
		if sum != total {
			t.Errorf("TOTAL %s = %d, want Σ details %d", spendReconCSVColumns[j], total, sum)
		}
	}
}

// TestSpendReconExportCentsSumPerRow pins the rounding placement: cents
// columns are rounded once per detail row and the TOTAL cents is the sum
// of the displayed rows — never the projection of the summed micro, which
// would silently disagree with the detail rows a reader re-adds.
func TestSpendReconExportCentsSumPerRow(t *testing.T) {
	in := SpendReconInput{
		OrgID: "org-cents",
		From:  timeUTC(2026, 9, 1),
		To:    timeUTC(2026, 9, 3),
		Usage: []SpendReconUsageDay{
			{Day: "2026-09-01", ConfirmedMicro: 5_000, Requests: 1},
			{Day: "2026-09-02", ConfirmedMicro: 5_000, Requests: 1},
		},
		Invoice: []SpendReconInvoiceDay{
			{Day: "2026-09-01", InvoiceMicro: 5_000},
			{Day: "2026-09-02", InvoiceMicro: 5_000},
		},
		UITotalMicro: 10_000,
	}
	rep := ReconcileSpend(in)
	if rep.Status != SpendReconStatusOK {
		t.Fatalf("status = %q, want ok (violations: %+v)", rep.Status, rep.Violations)
	}
	recs := spendReconExportRecords(t, rep)
	total := recs[len(recs)-1]
	confirmedCents, err := strconv.ParseInt(total[13], 10, 64)
	if err != nil {
		t.Fatalf("TOTAL confirmed cents: %v", err)
	}
	if projected := money.MicroUSD(rep.ConfirmedTotalMicro).Cents(); projected != 1 {
		t.Fatalf("test precondition: projecting the summed micro once gives %d cents, want 1", projected)
	}
	if confirmedCents != 2 {
		t.Errorf("TOTAL confirmed cents = %d, want 2 (Σ per-row rounded rows, never re-rounded)", confirmedCents)
	}
	for i, want := range []int64{1, 1} {
		if got := recs[i+1][13]; got != strconv.FormatInt(want, 10) {
			t.Errorf("detail[%d] cents = %s, want %d", i, got, want)
		}
	}
}

// TestSpendReconDayCSVRowNegativeCents pins the negative-direction rounding
// of the export derivation: half away from zero (money-canonical), not
// toward zero.
func TestSpendReconDayCSVRowNegativeCents(t *testing.T) {
	if got := money.MicroUSD(-1_005_000).Cents(); got != -101 {
		t.Fatalf("precondition: MicroUSD(-1005000).Cents() = %d, want -101 (half away from zero)", got)
	}
	vals, flags := spendReconDayCSVRow(SpendReconDayReport{
		Day:            "2026-09-01",
		ConfirmedMicro: -1_005_000,
	})
	if vals[0] != -1_005_000 {
		t.Errorf("confirmed micro passthrough = %d, want -1005000", vals[0])
	}
	if vals[11] != -101 {
		t.Errorf("confirmed cents = %d, want -101 (half away from zero)", vals[11])
	}
	if flags != "" {
		t.Errorf("flags = %q, want empty", flags)
	}
	// Half case rounds away from zero too.
	vals, _ = spendReconDayCSVRow(SpendReconDayReport{ConfirmedMicro: 1_500_000})
	if vals[11] != 150 {
		t.Errorf("exact half-dollar cents = %d, want 150", vals[11])
	}
	vals, _ = spendReconDayCSVRow(SpendReconDayReport{ConfirmedMicro: 500_000})
	if vals[11] != 50 {
		t.Errorf("exact 50 cents = %d, want 50", vals[11])
	}
}

// TestSpendReconExportPriceProvenanceKeepsBytes: provenance labels are
// echoed in the text render but must never change the exported numbers —
// two renders over different pricing-snapshot labels are byte-identical
// (the price-change non-rewrite guarantee, surfaced for exports).
func TestSpendReconExportPriceProvenanceKeepsBytes(t *testing.T) {
	a := spendReconHappyInput()
	a.UsagePricingAsOf = "openrouter@2026-09-01"
	a.InvoiceLabel = "provider-invoice-2026-09"
	b := a
	b.UsagePricingAsOf = "openrouter@2026-12-15" // as if prices changed meanwhile
	b.InvoiceLabel = "provider-invoice-2026-09-corrected"

	var bufA, bufB bytes.Buffer
	if err := ReconcileSpend(a).WriteCSV(&bufA); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileSpend(b).WriteCSV(&bufB); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bufA.Bytes(), bufB.Bytes()) {
		t.Errorf("export changed with provenance labels only:\nA=%q\nB=%q", bufA.String(), bufB.String())
	}
	if strings.Contains(bufA.String(), "openrouter") {
		t.Error("export must not embed provenance labels")
	}
}

// TestSpendReconExportLateEventAppendOnly mirrors the core's append-only
// guarantee at the export level: adding a late day appends one detail row
// and adjusts the TOTAL row; previously exported rows are byte-identical.
func TestSpendReconExportLateEventAppendOnly(t *testing.T) {
	in := spendReconHappyInput()
	r1 := ReconcileSpend(in)

	late := spendReconHappyInput()
	late.Usage = append(late.Usage, SpendReconUsageDay{Day: "2026-09-03", ConfirmedMicro: 250_000, Requests: 1})
	late.UITotalMicro += 250_000
	late.Invoice = append(late.Invoice, SpendReconInvoiceDay{Day: "2026-09-03", InvoiceMicro: 250_000})
	// The happy window ends 2026-09-03T00:00Z; the late event belongs to
	// the day that just closed, so the operator widens the period by one
	// local day and re-runs (day "2026-09-03" is outside the old window).
	late.To = timeUTC(2026, 9, 4)
	r2 := ReconcileSpend(late)

	recs1 := spendReconExportRecords(t, r1)
	recs2 := spendReconExportRecords(t, r2)

	if len(recs2) != len(recs1)+1 {
		t.Fatalf("records %d -> %d, want exactly +1 detail row", len(recs1), len(recs2))
	}
	for i := range recs1[:len(recs1)-1] { // header + prior detail rows
		if diff := cmp.Diff(recs1[i], recs2[i]); diff != "" {
			t.Errorf("row %d changed after late event (-old +new):\n%s", i, diff)
		}
	}
	if day := recs2[len(recs2)-2][0]; day != "2026-09-03" {
		t.Errorf("appended detail day = %q, want 2026-09-03", day)
	}
	// TOTAL row grows by exactly the late event on the touched columns.
	confirmedOld, _ := strconv.ParseInt(recs1[len(recs1)-1][1], 10, 64)
	confirmedNew, _ := strconv.ParseInt(recs2[len(recs2)-1][1], 10, 64)
	if confirmedNew != confirmedOld+250_000 {
		t.Errorf("TOTAL confirmed %d -> %d, want +250000", confirmedOld, confirmedNew)
	}
	centsOld, _ := strconv.ParseInt(recs1[len(recs1)-1][12], 10, 64)
	centsNew, _ := strconv.ParseInt(recs2[len(recs2)-1][12], 10, 64)
	if centsNew != centsOld+25 { // late day = 250_000 micro = exactly 25 cents
		t.Errorf("TOTAL confirmed cents %d -> %d, want +25", centsOld, centsNew)
	}
}

// TestSpendReconExportEmptyReport: an empty period still emits a valid
// table whose TOTAL is all zeros.
func TestSpendReconExportEmptyReport(t *testing.T) {
	rep := ReconcileSpend(SpendReconInput{OrgID: "org-empty"})
	recs := spendReconExportRecords(t, rep)
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2 (header + TOTAL)", len(recs))
	}
	for j := 1; j < len(spendReconCSVColumns)-1; j++ {
		if recs[1][j] != "0" {
			t.Errorf("empty TOTAL %s = %s, want 0", spendReconCSVColumns[j], recs[1][j])
		}
	}
}

func timeUTC(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// failingWriter fails after n successful bytes, so WriteCSV's error paths
// (header write, detail/TOTAL writes, final Flush error) are exercised.
type failingWriter struct{ n int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, errors.New("disk full")
	}
	if len(p) > w.n {
		n := w.n
		w.n = 0
		return n, errors.New("disk full")
	}
	w.n -= len(p)
	return len(p), nil
}

func TestSpendReconExportWriteErrorPropagates(t *testing.T) {
	rep := ReconcileSpend(spendReconHappyInput())
	for _, budget := range []int{0, 1} { // fails on header; fails mid-table
		if err := rep.WriteCSV(&failingWriter{n: budget}); err == nil {
			t.Errorf("WriteCSV to failing writer (budget %d): expected error, got nil", budget)
		}
	}

	// A report large enough to exceed the csv.Writer's internal buffer must
	// surface a mid-table write error instead of silently producing a
	// truncated file (financial exports fail loudly or not at all).
	big := SpendReconInput{OrgID: "org-big"}
	for i := 0; i < 400; i++ {
		day := timeUTC(2026, 1, 1).AddDate(0, 0, i).Format("2006-01-02")
		big.Usage = append(big.Usage, SpendReconUsageDay{
			Day: day, ConfirmedMicro: int64(1_000_000 + i), Requests: 2,
			UnpricedMicro: 1, LegacyRows: 3, ShadowMicro: 7, // pad rows past the buffer
		})
		big.UITotalMicro += int64(1_000_000 + i)
	}
	repBig := ReconcileSpend(big)
	if err := repBig.WriteCSV(&failingWriter{n: 2048}); err == nil {
		t.Error("WriteCSV past writer budget: expected mid-table error, got nil")
	}
	// The same report writes completely under a sufficient budget.
	var buf bytes.Buffer
	if err := repBig.WriteCSV(&buf); err != nil {
		t.Fatalf("WriteCSV with sufficient budget: %v", err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 400+2 {
		t.Errorf("big export rows = %d, want 402 (header + 400 days + TOTAL)", len(recs))
	}
}
