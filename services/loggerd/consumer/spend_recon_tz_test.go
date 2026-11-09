package consumer

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/reireirei/yabanin/pkg/budget"
)

// spendReconNYMonth builds the March 2026 reporting month for an
// America/New_York org — the month containing the US spring-forward
// transition (2026-03-08, a 23-hour local day).
func spendReconNYMonth(t *testing.T) budget.ReportPeriod {
	t.Helper()
	p, err := budget.MonthReportPeriod("2026-03", "America/New_York")
	if err != nil {
		t.Fatalf("MonthReportPeriod: %v", err)
	}
	return p
}

func TestSpendReconDayInWindowReportZone(t *testing.T) {
	month := spendReconNYMonth(t)
	cases := []struct {
		day  string
		want bool
	}{
		{"2026-02-28", false}, // ends exactly at From (local midnight) → outside
		{"2026-03-01", true},
		{"2026-03-07", true},
		{"2026-03-08", true}, // the 23h DST day must intersect normally
		{"2026-03-31", true}, // ends exactly at To (local midnight) → inside
		{"2026-04-01", false},
	}
	for _, tc := range cases {
		got, err := spendReconDayInWindow(tc.day, month.From, month.To, mustNY(t))
		if err != nil {
			t.Errorf("spendReconDayInWindow(%q, NY month): %v", tc.day, err)
			continue
		}
		if got != tc.want {
			t.Errorf("spendReconDayInWindow(%q, NY month) = %v, want %v", tc.day, got, tc.want)
		}
	}

	// A window clipped mid-day: [2026-03-09 12:00 .. 2026-03-10 12:00) local.
	ny := mustNY(t)
	from := time.Date(2026, 3, 9, 12, 0, 0, 0, ny)
	to := time.Date(2026, 3, 10, 12, 0, 0, 0, ny)
	for day, want := range map[string]bool{
		"2026-03-08": false,
		"2026-03-09": true,
		"2026-03-10": true,
		"2026-03-11": false,
	} {
		got, err := spendReconDayInWindow(day, from, to, ny)
		if err != nil {
			t.Errorf("spendReconDayInWindow(%q, clipped): %v", day, err)
			continue
		}
		if got != want {
			t.Errorf("spendReconDayInWindow(%q, clipped) = %v, want %v", day, got, want)
		}
	}

	// nil location must mean UTC.
	utcFrom := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	utcTo := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	got, err := spendReconDayInWindow("2026-09-02", utcFrom, utcTo, nil)
	if err != nil || !got {
		t.Errorf("nil zone day-in-window = %v, %v; want true, nil", got, err)
	}
	if got, err := spendReconDayInWindow("2026-09-03", utcFrom, utcTo, nil); err != nil || got {
		t.Errorf("nil zone day-in-window(end) = %v, %v; want false, nil", got, err)
	}
}

func mustNY(t *testing.T) *time.Location {
	t.Helper()
	loc, err := budget.ResolveReportZone("America/New_York")
	if err != nil {
		t.Fatalf("ResolveReportZone: %v", err)
	}
	return loc
}

// TestReconcileSpendOrgZoneMonth reconciles a whole org-local month for a
// New York org: every local day bucket (including the 23h DST day) is
// accepted, sums match per-day and total, and the zone is echoed.
func TestReconcileSpendOrgZoneMonth(t *testing.T) {
	month := spendReconNYMonth(t)
	buckets := month.DayBuckets()
	if len(buckets) != 31 {
		t.Fatalf("NY March buckets = %d, want 31", len(buckets))
	}

	in := SpendReconInput{
		OrgID: "org-ny",
		From:  month.From,
		To:    month.To,
		Zone:  mustNY(t),
	}
	var uiTotal int64
	for i, day := range buckets {
		confirmed := int64(1_500_000 + 250_000*i)
		in.Usage = append(in.Usage, SpendReconUsageDay{Day: day, ConfirmedMicro: confirmed, Requests: 2})
		in.Ledger = append(in.Ledger, SpendReconLedgerDay{
			Day: day, WalletMicro: -confirmed, WalletCentsAppliedMicro: -confirmed, WalletTxns: 1,
		})
		in.Invoice = append(in.Invoice, SpendReconInvoiceDay{Day: day, InvoiceMicro: confirmed})
		uiTotal += confirmed
	}
	in.UITotalMicro = uiTotal

	rep := ReconcileSpend(in)
	if rep.Status != SpendReconStatusOK {
		t.Fatalf("status = %q, want ok (violations: %+v)", rep.Status, rep.Violations)
	}
	if rep.Zone != "America/New_York" {
		t.Errorf("report zone = %q, want America/New_York", rep.Zone)
	}
	if rep.ConfirmedTotalMicro != uiTotal {
		t.Errorf("confirmed total = %d, want %d (Σ org-local days)", rep.ConfirmedTotalMicro, uiTotal)
	}
	if rep.InvoiceDeltaMicro != 0 || rep.WalletGapMicro != 0 {
		t.Errorf("deltas = %d/%d, want 0/0", rep.InvoiceDeltaMicro, rep.WalletGapMicro)
	}
	if rep.InvoiceDaysOutsidePeriod != 0 {
		t.Errorf("invoice days outside period = %d, want 0 (same zone on both sides)", rep.InvoiceDaysOutsidePeriod)
	}
	if len(rep.Days) != len(buckets) {
		t.Fatalf("report days = %d, want %d", len(rep.Days), len(buckets))
	}
	for i, d := range rep.Days {
		if d.Day != buckets[i] {
			t.Errorf("day[%d] = %q, want %q (local bucket)", i, d.Day, buckets[i])
		}
	}

	// The same window interpreted as UTC would have excluded the first
	// local bucket (which starts at 2026-03-01T05:00Z, inside 2026-03-01
	// UTC) and included 2026-04-01 local midnight rows — pin that the zoned
	// window is genuinely different from naive UTC math.
	naive, err := spendReconDayInWindow("2026-04-01", month.From, month.To, mustNY(t))
	if err != nil {
		t.Fatal(err)
	}
	naiveUTC, err := spendReconDayInWindow("2026-04-01", month.From, month.To, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if naive != false || naiveUTC != true {
		t.Errorf("zone did not change the bucket decision: NY=%v UTC=%v, want false/true", naive, naiveUTC)
	}
}

// TestReconcileSpendLateEventInOrgZoneKeepsHistory mirrors the UTC
// append-only contract inside an org-local period that contains a DST
// transition: recomputation after a late event changes exactly one day row
// and the totals; all previously emitted day rows are byte-identical and
// the invariant set still holds.
func TestReconcileSpendLateEventInOrgZoneKeepsHistory(t *testing.T) {
	month := spendReconNYMonth(t)

	base := func() SpendReconInput {
		in := SpendReconInput{
			OrgID: "org-ny",
			From:  month.From,
			To:    month.To,
			Zone:  mustNY(t),
		}
		for _, day := range []struct {
			label     string
			confirmed int64
		}{{"2026-03-07", 1_500_000}, {"2026-03-08", 2_250_000}} { // 03-08 is the 23h day
			in.Usage = append(in.Usage, SpendReconUsageDay{Day: day.label, ConfirmedMicro: day.confirmed, Requests: 3})
			in.Ledger = append(in.Ledger, SpendReconLedgerDay{
				Day: day.label, WalletMicro: -day.confirmed, WalletCentsAppliedMicro: -day.confirmed, WalletTxns: 1,
			})
			in.Invoice = append(in.Invoice, SpendReconInvoiceDay{Day: day.label, InvoiceMicro: day.confirmed})
			in.UITotalMicro += day.confirmed
		}
		return in
	}

	r1 := ReconcileSpend(base())
	if r1.Status != SpendReconStatusOK {
		t.Fatalf("r1 status = %q, want ok (violations: %+v)", r1.Status, r1.Violations)
	}

	late := base()
	late.Usage = append(late.Usage, SpendReconUsageDay{Day: "2026-03-09", ConfirmedMicro: 250_000, Requests: 1})
	late.Ledger = append(late.Ledger, SpendReconLedgerDay{
		Day: "2026-03-09", WalletMicro: -250_000, WalletCentsAppliedMicro: -250_000, WalletTxns: 1,
	})
	late.Invoice = append(late.Invoice, SpendReconInvoiceDay{Day: "2026-03-09", InvoiceMicro: 250_000})
	late.UITotalMicro += 250_000
	r2 := ReconcileSpend(late)

	if r2.Status != SpendReconStatusOK {
		t.Fatalf("r2 status = %q, want ok (violations: %+v)", r2.Status, r2.Violations)
	}
	// Previously emitted day rows must be identical (append-only history).
	if diff := cmp.Diff(r1.Days, r2.Days[:len(r1.Days)]); diff != "" {
		t.Errorf("late event rewrote prior day rows (-r1 +r2):\n%s", diff)
	}
	// Totals grow exactly by the late event.
	if r2.ConfirmedTotalMicro != r1.ConfirmedTotalMicro+250_000 {
		t.Errorf("r2 confirmed %d, want %d (+250000)", r2.ConfirmedTotalMicro, r1.ConfirmedTotalMicro+250_000)
	}
	if r2.UITotalMicro != r2.ConfirmedTotalMicro+r2.UnpricedTotalMicro {
		t.Errorf("r2 ui parity broken: %d != %d + %d",
			r2.UITotalMicro, r2.ConfirmedTotalMicro, r2.UnpricedTotalMicro)
	}
	if r2.InvoiceDeltaMicro != r1.InvoiceDeltaMicro {
		t.Errorf("r2 invoice delta %d changed from r1 %d (both sides must grow together)",
			r2.InvoiceDeltaMicro, r1.InvoiceDeltaMicro)
	}
	// Day labels stay the org-local buckets; no UTC re-bucketing happened.
	if r2.Days[0].Day != "2026-03-07" || r2.Days[1].Day != "2026-03-08" || r2.Days[2].Day != "2026-03-09" {
		t.Errorf("r2 day labels = %v, want local 03-07/03-08/03-09",
			[]string{r2.Days[0].Day, r2.Days[1].Day, r2.Days[2].Day})
	}
}

// TestSpendReconSQLZoneContract pins the SQL side of the timezone contract:
// the by-day queries must bucket with an explicit AT TIME ZONE parameter —
// never the bare date_trunc('day', created_at), which silently follows the
// database session TimeZone — and the UI-parity total must stay day-free.
func TestSpendReconSQLZoneContract(t *testing.T) {
	const bareBucket = "date_trunc('day', created_at)"
	for name, q := range map[string]string{
		"usage by-day":  spendReconUsageByDayQuery,
		"ledger by-day": spendReconLedgerByDayQuery,
	} {
		if strings.Contains(q, bareBucket) {
			t.Errorf("%s query uses bare %s (session-TZ dependent)", name, bareBucket)
		}
		if !strings.Contains(q, "created_at AT TIME ZONE $4::text") {
			t.Errorf("%s query must bucket with created_at AT TIME ZONE $4::text, got:\n%s", name, q)
		}
		if !strings.Contains(q, "created_at >= $2 AND created_at < $3") {
			t.Errorf("%s query window bounds must stay absolute ($2/$3), got:\n%s", name, q)
		}
	}
	if strings.Contains(spendReconUsageTotalQuery, "date_trunc") {
		t.Errorf("UI-parity total must stay day-free (no date_trunc), got:\n%s", spendReconUsageTotalQuery)
	}
}

// TestSpendReconReportZoneResolver pins the reader-side zone resolution:
// empty is UTC, a valid zone resolves to its canonical name, and an
// unknown zone errors instead of silently falling back to UTC.
func TestSpendReconReportZoneResolver(t *testing.T) {
	for in, want := range map[string]string{
		"":                 "UTC",
		"UTC":              "UTC",
		"America/New_York": "America/New_York",
	} {
		got, err := spendReconReportZone(in)
		if err != nil {
			t.Errorf("spendReconReportZone(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("spendReconReportZone(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := spendReconReportZone("Mars/Olympus_Mons"); err == nil {
		t.Error("spendReconReportZone(unknown zone): expected error, got none")
	}
}

// TestReconcileSpendZoneEchoAndText checks the zone surfaces a caller reads:
// nil input zone means UTC (legacy default), a zone is echoed as resolved,
// and the text render names it.
func TestReconcileSpendZoneEchoAndText(t *testing.T) {
	rep := ReconcileSpend(spendReconHappyInput())
	if rep.Zone != "UTC" {
		t.Errorf("nil-zone report zone = %q, want UTC", rep.Zone)
	}
	out := rep.RenderText()
	if !strings.Contains(out, "UTC — ok") {
		t.Errorf("RenderText = %q, want it to contain %q", out, "UTC — ok")
	}

	in := spendReconHappyInput()
	in.Zone = mustNY(t)
	ny := ReconcileSpend(in)
	if ny.Zone != "America/New_York" {
		t.Errorf("zoned report zone = %q, want America/New_York", ny.Zone)
	}
	if out := ny.RenderText(); !strings.Contains(out, "America/New_York") {
		t.Errorf("RenderText = %q, want it to contain the zone", out)
	}
}
