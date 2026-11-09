package consumer

// N06-P06-T07 boundary corpus (aspect battery, mock/unit stand): the three
// packet aspects pinned as POINTWISE edge cases, complementing the packet's
// accepted records — T02's shape pins, T03's NY-March window pins, T05's
// per-seam negative corpus and T06's single joint operator journey. This
// file holds every case that is deterministic without Postgres; the live
// ±1µs reader boundaries are in n06p6t07_boundary_real_pg_test.go.
//
//   - Aspect A (parse): the full ±int64 micro-USD lattice of
//     ParseInvoiceUSDMicro. The negative endpoint MinInt64 was REJECTED
//     before this card (the bound checked only the positive side) although
//     the documented contract errors only on values that do not fit int64 —
//     fixed here and pinned on both sides of both endpoints.
//   - Aspect B (zoned bucketing): exact absolute instants of DST days,
//     half-open window membership at exact-touch boundaries (day ending at
//     From, day starting at To, sub-day window around the spring-forward
//     instant), adversarial byte labels failing closed, and cross-zone
//     recompute stability of an already-exported report.
//   - Aspect C (export/reconcile): the once-per-row cents kernel at
//     half-cent edges, the TOTAL-cents = Σ row-cents (never cents of Σ
//     micro) conservation pin, the four-fact-class window-edge corpus in
//     one report, and the CSV shape under adversarial day labels.

import (
	"bytes"
	"encoding/csv"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/require"
)

const n06p6t07NY = "America/New_York"

// TestN06P6T07ParseInt64Lattice — aspect A: ParseInvoiceUSDMicro at both
// int64 endpoints and the malformed shapes around them. The four negative
// endpoint cases are the T07 defect fix points (MinInt64 = -2^63 µUSD is
// representable and must parse; one micro more must not).
func TestN06P6T07ParseInt64Lattice(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    int64
		wantErr bool
	}{
		// --- int64 endpoint lattice (µUSD) ---
		{"max positive exact", "9223372036854.775807", math.MaxInt64, false},
		{"max positive +1µ", "9223372036854.775808", 0, true},
		{"max positive next dollar", "9223372036855.0", 0, true},
		{"min negative exact (MinInt64)", "-9223372036854.775808", math.MinInt64, false},
		{"min negative −1µ", "-9223372036854.775809", 0, true},
		{"min negative next dollar", "-9223372036855.000000", 0, true},
		{"integer part ParseInt overflow", "9223372036854775808", 0, true},
		{"negative integer part overflow", "-9223372036854775808", 0, true},
		// --- shape lattice (new points vs the T02 pins) ---
		{"negative sub-micro truncates", "-0.000001", -1, false},
		{"negative zero", "-0", 0, false},
		{"leading zeros both parts", "000001.000001", 1_000_001, false},
		{"fraction only", ".000001", 1, false},
		{"integer part with trailing dot", "1.", 1_000_000, false},
		{"tab padded", "\t2.5\t", 2_500_000, false},
		{"comma as decimal mark", "12,34", 0, true},
		{"thousands separated", "1,234.56", 0, true},
		{"uppercase exponent", "1E5", 0, true},
		{"negative exponent", "1.5e-2", 0, true},
		{"column shift day label", "2026-09-01", 0, true},
		{"fullwidth digits", "１２.５", 0, true},
		{"whitespace only", "   ", 0, true},
		{"inner space", "1 2", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseInvoiceUSDMicro(tc.in)
			if tc.wantErr {
				require.Error(t, err, "input %q must be rejected", tc.in)
				return
			}
			require.NoError(t, err, "input %q must parse", tc.in)
			require.Equal(t, tc.want, got)
		})
	}
	// MinInt64's magnitude is MaxInt64+1: the pair must be asymmetric by
	// exactly one micro-USD (the fix's observable contract).
	min, err := ParseInvoiceUSDMicro("-9223372036854.775808")
	require.NoError(t, err)
	max, err := ParseInvoiceUSDMicro("9223372036854.775807")
	require.NoError(t, err)
	require.Equal(t, -max-1, min, "|MinInt64| = MaxInt64+1")
}

// TestN06P6T07ZonedDayWindowLattice — aspect B (unit): exact DST-day
// instants, exact-touch window membership and adversarial byte labels.
func TestN06P6T07ZonedDayWindowLattice(t *testing.T) {
	ny, err := budget.ResolveReportZone(n06p6t07NY)
	require.NoError(t, err)

	// Exact absolute instants: the NY spring-forward day is 23h (local
	// midnight 05:00Z), the fall-back day 25h (04:00Z), the day after the
	// jump back to 24h EDT (04:00Z).
	dayCases := []struct {
		day      string
		wantFrom time.Time
		wantTo   time.Time
	}{
		{"2026-03-08", time.Date(2026, 3, 8, 5, 0, 0, 0, time.UTC), time.Date(2026, 3, 9, 4, 0, 0, 0, time.UTC)},
		{"2026-03-09", time.Date(2026, 3, 9, 4, 0, 0, 0, time.UTC), time.Date(2026, 3, 10, 4, 0, 0, 0, time.UTC)},
		{"2026-11-01", time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC), time.Date(2026, 11, 2, 5, 0, 0, 0, time.UTC)},
	}
	for _, tc := range dayCases {
		p, err := budget.DayReportPeriod(tc.day, n06p6t07NY)
		require.NoError(t, err)
		require.Equal(t, tc.day, p.Label)
		require.Equal(t, n06p6t07NY, p.Zone)
		require.True(t, p.From.Equal(tc.wantFrom), "%s From = %s, want %s", tc.day, p.From, tc.wantFrom)
		require.True(t, p.To.Equal(tc.wantTo), "%s To = %s, want %s", tc.day, p.To, tc.wantTo)
		require.Equal(t, tc.wantTo.Sub(tc.wantFrom), p.To.Sub(p.From))
	}

	// Month windows spanning the transitions.
	march, err := budget.MonthReportPeriod("2026-03", n06p6t07NY)
	require.NoError(t, err)
	require.True(t, march.From.Equal(time.Date(2026, 3, 1, 5, 0, 0, 0, time.UTC)), "march From = %s", march.From)
	require.True(t, march.To.Equal(time.Date(2026, 4, 1, 4, 0, 0, 0, time.UTC)), "march To = %s", march.To)
	nov, err := budget.MonthReportPeriod("2026-11", n06p6t07NY)
	require.NoError(t, err)
	require.True(t, nov.From.Equal(time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC)), "nov From = %s", nov.From)
	require.True(t, nov.To.Equal(time.Date(2026, 12, 1, 5, 0, 0, 0, time.UTC)), "nov To = %s", nov.To)
	for label, want := range map[string]struct {
		n         int
		firstLast [2]string
	}{
		"2026-03": {31, [2]string{"2026-03-01", "2026-03-31"}},
		"2026-11": {30, [2]string{"2026-11-01", "2026-11-30"}},
	} {
		p := march
		if label == "2026-11" {
			p = nov
		}
		buckets := p.DayBuckets()
		require.Len(t, buckets, want.n)
		require.Equal(t, want.firstLast[0], buckets[0])
		require.Equal(t, want.firstLast[1], buckets[len(buckets)-1])
	}

	// Half-open membership at the month-window extremes (T03 endpoints kept
	// so the lattice is self-contained) and at the DST-day windows
	// themselves: a day ENDING exactly at From and a day STARTING exactly
	// at To are both outside.
	for day, want := range map[string]bool{
		"2026-02-28": false, "2026-03-01": true, "2026-03-31": true, "2026-04-01": false,
	} {
		got, err := spendReconDayInWindow(day, march.From, march.To, ny)
		require.NoError(t, err)
		require.Equal(t, want, got, "march window membership of %s", day)
	}
	spring, err := budget.DayReportPeriod("2026-03-08", n06p6t07NY)
	require.NoError(t, err)
	for day, want := range map[string]bool{"2026-03-07": false, "2026-03-08": true, "2026-03-09": false} {
		got, err := spendReconDayInWindow(day, spring.From, spring.To, ny)
		require.NoError(t, err)
		require.Equal(t, want, got, "spring-forward day window membership of %s", day)
	}
	fall, err := budget.DayReportPeriod("2026-11-01", n06p6t07NY)
	require.NoError(t, err)
	for day, want := range map[string]bool{"2026-10-31": false, "2026-11-01": true, "2026-11-02": false} {
		got, err := spendReconDayInWindow(day, fall.From, fall.To, ny)
		require.NoError(t, err)
		require.Equal(t, want, got, "fall-back day window membership of %s", day)
	}

	// A sub-day window around the spring-forward instant (02:00 local =
	// 07:00Z) still classifies by [From, To) intersection, not by calendar
	// day equality.
	clipFrom := time.Date(2026, 3, 8, 6, 30, 0, 0, time.UTC)
	clipTo := time.Date(2026, 3, 8, 7, 30, 0, 0, time.UTC)
	for day, want := range map[string]bool{"2026-03-07": false, "2026-03-08": true, "2026-03-09": false} {
		got, err := spendReconDayInWindow(day, clipFrom, clipTo, ny)
		require.NoError(t, err)
		require.Equal(t, want, got, "clipped spring-forward window membership of %s", day)
	}

	// Adversarial byte labels fail closed: BOM, CR, LF and space padding
	// are parse errors (violations upstream), never silent in-window days.
	for _, day := range []string{"\ufeff2026-03-08", "2026-03-08\r", " 2026-03-08", "2026-03-08 ", "2026-03-08\n"} {
		_, err := spendReconDayInWindow(day, march.From, march.To, ny)
		require.Error(t, err, "byte-padded day %q must not parse", day)
	}
}

// TestN06P6T07CrossZoneRecomputeStable — aspect B: computing a second
// report in another zone must not mutate the first report or its export
// bytes (the T06 determinism pin, extended across zones).
func TestN06P6T07CrossZoneRecomputeStable(t *testing.T) {
	inUTC := spendReconHappyInput()
	inUTC.Zone = time.UTC
	inNY := spendReconHappyInput()
	inNY.Zone = nyLoc(t)

	repUTC := ReconcileSpend(inUTC)
	require.Equal(t, SpendReconStatusOK, repUTC.Status)
	require.Equal(t, "UTC", repUTC.Zone)
	var buf bytes.Buffer
	require.NoError(t, repUTC.WriteCSV(&buf))
	bytesBefore := buf.Bytes()

	repNY := ReconcileSpend(inNY)
	require.Equal(t, SpendReconStatusOK, repNY.Status)
	require.Equal(t, n06p6t07NY, repNY.Zone)
	// Identical facts ⇒ identical numbers; only the zone echo differs.
	require.True(t, reflect.DeepEqual(repUTC.Days, repNY.Days),
		"same facts in another zone must not change day rows")

	// The first report's bytes are stable after the second computation,
	// and recomputing from the same input reproduces it exactly.
	var bufAfter bytes.Buffer
	require.NoError(t, repUTC.WriteCSV(&bufAfter))
	require.True(t, bytes.Equal(bytesBefore, bufAfter.Bytes()),
		"cross-zone recompute mutated the first report's export")
	require.True(t, reflect.DeepEqual(repUTC, ReconcileSpend(inUTC)),
		"first input/report changed by the interleaved NY run")
}

func nyLoc(t *testing.T) *time.Location {
	t.Helper()
	loc, err := budget.ResolveReportZone(n06p6t07NY)
	require.NoError(t, err)
	return loc
}

// TestN06P6T07CentsHalfCentLattice — aspect C: the once-per-row cents
// kernel (money.MicroUSD.Cents, half away from zero) at the ±half-cent
// edges, pinned through the export row projection (spendReconDayCSVRow).
func TestN06P6T07CentsHalfCentLattice(t *testing.T) {
	cases := []struct {
		name      string
		confirmed int64
		wantCents int64
	}{
		{"+4999µ rounds toward zero", 4_999, 0},
		{"+5000µ half rounds away", 5_000, 1},
		{"+5001µ rounds up", 5_001, 1},
		{"−4999µ rounds toward zero", -4_999, 0},
		{"−5000µ half rounds away", -5_000, -1},
		{"−5001µ rounds away", -5_001, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vals, _ := spendReconDayCSVRow(SpendReconDayReport{ConfirmedMicro: tc.confirmed})
			// vals[11] = confirmed_cents_usd, vals[12] = captured_cents_usd
			// (captured = confirmed + 0 shadow).
			require.Equal(t, tc.wantCents, vals[11])
			require.Equal(t, tc.wantCents, vals[12])
		})
	}
}

// TestN06P6T07CentsConservationInTotal — aspect C: TOTAL cents is the sum
// of the emitted per-row cents, NOT the cents of the summed micro. Two
// days of $4.994999 display 499¢ each (Σ 998¢) while the period's
// $9.989998 would round to 999¢ if rounded once; the export must emit 998.
func TestN06P6T07CentsConservationInTotal(t *testing.T) {
	in := spendReconHappyInput()
	in.Usage[0].ConfirmedMicro = 4_994_999
	in.Usage[0].Requests = 1
	in.Usage[1].ConfirmedMicro = 4_994_999
	in.Usage[1].Requests = 1
	// Usage[1] keeps its $0.10 shadow: captured day 2 = $5.094999 → 509¢.
	in.UITotalMicro = 9_989_998
	in.Invoice = []SpendReconInvoiceDay{
		{Day: "2026-09-01", InvoiceMicro: 4_994_999},
		{Day: "2026-09-02", InvoiceMicro: 5_094_999},
	}
	rep := ReconcileSpend(in)
	require.Equal(t, SpendReconStatusOK, rep.Status, "violations: %+v", rep.Violations)

	recs := spendReconExportRecords(t, rep)
	require.Len(t, recs, 4) // header + 2 days + TOTAL
	// confirmed_cents_usd (col 12): 499 + 499 = 998, not cents($9.989998)=999.
	require.Equal(t, "499", recs[1][12])
	require.Equal(t, "499", recs[2][12])
	require.Equal(t, "998", recs[3][12])
	require.Equal(t, int64(999), money.MicroUSD(9_989_998).Cents(),
		"counterfactual: rounding the summed micro once would differ")
	// captured_cents_usd (col 13): 499 + 509 = 1008, not cents($10.089998)=1009.
	require.Equal(t, "499", recs[1][13])
	require.Equal(t, "509", recs[2][13])
	require.Equal(t, "1008", recs[3][13])
	require.Equal(t, int64(1009), money.MicroUSD(10_089_998).Cents())
	// The totals columns stay the exact micro sums.
	require.Equal(t, "9989998", recs[3][1])
	require.Equal(t, "10089998", recs[3][7])
	// The generic detail/total identity still holds.
	n06p6t05AssertDetailSumsToTotals(t, rep)
}

// n06p6t07EdgeLabels — the day labels at, and one micro-step of bytes
// beyond, the happy window [2026-09-01, 2026-09-03): the day ending
// exactly at From, the day starting exactly at To, and the byte-padded
// variants of an in-window day.
func n06p6t07EdgeLabels() []string {
	return []string{"2026-08-31", "2026-09-03", "\ufeff2026-09-01", "2026-09-01\r", " 2026-09-01", "2026-09-01\n"}
}

// TestN06P6T07WindowEdgeViolationCorpus — aspect C: all four fact classes
// probed at the same window-edge labels in ONE report; every reader-side
// class must fail closed with a visible day_outside_period violation, the
// invoice class separates countable-outside from malformed-violation, and
// no total moves.
func TestN06P6T07WindowEdgeViolationCorpus(t *testing.T) {
	t.Run("usage days at edges fail closed", func(t *testing.T) {
		in := spendReconHappyInput()
		for _, label := range n06p6t07EdgeLabels() {
			in.Usage = append(in.Usage, SpendReconUsageDay{Day: label, ConfirmedMicro: 111_111, Requests: 1})
		}
		rep := ReconcileSpend(in)
		require.Equal(t, SpendReconStatusViolation, rep.Status)
		for _, label := range n06p6t07EdgeLabels() {
			if spendReconFindViolation(rep, ViolationDayOutsidePeriod, label) == nil {
				t.Errorf("violations %+v missing day_outside_period for %q", rep.Violations, label)
			}
		}
		require.Equal(t, int64(3_750_000), rep.ConfirmedTotalMicro, "out-of-window rows must not move the total")
		require.Len(t, rep.Days, 2)
	})
	t.Run("ledger days at edges fail closed", func(t *testing.T) {
		in := spendReconHappyInput()
		for _, label := range n06p6t07EdgeLabels() {
			in.Ledger = append(in.Ledger, SpendReconLedgerDay{Day: label, WalletMicro: -222_222, WalletCentsAppliedMicro: -222_222, WalletTxns: 1})
		}
		rep := ReconcileSpend(in)
		require.Equal(t, SpendReconStatusViolation, rep.Status)
		for _, label := range n06p6t07EdgeLabels() {
			if spendReconFindViolation(rep, ViolationDayOutsidePeriod, label) == nil {
				t.Errorf("violations %+v missing day_outside_period for %q", rep.Violations, label)
			}
		}
		require.Equal(t, int64(-3_000_000), rep.WalletMicro, "out-of-window rows must not move the wallet")
	})
	t.Run("settlement days at edges fail closed", func(t *testing.T) {
		in := spendReconHappyInput()
		for _, label := range n06p6t07EdgeLabels() {
			in.Settlements = append(in.Settlements, SpendReconSettlementDay{Day: label, EstimatedMicro: 333_333, EstimatedRequests: 1})
		}
		rep := ReconcileSpend(in)
		require.Equal(t, SpendReconStatusViolation, rep.Status)
		for _, label := range n06p6t07EdgeLabels() {
			if spendReconFindViolation(rep, ViolationDayOutsidePeriod, label) == nil {
				t.Errorf("violations %+v missing day_outside_period for %q", rep.Violations, label)
			}
		}
		require.Equal(t, int64(0), rep.EstimatedTotalMicro, "out-of-window rows must not move the estimated total")
	})
	t.Run("invoice edges split countable vs malformed", func(t *testing.T) {
		in := spendReconHappyInput()
		in.Invoice = append(in.Invoice,
			SpendReconInvoiceDay{Day: "2026-08-31", InvoiceMicro: 11},       // ends at From → counted outside
			SpendReconInvoiceDay{Day: "2026-08-31", InvoiceMicro: 22},       // duplicate outside day still counted
			SpendReconInvoiceDay{Day: "2026-09-03", InvoiceMicro: 33},       // starts at To → counted outside
			SpendReconInvoiceDay{Day: "2028-02-29", InvoiceMicro: 44},       // valid leap day, out of window → counted
			SpendReconInvoiceDay{Day: "\ufeff2026-09-01", InvoiceMicro: 55}, // BOM byte → violation
			SpendReconInvoiceDay{Day: "2026-02-29", InvoiceMicro: 66},       // impossible date → violation
		)
		rep := ReconcileSpend(in)
		require.Equal(t, SpendReconStatusViolation, rep.Status)
		require.Equal(t, int64(4), rep.InvoiceDaysOutsidePeriod, "parseable out-of-window days are counted, not violated")
		for _, label := range []string{"2026-08-31", "2026-09-03", "2028-02-29"} {
			if v := spendReconFindViolation(rep, ViolationDayOutsidePeriod, label); v != nil {
				t.Errorf("countable day %q must not be a violation: %+v", label, v)
			}
		}
		for _, label := range []string{"\ufeff2026-09-01", "2026-02-29"} {
			if spendReconFindViolation(rep, ViolationDayOutsidePeriod, label) == nil {
				t.Errorf("violations %+v missing day_outside_period for malformed %q", rep.Violations, label)
			}
		}
		require.Equal(t, int64(3_850_000), rep.InvoiceTotalMicro, "outside/malformed lines must not move the invoice total")
		require.Len(t, rep.Days, 2)
	})
	t.Run("all four classes jointly export the happy rows only", func(t *testing.T) {
		in := spendReconHappyInput()
		for _, label := range n06p6t07EdgeLabels() {
			in.Usage = append(in.Usage, SpendReconUsageDay{Day: label, ConfirmedMicro: 111_111, Requests: 1})
			in.Ledger = append(in.Ledger, SpendReconLedgerDay{Day: label, WalletMicro: -222_222, WalletCentsAppliedMicro: -222_222, WalletTxns: 1})
			in.Settlements = append(in.Settlements, SpendReconSettlementDay{Day: label, EstimatedMicro: 333_333, EstimatedRequests: 1})
			in.Invoice = append(in.Invoice, SpendReconInvoiceDay{Day: label, InvoiceMicro: 444_444})
		}
		rep := ReconcileSpend(in)
		require.Equal(t, SpendReconStatusViolation, rep.Status)
		require.Len(t, rep.Days, 2)

		recs := spendReconExportRecords(t, rep)
		require.Len(t, recs, 4) // header + 2 happy days + TOTAL
		for _, row := range recs {
			require.Len(t, row, len(spendReconCSVColumns))
		}
		for _, row := range recs {
			for _, cell := range row {
				for _, label := range n06p6t07EdgeLabels() {
					require.NotEqual(t, label, cell, "adversarial day label must never become a CSV cell")
				}
				require.NotContains(t, cell, "\ufeff")
				require.NotContains(t, cell, "\r")
				require.NotContains(t, cell, "\n")
			}
		}
		require.Equal(t, "TOTAL", recs[len(recs)-1][0])
		n06p6t05AssertDetailSumsToTotals(t, rep)
	})
}

// TestN06P6T07CSVFlagsCellRoundTrip — aspect C: a day carrying two
// violations exports them in ONE pipe-joined flags cell, and an
// encoding/csv round-trip preserves the cell and the column count.
func TestN06P6T07CSVFlagsCellRoundTrip(t *testing.T) {
	in := spendReconHappyInput()
	in.Usage[0].UnpricedMicro = 5 // day 09-01 → unpriced_nonzero flag
	in.Usage[0].UnpricedRequests = 1
	in.Invoice[0].InvoiceMicro = 900_000 // day gap $0.60 > $0.50 tolerance → invoice_gap_exceeded on 09-01
	rep := ReconcileSpend(in)
	require.Equal(t, SpendReconStatusViolation, rep.Status)
	require.Len(t, rep.Days[0].Flags, 2, "day 09-01 must carry both flags: %+v", rep.Days[0].Flags)

	var buf bytes.Buffer
	require.NoError(t, rep.WriteCSV(&buf))
	recs, err := csv.NewReader(&buf).ReadAll()
	require.NoError(t, err)
	require.Len(t, recs, 4)
	for _, row := range recs {
		require.Len(t, row, len(spendReconCSVColumns))
	}
	want := strings.Join(rep.Days[0].Flags, "|")
	require.Equal(t, want, recs[1][len(spendReconCSVColumns)-1],
		"two violations must survive as one pipe-joined cell, not split rows")
	require.Equal(t, "TOTAL", recs[len(recs)-1][0])
}
