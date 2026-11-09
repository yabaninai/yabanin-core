package consumer

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"github.com/reireirei/yabanin/pkg/money"
)

// CSV export of the spend reconciliation report (N06-P06-T03). The file is
// a flat detail table: header, one row per reconciled day, then a TOTAL
// row. It must stay loadable in a spreadsheet and recomputable by hand, so
// the export carries one hard formatting contract:
//
//   - For every numeric column, the TOTAL row is the exact int64 sum of
//     the emitted detail rows — never re-derived from the report fields.
//     A reader re-adding the detail rows always reproduces the TOTAL row.
//   - Micro-USD columns are exact (no rounding anywhere).
//   - The cents columns are the money-canonical half-away-from-zero
//     projection (money.MicroUSD.Cents) of the same micro values,
//     rounded ONCE PER ROW; the TOTAL cents is the sum of the per-row
//     cents, NOT the cents of the summed micro. Rounding a whole period
//     once instead could differ from the sum of displayed details by up
//     to half a cent per day — this export never does that, so the
//     invoice-comparable cents are Σ displayed details by construction.
//   - The wallet gap, invoice delta and captured columns are derived from
//     the row's own confirmed/shadow/wallet/invoice values, so every row
//     is arithmetically self-contained.
//
// N06-P06-T04 appends the estimated/unresolved dimension as its own
// numeric columns (estimated_micro_usd, estimated_requests,
// unresolved_price_rows, unresolved_price_micro_usd). They are exact
// passthrough of the report's day fields — no cents projection exists for
// them because they are not invoice-comparable dollars (estimated usage is
// not yet captured; unresolved rows are never billed). They are never
// folded into confirmed/captured/wallet/invoice columns: the TOTAL row
// sums each column independently, so the detail rows still re-add to the
// totals per column, including the new ones.
//
// The column order is fixed; new columns append after the last numeric
// column (before the trailing flags annotation) so the positions of all
// previously existing columns stay stable for positional readers.

// spendReconCSVColumns is the fixed column order of the export.
var spendReconCSVColumns = []string{
	"day",
	"confirmed_micro_usd",
	"unpriced_micro_usd",
	"unpriced_requests",
	"legacy_rows",
	"requests",
	"shadow_micro_usd",
	"captured_micro_usd",
	"wallet_micro_usd",
	"wallet_gap_micro_usd",
	"invoice_micro_usd",
	"invoice_delta_micro_usd",
	"confirmed_cents_usd",
	"captured_cents_usd",
	"estimated_micro_usd",
	"estimated_requests",
	"unresolved_price_rows",
	"unresolved_price_micro_usd",
	"flags",
}

// spendReconDayCSVRow derives one detail row's exported numbers from the
// row's own emitted values (the totals columns ReconcileSpend already
// produced) plus the two canonical cent projections. The estimated /
// unresolved columns pass the day fields through untouched — their values
// are already exact integers and are never re-derived, re-rounded or
// mixed into the settled columns.
func spendReconDayCSVRow(d SpendReconDayReport) (vals []int64, flags string) {
	captured := d.ConfirmedMicro + d.ShadowMicro
	gap := d.ConfirmedMicro + d.WalletMicro
	delta := captured - d.InvoiceMicro
	vals = []int64{
		d.ConfirmedMicro,
		d.UnpricedMicro,
		d.UnpricedRequests,
		d.LegacyRows,
		d.Requests,
		d.ShadowMicro,
		captured,
		d.WalletMicro,
		gap,
		d.InvoiceMicro,
		delta,
		money.MicroUSD(d.ConfirmedMicro).Cents(),
		money.MicroUSD(captured).Cents(),
		d.EstimatedMicro,
		d.EstimatedRequests,
		d.UnresolvedPriceRows,
		d.UnresolvedPriceMicro,
	}
	return vals, strings.Join(d.Flags, "|")
}

// WriteCSV renders the report as a flat CSV table: the fixed header, one
// row per day (Days order, chronological), then a TOTAL row whose day
// column is "TOTAL" and whose every numeric column is the exact sum of the
// emitted detail rows (flags empty). The report's day labels are local
// calendar days in r.Zone (see SpendReconInput.Zone) — the export carries
// no timezone column because the whole table is one zone, the one the
// report was computed in. An empty report still emits the header and a
// zero TOTAL row.
func (r SpendReconReport) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(spendReconCSVColumns); err != nil {
		return err
	}

	totals := make([]int64, len(spendReconCSVColumns)-2) // minus day and flags
	row := make([]string, len(spendReconCSVColumns))
	writeRow := func(day string, vals []int64, flags string) error {
		row[0] = day
		for i, v := range vals {
			row[i+1] = strconv.FormatInt(v, 10)
		}
		row[len(row)-1] = flags
		return cw.Write(row)
	}

	for _, d := range r.Days {
		vals, flags := spendReconDayCSVRow(d)
		for i, v := range vals {
			totals[i] += v
		}
		if err := writeRow(d.Day, vals, flags); err != nil {
			return err
		}
	}
	if err := writeRow("TOTAL", totals, ""); err != nil {
		return err
	}

	cw.Flush()
	return cw.Error()
}
