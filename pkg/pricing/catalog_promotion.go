package pricing

import (
	"sort"
	"strings"
)

// Day0UpdatedByPromotionPrefix stamps the updated_by column of rows a rates
// promotion writes: the promoted operator identity follows the prefix (the
// durable rates_catalog_state row records the same identity in activated_by).
// The day-0 sync keeps its own Day0UpdatedBy stamp.
const Day0UpdatedByPromotionPrefix = "rates-promotion:"

// PlanCatalogPromotion plans the models_pricing materialization for a rates
// promotion: the ops that make the table's open rows serve exactly the
// promoted catalog's serveable projection (plus operator overrides). Pure —
// the promotion flow plans outside its transaction, then applies with
// ApplyDay0SyncTx inside it.
//
// Semantics, contrasted with the day-0 sync (PlanDay0Sync):
//
//   - duplicates in the catalog project one key once, LAST entry wins —
//     this mirrors NewFilePricer's byKey construction, so the materialized
//     rows can never diverge from the prices a pack-seated pricer serves;
//   - an open row with source 'catalog' OR 'seed' is superseded (close +
//     re-insert) when prices differ and skipped as unchanged when they do
//     not — seed rows are catalog-machinery defaults a promotion owns, not
//     operator intent;
//   - an open row with source 'manual' or 'local_gpu' is an operator
//     override and is skipped, exactly like the day-0 sync;
//   - a key the promoted catalog no longer projects closes ALL its open
//     seed/catalog rows (Day0ActionClose) unless its newest open row is an
//     operator override — the override keeps serving, and is reported as
//     retained by the caller;
//   - a projected price outside numeric(10,6) is skipped with a range
//     reason (same guard as the day-0 sync).
//
// Ops are sorted by (provider, model) and the close block after them, so two
// runs on the same inputs produce identical reports.
func PlanCatalogPromotion(catalog PriceFile, active map[string]*Day0ActiveRow) Day0Report {
	projected, order := promoProjection(catalog)

	var report Day0Report
	report.Total = len(order)
	for _, k := range order {
		op := promoEntryOp(catalog.Source, projected[k], active[k])
		report.Ops = append(report.Ops, op)
		switch op.Action {
		case Day0ActionAdd:
			report.Added++
		case Day0ActionUpdate:
			report.Updated++
		default:
			report.Skipped++
		}
	}

	for _, k := range promoRetiredKeys(projected, active) {
		provider, model, _ := strings.Cut(k, "\x00")
		report.Ops = append(report.Ops, Day0Op{
			Provider: provider,
			Model:    model,
			Action:   Day0ActionClose,
			Reason:   "catalog entry removed",
		})
		report.Removed++
	}
	return report
}

// promoProjection projects the catalog the way NewFilePricer builds byKey:
// one key per (provider, model) with the LAST entry winning, and the keys
// in sorted order so the plan is deterministic.
func promoProjection(catalog PriceFile) (projected map[string]PriceFileModel, order []string) {
	projected = make(map[string]PriceFileModel, len(catalog.Models))
	order = make([]string, 0, len(catalog.Models))
	for _, m := range catalog.Models {
		k := day0Key(m.Provider, m.Model)
		if _, dup := projected[k]; !dup {
			order = append(order, k)
		}
		projected[k] = m
	}
	sort.Strings(order)
	return projected, order
}

// promoEntryOp plans one projected entry against its newest open row.
func promoEntryOp(source string, m PriceFileModel, row *Day0ActiveRow) Day0Op {
	op := Day0Op{
		Provider: m.Provider,
		Model:    m.Model,
		Insert: Day0Insert{
			Provider:       m.Provider,
			Model:          m.Model,
			InputPerM:      m.Input,
			OutputPerM:     m.Output,
			CacheWritePerM: m.CacheW,
			CacheReadPerM:  m.CacheR,
			SourceRef:      source + "#" + m.Provider + "/" + m.Model,
		},
	}
	switch {
	case !day0Storable(m.Input) || !day0Storable(m.Output) ||
		!day0Storable(m.CacheW) || !day0Storable(m.CacheR):
		op.Action = Day0ActionSkip
		op.Reason = "price outside numeric(10,6) range"
	default:
		promoRowDecision(&op, row, m)
	}
	return op
}

// promoRowDecision resolves the newest open row for one projected entry:
// no row → add; a catalog or seed row is superseded when prices differ and
// skipped as unchanged otherwise (seed rows are catalog-machinery defaults
// a promotion owns, not operator intent); any other source is an operator
// override and is skipped, exactly like the day-0 sync.
func promoRowDecision(op *Day0Op, row *Day0ActiveRow, m PriceFileModel) {
	switch {
	case row == nil:
		op.Action = Day0ActionAdd
	case row.Source == Day0SourceCatalog || row.Source == Day0SourceSeed:
		if day0SamePrice(row, m) {
			op.Action = Day0ActionSkip
			op.Reason = "unchanged"
		} else {
			op.Action = Day0ActionUpdate
			op.Reason = "catalog price changed"
			op.CloseID = row.ID
		}
	default:
		op.Action = Day0ActionSkip
		op.Reason = "manual override (source=" + row.Source + ")"
	}
}

// promoRetiredKeys lists the sorted active keys whose newest open row is
// catalog machinery (seed or catalog) and that the promoted catalog no
// longer projects. Operator overrides (manual / local_gpu newest row) keep
// serving — the close block must not retire operator intent.
func promoRetiredKeys(projected map[string]PriceFileModel, active map[string]*Day0ActiveRow) []string {
	var retired []string
	for k, row := range active {
		if _, projectedKey := projected[k]; projectedKey {
			continue
		}
		if row.Source == Day0SourceCatalog || row.Source == Day0SourceSeed {
			retired = append(retired, k)
		}
	}
	sort.Strings(retired)
	return retired
}
