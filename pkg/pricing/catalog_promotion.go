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
	projected := make(map[string]PriceFileModel, len(catalog.Models))
	order := make([]string, 0, len(catalog.Models))
	for _, m := range catalog.Models {
		k := day0Key(m.Provider, m.Model)
		if _, dup := projected[k]; !dup {
			order = append(order, k)
		}
		projected[k] = m // last entry wins, matching the FilePricer projection
	}
	sort.Strings(order)

	var report Day0Report
	report.Total = len(order)
	for _, k := range order {
		m := projected[k]
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
				SourceRef:      catalog.Source + "#" + m.Provider + "/" + m.Model,
			},
		}
		switch {
		case !day0Storable(m.Input) || !day0Storable(m.Output) ||
			!day0Storable(m.CacheW) || !day0Storable(m.CacheR):
			op.Action = Day0ActionSkip
			op.Reason = "price outside numeric(10,6) range"
			report.Skipped++
		default:
			row := active[k]
			switch {
			case row == nil:
				op.Action = Day0ActionAdd
				report.Added++
			case row.Source == Day0SourceCatalog || row.Source == Day0SourceSeed:
				if day0SamePrice(row, m) {
					op.Action = Day0ActionSkip
					op.Reason = "unchanged"
					report.Skipped++
				} else {
					op.Action = Day0ActionUpdate
					op.Reason = "catalog price changed"
					op.CloseID = row.ID
					report.Updated++
				}
			default:
				op.Action = Day0ActionSkip
				op.Reason = "manual override (source=" + row.Source + ")"
				report.Skipped++
			}
		}
		report.Ops = append(report.Ops, op)
	}

	// Retired keys: every active key whose newest open row is catalog
	// machinery (seed or catalog) and that the promoted catalog no longer
	// projects. Operator overrides (manual / local_gpu newest row) keep
	// serving — the close block must not retire operator intent.
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
	for _, k := range retired {
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
