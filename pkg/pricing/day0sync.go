package pricing

import (
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Day0SourceCatalog is the models_pricing.source value that marks rows owned
// by a catalog sync (the day-0 pricing sync and the admin catalog import
// share the convention). The schema already constrains source to
// {manual, catalog, local_gpu, seed} (migrations/0001_init.up.sql), so the
// sync can tell its own rows from operator overrides without a migration:
// any open row whose source is not "catalog" is a human/seed override and
// must never be rewritten by a sync.
const Day0SourceCatalog = "catalog"

// Day0SourceSeed is the models_pricing.source value shipped by 0001_init for
// the baseline rows. Promotion semantics supersede seed rows together with
// catalog rows (they are catalog machinery defaults, not operator intent);
// manual and local_gpu rows stay operator-owned and are never rewritten.
const Day0SourceSeed = "seed"

// Day0UpdatedBy stamps the updated_by column of rows the day-0 sync writes,
// so sync-created rows are auditable separately from admin-UI edits.
const Day0UpdatedBy = "pricing-sync"

// day0PerMMax mirrors the numeric(10,6) upper bound of models_pricing price
// columns: a per-1M price above this would fail the INSERT, so the planner
// skips the entry with an explicit reason instead of aborting the batch.
const day0PerMMax = 9999.999999

// day0Epsilon is the price equality tolerance. Prices are stored as
// numeric(10,6) and cross float64 twice (write, then read back); 5e-7 is
// half of the last stored decimal, so a re-sync of an identical catalog
// classifies every row as unchanged instead of flapping update/skip.
const day0Epsilon = 5e-7

// Day-0 sync actions reported per catalog entry.
const (
	Day0ActionAdd    = "add"
	Day0ActionUpdate = "update"
	Day0ActionSkip   = "skip"
	// Day0ActionClose retires an open row set by key: promotion closes every
	// open seed/catalog row for keys the promoted catalog no longer projects
	// (operator-owned manual/local_gpu rows are never closed). Only
	// PlanCatalogPromotion emits it; the day-0 planner never does.
	Day0ActionClose = "close"
)

// Day0ActiveRow is the open (effective_to IS NULL) models_pricing state for
// one (provider, model) key — the row DBPricer would read for that key.
type Day0ActiveRow struct {
	ID             int64
	Source         string
	InputPerM      float64
	OutputPerM     float64
	CacheWritePerM float64
	CacheReadPerM  float64
}

// Day0Insert is the row a sync op writes into models_pricing. Prices are
// USD per 1M tokens (the models_pricing unit).
type Day0Insert struct {
	Provider       string
	Model          string
	InputPerM      float64
	OutputPerM     float64
	CacheWritePerM float64
	CacheReadPerM  float64
	SourceRef      string
}

// Day0Op is the planned outcome for one catalog entry. Ops are sorted by
// (provider, model), so two runs on the same inputs produce identical
// reports.
type Day0Op struct {
	Provider string
	Model    string
	Action   string // Day0ActionAdd | Day0ActionUpdate | Day0ActionSkip | Day0ActionClose
	Reason   string // empty for add; otherwise why the entry updated or was skipped
	CloseID  int64  // update: id of the open catalog row to close (effective_to = now())
	Insert   Day0Insert
}

// Day0Report is the deterministic dry-run/apply plan for one sync run.
type Day0Report struct {
	Added   int
	Updated int
	Skipped int
	// Removed counts the Day0ActionClose ops (promotion-only): keys the
	// promoted catalog retired. The day-0 planner always leaves it zero.
	Removed int
	Total   int
	Ops     []Day0Op
}

// PlanDay0Sync compares a converted catalog (USD per 1M tokens, as produced
// by ImportLiteLLM) against the active models_pricing rows and returns the
// ops ApplyDay0Sync would execute:
//
//   - no open row for the key           → add: insert with source='catalog'
//   - open row with source='catalog'    → update (close + re-insert) when
//     prices differ, otherwise skip "unchanged"
//   - open row with any other source    → skip "manual override": the sync
//     never clobbers manual/seed/local_gpu rows
//
// A price that cannot be stored in numeric(10,6) (NaN, negative or above
// day0PerMMax per 1M) is skipped with a range reason.
func PlanDay0Sync(catalog PriceFile, active map[string]*Day0ActiveRow) Day0Report {
	models := make([]PriceFileModel, len(catalog.Models))
	copy(models, catalog.Models)
	sort.Slice(models, func(i, j int) bool {
		if models[i].Provider != models[j].Provider {
			return models[i].Provider < models[j].Provider
		}
		return models[i].Model < models[j].Model
	})

	var report Day0Report
	report.Total = len(models)
	for _, m := range models {
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
			row := active[day0Key(m.Provider, m.Model)]
			switch {
			case row == nil:
				op.Action = Day0ActionAdd
				report.Added++
			case row.Source == Day0SourceCatalog:
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
	return report
}

// day0Querier is the read surface shared by pools and open transactions;
// both *pgxpool.Pool and pgx.Tx satisfy it.
type day0Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// LoadActivePricing reads every open models_pricing row into the
// (provider, model) → row map the planner compares against. When several
// rows are open for one key (history that was never closed) the newest
// effective_from wins, matching which row DBPricer serves for that key.
func LoadActivePricing(ctx context.Context, pool *pgxpool.Pool) (map[string]*Day0ActiveRow, error) {
	return loadActivePricingQ(ctx, pool)
}

// LoadActivePricingTx is LoadActivePricing for an open transaction. The
// durable promotion flow must plan against the projection it is about to
// mutate, serialized by the same transaction's advisory lock — planning on
// the pool would race the write it is about to apply.
func LoadActivePricingTx(ctx context.Context, tx pgx.Tx) (map[string]*Day0ActiveRow, error) {
	return loadActivePricingQ(ctx, tx)
}

func loadActivePricingQ(ctx context.Context, q day0Querier) (map[string]*Day0ActiveRow, error) {
	rows, err := q.Query(ctx, `
		SELECT id, provider, model, source, input_per_m, output_per_m,
		       COALESCE(cache_write_per_m, 0), COALESCE(cache_read_per_m, 0)
		FROM models_pricing
		WHERE effective_to IS NULL
		ORDER BY effective_from DESC, id DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("read active pricing: %w", err)
	}
	defer rows.Close()

	out := make(map[string]*Day0ActiveRow)
	for rows.Next() {
		var (
			row             Day0ActiveRow
			provider, model string
		)
		if err := rows.Scan(&row.ID, &provider, &model, &row.Source,
			&row.InputPerM, &row.OutputPerM, &row.CacheWritePerM, &row.CacheReadPerM); err != nil {
			return nil, fmt.Errorf("scan active pricing: %w", err)
		}
		key := day0Key(provider, model)
		if _, dup := out[key]; !dup { // newest-first: the first row seen wins
			out[key] = &row
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active pricing: %w", err)
	}
	return out, nil
}

// ApplyDay0Sync executes the add/update ops of a report in one transaction.
// Skips write nothing. Updates close the planned row
// (effective_to = now()) guarded by "AND effective_to IS NULL": if the row
// changed between planning and apply the guard fails and the whole run
// aborts with an error instead of writing a divergent history.
func ApplyDay0Sync(ctx context.Context, pool *pgxpool.Pool, report Day0Report) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin pricing sync: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := ApplyDay0SyncTx(ctx, tx, Day0UpdatedBy, report); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit pricing sync: %w", err)
	}
	return nil
}

// ApplyDay0SyncTx executes the add/update/close ops of a report on an open
// transaction — the transactional core shared by ApplyDay0Sync and the admin
// rates-catalog promotion (which must write its durable state row and this
// models_pricing materialization atomically). updatedBy stamps the written
// rows' updated_by column; the day-0 sync passes Day0UpdatedBy, promotion
// passes its operator-stamped actor. A close op retires EVERY open
// seed/catalog row for the op's (provider, model) key; if none is open the
// run aborts (changed-since-plan, same guard philosophy as update).
func ApplyDay0SyncTx(ctx context.Context, tx pgx.Tx, updatedBy string, report Day0Report) error {
	for _, op := range report.Ops {
		switch op.Action {
		case Day0ActionAdd:
			if err := day0InsertTx(ctx, tx, op.Insert, updatedBy); err != nil {
				return err
			}
		case Day0ActionUpdate:
			tag, err := tx.Exec(ctx,
				`UPDATE models_pricing SET effective_to = now() WHERE id = $1 AND effective_to IS NULL`,
				op.CloseID)
			if err != nil {
				return fmt.Errorf("close pricing %d: %w", op.CloseID, err)
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("close pricing %d: row is no longer open (changed since plan)", op.CloseID)
			}
			if err := day0InsertTx(ctx, tx, op.Insert, updatedBy); err != nil {
				return err
			}
		case Day0ActionClose:
			tag, err := tx.Exec(ctx,
				`UPDATE models_pricing SET effective_to = now()
				 WHERE provider = $1 AND model = $2 AND effective_to IS NULL
				   AND source = ANY($3)`,
				op.Provider, op.Model, []string{Day0SourceCatalog, Day0SourceSeed})
			if err != nil {
				return fmt.Errorf("close pricing %s/%s: %w", op.Provider, op.Model, err)
			}
			if tag.RowsAffected() == 0 {
				return fmt.Errorf("close pricing %s/%s: no open catalog row (changed since plan)",
					op.Provider, op.Model)
			}
		case Day0ActionSkip:
			// nothing to write
		}
	}
	return nil
}

func day0InsertTx(ctx context.Context, tx pgx.Tx, in Day0Insert, updatedBy string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO models_pricing
			(provider, model, input_per_m, output_per_m, cache_write_per_m, cache_read_per_m, source, source_ref, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9)
	`, in.Provider, in.Model, in.InputPerM, in.OutputPerM, in.CacheWritePerM, in.CacheReadPerM,
		Day0SourceCatalog, in.SourceRef, updatedBy); err != nil {
		return fmt.Errorf("insert pricing %s/%s: %w", in.Provider, in.Model, err)
	}
	return nil
}

func day0Key(provider, model string) string {
	return provider + "\x00" + model
}

func day0Storable(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= day0PerMMax
}

func day0SamePrice(row *Day0ActiveRow, m PriceFileModel) bool {
	return day0Close(row.InputPerM, m.Input) &&
		day0Close(row.OutputPerM, m.Output) &&
		day0Close(row.CacheWritePerM, m.CacheW) &&
		day0Close(row.CacheReadPerM, m.CacheR)
}

func day0Close(a, b float64) bool {
	return math.Abs(a-b) < day0Epsilon
}
