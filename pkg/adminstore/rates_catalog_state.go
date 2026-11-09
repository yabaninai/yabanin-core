package adminstore

// Durable rates-catalog promotion (AUDIT-P1-04).
//
// PromoteRefCatalog re-seats the process pricer in memory only: a restart
// silently falls back to the committed pack and every other replica keeps
// serving the old prices until each process is promoted by hand. This file
// closes both gaps with a single-row durable record plus a transactional
// materialization:
//
//   - migration 0019 adds rates_catalog_state (id = 1 CHECK): the active
//     pack bytes plus their provenance (catalog version/digest, pack
//     SHA256, operator, instant). Active-of-record = that row when it
//     exists, else the committed bundled pack;
//   - PromoteRefCatalogDurable verifies the next pack against the
//     active-of-record (chain), renders the review diff, plans the
//     models_pricing materialization with pricing.PlanCatalogPromotion and
//     applies it with pricing.ApplyDay0SyncTx — upsert of the state row and
//     materialization commit together, serialized by
//     pg_advisory_xact_lock(hashtext('rates_catalog_state')) so two racing
//     promotions cannot interleave plan and write;
//   - after commit the process re-seats its pricer (parity with the legacy
//     path); OTHER processes and post-restart processes read
//     rates_catalog_state directly and serve the promoted prices through
//     the existing DBPricer per-entry TTL (≤5 min propagation, no restart,
//     no explicit invalidation — pinned by the pricing TTL test);
//   - GET /api/rates/catalog reads the active-of-record bytes, so every
//     process reports the same catalog citation.
//
// The gateway serving path (pkg/gateway) is deliberately untouched: it
// already reads models_pricing through DBPricer.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// ratesCatalogQuerier is the read/write surface shared by the pool and open
// transactions; both *pgxpool.Pool and pgx.Tx satisfy it.
type ratesCatalogQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// RatesCatalogStateRow is the durable active-of-record: the pack bytes a
// deployment serves after a promotion, plus the citation provenance and the
// operator stamp.
type RatesCatalogStateRow struct {
	Version     string    // catalog_version — the promoted catalog's version
	Digest      string    // catalog_digest — sealed catalog digest
	PackSHA256  string    // pack_sha256 — envelope digest
	PackJSON    []byte    // pack_json — the full sealed envelope bytes
	ActivatedBy string    // activated_by — promoting operator identity
	ActivatedAt time.Time // activated_at — promotion instant
}

// LoadRatesCatalogState returns the durable active-of-record row, or nil
// when no promotion has landed yet (bundled pack is then the anchor).
func (s *Store) LoadRatesCatalogState(ctx context.Context) (*RatesCatalogStateRow, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("rates catalog state: store has no database pool")
	}
	return loadRatesCatalogStateQ(ctx, s.pool)
}

func loadRatesCatalogStateQ(ctx context.Context, q ratesCatalogQuerier) (*RatesCatalogStateRow, error) {
	row := &RatesCatalogStateRow{}
	err := q.QueryRow(ctx, `
		SELECT catalog_version, catalog_digest, pack_sha256, pack_json,
		       activated_by, activated_at
		FROM rates_catalog_state
		WHERE id = 1
	`).Scan(&row.Version, &row.Digest, &row.PackSHA256, &row.PackJSON,
		&row.ActivatedBy, &row.ActivatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil //nolint:nilnil // absent row is a meaningful state, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("read rates_catalog_state: %w", err)
	}
	return row, nil
}

// DurableRatesCatalogPackJSON returns the active-of-record pack bytes plus a
// found flag: the durable row's bytes when a promotion has landed, else the
// committed bundled pack (true anchor semantics for the chain check). A
// transient database error is an error, NOT a silent fallback to the
// bundled pack — a stale anchor could bless a promotion the active chain
// forbids.
func (s *Store) DurableRatesCatalogPackJSON(ctx context.Context) ([]byte, bool, error) {
	row, err := s.LoadRatesCatalogState(ctx)
	if err != nil {
		return nil, false, err
	}
	if row == nil {
		return pricing.BundledRefPackJSON(), false, nil
	}
	return row.PackJSON, true, nil
}

// CurrentDurableRatesCatalog is the active-of-record GET payload: the
// promoted catalog when one has landed, else the committed reference pack.
func (s *Store) CurrentDurableRatesCatalog(ctx context.Context) (*RatesCatalog, error) {
	packJSON, found, err := s.DurableRatesCatalogPackJSON(ctx)
	if err != nil {
		return nil, err
	}
	if !found {
		return CurrentRefRatesCatalog()
	}
	return RefRatesCatalogFromPack(packJSON)
}

// PromoteRefCatalogDurable is the durable PromoteRefCatalog: one
// transaction writes the active-of-record row and materializes models_pricing
// so the promoted prices are served by every process (within the DBPricer
// TTL) and survive restarts. Refusals and chain failures behave exactly
// like the legacy path — *RatesRefusal for the review gate (422 body),
// plain errors for load/chain/serve failures — and on any failure nothing
// is written and the current pricer is left untouched.
func (s *Store) PromoteRefCatalogDurable(ctx context.Context, nextPackJSON []byte, activatedBy string) (*RatesPromotion, error) {
	if strings.TrimSpace(activatedBy) == "" {
		return nil, errors.New("rates promotion: activated_by is required")
	}
	if s == nil || s.pool == nil {
		return nil, errors.New("rates promotion: durable promotion requires a database pool")
	}
	// Offline gates before any lock is held (fail fast, no DB pressure):
	// seal + envelope verification, the serveability probe (the exact
	// pricer that will be seated) and the planner projection.
	pricer, err := pricing.ServeCatalogFromPack(nextPackJSON)
	if err != nil {
		return nil, fmt.Errorf("rates promotion: %w", err)
	}
	projection, err := pricing.ProjectionFromPack(nextPackJSON)
	if err != nil {
		return nil, fmt.Errorf("rates promotion: %w", err)
	}
	nextPack, _, err := pricing.LoadRefPack(nextPackJSON)
	if err != nil {
		return nil, fmt.Errorf("rates promotion: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("rates promotion: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after commit

	// Serialize promotions: every plan→write sequence for the catalog
	// state holds this transaction-scoped advisory lock, so the chain
	// anchor cannot change between the read below and the upsert.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('rates_catalog_state'))`); err != nil {
		return nil, fmt.Errorf("rates promotion: lock: %w", err)
	}

	// Active-of-record INSIDE the locked transaction (TOCTOU-safe anchor).
	prevJSON, _, err := s.DurableRatesCatalogPackJSONTx(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("rates promotion: %w", err)
	}

	if err := pricing.VerifyRefPackChain(prevJSON, nextPackJSON); err != nil {
		return nil, fmt.Errorf("rates promotion: %w", err)
	}
	diff, err := DiffRefRatesCatalogs(prevJSON, nextPackJSON)
	if err != nil {
		return nil, err
	}
	if diff.Refused {
		return nil, &RatesRefusal{Report: diff}
	}

	// Plan against the models_pricing projection this transaction sees,
	// then write row + materialization together.
	active, err := pricing.LoadActivePricingTx(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("rates promotion: plan: %w", err)
	}
	report := pricing.PlanCatalogPromotion(projection, active)

	if _, err := tx.Exec(ctx, `
		INSERT INTO rates_catalog_state
			(id, catalog_version, catalog_digest, pack_sha256, pack_json,
			 activated_by, activated_at)
		VALUES (1, $1, $2, $3, $4, $5, now())
		ON CONFLICT (id) DO UPDATE SET
			catalog_version = EXCLUDED.catalog_version,
			catalog_digest  = EXCLUDED.catalog_digest,
			pack_sha256     = EXCLUDED.pack_sha256,
			pack_json       = EXCLUDED.pack_json,
			activated_by    = EXCLUDED.activated_by,
			activated_at    = now()
	`, diff.To.Version, diff.To.Digest, nextPack.PackSHA256, nextPackJSON, activatedBy); err != nil {
		return nil, fmt.Errorf("rates promotion: write state: %w", err)
	}
	if err := pricing.ApplyDay0SyncTx(ctx, tx,
		pricing.Day0UpdatedByPromotionPrefix+activatedBy, report); err != nil {
		return nil, fmt.Errorf("rates promotion: materialize: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("rates promotion: commit: %w", err)
	}

	// Process parity: this process serves the promoted prices immediately;
	// peers converge via DBPricer's per-entry TTL off rates_catalog_state.
	pricing.SetDefaultFilePricer(pricer)
	return &RatesPromotion{
		Before:          diff.From,
		After:           diff.To,
		Diff:            diff,
		Applied:         true,
		Persisted:       true,
		Materialization: ratesMaterializationSummary(report),
	}, nil
}

// DurableRatesCatalogPackJSONTx is DurableRatesCatalogPackJSON over an open
// transaction — the promotion's TOCTOU-safe anchor read.
func (s *Store) DurableRatesCatalogPackJSONTx(ctx context.Context, tx pgx.Tx) ([]byte, bool, error) {
	row, err := loadRatesCatalogStateQ(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	if row == nil {
		return pricing.BundledRefPackJSON(), false, nil
	}
	return row.PackJSON, true, nil
}

// ratesMaterializationSummary renders the operator-facing materialization
// summary from the plan. Ops arrive sorted, so the lists are deterministic.
func ratesMaterializationSummary(report pricing.Day0Report) *RatesMaterializationSummary {
	summary := &RatesMaterializationSummary{
		Added:             report.Added,
		Updated:           report.Updated,
		Skipped:           report.Skipped,
		Removed:           report.Removed,
		RetainedOverrides: []string{},
		RangeSkipped:      []string{},
	}
	for _, op := range report.Ops {
		switch {
		case strings.HasPrefix(op.Reason, "manual override"):
			summary.RetainedOverrides = append(summary.RetainedOverrides, op.Provider+"/"+op.Model)
		case strings.HasPrefix(op.Reason, "price outside"):
			summary.RangeSkipped = append(summary.RangeSkipped, op.Provider+"/"+op.Model)
		}
	}
	return summary
}
