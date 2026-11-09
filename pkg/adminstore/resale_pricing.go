package adminstore

// services/admin/handlers/resale_handlers.go. Every statement below is the
// byte-equivalent of the handler query it replaces (behavior-preserving
// move). The upsert pair intentionally differs, exactly as the original
// call sites did: UpsertResalePricing (HTTP PUT) reactivates the rule and
// refreshes the fixed per-M rates on conflict; CreateResalePricing
// (programmatic) only refreshes markup_pct and updated_at.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ResalePricing is one reseller_pricing row — the JSON surface of the
// admin resale-pricing list/get endpoints (field order and tags must stay
// identical to the former in-handler pricingRow).
type ResalePricing struct {
	ID              int64     `json:"id"`
	OrgID           *string   `json:"org_id,omitempty"`
	ModelName       *string   `json:"model_name,omitempty"`
	MarkupPct       float64   `json:"markup_pct"`
	FixedInputPerM  *float64  `json:"fixed_input_per_m,omitempty"`
	FixedOutputPerM *float64  `json:"fixed_output_per_m,omitempty"`
	Active          bool      `json:"active"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// resaleModelName normalizes the optional model name: nil or empty means
// "all models" and is stored as SQL NULL so pkg/pricing markup resolution
// can match org-wide rules via model_name IS NULL.
func resaleModelName(modelName *string) *string {
	if modelName == nil || *modelName == "" {
		return nil
	}
	return modelName
}

// UpsertResalePricing inserts or updates a resale pricing rule (HTTP PUT
// path) and returns the row id.
func (s *Store) UpsertResalePricing(ctx context.Context, orgID string, modelName *string, markupPct float64, fixedInputPerM, fixedOutputPerM *float64) (int64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not configured")
	}

	var id int64
	err := s.db.QueryRow(ctx, `
	INSERT INTO reseller_pricing (org_id, model_name, markup_pct, fixed_input_per_m, fixed_output_per_m, active)
	VALUES ($1, $2, $3, $4, $5, true)
	ON CONFLICT (org_id, model_name) DO UPDATE SET
		markup_pct = EXCLUDED.markup_pct,
		fixed_input_per_m = EXCLUDED.fixed_input_per_m,
		fixed_output_per_m = EXCLUDED.fixed_output_per_m,
		active = true,
		updated_at = now()
	RETURNING id
	`, orgID, resaleModelName(modelName), markupPct, fixedInputPerM, fixedOutputPerM).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// CreateResalePricing is the programmatic upsert (original handler helper
// CreateResalePricing): on conflict only markup_pct and updated_at change.
func (s *Store) CreateResalePricing(ctx context.Context, orgID string, modelName *string, markupPct float64, fixedInputPerM, fixedOutputPerM *float64) (int64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not configured")
	}

	var id int64
	err := s.db.QueryRow(ctx, `
		INSERT INTO reseller_pricing (org_id, model_name, markup_pct, fixed_input_per_m, fixed_output_per_m, active)
		VALUES ($1, $2, $3, $4, $5, true)
		ON CONFLICT (org_id, model_name) DO UPDATE SET
			markup_pct = EXCLUDED.markup_pct, updated_at = now()
		RETURNING id
	`, orgID, resaleModelName(modelName), markupPct, fixedInputPerM, fixedOutputPerM).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// ListResalePricing returns all resale pricing rules (HTTP list surface),
// org-wide rules (org_id NULL) first.
func (s *Store) ListResalePricing(ctx context.Context) ([]ResalePricing, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	rows, err := s.db.Query(ctx, `
		SELECT id, org_id, model_name, markup_pct, fixed_input_per_m, fixed_output_per_m, active, created_at, updated_at
		FROM reseller_pricing
		ORDER BY CASE WHEN org_id IS NULL THEN 0 ELSE 1 END, org_id, model_name
	`)
	if err != nil {
		return nil, err
	}
	return scanResalePricingRows(rows, scanResalePricingFull)
}

// ListActiveResalePricing returns the active rules only (original
// programmatic helper ListAllResalePricing); created_at/updated_at are not
// part of that query and stay zero on the returned rows.
func (s *Store) ListActiveResalePricing(ctx context.Context) ([]ResalePricing, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	rows, err := s.db.Query(ctx, `SELECT id, org_id, model_name, markup_pct, fixed_input_per_m, fixed_output_per_m, active FROM reseller_pricing WHERE active = true ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return scanResalePricingRows(rows, scanResalePricingLight)
}

// ListOrgResalePricing returns all pricing rules for an org (HTTP org list),
// org-wide model rules first.
func (s *Store) ListOrgResalePricing(ctx context.Context, orgID string) ([]ResalePricing, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	rows, err := s.db.Query(ctx, `
		SELECT id, org_id, model_name, markup_pct, fixed_input_per_m, fixed_output_per_m, active, created_at, updated_at
		FROM reseller_pricing WHERE org_id = $1 ORDER BY CASE WHEN model_name IS NULL THEN 0 ELSE 1 END, model_name
	`, orgID)
	if err != nil {
		return nil, err
	}
	return scanResalePricingRows(rows, scanResalePricingFull)
}

// ListOrgResalePricingSummary is the original programmatic helper
// GetOrgResalePricing (7 columns, no timestamps) for one org.
func (s *Store) ListOrgResalePricingSummary(ctx context.Context, orgID string) ([]ResalePricing, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	rows, err := s.db.Query(ctx, `SELECT id, org_id, model_name, markup_pct, fixed_input_per_m, fixed_output_per_m, active FROM reseller_pricing WHERE org_id = $1 ORDER BY CASE WHEN model_name IS NULL THEN 0 ELSE 1 END, model_name`, orgID)
	if err != nil {
		return nil, err
	}
	return scanResalePricingRows(rows, scanResalePricingLight)
}

// scanResalePricingRows drains a reseller_pricing rows stream, delegating
// each row to the caller's scan (the full and light projections differ).
func scanResalePricingRows(rows pgx.Rows, scan func(pgx.Rows, *ResalePricing) error) ([]ResalePricing, error) {
	defer rows.Close()
	var items []ResalePricing
	for rows.Next() {
		var pr ResalePricing
		if err := scan(rows, &pr); err != nil {
			return nil, err
		}
		items = append(items, pr)
	}
	return items, rows.Err()
}

// scanResalePricingFull reads the 9-column projection (with timestamps).
func scanResalePricingFull(rows pgx.Rows, pr *ResalePricing) error {
	return rows.Scan(&pr.ID, &pr.OrgID, &pr.ModelName, &pr.MarkupPct, &pr.FixedInputPerM, &pr.FixedOutputPerM, &pr.Active, &pr.CreatedAt, &pr.UpdatedAt)
}

// scanResalePricingLight reads the 7-column projection (no timestamps).
func scanResalePricingLight(rows pgx.Rows, pr *ResalePricing) error {
	return rows.Scan(&pr.ID, &pr.OrgID, &pr.ModelName, &pr.MarkupPct, &pr.FixedInputPerM, &pr.FixedOutputPerM, &pr.Active)
}

// DeactivateResalePricing deactivates a rule by id (both delete paths) and
// reports whether an active row was found.
func (s *Store) DeactivateResalePricing(ctx context.Context, id int64) (bool, error) {
	if s.db == nil {
		return false, fmt.Errorf("database not configured")
	}
	result, err := s.db.Exec(ctx, `UPDATE reseller_pricing SET active = false, updated_at = now() WHERE id = $1 AND active = true`, id)
	if err != nil {
		return false, err
	}
	return result.RowsAffected() > 0, nil
}

// GetResalePricing returns a single pricing rule with timestamps (HTTP get
// surface). A missing row surfaces as pgx.ErrNoRows so the handler maps it
// to 404 exactly as before.
func (s *Store) GetResalePricing(ctx context.Context, id int64) (*ResalePricing, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	var pr ResalePricing
	err := s.db.QueryRow(ctx, `
		SELECT org_id, model_name, markup_pct, fixed_input_per_m, fixed_output_per_m, active, created_at, updated_at
		FROM reseller_pricing WHERE id = $1
	`, id).Scan(&pr.OrgID, &pr.ModelName, &pr.MarkupPct, &pr.FixedInputPerM, &pr.FixedOutputPerM, &pr.Active, &pr.CreatedAt, &pr.UpdatedAt)
	if err != nil {
		return nil, err
	}
	pr.ID = id
	return &pr, nil
}

// GetResalePricingByID is the original programmatic helper (7 columns, no
// timestamps): found=false together with the raw scan error when the row
// does not exist.
func (s *Store) GetResalePricingByID(ctx context.Context, id int64) (*ResalePricing, bool, error) {
	if s.db == nil {
		return nil, false, fmt.Errorf("database not configured")
	}
	var pr ResalePricing
	err := s.db.QueryRow(ctx, `SELECT org_id, model_name, markup_pct, fixed_input_per_m, fixed_output_per_m, active FROM reseller_pricing WHERE id = $1`, id).Scan(&pr.OrgID, &pr.ModelName, &pr.MarkupPct, &pr.FixedInputPerM, &pr.FixedOutputPerM, &pr.Active)
	if err != nil {
		return nil, false, err
	}
	pr.ID = id
	return &pr, true, nil
}
