package adminstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PricingEntry represents a row in the models_pricing table.
type PricingEntry struct {
	ID             int64      `json:"id"`
	Provider       string     `json:"provider"`
	Model          string     `json:"model"`
	InputPerM      float64    `json:"input_per_m"`
	OutputPerM     float64    `json:"output_per_m"`
	CacheWritePerM float64    `json:"cache_write_per_m"`
	CacheReadPerM  float64    `json:"cache_read_per_m"`
	Source         string     `json:"source"`
	SourceRef      string     `json:"source_ref,omitempty"`
	UpdatedBy      string     `json:"updated_by,omitempty"`
	EffectiveFrom  time.Time  `json:"effective_from"`
	EffectiveTo    *time.Time `json:"effective_to,omitempty"`
}

// CreatePricingParams holds parameters for creating a new pricing entry.
type CreatePricingParams struct {
	Provider       string  `json:"provider"`
	Model          string  `json:"model"`
	InputPerM      float64 `json:"input_per_m"`
	OutputPerM     float64 `json:"output_per_m"`
	CacheWritePerM float64 `json:"cache_write_per_m"`
	CacheReadPerM  float64 `json:"cache_read_per_m"`
	Source         string  `json:"source,omitempty"`
	SourceRef      string  `json:"source_ref,omitempty"`
	UpdatedBy      string  `json:"updated_by,omitempty"`
}

// UpdatePricingParams holds parameters for updating an existing pricing entry.
type UpdatePricingParams struct {
	ID             int64      `json:"-"`
	InputPerM      *float64   `json:"input_per_m,omitempty"`
	OutputPerM     *float64   `json:"output_per_m,omitempty"`
	CacheWritePerM *float64   `json:"cache_write_per_m,omitempty"`
	CacheReadPerM  *float64   `json:"cache_read_per_m,omitempty"`
	EffectiveTo    *time.Time `json:"effective_to,omitempty"`
	Source         *string    `json:"source,omitempty"`
	SourceRef      *string    `json:"source_ref,omitempty"`
}

// ListPricingOptions holds filter options for listing pricing entries.
type ListPricingOptions struct {
	Provider string // Optional filter by provider
	Model    string // Optional filter by model
	Active   bool   // If true, only return entries where effective_to IS NULL
}

// CreatePricing inserts a new pricing entry into models_pricing.
// It automatically sets effective_from to now() and effective_to to NULL (active).
func (s *Store) CreatePricing(ctx context.Context, p CreatePricingParams) (*PricingEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	source := p.Source
	if source == "" {
		source = "manual"
	}
	if err := validatePricingSource(source); err != nil {
		return nil, err
	}

	var entry PricingEntry
	var buf pricingScanBuf
	buf.entry = &entry
	err := s.db.QueryRow(ctx, `
		INSERT INTO models_pricing (provider, model, input_per_m, output_per_m, cache_write_per_m, cache_read_per_m, source, source_ref, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''))
		RETURNING `+pricingReturningCols+`
	`, p.Provider, p.Model, p.InputPerM, p.OutputPerM, p.CacheWritePerM, p.CacheReadPerM, source, p.SourceRef, p.UpdatedBy).Scan(buf.dest()...)
	if err != nil {
		return nil, fmt.Errorf("create pricing: %w", err)
	}
	buf.finish()

	return &entry, nil
}

// UpdatePricing modifies an existing pricing entry.
// If EffectiveTo is set, it marks the entry as deprecated/expired.
func (s *Store) UpdatePricing(ctx context.Context, p UpdatePricingParams) (*PricingEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	query := `UPDATE models_pricing SET`
	args := []interface{}{}
	argIdx := 1

	if p.InputPerM != nil {
		if argIdx > 1 {
			query += ","
		}
		query += fmt.Sprintf(" input_per_m = $%d", argIdx)
		args = append(args, *p.InputPerM)
		argIdx++
	}
	if p.OutputPerM != nil {
		if argIdx > 1 {
			query += ","
		}
		query += fmt.Sprintf(" output_per_m = $%d", argIdx)
		args = append(args, *p.OutputPerM)
		argIdx++
	}
	if p.CacheWritePerM != nil {
		if argIdx > 1 {
			query += ","
		}
		query += fmt.Sprintf(" cache_write_per_m = $%d", argIdx)
		args = append(args, *p.CacheWritePerM)
		argIdx++
	}
	if p.CacheReadPerM != nil {
		if argIdx > 1 {
			query += ","
		}
		query += fmt.Sprintf(" cache_read_per_m = $%d", argIdx)
		args = append(args, *p.CacheReadPerM)
		argIdx++
	}
	if p.EffectiveTo != nil {
		if argIdx > 1 {
			query += ","
		}
		query += fmt.Sprintf(" effective_to = $%d", argIdx)
		args = append(args, *p.EffectiveTo)
		argIdx++
	}

	if p.Source != nil {
		if err := validatePricingSource(*p.Source); err != nil {
			return nil, err
		}
		if argIdx > 1 {
			query += ","
		}
		query += fmt.Sprintf(" source = $%d", argIdx)
		args = append(args, *p.Source)
		argIdx++
	}
	if p.SourceRef != nil {
		if argIdx > 1 {
			query += ","
		}
		query += fmt.Sprintf(" source_ref = $%d", argIdx)
		args = append(args, *p.SourceRef)
		argIdx++
	}

	if argIdx == 1 {
		return nil, fmt.Errorf("no fields to update")
	}

	query += fmt.Sprintf(" WHERE id = $%d RETURNING "+pricingReturningCols, argIdx)
	args = append(args, p.ID)

	var entry PricingEntry
	var buf pricingScanBuf
	buf.entry = &entry
	err := s.db.QueryRow(ctx, query, args...).Scan(buf.dest()...)
	if err != nil {
		return nil, fmt.Errorf("update pricing: %w", err)
	}
	buf.finish()

	return &entry, nil
}

// DeletePricing permanently removes a pricing entry from models_pricing.
func (s *Store) DeletePricing(ctx context.Context, id int64) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}

	result, err := s.db.Exec(ctx, "DELETE FROM models_pricing WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete pricing: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("pricing entry with id %d not found", id)
	}

	return nil
}

// ListPricing returns pricing entries with optional filters.
func (s *Store) ListPricing(ctx context.Context, opts ListPricingOptions) ([]PricingEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	query := `SELECT ` + pricingReturningCols + ` FROM models_pricing WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if opts.Provider != "" {
		query += fmt.Sprintf(" AND provider = $%d", argIdx)
		args = append(args, opts.Provider)
		argIdx++
	}
	if opts.Model != "" {
		query += fmt.Sprintf(" AND model = $%d", argIdx)
		args = append(args, opts.Model)
	}
	if opts.Active {
		query += " AND effective_to IS NULL"
	}

	query += " ORDER BY provider, model, effective_from DESC"

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list pricing: %w", err)
	}
	defer rows.Close()

	var entries []PricingEntry
	for rows.Next() {
		var e PricingEntry
		var buf pricingScanBuf
		buf.entry = &e
		if err := rows.Scan(buf.dest()...); err != nil {
			break
		}
		buf.finish()
		entries = append(entries, e)
	}

	return entries, nil
}

const pricingReturningCols = `id, provider, model, input_per_m, output_per_m, cache_write_per_m, cache_read_per_m, source, source_ref, updated_by, effective_from, effective_to`

type pricingScanBuf struct {
	entry     *PricingEntry
	sourceRef sql.NullString
	updatedBy sql.NullString
}

func (b *pricingScanBuf) dest() []any {
	return []any{
		&b.entry.ID, &b.entry.Provider, &b.entry.Model,
		&b.entry.InputPerM, &b.entry.OutputPerM, &b.entry.CacheWritePerM, &b.entry.CacheReadPerM,
		&b.entry.Source, &b.sourceRef, &b.updatedBy,
		&b.entry.EffectiveFrom, &b.entry.EffectiveTo,
	}
}

func (b *pricingScanBuf) finish() {
	if b.sourceRef.Valid {
		b.entry.SourceRef = b.sourceRef.String
	}
	if b.updatedBy.Valid {
		b.entry.UpdatedBy = b.updatedBy.String
	}
}

func validatePricingSource(source string) error {
	switch source {
	case "manual", "catalog", "local_gpu", "seed":
		return nil
	default:
		return fmt.Errorf("pricing source %q is not allowed", source)
	}
}
