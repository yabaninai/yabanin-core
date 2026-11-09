package adminstore

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// CatalogPriceMap pairs a registry model with a catalog model.
type CatalogPriceMap struct {
	RegistryProvider string `json:"registry_provider"`
	RegistryModel    string `json:"registry_model"`
	CatalogProvider  string `json:"catalog_provider"`
	CatalogModel     string `json:"catalog_model"`
}

// CatalogImportResult is the dry-run or apply report for a price catalog import.
type CatalogImportResult struct {
	Mode      string   `json:"mode"`
	Created   int      `json:"created"`
	Unchanged int      `json:"unchanged"`
	Unmatched []string `json:"unmatched"`
	Errors    []string `json:"errors"`
}

// CatalogWrite is one price row to close and the replacement to insert.
type CatalogWrite struct {
	CloseID int64
	Insert  CreatePricingParams
}

// PlanCatalogImport decides which registry prices to close and replace.
// active is keyed by "provider\x00model" and is nil when no open row exists.
func PlanCatalogImport(catalog pricing.PriceFile, mappings []CatalogPriceMap, active map[string]*PricingEntry, onlyMapped bool, updatedBy string) (CatalogImportResult, []CatalogWrite) {
	result := CatalogImportResult{Unmatched: []string{}, Errors: []string{}}
	byCatalog := make(map[string]pricing.PriceFileModel, len(catalog.Models))
	for _, m := range catalog.Models {
		byCatalog[m.Provider+"\x00"+m.Model] = m
	}
	used := make(map[string]struct{}, len(mappings))
	var ops []CatalogWrite
	for _, pair := range mappings {
		label := pair.RegistryProvider + "/" + pair.RegistryModel
		if pair.RegistryProvider == "" || pair.RegistryModel == "" || pair.CatalogProvider == "" || pair.CatalogModel == "" {
			result.Errors = append(result.Errors, label+": map entry is incomplete")
			continue
		}
		catKey := pair.CatalogProvider + "\x00" + pair.CatalogModel
		used[catKey] = struct{}{}
		model, ok := byCatalog[catKey]
		if !ok {
			result.Unmatched = append(result.Unmatched, label+": catalog "+pair.CatalogProvider+"/"+pair.CatalogModel+" not found")
			continue
		}
		ref := catalog.Source + "#" + pair.CatalogProvider + "/" + pair.CatalogModel
		current := active[pair.RegistryProvider+"\x00"+pair.RegistryModel]
		if current != nil && pricesMatch(*current, model) {
			result.Unchanged++
			continue
		}
		op := CatalogWrite{Insert: CreatePricingParams{
			Provider:       pair.RegistryProvider,
			Model:          pair.RegistryModel,
			InputPerM:      model.Input,
			OutputPerM:     model.Output,
			CacheWritePerM: model.CacheW,
			CacheReadPerM:  model.CacheR,
			Source:         "catalog",
			SourceRef:      ref,
			UpdatedBy:      updatedBy,
		}}
		if current != nil {
			op.CloseID = current.ID
		}
		ops = append(ops, op)
		result.Created++
	}
	if !onlyMapped {
		for _, m := range catalog.Models {
			key := m.Provider + "\x00" + m.Model
			if _, ok := used[key]; ok {
				continue
			}
			result.Unmatched = append(result.Unmatched, "catalog "+m.Provider+"/"+m.Model+" not mapped")
		}
	}
	return result, ops
}

func pricesMatch(row PricingEntry, model pricing.PriceFileModel) bool {
	return priceClose(row.InputPerM, model.Input) &&
		priceClose(row.OutputPerM, model.Output) &&
		priceClose(row.CacheWritePerM, model.CacheW) &&
		priceClose(row.CacheReadPerM, model.CacheR)
}

func priceClose(a, b float64) bool {
	return math.Abs(a-b) < 5e-7
}

// ImportCatalogPricing applies or previews a catalog import in one transaction.
// dry-run reads the open rows and rolls back without writing.
func (s *Store) ImportCatalogPricing(ctx context.Context, catalog pricing.PriceFile, mappings []CatalogPriceMap, onlyMapped, apply bool, updatedBy string) (CatalogImportResult, error) {
	if s.db == nil {
		return CatalogImportResult{}, fmt.Errorf("database not available")
	}
	tx, err := s.db.BeginAuditTx(ctx)
	if err != nil {
		return CatalogImportResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	active := make(map[string]*PricingEntry, len(mappings))
	for _, pair := range mappings {
		if pair.RegistryProvider == "" || pair.RegistryModel == "" {
			continue
		}
		var row PricingEntry
		var buf pricingScanBuf
		buf.entry = &row
		err := tx.QueryRow(ctx, `
			SELECT `+pricingReturningCols+`
			FROM models_pricing
			WHERE provider = $1 AND model = $2 AND effective_to IS NULL
			ORDER BY effective_from DESC
			LIMIT 1
		`, pair.RegistryProvider, pair.RegistryModel).Scan(buf.dest()...)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return CatalogImportResult{}, fmt.Errorf("read active price: %w", err)
		}
		buf.finish()
		copied := row
		active[pair.RegistryProvider+"\x00"+pair.RegistryModel] = &copied
	}

	result, ops := PlanCatalogImport(catalog, mappings, active, onlyMapped, updatedBy)
	if apply {
		result.Mode = "apply"
	} else {
		result.Mode = "dry_run"
	}
	if !apply {
		return result, nil
	}
	for _, op := range ops {
		if op.CloseID != 0 {
			if _, err := tx.Exec(ctx, `UPDATE models_pricing SET effective_to = now() WHERE id = $1 AND effective_to IS NULL`, op.CloseID); err != nil {
				return CatalogImportResult{}, fmt.Errorf("close pricing %d: %w", op.CloseID, err)
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO models_pricing (provider, model, input_per_m, output_per_m, cache_write_per_m, cache_read_per_m, source, source_ref, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''))
		`, op.Insert.Provider, op.Insert.Model, op.Insert.InputPerM, op.Insert.OutputPerM, op.Insert.CacheWritePerM, op.Insert.CacheReadPerM, op.Insert.Source, op.Insert.SourceRef, op.Insert.UpdatedBy); err != nil {
			return CatalogImportResult{}, fmt.Errorf("insert catalog price: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return CatalogImportResult{}, err
	}
	return result, nil
}
