package adminstore

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/pricing"
)

func TestPlanCatalogImport_ClosesChangedRowAndSkipsMatch(t *testing.T) {
	catalog := pricing.PriceFile{
		Source: "litellm@abc", Date: "2026-09-30", Currency: "USD", Units: "per_1m_tokens",
		Models: []pricing.PriceFileModel{
			{Provider: "openai", Model: "gpt-4o", Input: 2.5, Output: 10},
			{Provider: "openai", Model: "gpt-4o-mini", Input: 0.15, Output: 0.6},
		},
	}
	mappings := []CatalogPriceMap{
		{RegistryProvider: "openai", RegistryModel: "gpt-4o", CatalogProvider: "openai", CatalogModel: "gpt-4o"},
		{RegistryProvider: "openai", RegistryModel: "gpt-4o-mini", CatalogProvider: "openai", CatalogModel: "gpt-4o-mini"},
	}
	active := map[string]*PricingEntry{
		"openai\x00gpt-4o": {ID: 9, Provider: "openai", Model: "gpt-4o", InputPerM: 5, OutputPerM: 15},
	}

	first, ops := PlanCatalogImport(catalog, mappings, active, true, "root@example.com")
	assert.Equal(t, 2, first.Created)
	assert.Equal(t, 0, first.Unchanged)
	require.Len(t, ops, 2)
	assert.Equal(t, int64(9), ops[0].CloseID)
	assert.Equal(t, int64(0), ops[1].CloseID)
	assert.Equal(t, "catalog", ops[0].Insert.Source)
	assert.Equal(t, "litellm@abc#openai/gpt-4o", ops[0].Insert.SourceRef)
	assert.Equal(t, "root@example.com", ops[0].Insert.UpdatedBy)

	active["openai\x00gpt-4o"] = &PricingEntry{ID: 10, InputPerM: 2.5, OutputPerM: 10}
	active["openai\x00gpt-4o-mini"] = &PricingEntry{ID: 11, InputPerM: 0.15, OutputPerM: 0.6}
	second, ops := PlanCatalogImport(catalog, mappings, active, true, "root@example.com")
	assert.Equal(t, 0, second.Created)
	assert.Equal(t, 2, second.Unchanged)
	assert.Empty(t, ops)
}

func TestImportCatalogPricing_ApplyInsertsAndDryRunDoesNot(t *testing.T) {
	catalog := pricing.PriceFile{
		Source: "litellm@abc", Date: "2026-09-30", Currency: "USD", Units: "per_1m_tokens",
		Models: []pricing.PriceFileModel{{Provider: "openai", Model: "gpt-4o", Input: 2.5, Output: 10}},
	}
	mappings := []CatalogPriceMap{{
		RegistryProvider: "openai", RegistryModel: "gpt-4o", CatalogProvider: "openai", CatalogModel: "gpt-4o",
	}}

	dry := &recordingTx{scanErr: pgx.ErrNoRows}
	store := newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return dry, nil }}, newTestLogger(), nil)
	preview, err := store.ImportCatalogPricing(context.Background(), catalog, mappings, true, false, "root@example.com")
	require.NoError(t, err)
	assert.Equal(t, "dry_run", preview.Mode)
	assert.Equal(t, 1, preview.Created)
	assert.False(t, dry.committed)
	assert.Empty(t, dry.execs)

	applyTx := &recordingTx{scanErr: pgx.ErrNoRows}
	store = newForTest(&mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return applyTx, nil }}, newTestLogger(), nil)
	applied, err := store.ImportCatalogPricing(context.Background(), catalog, mappings, true, true, "root@example.com")
	require.NoError(t, err)
	assert.Equal(t, "apply", applied.Mode)
	assert.Equal(t, 1, applied.Created)
	assert.True(t, applyTx.committed)
	require.Len(t, applyTx.execs, 1)
	assert.Contains(t, applyTx.execs[0], "INSERT INTO models_pricing")
}

type recordingTx struct {
	scanErr   error
	execs     []string
	committed bool
}

func (t *recordingTx) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, pgx.ErrNoRows
}
func (t *recordingTx) QueryRow(context.Context, string, ...interface{}) pgx.Row { return t }
func (t *recordingTx) Scan(...interface{}) error                                { return t.scanErr }
func (t *recordingTx) Exec(_ context.Context, sql string, _ ...interface{}) (pgconn.CommandTag, error) {
	t.execs = append(t.execs, sql)
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}
func (t *recordingTx) Commit(context.Context) error {
	t.committed = true
	return nil
}
func (t *recordingTx) Rollback(context.Context) error { return nil }

func TestImportCatalogPricing_UnmatchedCatalog(t *testing.T) {
	catalog := pricing.PriceFile{
		Source: "src", Date: "2026-09-30", Currency: "USD", Units: "per_1m_tokens",
		Models: []pricing.PriceFileModel{{Provider: "openai", Model: "gpt-4o", Input: 1, Output: 1}},
	}
	result, ops := PlanCatalogImport(catalog, []CatalogPriceMap{{
		RegistryProvider: "openai", RegistryModel: "missing", CatalogProvider: "openai", CatalogModel: "nope",
	}}, nil, true, "")
	assert.Empty(t, ops)
	require.Len(t, result.Unmatched, 1)
	assert.Contains(t, result.Unmatched[0], "not found")
}
