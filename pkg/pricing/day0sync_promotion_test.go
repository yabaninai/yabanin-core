package pricing

// Planner coverage for the AUDIT-P1-04 promotion materialization: supersede
// seed+catalog rows, keep operator overrides, close retired keys, dedupe
// duplicate projections exactly like the FilePricer byKey construction.
// The SQL side (ApplyDay0SyncTx close semantics) is exercised against the
// disposable testcontainers Postgres from the adminstore integration lane.

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// promoCatalog projects 9 unique keys: adds, a catalog-row update, a
// seed-row update, unchanged skips, an operator override skip and a
// numeric-range skip. It deliberately does NOT project the retired keys the
// active map carries (anthropic/old-catalog, azure/old-seed) nor the
// operator-owned orphans (openai/manual-gone, anthropic/gpu).
func promoCatalog() PriceFile {
	return PriceFile{
		Source: "yabanin-catalog@0.9.x",
		Date:   "2026-11-04",
		Models: []PriceFileModel{
			{Provider: "anthropic", Model: "gpu-retired", Input: 3, Output: 3}, // add (no active row)
			{Provider: "azure", Model: "gpu-retired", Input: 1, Output: 1},     // add (no active row)
			{Provider: "openai", Model: "changed", Input: 3, Output: 4},        // update catalog row 21
			{Provider: "openai", Model: "huge", Input: 20000, Output: 1},       // skip: range
			{Provider: "openai", Model: "new-model", Input: 2, Output: 8},      // add
			{Provider: "openai", Model: "override", Input: 7, Output: 7},       // skip: manual override
			{Provider: "openai", Model: "same", Input: 1, Output: 2},           // skip: unchanged catalog row 22
			{Provider: "openai", Model: "seed-priced", Input: 4, Output: 5},    // update seed row 23 (supersede)
			{Provider: "openai", Model: "seed-same", Input: 1, Output: 2},      // skip: unchanged seed row 24
		},
	}
}

func promoActive() map[string]*Day0ActiveRow {
	return map[string]*Day0ActiveRow{
		"openai\x00changed":       {ID: 21, Source: Day0SourceCatalog, InputPerM: 1, OutputPerM: 2},
		"openai\x00same":          {ID: 22, Source: Day0SourceCatalog, InputPerM: 1, OutputPerM: 2},
		"openai\x00seed-priced":   {ID: 23, Source: Day0SourceSeed, InputPerM: 9, OutputPerM: 9},
		"openai\x00seed-same":     {ID: 24, Source: Day0SourceSeed, InputPerM: 1, OutputPerM: 2},
		"openai\x00override":      {ID: 25, Source: "manual", InputPerM: 5, OutputPerM: 5},
		"openai\x00manual-gone":   {ID: 26, Source: "manual", InputPerM: 4, OutputPerM: 4},
		"anthropic\x00gpu":        {ID: 27, Source: "local_gpu", InputPerM: 0, OutputPerM: 0},
		"anthropic\x00old-cata":   {ID: 28, Source: Day0SourceCatalog, InputPerM: 6, OutputPerM: 6},
		"azure\x00old-seed-rogue": {ID: 29, Source: Day0SourceSeed, InputPerM: 2, OutputPerM: 2},
	}
}

func TestPlanCatalogPromotion_ActionsSortedAndCounted(t *testing.T) {
	report := PlanCatalogPromotion(promoCatalog(), promoActive())

	// 9 projected entries + 2 retired keys.
	require.Len(t, report.Ops, 11)
	assert.Equal(t, 9, report.Total)
	assert.Equal(t, 3, report.Added)   // anthropic/gpu-retired, azure/gpu-retired, new-model
	assert.Equal(t, 2, report.Updated) // changed (catalog), seed-priced (seed supersede)
	assert.Equal(t, 4, report.Skipped) // huge, override, same, seed-same
	assert.Equal(t, 2, report.Removed) // anthropic/old-cata, azure/old-seed-rogue

	type want struct {
		provider, model, action, reason string
		closeID                         int64
	}
	wants := []want{
		{"anthropic", "gpu-retired", Day0ActionAdd, "", 0},
		{"azure", "gpu-retired", Day0ActionAdd, "", 0},
		{"openai", "changed", Day0ActionUpdate, "catalog price changed", 21},
		{"openai", "huge", Day0ActionSkip, "price outside numeric(10,6) range", 0},
		{"openai", "new-model", Day0ActionAdd, "", 0},
		{"openai", "override", Day0ActionSkip, "manual override (source=manual)", 0},
		{"openai", "same", Day0ActionSkip, "unchanged", 0},
		{"openai", "seed-priced", Day0ActionUpdate, "catalog price changed", 23},
		{"openai", "seed-same", Day0ActionSkip, "unchanged", 0},
		{"anthropic", "old-cata", Day0ActionClose, "catalog entry removed", 0},
		{"azure", "old-seed-rogue", Day0ActionClose, "catalog entry removed", 0},
	}
	for i, w := range wants {
		op := report.Ops[i]
		assert.Equal(t, w.provider, op.Provider, "op %d provider", i)
		assert.Equal(t, w.model, op.Model, "op %d model", i)
		assert.Equal(t, w.action, op.Action, "op %d action", i)
		assert.Equal(t, w.reason, op.Reason, "op %d reason", i)
		assert.Equal(t, w.closeID, op.CloseID, "op %d closeID", i)
	}

	// The seed supersede inserts a catalog-owned row citing the promoted
	// catalog provenance; ApplyDay0SyncTx closes row 23 before inserting.
	upd := report.Ops[7]
	assert.Equal(t, "yabanin-catalog@0.9.x#openai/seed-priced", upd.Insert.SourceRef)
	assert.InDelta(t, 4, upd.Insert.InputPerM, 1e-12)
	assert.InDelta(t, 5, upd.Insert.OutputPerM, 1e-12)
}

func TestPlanCatalogPromotion_RetiredKeysNeverTouchOperatorRows(t *testing.T) {
	report := PlanCatalogPromotion(promoCatalog(), promoActive())
	var closed []string
	for _, op := range report.Ops {
		if op.Action == Day0ActionClose {
			closed = append(closed, op.Provider+"/"+op.Model)
		}
	}
	require.Len(t, closed, 2, "only catalog-machinery keys retire: %v", closed)
	assert.Contains(t, closed, "anthropic/old-cata")
	assert.Contains(t, closed, "azure/old-seed-rogue")
	assert.NotContains(t, closed, "openai/manual-gone", "manual overrides are retained")
	assert.NotContains(t, closed, "anthropic/gpu", "local_gpu overrides are retained")
	assert.NotContains(t, closed, "openai/override")
}

func TestPlanCatalogPromotion_DuplicateKeysLastEntryWins(t *testing.T) {
	// Region-scoped catalogs can carry the same (provider, model) twice; the
	// FilePricer serves the LAST entry for a key, so the materialization
	// must plan exactly that row once — any other choice diverges from the
	// served price.
	dup := PriceFile{
		Source: "yabanin-catalog@0.9.x",
		Models: []PriceFileModel{
			{Provider: "openai", Model: "gpt-x", Input: 1, Output: 2},
			{Provider: "openai", Model: "gpt-x", Input: 5, Output: 6}, // last wins
		},
	}
	report := PlanCatalogPromotion(dup, map[string]*Day0ActiveRow{
		"openai\x00gpt-x": {ID: 31, Source: Day0SourceCatalog, InputPerM: 9, OutputPerM: 9},
	})

	require.Len(t, report.Ops, 1)
	assert.Equal(t, 1, report.Total)
	op := report.Ops[0]
	assert.Equal(t, Day0ActionUpdate, op.Action)
	assert.Equal(t, int64(31), op.CloseID)
	assert.InDelta(t, 5, op.Insert.InputPerM, 1e-12, "the LAST entry's price must be materialized")
	assert.InDelta(t, 6, op.Insert.OutputPerM, 1e-12)
}

func TestPlanCatalogPromotion_DeterministicAcrossActiveMapOrder(t *testing.T) {
	// Go map iteration order is randomized; the retired-key block must not
	// leak it. Build two active maps with the same content and different
	// insertion churn, compare full ops.
	build := func(n int) map[string]*Day0ActiveRow {
		active := promoActive()
		for i := 0; i < n; i++ {
			active[fmt.Sprintf("noise\x00m%d", i)] = &Day0ActiveRow{
				ID: int64(100 + i), Source: "manual", InputPerM: 1, OutputPerM: 1}
		}
		return active
	}
	a := PlanCatalogPromotion(promoCatalog(), build(5))
	b := PlanCatalogPromotion(promoCatalog(), build(30))
	assert.Equal(t, a, b)
	assert.Equal(t, 2, a.Removed, "noise keys are operator rows and never retire")
}

func TestPlanCatalogPromotion_EmptyCatalogRetiresAllCatalogRows(t *testing.T) {
	// Degenerate but legal promotion: an empty projection retires every
	// catalog-machinery key and adds nothing; operator rows survive.
	active := map[string]*Day0ActiveRow{
		"a\x00x": {ID: 41, Source: Day0SourceCatalog},
		"b\x00y": {ID: 42, Source: Day0SourceSeed},
		"c\x00z": {ID: 43, Source: "manual"},
	}
	report := PlanCatalogPromotion(PriceFile{Source: "yabanin-catalog@0.9.x"}, active)

	assert.Equal(t, 0, report.Total)
	assert.Equal(t, 0, report.Added)
	assert.Equal(t, 2, report.Removed)
	require.Len(t, report.Ops, 2)
	for _, op := range report.Ops {
		assert.Equal(t, Day0ActionClose, op.Action)
		assert.NotEqual(t, "c", op.Provider, "the manual row must never be closed")
	}
}
