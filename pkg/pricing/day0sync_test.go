package pricing

// (LoadActivePricing / ApplyDay0Sync) is exercised against the disposable
// testcontainers Postgres from pkg/trcli (repo convention: DB stands live
// with the CLI integration tests, skipped in -short / without Docker).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func day0TestCatalog() PriceFile {
	return PriceFile{
		Source: "litellm-test",
		Date:   "2026-10-06",
		Models: []PriceFileModel{
			{Provider: "openai", Model: "manual", Input: 9, Output: 9},
			{Provider: "openai", Model: "catalog-changed", Input: 3, Output: 2},
			{Provider: "openai", Model: "catalog-same", Input: 1, Output: 2},
			{Provider: "openai", Model: "absent", Input: 1, Output: 1, CacheW: 0.5, CacheR: 0.25},
			{Provider: "seed", Model: "gpu", Input: 1, Output: 1},
			{Provider: "huge", Model: "overflow", Input: 20000, Output: 1},
		},
	}
}

func day0TestActive() map[string]*Day0ActiveRow {
	return map[string]*Day0ActiveRow{
		"openai\x00manual":          {ID: 11, Source: "manual", InputPerM: 5, OutputPerM: 5},
		"openai\x00catalog-changed": {ID: 12, Source: Day0SourceCatalog, InputPerM: 1, OutputPerM: 2},
		"openai\x00catalog-same":    {ID: 13, Source: Day0SourceCatalog, InputPerM: 1, OutputPerM: 2},
		"seed\x00gpu":               {ID: 14, Source: "local_gpu", InputPerM: 0, OutputPerM: 0},
	}
}

func TestPlanDay0Sync_ActionsSortedAndCounted(t *testing.T) {
	report := PlanDay0Sync(day0TestCatalog(), day0TestActive())

	require.Len(t, report.Ops, 6)
	assert.Equal(t, 6, report.Total)
	assert.Equal(t, 1, report.Added)
	assert.Equal(t, 1, report.Updated)
	assert.Equal(t, 4, report.Skipped)

	// Deterministic order: sorted by (provider, model).
	want := []struct{ provider, model, action, reason string }{
		{"huge", "overflow", Day0ActionSkip, "price outside numeric(10,6) range"},
		{"openai", "absent", Day0ActionAdd, ""},
		{"openai", "catalog-changed", Day0ActionUpdate, "catalog price changed"},
		{"openai", "catalog-same", Day0ActionSkip, "unchanged"},
		{"openai", "manual", Day0ActionSkip, "manual override (source=manual)"},
		{"seed", "gpu", Day0ActionSkip, "manual override (source=local_gpu)"},
	}
	for i, w := range want {
		op := report.Ops[i]
		assert.Equal(t, w.provider, op.Provider, "op %d", i)
		assert.Equal(t, w.model, op.Model, "op %d", i)
		assert.Equal(t, w.action, op.Action, "op %d", i)
		assert.Equal(t, w.reason, op.Reason, "op %d", i)
	}

	add := report.Ops[1]
	assert.Equal(t, "litellm-test#openai/absent", add.Insert.SourceRef)
	assert.InDelta(t, 1, add.Insert.InputPerM, 1e-12)
	assert.InDelta(t, 0.5, add.Insert.CacheWritePerM, 1e-12)
	assert.InDelta(t, 0.25, add.Insert.CacheReadPerM, 1e-12)
	assert.Equal(t, "openai", add.Insert.Provider)

	update := report.Ops[2]
	assert.InDelta(t, 3, update.Insert.InputPerM, 1e-12)
	assert.InDelta(t, 2, update.Insert.OutputPerM, 1e-12)
}

func TestPlanDay0Sync_ManualRowNeverPlannedForWrite(t *testing.T) {
	report := PlanDay0Sync(day0TestCatalog(), day0TestActive())
	for _, op := range report.Ops {
		if op.Reason == "manual override (source=manual)" || op.Reason == "manual override (source=local_gpu)" {
			assert.Zero(t, op.CloseID, "skip op must not close any row")
			continue
		}
		assert.NotEqual(t, "manual override", op.Action)
	}
}

func TestPlanDay0Sync_IdempotentAfterApply(t *testing.T) {
	catalog := PriceFile{Source: "src", Date: "d", Models: []PriceFileModel{
		{Provider: "p", Model: "a", Input: 1.5, Output: 3},
		{Provider: "p", Model: "b", Input: 0.15, Output: 0.6},
	}}

	active := map[string]*Day0ActiveRow{}
	first := PlanDay0Sync(catalog, active)
	assert.Equal(t, 2, first.Added)
	assert.Equal(t, 0, first.Skipped)

	// Simulate ApplyDay0Sync: every add/update becomes the new open
	// catalog row for its key (adds insert, updates replace).
	active = map[string]*Day0ActiveRow{}
	for i, op := range first.Ops {
		require.Equal(t, Day0ActionAdd, op.Action)
		active[op.Provider+"\x00"+op.Model] = &Day0ActiveRow{
			ID:             int64(100 + i),
			Source:         Day0SourceCatalog,
			InputPerM:      op.Insert.InputPerM,
			OutputPerM:     op.Insert.OutputPerM,
			CacheWritePerM: op.Insert.CacheWritePerM,
			CacheReadPerM:  op.Insert.CacheReadPerM,
		}
	}

	second := PlanDay0Sync(catalog, active)
	assert.Equal(t, 0, second.Added)
	assert.Equal(t, 0, second.Updated)
	assert.Equal(t, 2, second.Skipped)
	for _, op := range second.Ops {
		assert.Equal(t, Day0ActionSkip, op.Action)
		assert.Equal(t, "unchanged", op.Reason)
		assert.Zero(t, op.CloseID)
	}
}

func TestPlanDay0Sync_DeterministicAcrossInputOrder(t *testing.T) {
	catalog := day0TestCatalog()
	reversed := catalog
	reversed.Models = make([]PriceFileModel, len(catalog.Models))
	for i, m := range catalog.Models {
		reversed.Models[len(catalog.Models)-1-i] = m
	}

	a := PlanDay0Sync(catalog, day0TestActive())
	b := PlanDay0Sync(reversed, day0TestActive())
	require.Len(t, a.Ops, len(b.Ops))
	for i := range a.Ops {
		assert.Equal(t, a.Ops[i].Provider, b.Ops[i].Provider)
		assert.Equal(t, a.Ops[i].Model, b.Ops[i].Model)
		assert.Equal(t, a.Ops[i].Action, b.Ops[i].Action)
		assert.Equal(t, a.Ops[i].Reason, b.Ops[i].Reason)
	}
}

func TestPlanDay0Sync_RangeAndSpecialValuesSkipped(t *testing.T) {
	catalog := PriceFile{Source: "s", Date: "d", Models: []PriceFileModel{
		{Provider: "p", Model: "over", Input: 10000, Output: 1},
		{Provider: "p", Model: "exactly-max", Input: 9999.999999, Output: 1},
		{Provider: "p", Model: "negative", Input: -1, Output: 1},
	}}
	report := PlanDay0Sync(catalog, map[string]*Day0ActiveRow{})
	require.Len(t, report.Ops, 3)
	assert.Equal(t, Day0ActionAdd, report.Ops[0].Action, "9999.999999 is the numeric(10,6) max")
	assert.Equal(t, "exactly-max", report.Ops[0].Model)
	assert.Equal(t, Day0ActionSkip, report.Ops[1].Action, "negative price must not be written")
	assert.Equal(t, Day0ActionSkip, report.Ops[2].Action, "10000 overflows numeric(10,6)")
	assert.Equal(t, 2, report.Skipped)
	assert.Equal(t, 1, report.Added)
}
