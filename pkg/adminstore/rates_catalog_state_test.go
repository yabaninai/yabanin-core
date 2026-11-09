package adminstore

// Unit coverage for the durable rates-catalog promotion surfaces
// (AUDIT-P1-04). The transactional behavior — single-tx atomicity,
// advisory-lock serialization, override retention, restart persistence —
// is exercised against the disposable testcontainers Postgres in
// integration_rates_catalog_state_test.go; this file pins the pure parts.

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRatesMaterializationSummary_RendersPlanDeterministically(t *testing.T) {
	report := pricing.Day0Report{
		Total:   4,
		Added:   1,
		Updated: 1,
		Skipped: 2,
		Removed: 1,
		Ops: []pricing.Day0Op{
			{Provider: "openai", Model: "gpt-x", Action: pricing.Day0ActionAdd},
			{Provider: "openai", Model: "gpu", Action: pricing.Day0ActionSkip,
				Reason: "manual override (source=local_gpu)"},
			{Provider: "openai", Model: "huge", Action: pricing.Day0ActionSkip,
				Reason: "price outside numeric(10,6) range"},
			{Provider: "openai", Model: "retired", Action: pricing.Day0ActionClose,
				Reason: "catalog entry removed"},
		},
	}
	summary := ratesMaterializationSummary(report)
	require.NotNil(t, summary)
	assert.Equal(t, 1, summary.Added)
	assert.Equal(t, 1, summary.Updated)
	assert.Equal(t, 2, summary.Skipped)
	assert.Equal(t, 1, summary.Removed)
	assert.Equal(t, []string{"openai/gpu"}, summary.RetainedOverrides)
	assert.Equal(t, []string{"openai/huge"}, summary.RangeSkipped)

	// Same plan, same summary — twice (no map-order leakage).
	assert.Equal(t, summary, ratesMaterializationSummary(report))
}

func TestRatesMaterializationSummary_EmptyPlan(t *testing.T) {
	summary := ratesMaterializationSummary(pricing.Day0Report{})
	require.NotNil(t, summary)
	assert.Equal(t, 0, summary.Added)
	assert.Empty(t, summary.RetainedOverrides)
	assert.Empty(t, summary.RangeSkipped)
}

func TestPromoteRefCatalogDurable_Guards(t *testing.T) {
	ctx := context.Background()

	// A store without a pool must fail closed, not panic.
	var bare *Store
	_, err := bare.PromoteRefCatalogDurable(ctx, []byte("{}"), "op")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a database pool")

	_, err = (&Store{}).PromoteRefCatalogDurable(ctx, pricing.BundledRefPackJSON(), "op")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a database pool")

	// The promoting operator identity is mandatory — the audit column must
	// never hold an empty stamp.
	store := &Store{}
	_, err = store.PromoteRefCatalogDurable(ctx, pricing.BundledRefPackJSON(), "  ")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "activated_by")
}

func TestLoadRatesCatalogState_Guards(t *testing.T) {
	ctx := context.Background()
	var bare *Store
	_, err := bare.LoadRatesCatalogState(ctx)
	require.Error(t, err)
	_, _, err = bare.DurableRatesCatalogPackJSON(ctx)
	require.Error(t, err)
	_, err = bare.CurrentDurableRatesCatalog(ctx)
	require.Error(t, err)
}
