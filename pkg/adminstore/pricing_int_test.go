package adminstore

// QA-01: DB-gated pricing CRUD + org settings round-trips against the shared
// dev Postgres (skips when unavailable — repo convention).

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_PricingCRUD_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	model := "qa-pricing-model"
	// Self-sufficient: clean any previous run's rows (idempotent re-runs).
	_, err := pool.Exec(ctx, "DELETE FROM models_pricing WHERE model = $1", model)
	require.NoError(t, err)

	created, err := store.CreatePricing(ctx, CreatePricingParams{
		Provider: "qa", Model: model, InputPerM: 1.5, OutputPerM: 3.0,
		CacheWritePerM: 0.5, CacheReadPerM: 0.25,
	})
	require.NoError(t, err)
	require.Positive(t, created.ID)

	// Current schema keeps pricing history: a second row for the same
	// (provider, model) is allowed (distinct ids / effective_from windows).
	second, err := store.CreatePricing(ctx, CreatePricingParams{Provider: "qa", Model: model})
	require.NoError(t, err)
	require.NotEqual(t, created.ID, second.ID)
	t.Cleanup(func() {
		_ = store.DeletePricing(context.Background(), second.ID)
	})

	newIn := 2.5
	updated, err := store.UpdatePricing(ctx, UpdatePricingParams{ID: created.ID, InputPerM: &newIn})
	require.NoError(t, err)
	assert.InDelta(t, 2.5, updated.InputPerM, 1e-9)
	assert.InDelta(t, 3.0, updated.OutputPerM, 1e-9, "untouched fields keep their values")

	entries, err := store.ListPricing(ctx, ListPricingOptions{Provider: "qa"})
	require.NoError(t, err)
	found := false
	for _, e := range entries {
		if e.ID == created.ID {
			found = true
		}
	}
	assert.True(t, found, "listed entry must include the created row")

	active, err := store.ListPricing(ctx, ListPricingOptions{Active: true})
	require.NoError(t, err)
	assert.NotEmpty(t, active)

	require.NoError(t, store.DeletePricing(ctx, second.ID))
	require.NoError(t, store.DeletePricing(ctx, created.ID))
	entries, err = store.ListPricing(ctx, ListPricingOptions{Provider: "qa", Model: model})
	require.NoError(t, err)
	assert.Empty(t, entries, "deleted pricing must not be listed")
	err = store.DeletePricing(ctx, created.ID)
	require.Error(t, err, "deleting a missing row must fail")
}

// AF-07: coverage status flows from real DB rows through GetCostAnalytics —
// partial windows are marked, empty windows are a distinct state.
func TestStore_CostAnalytics_CoverageStatus_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	const pricedModel = "qa-coverage-priced"
	const mysteryModel = "qa-coverage-mystery"
	for _, m := range []string{pricedModel, mysteryModel} {
		_, err := pool.Exec(ctx, `DELETE FROM models_registry WHERE model_name = $1`, m)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `DELETE FROM models_pricing WHERE model = $1`, m)
		require.NoError(t, err)
	}
	_, err := pool.Exec(ctx, `INSERT INTO models_registry (model_name, display_name) VALUES ($1, $2)`,
		pricedModel, "QA coverage priced")
	require.NoError(t, err)
	created, err := store.CreatePricing(ctx, CreatePricingParams{
		Provider: "openai-compat", Model: pricedModel, InputPerM: 1.0, OutputPerM: 2.0,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM models_registry WHERE model_name IN ($1, $2)`, pricedModel, mysteryModel)
		_, _ = pool.Exec(context.Background(), `DELETE FROM models_pricing WHERE model IN ($1, $2)`, pricedModel, mysteryModel)
		_ = store.DeletePricing(context.Background(), created.ID)
	})

	seed := func(model string) {
		t.Helper()
		_, err := pool.Exec(ctx, `
			INSERT INTO request_logs (org_id, model_requested, model_used, status_code, duration_ms, tokens_in, tokens_out, method, home_region)
			VALUES ($1, $2, $2, 200, 10, 1, 1, 'POST', 'sg')`, orgID, model)
		require.NoError(t, err)
	}
	seed(pricedModel)
	seed(pricedModel)
	seed(mysteryModel) // not in models_pricing → unpriced

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)
	report, err := store.GetCostAnalytics(ctx, orgID, from, to, "")
	require.NoError(t, err)
	require.Equal(t, 3, report.RequestCount)
	p := report.Pricing
	require.Equal(t, CoveragePartial, p.CoverageStatus, "1 of 3 unpriced → explicit partial")
	require.NotNil(t, p.UnpricedShare)
	assert.InDelta(t, 1.0/3.0, *p.UnpricedShare, 1e-9)
	assert.Contains(t, p.UnpricedModels, mysteryModel)
	assert.NotContains(t, p.UnpricedModels, pricedModel)
	assert.Empty(t, p.CoverageError, "successful measurement carries no failure marker")
	assert.Contains(t, p.PricingAsOf, "sha256:",
		"provenance cites the file-backed snapshot, not an as-of claim over the window")

	empty, err := store.GetCostAnalytics(ctx, qaOrg(t, store, ctx), from, to, "")
	require.NoError(t, err)
	assert.Equal(t, CoverageEmpty, empty.Pricing.CoverageStatus, "empty window is a distinct state")
	require.NotNil(t, empty.Pricing.UnpricedShare)
	assert.InDelta(t, 0, *empty.Pricing.UnpricedShare, 0)
}

func TestStore_OrgSettingsRoundTrip_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	slug := "qa-settings-org"
	_, err := pool.Exec(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $2)
		 ON CONFLICT (slug) DO NOTHING`, "QA Settings Org", slug)
	require.NoError(t, err)
	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT id::text FROM organizations WHERE slug = $1", slug).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", orgID)
	})

	cs, err := store.GetOrgCacheSettings(ctx, orgID)
	require.NoError(t, err)
	assert.True(t, cs.CacheEnabled, "orgs default to cache enabled")

	require.NoError(t, store.UpdateOrgCacheSettings(ctx, orgID, false, "exact"))
	cs, err = store.GetOrgCacheSettings(ctx, orgID)
	require.NoError(t, err)
	assert.False(t, cs.CacheEnabled)
	assert.Equal(t, "exact", cs.CacheMode)

	require.NoError(t, store.UpdateOrgRoutingSettings(ctx, orgID, "rules", 0.75))
	rs, err := store.GetOrgRoutingSettings(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, "rules", rs.RoutingMode)
	assert.InDelta(t, 0.75, rs.RoutingThresholdConfidence, 1e-9)
}
