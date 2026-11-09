package adminstore

// W-CAPS DB round-trip for the org caps surface (migration 0004): defaults
// merge, per-org override isolation (org B never sees org A's caps), clear-
// to-default, unknown-org semantics, and the month-spend accounting window.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_OrgCaps_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	orgA := qaOrg(t, store, ctx)
	orgB := qaOrg(t, store, ctx)

	// No rows: both orgs sit on the beta defaults.
	for _, orgID := range []string{orgA, orgB} {
		eff, err := store.EffectiveOrgCaps(ctx, orgID)
		require.NoError(t, err)
		assert.Equal(t, DefaultOrgCapsRPM, eff.RPM)
		assert.Equal(t, DefaultOrgCapsTPM, eff.TPM)
		assert.Equal(t, DefaultOrgCapsMonthlyBudgetCents, eff.MonthlyBudgetCents)
		assert.Zero(t, eff.InputTPM)
		assert.Zero(t, eff.OutputTPM)
		assert.Zero(t, eff.KeyTPM)
		assert.Nil(t, eff.RPMOverride)
		assert.Nil(t, eff.TPMOverride)
		assert.Nil(t, eff.BudgetOverrideCents)
		spend, err := store.OrgMonthSpendCents(ctx, orgID)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, spend, int64(0))
	}

	_, err := store.GetOrgCaps(ctx, orgA)
	require.ErrorIs(t, err, ErrNotFound, "no row yet — distinct from an all-defaults org")

	// Org A overrides every dimension; org B stays on the defaults.
	rpm := int64(5000)
	tpm := int64(900_000)
	budget := int64(10_000_000)
	inputTPM := int64(300_000)
	outputTPM := int64(150_000)
	keyTPM := int64(80_000)
	require.NoError(t, store.UpdateOrgCaps(ctx, orgA, OrgCapsUpdate{
		RPM: &rpm, TPM: &tpm, MonthlyBudgetCents: &budget,
		InputTPM: &inputTPM, OutputTPM: &outputTPM, KeyTPM: &keyTPM,
	}))

	effA, err := store.EffectiveOrgCaps(ctx, orgA)
	require.NoError(t, err)
	assert.Equal(t, rpm, effA.RPM)
	assert.Equal(t, tpm, effA.TPM)
	assert.Equal(t, budget, effA.MonthlyBudgetCents)
	assert.Equal(t, inputTPM, effA.InputTPM, "OP-19: split input window round-trips")
	assert.Equal(t, outputTPM, effA.OutputTPM)
	assert.Equal(t, keyTPM, effA.KeyTPM)
	require.NotNil(t, effA.RPMOverride)
	require.NotNil(t, effA.TPMOverride)
	require.NotNil(t, effA.BudgetOverrideCents)
	require.NotNil(t, effA.InputTPMOverride)
	require.NotNil(t, effA.OutputTPMOverride)
	require.NotNil(t, effA.KeyTPMOverride)

	effB, err := store.EffectiveOrgCaps(ctx, orgB)
	require.NoError(t, err)
	assert.Equal(t, DefaultOrgCapsRPM, effB.RPM, "org B must not see org A's override")
	assert.Equal(t, DefaultOrgCapsTPM, effB.TPM)
	assert.Equal(t, DefaultOrgCapsMonthlyBudgetCents, effB.MonthlyBudgetCents)
	assert.Zero(t, effB.InputTPM, "org B must not see org A's split windows")
	assert.Zero(t, effB.KeyTPM)

	row, err := store.GetOrgCaps(ctx, orgA)
	require.NoError(t, err)
	assert.Equal(t, orgA, row.OrgID)
	require.NotNil(t, row.RPM)
	assert.Equal(t, rpm, *row.RPM)
	require.NotNil(t, row.InputTokensPerMin)
	assert.Equal(t, inputTPM, *row.InputTokensPerMin)
	require.NotNil(t, row.KeyTokensPerMin)
	assert.Equal(t, keyTPM, *row.KeyTokensPerMin)

	// A partial update clears the untouched dimensions (nil = beta default,
	rpm2 := int64(120)
	require.NoError(t, store.UpdateOrgCaps(ctx, orgA, OrgCapsUpdate{RPM: &rpm2}))
	row, err = store.GetOrgCaps(ctx, orgA)
	require.NoError(t, err)
	require.NotNil(t, row.RPM)
	assert.Equal(t, rpm2, *row.RPM)
	assert.Nil(t, row.TPM, "the replaced row must not keep the old tpm")
	assert.Nil(t, row.MonthlyBudgetCents)
	assert.Nil(t, row.InputTokensPerMin, "the replaced row must not keep the old input window")
	assert.Nil(t, row.OutputTokensPerMin)
	assert.Nil(t, row.KeyTokensPerMin)
	effA, err = store.EffectiveOrgCaps(ctx, orgA)
	require.NoError(t, err)
	assert.Equal(t, DefaultOrgCapsTPM, effA.TPM)
	assert.Zero(t, effA.InputTPM, "cleared split dimension lands on off")

	// Validation fires before the DB is touched.
	require.Error(t, store.UpdateOrgCaps(ctx, orgA, OrgCapsUpdate{RPM: int64ptr(0)}))

	// Unknown orgs are ErrNotFound — no orphan caps rows.
	badID := "33333333-3333-3333-3333-333333333333"
	require.ErrorIs(t, store.UpdateOrgCaps(ctx, badID, OrgCapsUpdate{RPM: &rpm2}), ErrNotFound)
	_, err = store.EffectiveOrgCaps(ctx, badID)
	require.ErrorIs(t, err, ErrNotFound)

	// The alert-target lookup resolves the reused webhook (empty when the
	// spend-alert webhook is not configured) and never leaks org A's row.
	target, err := store.OrgAlertTarget(ctx, orgB)
	require.NoError(t, err)
	assert.Empty(t, target.WebhookURL)
	_, err = store.OrgAlertTarget(ctx, badID)
	require.ErrorIs(t, err, ErrNotFound)
}
