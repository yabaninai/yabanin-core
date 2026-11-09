package adminstore

// (migration 0027) against a disposable Postgres: upsert/get/delete, unknown
// subjects, validation errors, and the per-scope effective resolution the
// gateway enforcer consumes (enabled rows only, per scope, strictest binds
// downstream).

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_KeyRateLimits_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	orgID := qaOrg(t, store, ctx)
	teamA, err := store.CreateTeam(ctx, orgID, "RL Team A", fmt.Sprintf("rl-team-a-%d", time.Now().UnixNano()), nil)
	require.NoError(t, err)
	key, err := store.CreateAPIKey(ctx, "rl-key-hash-1", "rl key", &orgID, &teamA.ID)
	require.NoError(t, err)

	// No limits yet: the effective resolution is empty (pass-through).
	eff, err := store.EffectiveKeyRateLimits(ctx, key.ID, teamA.ID, orgID)
	require.NoError(t, err)
	assert.Empty(t, eff)

	rpm := int64(60)
	tpm := int64(100_000)
	row := &KeyRateLimit{Scope: RateLimitScopeKey, SubjectID: key.ID, RPM: &rpm, TPM: &tpm, Enabled: true}
	require.NoError(t, store.UpsertKeyRateLimit(ctx, row))

	got, err := store.GetKeyRateLimit(ctx, RateLimitScopeKey, key.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RPM)
	require.NotNil(t, got.TPM)
	assert.Equal(t, rpm, *got.RPM)
	assert.Equal(t, tpm, *got.TPM)
	assert.True(t, got.Enabled)

	// Upsert replaces the row (60 → 30 rpm).
	rpm2 := int64(30)
	require.NoError(t, store.UpsertKeyRateLimit(ctx, &KeyRateLimit{
		Scope: RateLimitScopeKey, SubjectID: key.ID, RPM: &rpm2, Enabled: true,
	}))
	got, err = store.GetKeyRateLimit(ctx, RateLimitScopeKey, key.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RPM)
	assert.Equal(t, rpm2, *got.RPM)
	assert.Nil(t, got.TPM, "the replaced row must not keep the old tpm")

	// Unknown subjects are ErrNotFound, never orphan rows.
	badID := "22222222-2222-2222-2222-222222222222"
	require.ErrorIs(t, store.UpsertKeyRateLimit(ctx, &KeyRateLimit{
		Scope: RateLimitScopeOrg, SubjectID: badID, RPM: &rpm2,
	}), ErrNotFound)
	require.ErrorIs(t, store.UpsertKeyRateLimit(ctx, &KeyRateLimit{
		Scope: RateLimitScopeTeam, SubjectID: badID, TPM: &tpm,
	}), ErrNotFound)
	_, err = store.GetKeyRateLimit(ctx, RateLimitScopeOrg, badID)
	require.ErrorIs(t, err, ErrNotFound)

	// Validation fires before the DB is touched.
	require.Error(t, store.UpsertKeyRateLimit(ctx, &KeyRateLimit{
		Scope: RateLimitScopeKey, SubjectID: key.ID,
	}))

	// Effective resolution: enabled rows per scope only, each with its own
	// dimensions.
	orgRPM := int64(1000)
	teamTPM := int64(500_000)
	require.NoError(t, store.UpsertKeyRateLimit(ctx, &KeyRateLimit{
		Scope: RateLimitScopeOrg, SubjectID: orgID, RPM: &orgRPM, Enabled: true,
	}))
	require.NoError(t, store.UpsertKeyRateLimit(ctx, &KeyRateLimit{
		Scope: RateLimitScopeTeam, SubjectID: teamA.ID, TPM: &teamTPM, Enabled: true,
	}))

	eff, err = store.EffectiveKeyRateLimits(ctx, key.ID, teamA.ID, orgID)
	require.NoError(t, err)
	require.Len(t, eff, 3)
	byScope := map[string]KeyRateScopeLimits{}
	for _, l := range eff {
		byScope[l.Scope] = l
	}
	require.Contains(t, byScope, RateLimitScopeKey)
	require.Contains(t, byScope, RateLimitScopeTeam)
	require.Contains(t, byScope, RateLimitScopeOrg)
	assert.Equal(t, rpm2, *byScope[RateLimitScopeKey].RPM)
	assert.Nil(t, byScope[RateLimitScopeKey].TPM)
	assert.Equal(t, teamTPM, *byScope[RateLimitScopeTeam].TPM)
	assert.Nil(t, byScope[RateLimitScopeTeam].RPM)
	assert.Equal(t, orgRPM, *byScope[RateLimitScopeOrg].RPM)

	// A disabled row stops applying.
	require.NoError(t, store.UpsertKeyRateLimit(ctx, &KeyRateLimit{
		Scope: RateLimitScopeKey, SubjectID: key.ID, RPM: &rpm2, Enabled: false,
	}))
	eff, err = store.EffectiveKeyRateLimits(ctx, key.ID, teamA.ID, orgID)
	require.NoError(t, err)
	require.Len(t, eff, 2)
	for _, l := range eff {
		assert.NotEqual(t, RateLimitScopeKey, l.Scope)
	}

	// An unrelated org sees nothing.
	otherOrg := qaOrg(t, store, ctx)
	eff, err = store.EffectiveKeyRateLimits(ctx, otherOrg, otherOrg, otherOrg)
	require.NoError(t, err)
	assert.Empty(t, eff)

	// Delete removes the row and it stops resolving.
	require.NoError(t, store.DeleteKeyRateLimit(ctx, RateLimitScopeKey, key.ID))
	_, err = store.GetKeyRateLimit(ctx, RateLimitScopeKey, key.ID)
	require.ErrorIs(t, err, ErrNotFound)
	require.ErrorIs(t, store.DeleteKeyRateLimit(ctx, RateLimitScopeKey, key.ID), ErrNotFound)
}
