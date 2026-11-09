package adminstore

// NEXT-21 DB round-trip for the per-team retention policy surface
// (migration 0026) against a disposable Postgres: upsert/get/delete,
// unknown-team and validation errors, the enabled-only listing and the
// effective org MIN/OR aggregation the retention worker consumes.

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_TeamRetentionPolicy_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	teamA, err := store.CreateTeam(ctx, orgID, "Ret A", fmt.Sprintf("ret-a-%d", time.Now().UnixNano()), nil)
	require.NoError(t, err)
	teamB, err := store.CreateTeam(ctx, orgID, "Ret B", fmt.Sprintf("ret-b-%d", time.Now().UnixNano()), nil)
	require.NoError(t, err)

	// No policy yet: ErrNotFound (distinct from a stored, disabled policy).
	_, err = store.GetTeamRetentionPolicy(ctx, teamA.ID)
	require.ErrorIs(t, err, ErrNotFound)

	// Validation happens before the DB is touched.
	thirty, seven, ten := 30, 7, 10
	zero := 0
	bad := &TeamRetentionPolicy{TeamID: teamA.ID, RequestLogsDays: &zero}
	require.Error(t, store.UpsertTeamRetentionPolicy(ctx, bad))
	badDest := &TeamRetentionPolicy{TeamID: teamA.ID, ColdDestination: "/var/cold"}
	require.Error(t, store.UpsertTeamRetentionPolicy(ctx, badDest))

	// Unknown team is ErrNotFound, not a constraint error.
	ghost := &TeamRetentionPolicy{TeamID: "00000000-0000-4000-8000-00000000n210",
		RequestLogsDays: &thirty, Enabled: true}
	require.ErrorIs(t, store.UpsertTeamRetentionPolicy(ctx, ghost), ErrNotFound)

	// Round trip.
	policyA := &TeamRetentionPolicy{
		TeamID:          teamA.ID,
		RequestLogsDays: &thirty,
		LineageDays:     &seven,
		RedactContent:   true,
		ColdDestination: "file:///var/cold-a",
		Enabled:         true,
	}
	require.NoError(t, store.UpsertTeamRetentionPolicy(ctx, policyA))

	got, err := store.GetTeamRetentionPolicy(ctx, teamA.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RequestLogsDays)
	assert.Equal(t, 30, *got.RequestLogsDays)
	require.NotNil(t, got.LineageDays)
	assert.Equal(t, 7, *got.LineageDays)
	assert.Nil(t, got.CacheEntriesDays)
	assert.Nil(t, got.BackupSnapshotsDays)
	assert.True(t, got.RedactContent)
	assert.Equal(t, "file:///var/cold-a", got.ColdDestination)
	assert.True(t, got.Enabled)
	assert.False(t, got.CreatedAt.IsZero())

	// Second team: stricter lineage, own cache window, no redaction, s3 dest.
	policyB := &TeamRetentionPolicy{
		TeamID:           teamB.ID,
		CacheEntriesDays: &ten,
		LineageDays:      func() *int { d := 3; return &d }(),
		RedactContent:    false,
		ColdDestination:  "s3://bucket-b",
		Enabled:          true,
	}
	require.NoError(t, store.UpsertTeamRetentionPolicy(ctx, policyB))

	// Enabled-only listing carries the org join.
	assignments, err := store.ListEnabledTeamRetentionAssignments(ctx)
	require.NoError(t, err)
	byTeam := map[string]TeamRetentionAssignment{}
	for _, a := range assignments {
		byTeam[a.TeamID] = a
	}
	require.Contains(t, byTeam, teamA.ID)
	assert.Equal(t, orgID, byTeam[teamA.ID].OrgID)
	require.Contains(t, byTeam, teamB.ID)

	// Effective org window: MIN per family, OR for redaction,
	// lexicographically smallest destination.
	eff, err := store.EffectiveOrgRetention(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, eff)
	require.NotNil(t, eff.RequestLogsDays)
	assert.Equal(t, 30, *eff.RequestLogsDays, "only team A sets a request_logs window")
	require.NotNil(t, eff.CacheEntriesDays)
	assert.Equal(t, 10, *eff.CacheEntriesDays)
	require.NotNil(t, eff.LineageDays)
	assert.Equal(t, 3, *eff.LineageDays, "strictest (min) enabled window wins")
	assert.Nil(t, eff.BackupSnapshotsDays)
	assert.True(t, eff.RedactContent, "OR: team A's redaction wins")
	require.NotNil(t, eff.Destination)
	assert.Equal(t, "file:///var/cold-a", *eff.Destination, "lexicographically smallest")

	// Disabling a policy removes it from every resolution.
	policyA.Enabled = false
	require.NoError(t, store.UpsertTeamRetentionPolicy(ctx, policyA))
	assignments, err = store.ListEnabledTeamRetentionAssignments(ctx)
	require.NoError(t, err)
	assert.Len(t, assignments, 1)
	assert.Equal(t, teamB.ID, assignments[0].TeamID)

	eff, err = store.EffectiveOrgRetention(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, eff)
	assert.Nil(t, eff.RequestLogsDays, "disabled team A window no longer applies")
	assert.False(t, eff.RedactContent)
	require.NotNil(t, eff.Destination)
	assert.Equal(t, "s3://bucket-b", *eff.Destination)

	// Update-in-place: changing a window sticks (upsert, not insert-only).
	updated := thirty + 1
	policyA.Enabled = true
	policyA.RequestLogsDays = &updated
	require.NoError(t, store.UpsertTeamRetentionPolicy(ctx, policyA))
	got, err = store.GetTeamRetentionPolicy(ctx, teamA.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RequestLogsDays)
	assert.Equal(t, 31, *got.RequestLogsDays)

	// Delete: policy gone, team untouched, double delete is ErrNotFound.
	require.NoError(t, store.DeleteTeamRetentionPolicy(ctx, teamA.ID))
	_, err = store.GetTeamRetentionPolicy(ctx, teamA.ID)
	require.ErrorIs(t, err, ErrNotFound)
	require.ErrorIs(t, store.DeleteTeamRetentionPolicy(ctx, teamA.ID), ErrNotFound)
	team, err := store.GetTeamByID(ctx, teamA.ID)
	require.NoError(t, err)
	assert.Equal(t, teamA.ID, team.ID)

	// An org with no enabled policies resolves to ErrNoRetention —
	// retention is opt-in per team, never implicit.
	otherOrg := qaOrg(t, store, ctx)
	_, err = store.EffectiveOrgRetention(ctx, otherOrg)
	require.ErrorIs(t, err, ErrNoRetention)
}
