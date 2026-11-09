package adminstore

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/historyarchive"
)

// N10-P02-T02 acceptance evidence: the archive tier read model resolves the
// pinned contract constants plus the org's fail-closed originals decision.
func TestEffectiveHistoryTier_FailClosedDefaultAndOptIn(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	// Org without any explicit choice: fail-closed processed-only, pinned
	// 90-day boundary, metadata-only media, originals-org-opt-in policy.
	slug := fmt.Sprintf("history-tier-%d", time.Now().UnixNano())
	var orgID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`, slug, slug).Scan(&orgID))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID) })

	got, err := store.EffectiveHistoryTier(ctx, orgID)
	require.NoError(t, err)
	require.Equal(t, orgID, got.OrgID)
	require.Equal(t, historyarchive.HotRetentionDays, got.HotRetentionDays)
	require.Equal(t, 90, got.HotRetentionDays)
	require.Equal(t, historyarchive.MediaPolicyMetadataOnly, got.MediaPolicy)
	require.Equal(t, historyarchive.RedactionPolicyOriginalsOrgOptIn, got.RedactionPolicy)
	require.False(t, got.OriginalsOptIn, "unset orgs inherit the fail-closed processed-only default")

	// Explicit opt-in flips ONLY the originals dimension — the tier
	// boundary and media policy are contract constants, not per-org config.
	require.NoError(t, store.UpdateOrgOriginalRetention(ctx, orgID, boolPtr(true)))
	got, err = store.EffectiveHistoryTier(ctx, orgID)
	require.NoError(t, err)
	require.True(t, got.OriginalsOptIn)
	require.Equal(t, 90, got.HotRetentionDays)
	require.Equal(t, historyarchive.MediaPolicyMetadataOnly, got.MediaPolicy)

	require.NoError(t, store.UpdateOrgOriginalRetention(ctx, orgID, boolPtr(false)))
	got, err = store.EffectiveHistoryTier(ctx, orgID)
	require.NoError(t, err)
	require.False(t, got.OriginalsOptIn)

	// Unknown org is ErrNotFound, not a synthesized default policy.
	_, err = store.EffectiveHistoryTier(ctx, "00000000-0000-0000-0000-000000000000")
	require.ErrorIs(t, err, ErrNotFound)
}
