package adminstore

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOrgOriginalRetentionStore_InheritanceAndOverrides(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	slug := fmt.Sprintf("original-retention-%d", time.Now().UnixNano())
	var orgID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`, slug, slug).Scan(&orgID))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID) })

	got, err := store.GetOrgOriginalRetention(ctx, orgID)
	require.NoError(t, err)
	require.Nil(t, got.Enabled)
	require.True(t, got.Inherited)
	require.False(t, got.Effective, "unset orgs inherit processed-only")

	on := true
	require.NoError(t, store.UpdateOrgOriginalRetention(ctx, orgID, &on))
	got, err = store.GetOrgOriginalRetention(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, got.Enabled)
	require.True(t, *got.Enabled)
	require.False(t, got.Inherited)
	require.True(t, got.Effective)

	off := false
	require.NoError(t, store.UpdateOrgOriginalRetention(ctx, orgID, &off))
	got, err = store.GetOrgOriginalRetention(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, got.Enabled)
	require.False(t, *got.Enabled)
	require.False(t, got.Inherited)
	require.False(t, got.Effective)

	require.NoError(t, store.UpdateOrgOriginalRetention(ctx, orgID, nil))
	got, err = store.GetOrgOriginalRetention(ctx, orgID)
	require.NoError(t, err)
	require.Nil(t, got.Enabled)
	require.True(t, got.Inherited)
	require.False(t, got.Effective)

	_, err = store.GetOrgOriginalRetention(ctx, "00000000-0000-0000-0000-000000000000")
	require.ErrorIs(t, err, ErrNotFound)
}
