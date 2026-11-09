package adminstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAdminSessionRevocationStore_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, nil, nil)
	ctx := context.Background()
	sessionID := fmt.Sprintf("revocation-int-%d", time.Now().UnixNano())
	expires := time.Now().Add(time.Hour)
	require.NoError(t, store.Revoke(ctx, sessionID, expires))
	revoked, err := store.IsRevoked(ctx, sessionID)
	require.NoError(t, err)
	require.True(t, revoked)
	_, err = pool.Exec(ctx, `UPDATE revoked_admin_sessions SET expires_at = now() - interval '1 second' WHERE session_id = $1`, sessionID)
	require.NoError(t, err)
	revoked, err = store.IsRevoked(ctx, sessionID)
	require.NoError(t, err)
	require.False(t, revoked)
	var count int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM revoked_admin_sessions WHERE session_id = $1`, sessionID).Scan(&count))
	require.Zero(t, count, "IsRevoked lazily removes expired revocations")
}
