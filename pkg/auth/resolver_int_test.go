package auth

// AUTH-03 integration: the resolveSession SQL must deny a session key whose
// PARENT api_key has expired (or is inactive), not merely the session's own
// expiry. Proven against a real migrated Postgres because the guard lives in
// the SQL predicate, not in Go code.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func auth03Seed(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label string, parentExpires *time.Time, parentActive bool) string {
	t.Helper()
	prefix := "auth03-" + label // lowercase: name/slug constraints

	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		prefix+"-org").Scan(&orgID))
	// Cleanup is LIFO: registration order below yields the child-first run
	// order session_keys → api_keys → organizations_teams → organizations.
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM organizations WHERE id::text = $1`, orgID); err != nil {
			t.Errorf("auth03 org cleanup: %v", err)
		}
	})
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM organizations_teams WHERE org_id::text = $1`, orgID); err != nil {
			t.Errorf("auth03 teams cleanup: %v", err)
		}
	})
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM api_keys WHERE org_id::text = $1`, orgID); err != nil {
			t.Errorf("auth03 api_keys cleanup: %v", err)
		}
	})
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM session_keys WHERE org_id::text = $1`, orgID); err != nil {
			t.Errorf("auth03 session cleanup: %v", err)
		}
	})

	var teamID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations_teams (org_id, name, slug) VALUES ($1::uuid, $2, $2)
		RETURNING id::text`, orgID, prefix+"-team").Scan(&teamID))

	var parentID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO api_keys (id, key_hash, org_id, team_id, name, active, expires_at)
		VALUES (gen_random_uuid(), $1, $2::uuid, $3::uuid, $4, $5, $6::timestamptz)
		RETURNING id::text`,
		prefix+"-parent-hash", orgID, teamID, prefix+"-parent-key", parentActive, parentExpires,
	).Scan(&parentID))

	plaintext, err := GenerateSessionKey()
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(plaintext))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO session_keys (key_hash, org_id, parent_api_key_id, name, expires_at)
		VALUES ($1, $2::uuid, $3::uuid, $4, now() + interval '1 hour')
		RETURNING id::text`,
		hex.EncodeToString(sum[:]), orgID, parentID, prefix+"-session").Scan(new(string)))

	return plaintext
}

func TestAuth03SessionParentExpiry_RealSQL(t *testing.T) {
	pool := testdb.Postgres(t)
	r := NewResolver(pool, nil, 300, nil)
	ctx := context.Background()

	t.Run("live parent: session resolves with parent expiry attached", func(t *testing.T) {
		expires := time.Now().UTC().Add(time.Hour)
		plaintext := auth03Seed(t, ctx, pool, "live", &expires, true)
		res, err := r.Resolve(ctx, plaintext)
		require.NoError(t, err)
		require.False(t, res.KeyExpiresAt.IsZero(), "parent expiry must ride on the result")
		assert.WithinDuration(t, expires, res.KeyExpiresAt, 5*time.Second)
	})

	t.Run("expired parent: session denied even though its own TTL is fresh", func(t *testing.T) {
		expires := time.Now().UTC().Add(-time.Minute)
		plaintext := auth03Seed(t, ctx, pool, "expired", &expires, true)
		_, err := r.Resolve(ctx, plaintext)
		require.Error(t, err, "a session must never resolve after its parent expired; "+
			"the session branch reports the generic denial, not the parent's classification")
	})

	t.Run("inactive parent: session denied", func(t *testing.T) {
		plaintext := auth03Seed(t, ctx, pool, "inactive", nil, false)
		_, err := r.Resolve(ctx, plaintext)
		require.Error(t, err, "revoking the parent must revoke its sessions")
	})

	t.Run("parent without expiry: session resolves, no parent TTL", func(t *testing.T) {
		plaintext := auth03Seed(t, ctx, pool, "noexp", nil, true)
		res, err := r.Resolve(ctx, plaintext)
		require.NoError(t, err)
		assert.True(t, res.KeyExpiresAt.IsZero(), "NULL expires_at means no parent TTL")
	})
}
