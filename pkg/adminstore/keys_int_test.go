package adminstore

// QA-01: DB-gated API-key CRUD + audit hash-chain append against the shared
// dev Postgres (skips when unavailable — repo convention).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_APIKeyCRUD_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	slug := fmt.Sprintf("qa-keys-org-%d", time.Now().UnixNano())
	_, err := pool.Exec(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('QA Keys Org', $1)`, slug)
	require.NoError(t, err)
	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT id::text FROM organizations WHERE slug = $1", slug).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", orgID)
	})

	// api_keys.team_id is NOT NULL in the 0001 baseline; the handler now
	// REQUIRES an explicit team that belongs to the org (NEXT-01), so the
	// store test mirrors the real create path: seed the team, then pass it.
	var teamID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations_teams (org_id, name, slug)
		VALUES ($1, 'qa-keys-team', 'qa-keys-team')
		ON CONFLICT DO NOTHING
		RETURNING id::text`, orgID).Scan(&teamID))

	hash := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

	key, err := store.CreateAPIKey(ctx, hash("qa-key-material"), "qa-key", &orgID, &teamID)
	require.NoError(t, err)
	require.NotEmpty(t, key.ID)

	got, err := store.GetAPIKeyByID(ctx, key.ID)
	require.NoError(t, err)
	assert.True(t, got.Active)
	assert.Equal(t, "qa-key", got.Name)

	list, total, err := store.ListAPIKeys(ctx, &orgID, NewPageFilter(1, 50))
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, list, 1)

	require.NoError(t, store.UpdateAPIKeyActive(ctx, key.ID, false))
	got, err = store.GetAPIKeyByID(ctx, key.ID)
	require.NoError(t, err)
	assert.False(t, got.Active)

	require.NoError(t, store.RotateAPIKey(ctx, key.ID, hash("qa-rotated")))
	got, err = store.GetAPIKeyByID(ctx, key.ID)
	require.NoError(t, err)
	assert.Equal(t, hash("qa-rotated"), got.KeyHash, "rotation replaces the hash")

	require.NoError(t, store.DeleteAPIKey(ctx, key.ID))
	_, err = store.GetAPIKeyByID(ctx, key.ID)
	require.Error(t, err, "deleted key must not resolve")
}

// path exposing last_used_at/expires_at (NULL until the gateway records use).
func TestStore_APIKeyExpiry_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	slug := fmt.Sprintf("qa-keyexp-org-%d", time.Now().UnixNano())
	_, err := pool.Exec(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('QA KeyExpiry Org', $1)`, slug)
	require.NoError(t, err)
	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT id::text FROM organizations WHERE slug = $1", slug).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", orgID)
	})

	var teamID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations_teams (org_id, name, slug)
		VALUES ($1, 'qa-keyexp-team', 'qa-keyexp-team')
		RETURNING id::text`, orgID).Scan(&teamID))

	hash := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	key, err := store.CreateAPIKey(ctx, hash("qa-keyexp-material"), "qa-keyexp", &orgID, &teamID)
	require.NoError(t, err)

	// Fresh key: бессрочный — no expiry, never used.
	got, err := store.GetAPIKeyByID(ctx, key.ID)
	require.NoError(t, err)
	assert.Nil(t, got.ExpiresAt, "a fresh key never expires")
	assert.Nil(t, got.LastUsedAt, "a fresh key was never used")

	// Future expiry round-trips through set + read.
	future := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, store.UpdateAPIKeyExpiry(ctx, key.ID, &future))
	got, err = store.GetAPIKeyByID(ctx, key.ID)
	require.NoError(t, err)
	require.NotNil(t, got.ExpiresAt)
	assert.WithinDuration(t, future, *got.ExpiresAt, time.Second)

	// nil clears the column: NULL = бессрочный again.
	require.NoError(t, store.UpdateAPIKeyExpiry(ctx, key.ID, nil))
	got, err = store.GetAPIKeyByID(ctx, key.ID)
	require.NoError(t, err)
	assert.Nil(t, got.ExpiresAt)

	// Unknown id → ErrNotFound (the handler maps it to 404).
	err = store.UpdateAPIKeyExpiry(ctx, "00000000-0000-0000-0000-000000000000", &future)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

// column: a fresh key sits on the default 5, the setter round-trips 0..9,
// out-of-range values are rejected in memory, and unknown keys are ErrNotFound.
func TestStore_APIKeyPriority_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	slug := fmt.Sprintf("qa-keyprio-org-%d", time.Now().UnixNano())
	_, err := pool.Exec(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('QA KeyPriority Org', $1)`, slug)
	require.NoError(t, err)
	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT id::text FROM organizations WHERE slug = $1", slug).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", orgID)
	})

	var teamID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations_teams (org_id, name, slug)
		VALUES ($1, 'qa-keyprio-team', 'qa-keyprio-team')
		RETURNING id::text`, orgID).Scan(&teamID))

	hash := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	key, err := store.CreateAPIKey(ctx, hash("qa-keyprio-material"), "qa-keyprio", &orgID, &teamID)
	require.NoError(t, err)

	got, err := store.GetAPIKeyByID(ctx, key.ID)
	require.NoError(t, err)
	assert.Equal(t, DefaultAPIKeyPriority, got.Priority, "a fresh key sits on the default")

	require.NoError(t, store.SetAPIKeyPriority(ctx, key.ID, MaxAPIKeyPriority))
	p, err := store.APIKeyPriority(ctx, key.ID)
	require.NoError(t, err)
	assert.Equal(t, MaxAPIKeyPriority, p)

	require.NoError(t, store.SetAPIKeyPriority(ctx, key.ID, MinAPIKeyPriority))
	got, err = store.GetAPIKeyByID(ctx, key.ID)
	require.NoError(t, err)
	assert.Equal(t, MinAPIKeyPriority, got.Priority)

	// Out of range never reaches the DB; unknown key is ErrNotFound.
	require.Error(t, store.SetAPIKeyPriority(ctx, key.ID, MaxAPIKeyPriority+1))
	require.Error(t, store.SetAPIKeyPriority(ctx, key.ID, MinAPIKeyPriority-1))
	err = store.SetAPIKeyPriority(ctx, "00000000-0000-0000-0000-000000000000", 3)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = store.APIKeyPriority(ctx, "00000000-0000-0000-0000-000000000000")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestStore_InsertAuditLog_ChainAppend_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	var before int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT count(*) FROM admin_audit_logs").Scan(&before))

	id1 := fmt.Sprintf("qa-audit-%d-a", time.Now().UnixNano())
	id2 := fmt.Sprintf("qa-audit-%d-b", time.Now().UnixNano())
	require.NoError(t, store.InsertAuditLog(ctx, id1, "qa.action", "qa-resource",
		`{"k":1}`, "qa-admin", "QA Admin", "127.0.0.1"))
	require.NoError(t, store.InsertAuditLog(ctx, id2, "qa.action", "qa-resource",
		`{"k":2}`, "qa-admin", "QA Admin", "127.0.0.1"))

	var after int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT count(*) FROM admin_audit_logs").Scan(&after))
	assert.Equal(t, before+2, after)

	// Chain integrity for the appended rows: prev_hash links forward.
	var prev1, prev2 string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT prev_hash FROM admin_audit_logs WHERE id = $1", id1).Scan(&prev1))
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT prev_hash FROM admin_audit_logs WHERE id = $1", id2).Scan(&prev2))
	assert.NotEmpty(t, prev2, "second append links to the chain")

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM admin_audit_logs WHERE id IN ($1, $2)", id1, id2)
	})
}
