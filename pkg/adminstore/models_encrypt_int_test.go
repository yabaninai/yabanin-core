package adminstore

// write refusal in production, ciphertext/plaintext read tolerance, and the
// idempotent plaintext→ciphertext migration on a real Postgres.

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_ModelKeyPlaintextRefusedInProduction_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
	defer restore()

	name := fmt.Sprintf("imp87-prod-%d", time.Now().UnixNano())
	key := "sk-live-secret"
	_, err := store.CreateModel(ctx, name, "IMP87", "smart", nil, &key)
	require.Error(t, err, "production must refuse provider key writes without an encryptor")
	assert.Contains(t, err.Error(), "plaintext")

	// No row may have been written.
	var count int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT count(*) FROM models_registry WHERE model_name = $1", name).Scan(&count))
	assert.Zero(t, count, "refused write must not leave a row behind")
}

func TestStore_ModelKeyMigrationAndReads_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := New(pool, slog.Default(), enc)
	ctx := context.Background()

	name := fmt.Sprintf("imp87-mig-%d", time.Now().UnixNano())
	// Synthetic fixture value in the shape of a provider key; never a real credential.
	secret := "sk-live-migration-secret" //nolint:gosec // test fixture

	// With an encryptor: stored value is ciphertext, read returns the secret.
	m, err := store.CreateModel(ctx, name, "IMP87 Migration", "smart", nil, &secret)
	require.NoError(t, err)
	var stored string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT upstream_api_key::text FROM models_registry WHERE id::text = $1", m.ID).Scan(&stored))
	require.True(t, encryption.IsEncrypted(stored), "stored value must be enc:-prefixed ciphertext")

	got, err := store.GetModelByName(ctx, name)
	require.NoError(t, err)
	require.NotNil(t, got.UpstreamAPIKey)
	assert.Equal(t, secret, *got.UpstreamAPIKey, "ciphertext read must return the original secret")

	// Simulate a legacy plaintext row.
	_, err = pool.Exec(ctx,
		"UPDATE models_registry SET upstream_api_key = $1 WHERE id::text = $2", secret, m.ID)
	require.NoError(t, err)

	// Reads of the plaintext row work both with and without a key.
	got, err = store.GetModelByName(ctx, name)
	require.NoError(t, err)
	require.NotNil(t, got.UpstreamAPIKey)
	assert.Equal(t, secret, *got.UpstreamAPIKey, "plaintext read must return the original secret")

	storeNoEnc := New(pool, slog.Default(), nil)
	got, err = storeNoEnc.GetModelByName(ctx, name)
	require.NoError(t, err)
	require.NotNil(t, got.UpstreamAPIKey)
	assert.Equal(t, secret, *got.UpstreamAPIKey, "plaintext read without a key stays readable (read-only)")

	// Without an encryptor the migration is a no-op and keeps plaintext.
	n, err := storeNoEnc.MigratePlaintextSecrets(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT upstream_api_key::text FROM models_registry WHERE id::text = $1", m.ID).Scan(&stored))
	assert.Equal(t, secret, stored, "migration without a key must not touch the row")

	// With a key: one-time migration re-encrypts; idempotent on re-run.
	n, err = store.MigratePlaintextSecrets(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT upstream_api_key::text FROM models_registry WHERE id::text = $1", m.ID).Scan(&stored))
	assert.True(t, encryption.IsEncrypted(stored), "row must be encrypted after migration")

	n, err = store.MigratePlaintextSecrets(ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "second migration run must be a no-op (idempotent)")

	// The migrated row still reads back to the original secret.
	got, err = store.GetModelByName(ctx, name)
	require.NoError(t, err)
	require.NotNil(t, got.UpstreamAPIKey)
	assert.Equal(t, secret, *got.UpstreamAPIKey)

	_, err = pool.Exec(ctx, "DELETE FROM models_registry WHERE id::text = $1", m.ID)
	require.NoError(t, err)
}
