//go:build integration

package lineage

// production, encrypted write + decrypt-on-read round-trip (including the
// historical bug where enc:-stored keys could not be read back), and the
// idempotent plaintext→ciphertext migration on a real Postgres.

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_KeyStore_PlaintextRefusedInProduction(t *testing.T) {
	pool, _ := startLineageDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
	defer restore()

	ks := NewKeyStore(pool, nil)
	orgID := fmt.Sprintf("11111111-2222-4222-8222-%012d", time.Now().UnixNano()%1e12)
	_, _, _, err := ks.EnsureKeyPair(ctx, orgID)
	require.Error(t, err, "production must refuse lineage key generation without an encryptor")
	assert.Contains(t, err.Error(), "plaintext")

	var count int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT count(*) FROM org_lineage_keys WHERE org_id = $1", orgID).Scan(&count))
	assert.Zero(t, count, "refused generation must not leave a row behind")
}

func TestIntegration_KeyStore_EncryptedRoundTripAndMigration(t *testing.T) {
	pool, _ := startLineageDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	enc := mustEncryptor(t)
	ks := NewKeyStore(pool, enc)
	orgID := fmt.Sprintf("11111111-3333-4333-8333-%012d", time.Now().UnixNano()%1e12)

	// With an encryptor: stored private_key is enc:-prefixed ciphertext.
	keyID, pub, priv, err := ks.EnsureKeyPair(ctx, orgID)
	require.NoError(t, err)
	require.NotEmpty(t, keyID)

	var stored string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT private_key FROM org_lineage_keys WHERE key_id = $1", keyID).Scan(&stored))
	require.True(t, encryption.IsEncrypted(stored), "stored private key must be enc:-prefixed")

	// Second call reads the encrypted row back and must return the SAME key
	// (regression: the historical read path never decrypted enc: values).
	keyID2, pub2, priv2, err := ks.EnsureKeyPair(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, keyID, keyID2)
	assert.Equal(t, pub, pub2)
	assert.Equal(t, priv, priv2, "decrypted private key must round-trip")

	// Simulate a legacy plaintext row.
	privB64 := base64.StdEncoding.EncodeToString(priv)
	_, err = pool.Exec(ctx,
		"UPDATE org_lineage_keys SET private_key = $1 WHERE key_id = $2", privB64, keyID)
	require.NoError(t, err)

	// Plaintext stays readable without a key (read-only mode).
	ksNoEnc := NewKeyStore(pool, nil)
	_, pub3, priv3, err := ksNoEnc.EnsureKeyPair(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, pub, pub3)
	assert.Equal(t, priv, priv3, "plaintext read without a key must return the original key")

	// Without an encryptor the migration is a no-op.
	n, err := ksNoEnc.MigratePlaintextKeys(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)

	// With a key: migration re-encrypts exactly once and is idempotent.
	n, err = ks.MigratePlaintextKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	var storedAfter string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT private_key FROM org_lineage_keys WHERE key_id = $1", keyID).Scan(&storedAfter))
	assert.True(t, encryption.IsEncrypted(storedAfter), "row must be encrypted after migration")

	n, err = ks.MigratePlaintextKeys(ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "second migration run must be a no-op (idempotent)")

	// The migrated row still reads back to the original key material.
	_, pub4, priv4, err := ks.EnsureKeyPair(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, pub, pub4)
	assert.Equal(t, priv, priv4, "migrated ciphertext must decrypt to the original key")
}
