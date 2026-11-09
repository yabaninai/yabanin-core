package lineage

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/encryption"
)

// KeyStore reads and writes org Ed25519 keys from org_lineage_keys.
type KeyStore struct {
	pool *pgxpool.Pool
	enc  *encryption.Encryptor // optional; nil → plaintext writes refused in production (dev/test only, with a loud warning)
}

// NewKeyStore returns a KeyStore. enc may be nil only for development: in
// production, generating a lineage keypair without an encryptor fails closed
func NewKeyStore(pool *pgxpool.Pool, enc *encryption.Encryptor) *KeyStore {
	return &KeyStore{pool: pool, enc: enc}
}

// EnsureKeyPair generates or retrieves an org's Ed25519 keypair.
// On first call, creates version 1 and persists it. Subsequent calls return
// the latest active (non-revoked) key.
func (ks *KeyStore) EnsureKeyPair(ctx context.Context, orgID string) (keyID string, pub []byte, priv []byte, err error) {
	// Look for active key.
	row := ks.pool.QueryRow(ctx, `
		SELECT key_id, public_key, private_key FROM org_lineage_keys
		WHERE org_id = $1 AND revoked_at IS NULL ORDER BY version DESC LIMIT 1
	`, orgID)

	var kid string
	var pkBytes []byte
	var privStored string
	err = row.Scan(&kid, &pkBytes, &privStored)
	if err == nil {
		// Reads never fail on legacy plaintext rows; enc:-prefixed rows must
		// decrypt (a wrong encryption key is a hard error, not a fallback).
		privB64 := privStored
		if ks.enc != nil && encryption.IsEncrypted(privStored) {
			dec, decErr := ks.enc.Decrypt(privStored)
			if decErr != nil {
				return "", nil, nil, fmt.Errorf("decrypt existing lineage key: %w", decErr)
			}
			privB64 = dec
		} else if ks.enc == nil && encryption.IsEncrypted(privStored) {
			return "", nil, nil, fmt.Errorf("lineage private key is encrypted but no encryption_key is configured")
		}
		priv, decErr := DecodePrivateKey(privB64)
		if decErr != nil {
			return "", nil, nil, fmt.Errorf("decode existing key: %w", decErr)
		}
		return kid, pkBytes, priv, nil
	}

	// No active key — generate new.
	pub, privB64, genErr := GenerateKeyPair()
	if genErr != nil {
		return "", nil, nil, fmt.Errorf("generate key: %w", genErr)
	}

	priv, decErr := DecodePrivateKey(privB64)
	if decErr != nil {
		return "", nil, nil, fmt.Errorf("decode generated key: %w", decErr)
	}

	storedPriv, encErr := ks.Encrypt(privB64)
	if encErr != nil {
		return "", nil, nil, fmt.Errorf("encrypt private key: %w", encErr)
	}

	keyID = fmt.Sprintf("org:%s:v1", orgID)
	_, err = ks.pool.Exec(ctx, `
		INSERT INTO org_lineage_keys (key_id, org_id, version, public_key, private_key)
		VALUES ($1, $2, 1, $3, $4)
	`, keyID, orgID, pub, storedPriv)
	if err != nil {
		return "", nil, nil, fmt.Errorf("insert lineage key: %w", err)
	}

	return keyID, pub, priv, nil
}

// Encrypt wraps the private key (base64 string) using the encryption service.
// plaintext key material for storage; dev/test keeps the passthrough with a
// loud warning.
func (ks *KeyStore) Encrypt(plaintext string) (string, error) {
	if ks.enc == nil {
		if encryption.PlaintextWritesAllowed() {
			slog.Warn("lineage private key stored as PLAINTEXT: no encryption_key configured (dev/test fallback; production refuses this)")
			return plaintext, nil
		}
		return "", fmt.Errorf("refusing to store lineage private key as plaintext: encryption_key is not configured; set encryption_key (YABANIN_ENCRYPTION_KEY) before writing lineage keys")
	}
	ct, err := ks.enc.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt lineage key: %w", err)
	}
	return ct, nil
}

// MigratePlaintextKeys re-encrypts legacy plaintext org_lineage_keys
// a configured encryption key). Idempotent: enc:-prefixed rows are skipped,
// and each row is updated only while its stored value still matches what was
// read. Without an encryptor it is a no-op (0, nil) — plaintext stays
// read-only. Returns the number of rows migrated.
func (ks *KeyStore) MigratePlaintextKeys(ctx context.Context) (int, error) {
	if ks.pool == nil {
		return 0, fmt.Errorf("database not available")
	}
	if ks.enc == nil {
		return 0, nil
	}
	rows, err := ks.pool.Query(ctx, `
		SELECT key_id, private_key FROM org_lineage_keys
		WHERE private_key <> '' AND private_key NOT LIKE 'enc:%'
	`)
	if err != nil {
		return 0, fmt.Errorf("scan plaintext lineage keys: %w", err)
	}
	defer rows.Close()

	type pending struct {
		keyID, plain, ct string
	}
	var batch []pending
	for rows.Next() {
		var keyID, plain string
		if err := rows.Scan(&keyID, &plain); err != nil {
			return 0, fmt.Errorf("scan plaintext lineage key row: %w", err)
		}
		ct, err := ks.enc.Encrypt(plain)
		if err != nil {
			return 0, fmt.Errorf("encrypt lineage key %s: %w", keyID, err)
		}
		batch = append(batch, pending{keyID: keyID, plain: plain, ct: ct})
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate plaintext lineage keys: %w", err)
	}

	migrated := 0
	for _, p := range batch {
		tag, err := ks.pool.Exec(ctx, `
			UPDATE org_lineage_keys SET private_key = $1
			WHERE key_id = $2 AND private_key = $3
		`, p.ct, p.keyID, p.plain)
		if err != nil {
			return migrated, fmt.Errorf("migrate lineage key %s: %w", p.keyID, err)
		}
		if tag.RowsAffected() > 0 {
			migrated++
			slog.Info("migrated plaintext lineage private_key to encrypted storage", "key_id", p.keyID)
		}
	}
	return migrated, nil
}

// GetPublicKeyByOrgID fetches the public key for an org (used by the verifier).
func (ks *KeyStore) GetPublicKeyByOrgID(ctx context.Context, orgID string) (keyID string, pub []byte, err error) {
	row := ks.pool.QueryRow(ctx, `
		SELECT key_id, public_key FROM org_lineage_keys
		WHERE org_id = $1 AND revoked_at IS NULL ORDER BY version DESC LIMIT 1
	`, orgID)

	var kid string
	var pkBytes []byte
	err = row.Scan(&kid, &pkBytes)
	if err != nil {
		return "", nil, fmt.Errorf("fetch public key for org %s: %w", orgID, err)
	}
	return kid, pkBytes, nil
}
