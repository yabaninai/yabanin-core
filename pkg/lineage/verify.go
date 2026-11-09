package lineage

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Verifier validates an attestation against the stored public key.
type Verifier struct {
	pool *pgxpool.Pool
}

// NewVerifier returns a Verifier.
func NewVerifier(pool *pgxpool.Pool) *Verifier {
	return &Verifier{pool: pool}
}

// VerifyRequest checks that an attestation for a given request is valid:
// 1. Look up the org's active public key from org_lineage_keys.
// 2. Re-compute the hash from raw_attestation in request_lineage.
// 3. Verify the Ed25519 signature over the hash.
func (v *Verifier) VerifyRequest(ctx context.Context, requestID string) (bool, error) {
	// Get raw attestation.
	var raw json.RawMessage
	err := v.pool.QueryRow(ctx, `
		SELECT raw_attestation FROM request_lineage WHERE request_id = $1
	`, requestID).Scan(&raw)
	if err != nil {
		return false, fmt.Errorf("get lineage for verify: %w", err)
	}

	var att Attestation
	if err := json.Unmarshal(raw, &att); err != nil {
		return false, fmt.Errorf("unmarshal attestation for verify: %w", err)
	}

	// Get the org's public key.
	var pubKeyBytes []byte
	err = v.pool.QueryRow(ctx, `
		SELECT public_key FROM org_lineage_keys
		WHERE org_id = $1 AND revoked_at IS NULL ORDER BY version DESC LIMIT 1
	`, att.OrgID).Scan(&pubKeyBytes)
	if err != nil {
		return false, fmt.Errorf("get public key for verify: %w", err)
	}

	// Recompute hash.
	hash, err := att.Hash()
	if err != nil {
		return false, err
	}

	// Verify signature from the lineage row.
	var sigB64 string
	err = v.pool.QueryRow(ctx, `
		SELECT attestation_signature FROM request_lineage WHERE request_id = $1
	`, requestID).Scan(&sigB64)
	if err != nil {
		return false, fmt.Errorf("get signature for verify: %w", err)
	}

	return Verify(ed25519.PublicKey(pubKeyBytes), hash, sigB64), nil
}
