package handlers

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/reireirei/yabanin/pkg/lineage"
)

// lineageVerifyImpl verifies attestation signatures for admin endpoints.
type lineageVerifyImpl struct {
	store LineageStore
	ks    *lineage.KeyStore
	ls    *lineage.LedgerStore
}

// NewLineageVerifier creates a LineageVerifier backed by the KeyStore and LedgerStore.
func NewLineageVerifier(store LineageStore, ks *lineage.KeyStore, ls *lineage.LedgerStore) LineageVerifier {
	return &lineageVerifyImpl{store: store, ks: ks, ls: ls}
}

// VerifyRequest recomputes the attestation hash and verifies its Ed25519 signature.
func (v *lineageVerifyImpl) VerifyRequest(ctx context.Context, requestID string) (bool, error) {
	att, err := v.store.GetLineageByRequestID(ctx, requestID)
	if err != nil {
		return false, fmt.Errorf("get lineage for verification: %w", err)
	}

	// Recompute hash from the attestation struct.
	hashHex, err := att.Hash()
	if err != nil {
		return false, fmt.Errorf("compute attestation hash: %w", err)
	}

	// Fetch stored signature and key_id from ledger.
	sigB64, keyID, err := v.ls.GetSignatureByRequestID(ctx, requestID)
	if err != nil {
		return false, fmt.Errorf("get stored signature: %w", err)
	}

	// Decode to validate it's well-formed (full verification uses lineage.Verify).
	if _, err := base64.StdEncoding.DecodeString(sigB64); err != nil {
		return false, fmt.Errorf("decode stored signature: %w", err)
	}

	// Fetch the org's public key.
	storedKeyID, pub, err := v.ks.GetPublicKeyByOrgID(ctx, att.OrgID)
	if err != nil {
		return false, fmt.Errorf("retrieve public key for org %s: %w", att.OrgID, err)
	}

	if storedKeyID != keyID {
		return false, fmt.Errorf("key mismatch: expected %s, got %s", keyID, storedKeyID)
	}

	// Verify Ed25519 signature using the lineage package's built-in verifier.
	valid := lineage.Verify(pub, hashHex, sigB64)
	if !valid {
		return false, nil // signature is invalid (not an error)
	}

	return true, nil
}
