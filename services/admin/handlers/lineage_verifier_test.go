package handlers_test

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/lineage"
)

// TestLineageVerifier_Ed25519 verifies full Ed25519 signature verification.
func TestLineageVerifier_Ed25519(t *testing.T) {
	// Generate a test keypair using the lineage package.
	pub, privB64, err := lineage.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	// Create a signer with the private key.
	priv, err := lineage.DecodePrivateKey(privB64)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	signer, err := lineage.NewSigner("test:key:v1", priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	// Create an attestation and sign its hash.
	att := lineage.Attestation{
		RequestID:        "req-001",
		OrgID:            "org-test",
		Timestamp:        "2026-01-01T00:00:00Z",
		ModelUsed:        "gpt-4",
		InferenceRegion:  "US",
		ModelOrigin:      "US",
		LogStorageRegion: "US",
		ProviderEntity:   "US",
	}

	hashHex, err := att.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	_, sigB64, err := signer.Sign(hashHex)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify with lineage.Verify.
	if !lineage.Verify(pub, hashHex, sigB64) {
		t.Fatal("expected valid signature")
	}

	// Tamper: change the model_used → hash changes → verify fails.
	att.ModelUsed = "gpt-5"
	hashTampered, err := att.Hash()
	if err != nil {
		t.Fatalf("hash tampered: %v", err)
	}
	if lineage.Verify(pub, hashTampered, sigB64) {
		t.Fatal("expected invalid signature after tampering")
	}

	// Wrong key should fail.
	_, priv2B64, err := lineage.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}
	priv2, _ := lineage.DecodePrivateKey(priv2B64)
	signer2, _ := lineage.NewSigner("test:key:v2", priv2)
	_, badSigB64, _ := signer2.Sign(hashHex)
	if lineage.Verify(pub, hashHex, badSigB64) {
		t.Fatal("expected invalid signature from different key")
	}
}
