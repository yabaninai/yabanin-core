package lineage

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleAttestation() Attestation {
	return Attestation{
		RequestID:        "req-001",
		OrgID:            "org-abc",
		Timestamp:        "2026-07-23T10:00:00Z",
		ModelUsed:        "gpt-4o",
		InferenceRegion:  "US",
		ModelOrigin:      "US",
		LogStorageRegion: "SG",
		ProviderEntity:   "US",
	}
}

func TestAttestation_HashDeterminism(t *testing.T) {
	h1, err := sampleAttestation().Hash()
	if err != nil {
		t.Fatalf("hash1: %v", err)
	}
	h2, err := sampleAttestation().Hash()
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("non-deterministic hash: %s != %s", h1, h2)
	}
	if len(h1) != 64 { // hex sha256
		t.Errorf("hash length %d, want 64", len(h1))
	}
}

func TestAttestation_HashChangesOnMutation(t *testing.T) {
	base := sampleAttestation()
	h1, _ := base.Hash()
	mutated := base
	mutated.InferenceRegion = "SG"
	h2, _ := mutated.Hash()
	if h1 == h2 {
		t.Fatal("hash unchanged after mutating InferenceRegion")
	}
}

// TestAttestation_LegacyJSON_HashBackcompat proves that attestations signed
// BEFORE region_evidence existed still verify: their JSON unmarshals into the
// struct (new field zero), and re-marshaling with omitempty reproduces the
// original bytes, so the recomputed hash matches the stored signature.
func TestAttestation_LegacyJSON_HashBackcompat(t *testing.T) {
	legacy := sampleAttestation()
	legacyBytes, err := legacy.CanonicalBytes() // what a pre-PB1.7 gateway signed
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	if strings.Contains(string(legacyBytes), "region_evidence") {
		t.Fatalf("legacy bytes must not contain region_evidence, got %s", legacyBytes)
	}
	legacyHash, err := legacy.Hash()
	if err != nil {
		t.Fatalf("hash legacy: %v", err)
	}

	// Round-trip through JSON the way the admin verifier does.
	var decoded Attestation
	if err := json.Unmarshal(legacyBytes, &decoded); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	reHash, err := decoded.Hash()
	if err != nil {
		t.Fatalf("rehash: %v", err)
	}
	if reHash != legacyHash {
		t.Fatal("re-marshaled legacy attestation changed hash — verification of historical rows would break")
	}

	// A NEW attestation carries the field and hashes differently.
	withEvidence := legacy
	withEvidence.RegionEvidence = "endpoint_pinned"
	newBytes, err := withEvidence.CanonicalBytes()
	if err != nil {
		t.Fatalf("marshal new: %v", err)
	}
	if !strings.Contains(string(newBytes), `"region_evidence":"endpoint_pinned"`) {
		t.Fatalf("new attestation must carry region_evidence, got %s", newBytes)
	}
	newHash, _ := withEvidence.Hash()
	if newHash == legacyHash {
		t.Fatal("evidence tier must change the hash (it is signed material)")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	pub, privB64, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(pub) != 32 {
		t.Errorf("pub size %d, want 32", len(pub))
	}
	priv, err := DecodePrivateKey(privB64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(priv) != 64 {
		t.Errorf("priv size %d, want 64", len(priv))
	}
}

func TestSigner_RoundTrip_SignVerify(t *testing.T) {
	pub, privB64, _ := GenerateKeyPair()
	priv, _ := DecodePrivateKey(privB64)
	s, err := NewSigner("org:test:v1", priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	hash, _ := sampleAttestation().Hash()

	keyID, sig, err := s.Sign(hash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if keyID != "org:test:v1" {
		t.Errorf("keyID %q", keyID)
	}
	if !Verify(pub, hash, sig) {
		t.Fatal("valid signature failed to verify")
	}

	// Tamper the hash — should fail verification.
	if Verify(pub, "tampered", sig) {
		t.Fatal("tampered hash should not verify")
	}

	// Wrong pubkey — should fail.
	pub2, _, _ := GenerateKeyPair()
	if Verify(pub2, hash, sig) {
		t.Fatal("wrong pubkey should not verify")
	}

	// Nil signer.
	var nilSig *Signer
	if _, _, err := nilSig.Sign(hash); err == nil || !strings.Contains(err.Error(), "not initialised") {
		t.Fatalf("expected 'not initialised' error, got %v", err)
	}

	// Empty hash.
	if _, _, err := s.Sign(""); err == nil || !strings.Contains(err.Error(), "empty hash") {
		t.Fatalf("expected 'empty hash' error, got %v", err)
	}

	// Invalid key size.
	if _, err := NewSigner("x", []byte("short")); err == nil {
		t.Fatal("expected error for short key")
	}

	// Invalid base64 private key.
	if _, err := DecodePrivateKey("not-base64!!!"); err == nil {
		t.Fatal("expected decode error for invalid base64")
	}

	// Valid base64 but wrong size.
	if _, err := DecodePrivateKey("YWJjZA=="); err == nil { // "abcd" = 4 bytes
		t.Fatal("expected size error for short decoded key")
	}
}
