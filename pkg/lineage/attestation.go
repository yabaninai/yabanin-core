package lineage

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Attestation is the canonical claim signed per request. Field order is FIXED
// — hashing uses json.Marshal of this struct directly, and Go marshals struct
// fields in source order, which is byte-identical across machines and builds.
// DO NOT reorder fields without bumping a schema version (would invalidate
// every historical attestation hash).
type Attestation struct {
	RequestID        string `json:"request_id"`
	OrgID            string `json:"org_id"`
	Timestamp        string `json:"timestamp"` // RFC3339Nano UTC
	ModelUsed        string `json:"model_used"`
	InferenceRegion  string `json:"inference_region"`
	ModelOrigin      string `json:"model_origin_country"`
	LogStorageRegion string `json:"log_storage_region"`
	ProviderEntity   string `json:"provider_entity_jurisdiction"`
	// RegionEvidence grades InferenceRegion: "provider_attested" |
	// "endpoint_pinned" | "header_observed" | "provider_declared".
	// MUST stay the LAST field with omitempty: historical attestations were
	// signed without it, and an omitted field keeps their re-marshaled JSON
	// byte-identical so verification of old rows still succeeds.
	RegionEvidence string `json:"region_evidence,omitempty"`
}

// CanonicalBytes returns the deterministic JSON encoding used for hashing.
// Single source of truth — both the gateway signer and the loggerd consumer
// call this so the stored raw_attestation is byte-identical to the signed one.
func (a Attestation) CanonicalBytes() ([]byte, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("marshal attestation: %w", err)
	}
	return b, nil
}

// Hash returns hex SHA-256 of the canonical attestation JSON.
func (a Attestation) Hash() (string, error) {
	b, err := a.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Signer signs attestation hashes with an org's Ed25519 private key.
type Signer struct {
	keyID string
	priv  ed25519.PrivateKey // 64 bytes
}

// NewSigner builds a signer. priv must be ed25519.PrivateKeySize (64) bytes.
func NewSigner(keyID string, priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return &Signer{keyID: keyID, priv: priv}, nil
}

// KeyID returns the signing key identifier.
func (s *Signer) KeyID() string { return s.keyID }

// Sign returns (keyID, base64 signature) over the hex hash string.
func (s *Signer) Sign(hashHex string) (keyID, signatureB64 string, err error) {
	if s == nil || s.priv == nil {
		return "", "", errors.New("signer not initialised")
	}
	if hashHex == "" {
		return "", "", errors.New("empty hash")
	}
	sig := ed25519.Sign(s.priv, []byte(hashHex))
	return s.keyID, base64.StdEncoding.EncodeToString(sig), nil
}

// Verify checks a base64 Ed25519 signature against a pubkey over the hash.
func Verify(pub ed25519.PublicKey, hashHex, signatureB64 string) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(hashHex), sig)
}

// GenerateKeyPair creates a new Ed25519 keypair. Returns the 32-byte pubkey
// and the base64-encoded 64-byte private key (caller wraps it with
// pkg/encryption before persisting to org_lineage_keys.private_key).
func GenerateKeyPair() (pub []byte, privB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	return pub, base64.StdEncoding.EncodeToString(priv), nil
}

// DecodePrivateKey base64-decodes the stored private key back to 64 bytes.
func DecodePrivateKey(privB64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key wrong size %d, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}
