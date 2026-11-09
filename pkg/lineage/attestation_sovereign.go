package lineage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// AttestationSovereign extends the base Ed25519-attestation with sovereignty
// provenance fields. PB4.6 ensures these are included in the HMAC signature
// so tampering with model_origin_country invalidates the signature.
//
// Scope note (N09-P05 negative criterion): an attestation proves where ONE
// request's inference ran for ONE egress kind. It is NOT a blanket legal
// residency guarantee — a country endpoint, pinned region or observed
// header is evidence for this request and egress kind only.
type AttestationSovereign struct {
	RequestID            string `json:"request_id"`
	ModelUsed            string `json:"model_used"`
	HomeRegion           string `json:"home_region"`
	InferenceRegion      string `json:"inference_region"`
	ModelOriginCountry   string `json:"model_origin_country,omitempty"`
	ModelSovereigntyTier string `json:"model_sovereignty_tier,omitempty"`
	ModelVendorHQ        string `json:"model_vendor_hq,omitempty"`
	// EgressKind records WHICH data boundary this attestation covers — a
	// sovereign.EgressKind value ("inference","embeddings","logs",
	// "export","tools"). A per-inference attestation must not be presented
	// as a logs-export or tool egress residency proof. Empty means the
	// legacy inference-egress-only attestation format. Signature-covered:
	// tampering with egress_kind invalidates verification.
	EgressKind string `json:"egress_kind,omitempty"`
	// Signature = HMAC-SHA256(canonical fields, orgKey).
	Signature string `json:"signature,omitempty"`
}

// canonical returns the deterministic JSON byte form that the signature covers.
// Field order is fixed; omitempty fields are omitted so partial attestations
// still verify. The sovereignty fields are INCLUDED so any tampering with
// origin_country invalidates the signature. EgressKind is included for the
// same reason; attestations signed before the field existed verify unchanged
// because empty omits it.
func (a AttestationSovereign) canonical() ([]byte, error) {
	payload := struct {
		RequestID            string `json:"request_id"`
		ModelUsed            string `json:"model_used"`
		HomeRegion           string `json:"home_region"`
		InferenceRegion      string `json:"inference_region"`
		ModelOriginCountry   string `json:"model_origin_country,omitempty"`
		ModelSovereigntyTier string `json:"model_sovereignty_tier,omitempty"`
		ModelVendorHQ        string `json:"model_vendor_hq,omitempty"`
		EgressKind           string `json:"egress_kind,omitempty"`
	}{
		RequestID: a.RequestID, ModelUsed: a.ModelUsed,
		HomeRegion: a.HomeRegion, InferenceRegion: a.InferenceRegion,
		ModelOriginCountry:   a.ModelOriginCountry,
		ModelSovereigntyTier: a.ModelSovereigntyTier,
		ModelVendorHQ:        a.ModelVendorHQ,
		EgressKind:           a.EgressKind,
	}
	return json.Marshal(payload)
}

// Sign computes and sets the HMAC-SHA256 signature over the canonical form.
// orgKey is the per-org lineage signing key (PB1.5, 32 bytes recommended).
func (a *AttestationSovereign) Sign(orgKey []byte) error {
	body, err := a.canonical()
	if err != nil {
		return fmt.Errorf("attestation canonical: %w", err)
	}
	mac := hmac.New(sha256.New, orgKey)
	mac.Write(body)
	a.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// Verify checks the signature matches the canonical form. Returns false (not
// an error) when the signature is absent or mismatched — callers decide
// severity. A mismatched origin_country flips this to false.
func (a AttestationSovereign) Verify(orgKey []byte) (bool, error) {
	if a.Signature == "" {
		return false, nil
	}
	body, err := a.canonical()
	if err != nil {
		return false, fmt.Errorf("attestation canonical: %w", err)
	}
	mac := hmac.New(sha256.New, orgKey)
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(a.Signature)), nil
}
