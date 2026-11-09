package lineage

import (
	"encoding/hex"
	"testing"
)

func TestAttestationSovereign_SignThenVerify(t *testing.T) {
	key, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	a := AttestationSovereign{
		RequestID: "req-1", ModelUsed: "sakana-evo",
		HomeRegion: "jp", InferenceRegion: "jp",
		ModelOriginCountry: "JP", ModelSovereigntyTier: "full", ModelVendorHQ: "JP",
	}
	if err := a.Sign(key); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if a.Signature == "" {
		t.Fatal("signature empty after Sign")
	}
	ok, err := a.Verify(key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("verify failed on unmodified attestation")
	}
}

func TestAttestationSovereign_TamperedOriginCountry_FailsVerify(t *testing.T) {
	key, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	a := AttestationSovereign{
		RequestID: "req-2", ModelUsed: "m", HomeRegion: "jp",
		ModelOriginCountry: "JP",
	}
	if err := a.Sign(key); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Tamper AFTER signing.
	a.ModelOriginCountry = "CN"
	ok, _ := a.Verify(key)
	if ok {
		t.Fatal("tampered origin_country must fail verify")
	}
}

func TestAttestationSovereign_EmptySignature_VerifyFalse(t *testing.T) {
	a := AttestationSovereign{}
	ok, _ := a.Verify([]byte("k"))
	if ok {
		t.Fatal("empty signature must verify false")
	}
}
