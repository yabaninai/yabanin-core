package lineage

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const testOrgKeyHex = "00112233445566778899aabbccddeeff"

// TestAttestationSovereign_EgressKind_SignThenVerify: the egress-kind scope
// field signs and verifies.
func TestAttestationSovereign_EgressKind_SignThenVerify(t *testing.T) {
	key, _ := hex.DecodeString(testOrgKeyHex)
	a := AttestationSovereign{
		RequestID: "req-eg-1", ModelUsed: "sakana-evo",
		HomeRegion: "sg", InferenceRegion: "sg",
		ModelOriginCountry: "SG", ModelSovereigntyTier: "full",
		EgressKind: "inference",
	}
	if err := a.Sign(key); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := a.Verify(key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("verify failed on unmodified attestation with egress_kind")
	}
}

// TestAttestationSovereign_TamperedEgressKind_FailsVerify: swapping the
// egress kind after signing (e.g. passing an inference attestation off as a
// logs-export proof) must invalidate the signature.
func TestAttestationSovereign_TamperedEgressKind_FailsVerify(t *testing.T) {
	key, _ := hex.DecodeString(testOrgKeyHex)
	a := AttestationSovereign{
		RequestID: "req-eg-2", ModelUsed: "m",
		HomeRegion: "sg", InferenceRegion: "sg",
		EgressKind: "inference",
	}
	if err := a.Sign(key); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	a.EgressKind = "logs"
	ok, _ := a.Verify(key)
	if ok {
		t.Fatal("tampered egress_kind must fail verify")
	}
}

// TestAttestationSovereign_LegacyFormatUnchanged: attestations without an
// egress kind produce the exact legacy canonical form — the omitempty field
// is absent from the signed JSON, so pre-existing signatures verify.
func TestAttestationSovereign_LegacyFormatUnchanged(t *testing.T) {
	key, _ := hex.DecodeString(testOrgKeyHex)
	legacy := AttestationSovereign{
		RequestID: "req-eg-3", ModelUsed: "m",
		HomeRegion: "jp", InferenceRegion: "jp",
		ModelOriginCountry: "JP",
	}
	if err := legacy.Sign(key); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := legacy.Verify(key)
	if err != nil || !ok {
		t.Fatalf("legacy attestation must verify (ok=%v err=%v)", ok, err)
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "egress_kind") {
		t.Errorf("empty egress_kind must be omitted from JSON, got: %s", raw)
	}
}

// TestAttestationSovereign_EgressKindJSON: the field serializes when set.
func TestAttestationSovereign_EgressKindJSON(t *testing.T) {
	a := AttestationSovereign{RequestID: "r", EgressKind: "tools"}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"egress_kind":"tools"`) {
		t.Errorf("expected egress_kind in JSON, got: %s", raw)
	}
	var back AttestationSovereign
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.EgressKind != "tools" {
		t.Errorf("round trip lost egress_kind: %q", back.EgressKind)
	}
}
