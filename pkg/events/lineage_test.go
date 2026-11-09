package events

import (
	"encoding/json"
	"testing"
)

// TestPayload_LineageFields_RoundTrip verifies that all lineage fields
// survive a JSON marshal/unmarshal round-trip on the Payload struct.
// This guards against producer/consumer drift (the exact bug P5 had with tier_used).
func TestPayload_LineageFields_RoundTrip(t *testing.T) {
	p := Payload{
		InferenceRegion:            "SG",
		RegionEvidence:             "endpoint_pinned",
		ModelOriginCountry:         "US",
		LogStorageRegion:           "SG",
		ProviderEntityJurisdiction: "US",
		AttestationHash:            "abcdef0123456789",
		AttestationSignature:       "c2lnbmF0dXJl",
		AttestationKeyID:           "org:abc-123:v1",
	}

	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	var p2 Payload
	if err := json.Unmarshal(raw, &p2); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	cases := []struct{ name, got, want string }{
		{"inference_region", p2.GetInferenceRegion(), "SG"},
		{"region_evidence", p2.GetRegionEvidence(), "endpoint_pinned"},
		{"model_origin_country", p2.GetModelOriginCountry(), "US"},
		{"log_storage_region", p2.GetLogStorageRegion(), "SG"},
		{"provider_entity_jurisdiction", p2.GetProviderEntityJurisdiction(), "US"},
		{"attestation_hash", p2.GetAttestationHash(), "abcdef0123456789"},
		{"attestation_signature", p2.GetAttestationSignature(), "c2lnbmF0dXJl"},
		{"attestation_key_id", p2.GetAttestationKeyID(), "org:abc-123:v1"},
	}
	if len(cases) != LineageFieldsCount {
		t.Fatalf("test cases %d != LineageFieldsCount %d", len(cases), LineageFieldsCount)
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q want %q", c.name, c.got, c.want)
		}
	}
}
