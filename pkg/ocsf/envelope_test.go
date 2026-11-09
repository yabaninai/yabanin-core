package ocsf

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Envelope fixtures: two mapped records of one org (built through the
// real mapper so the corpus never drifts from the record contract).
func envelopeRecords(t *testing.T) []NormalizedRecord {
	t.Helper()
	out := make([]NormalizedRecord, 0, 2)
	for _, eventType := range []string{"policy.deny", "policy.mask"} {
		rec, err := MapEvent(fixture(eventType))
		if err != nil {
			t.Fatalf("MapEvent(%s): %v", eventType, err)
		}
		out = append(out, rec)
	}
	return out
}

const (
	testSecret    = "whsec_e07p01b_test_secret" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	testTolerance = 5 * time.Minute
)

var testSignTime = time.Date(2026, 11, 7, 20, 0, 0, 0, time.UTC)

func testVerifyTime() time.Time { return testSignTime.Add(time.Minute) }

// TestEnvelopeNewDeterministicID pins the W03-C01 identity contract:
// EnvelopeID is a derivative of (org, schema_version, records) ONLY —
// identical inputs re-derive the identical id; issuedAt (an instance
// attribute) never shifts it; any content/org/version change does.
func TestEnvelopeNewDeterministicID(t *testing.T) {
	records := envelopeRecords(t)
	issued := time.Date(2026, 11, 7, 19, 0, 0, 0, time.UTC)

	first, err := NewEnvelope("org-1", records, issued)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	again, err := NewEnvelope("org-1", records, issued.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("NewEnvelope (later issue): %v", err)
	}
	if first.EnvelopeID != again.EnvelopeID {
		t.Fatalf("envelope_id changed with issued_at: %q vs %q", first.EnvelopeID, again.EnvelopeID)
	}
	if !strings.HasPrefix(first.EnvelopeID, "env-") {
		t.Fatalf("envelope_id %q must carry the env- prefix", first.EnvelopeID)
	}

	foreign := records[0]
	foreign.OrgID = "org-2"
	other, err := NewEnvelope("org-2", []NormalizedRecord{foreign}, issued)
	if err != nil {
		t.Fatalf("NewEnvelope(org-2): %v", err)
	}
	if other.EnvelopeID == first.EnvelopeID {
		t.Fatalf("different (org, records) produced the same envelope_id")
	}

	trimmed, err := NewEnvelope("org-1", records[:1], issued)
	if err != nil {
		t.Fatalf("NewEnvelope(trimmed): %v", err)
	}
	if trimmed.EnvelopeID == first.EnvelopeID {
		t.Fatalf("different records produced the same envelope_id")
	}
}

// TestEnvelopeNewCrossOrgRejected: an envelope is single-org; a record
// of another org is rejected at construction (DISPATCH §8 отказ
// прав/cross-org for W03; the adversarial battery re-proves it at
// verification time).
func TestEnvelopeNewCrossOrgRejected(t *testing.T) {
	records := envelopeRecords(t)
	foreign := records[0]
	foreign.OrgID = "org-other"
	if _, err := NewEnvelope("org-1", []NormalizedRecord{records[1], foreign}, testSignTime); !errors.Is(err, ErrCrossOrgRecord) {
		t.Fatalf("err = %v, want ErrCrossOrgRecord", err)
	}
}

// TestEnvelopeNewInvalidInput: constructor input discipline (empty org,
// zero/ pre-epoch issue time, record version drift, missing anchor).
func TestEnvelopeNewInvalidInput(t *testing.T) {
	records := envelopeRecords(t)
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"empty org", func(t *testing.T) {
			t.Helper()
			_, err := NewEnvelope("", records, testSignTime)
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("err = %v, want ErrInvalidEnvelope", err)
			}
		}},
		{"zero issued at", func(t *testing.T) {
			t.Helper()
			_, err := NewEnvelope("org-1", records, time.Time{})
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("err = %v, want ErrInvalidEnvelope", err)
			}
		}},
		{"pre-epoch issued at", func(t *testing.T) {
			t.Helper()
			_, err := NewEnvelope("org-1", records, time.UnixMilli(-1))
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("err = %v, want ErrInvalidEnvelope", err)
			}
		}},
		{"record schema version drift", func(t *testing.T) {
			t.Helper()
			drifted := records
			drifted[0].SchemaVersion = ExportSchemaVersion + 1
			_, err := NewEnvelope("org-1", drifted, testSignTime)
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("err = %v, want ErrInvalidEnvelope", err)
			}
		}},
		{"record without dedup anchor", func(t *testing.T) {
			t.Helper()
			anchorless := records
			anchorless[0].FindingInfo.UID = ""
			_, err := NewEnvelope("org-1", anchorless, testSignTime)
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("err = %v, want ErrInvalidEnvelope", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

// TestEnvelopeEmptyRecordsValid records the explicit empty-batch
// decision (DISPATCH W03-C02 «пустое»): an envelope with zero records
// is valid, encodes as [] (never null), validates against the schema
// and is signable. It stays org-bound through its identity.
func TestEnvelopeEmptyRecordsValid(t *testing.T) {
	env, err := NewEnvelope("org-1", nil, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope(empty): %v", err)
	}
	if len(env.Records) != 0 {
		t.Fatalf("records len = %d, want 0", len(env.Records))
	}
	body, err := EncodeEnvelope(env)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	if !strings.Contains(string(body), `"records":[]`) {
		t.Fatalf("empty batch must encode as [], got %s", body)
	}
	if err := ValidateEnvelopeJSON(body); err != nil {
		t.Fatalf("empty envelope must validate: %v", err)
	}
	if _, _, err := SignEnvelope(testSecret, env, testSignTime); err != nil {
		t.Fatalf("empty envelope must be signable: %v", err)
	}
}

// TestEnvelopeEncodeCanonical: the encoding is byte-deterministic and
// schema-valid by construction — the signature input must be stable.
func TestEnvelopeEncodeCanonical(t *testing.T) {
	records := envelopeRecords(t)
	first, err := NewEnvelope("org-1", records, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	second, err := NewEnvelope("org-1", records, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	a, err := EncodeEnvelope(first)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	b, err := EncodeEnvelope(second)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if sha256.Sum256(a) != sha256.Sum256(b) {
		t.Fatalf("canonical encoding is not byte-deterministic")
	}
	if err := ValidateEnvelopeJSON(a); err != nil {
		t.Fatalf("envelope output must validate against export-v1: %v", err)
	}
	// Attempt stays omitted at first issue (W04 populates it later).
	var raw map[string]any
	if err := json.Unmarshal(a, &raw); err != nil {
		t.Fatalf("decode own output: %v", err)
	}
	if _, has := raw["attempt"]; has {
		t.Fatalf("first issue must omit attempt, got %s", a)
	}
}

// TestEnvelopeSignVerifyRoundtrip: the разрешённый scenario — sign once
// with the issuing secret, verify with the same secret inside the
// tolerance window. Composition round-trip through pkg/webhooks v2.
func TestEnvelopeSignVerifyRoundtrip(t *testing.T) {
	env, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	body, header, err := SignEnvelope(testSecret, env, testSignTime)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	if !strings.HasPrefix(header, "t=") || !strings.Contains(header, ",v1=") {
		t.Fatalf("header %q must be the webhooks v2 form", header)
	}
	if err := VerifyEnvelope(testSecret, header, body, "org-1", testTolerance, testVerifyTime()); err != nil {
		t.Fatalf("roundtrip verify: %v", err)
	}
}

// TestEnvelopeVerifyMissingSignature: no signature ⇒ FAIL (отказ).
func TestEnvelopeVerifyMissingSignature(t *testing.T) {
	env, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	body, _, err := SignEnvelope(testSecret, env, testSignTime)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	for name, header := range map[string]string{"empty": "", "garbage": "not-a-signature"} {
		if err := VerifyEnvelope(testSecret, header, body, "org-1", testTolerance, testVerifyTime()); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("%s header: err = %v, want ErrBadSignature", name, err)
		}
	}
}

// TestEnvelopeVerifyWrongKey: a different secret never verifies.
func TestEnvelopeVerifyWrongKey(t *testing.T) {
	env, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	body, header, err := SignEnvelope(testSecret, env, testSignTime)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	err = VerifyEnvelope("whsec_wrong_key", header, body, "org-1", testTolerance, testVerifyTime())
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// TestEnvelopeVerifyIdempotentWithinWindow (повтор): re-verifying the
// same envelope inside the tolerance window keeps returning OK — the
// verdict is a pure function of (secret, header, body, org, now).
func TestEnvelopeVerifyIdempotentWithinWindow(t *testing.T) {
	env, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	body, header, err := SignEnvelope(testSecret, env, testSignTime)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	for i, now := range []time.Time{
		testVerifyTime(),
		testSignTime.Add(testTolerance - 10*time.Second),       // still inside
		testSignTime.Add(-testTolerance).Add(10 * time.Second), // symmetric future skew, inside
	} {
		if err := VerifyEnvelope(testSecret, header, body, "org-1", testTolerance, now); err != nil {
			t.Fatalf("verify rep %d inside window: %v", i, err)
		}
	}
}

// TestEnvelopeVerifyOutsideWindow (задержка): a signature older than
// the tolerance is expired; one dated beyond the symmetric future bound
// is rejected as well (webhooks v2 window semantics).
func TestEnvelopeVerifyOutsideWindow(t *testing.T) {
	env, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	body, header, err := SignEnvelope(testSecret, env, testSignTime)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	if err := VerifyEnvelope(testSecret, header, body, "org-1", testTolerance, testSignTime.Add(testTolerance+time.Second)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expired signature: err = %v, want ErrBadSignature", err)
	}
	if err := VerifyEnvelope(testSecret, header, body, "org-1", testTolerance, testSignTime.Add(-testTolerance-time.Second)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("future signature: err = %v, want ErrBadSignature", err)
	}
}

// TestEnvelopeSignEnvelopeGuards: empty secret / zero signing time fail
// closed instead of producing a forgeable MAC.
func TestEnvelopeSignEnvelopeGuards(t *testing.T) {
	env, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if _, _, err := SignEnvelope("", env, testSignTime); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("empty secret: err = %v, want ErrEmptySecret", err)
	}
	if _, _, err := SignEnvelope(testSecret, env, time.Time{}); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("zero sign time: err = %v, want ErrInvalidEnvelope", err)
	}
	if err := VerifyEnvelope("", "t=1,v1=x", []byte("{}"), "org-1", testTolerance, testVerifyTime()); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("verify empty secret: err = %v, want ErrEmptySecret", err)
	}
}
