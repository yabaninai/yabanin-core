package ocsf

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/webhooks"
)

// W03-C02 tamper/rotation battery. Every case verifies FAIL-closed
// except the two explicitly-valid ones (dual-key window, empty batch).
//
// Recorded decisions:
//   - An envelope with 0 records is VALID and signable (explicit empty
//     export — DISPATCH §8 «пустое»); it is still org-bound through its
//     identity.
//   - Key rotation is a CONNECTOR-side accepted-secrets set (dual-key
//     window, the pkg/webhooks pattern); the library stays single-secret
//     per call — see verifyDualKey below.

// signForTest is the battery's signing shortcut.
func signForTest(t *testing.T, secret string, env Envelope) (body []byte, header string) {
	t.Helper()
	b, h, err := SignEnvelope(secret, env, testSignTime)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	return b, h
}

// verifyDualKey is the consumer-side rotation pattern (pkg/webhooks
// dual-key precedent): during a rotation window the connector accepts
// BOTH the outgoing and the incoming secret; the library itself takes
// one secret per call, so rotation composes without new crypto.
func verifyDualKey(secrets []string, header string, body []byte, orgID string, tolerance time.Duration, now time.Time) error {
	var first error
	for i, secret := range secrets {
		err := VerifyEnvelope(secret, header, body, orgID, tolerance, now)
		if err == nil {
			return nil
		}
		if i == 0 {
			first = err
		}
	}
	return first
}

// TestEnvelopeAdversarialModifiedPayload: any byte-level change to the
// signed body breaks the HMAC — here a semantic record edit (severity
// downgrade attempt) re-encoded canonically.
func TestEnvelopeAdversarialModifiedPayload(t *testing.T) {
	env, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	body, header := signForTest(t, testSecret, env)

	var mutated map[string]any
	if err := json.Unmarshal(body, &mutated); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	mutated["records"].([]any)[0].(map[string]any)["severity_id"] = json.Number("1") // 4 → 1 downgrade
	reencoded, err := json.Marshal(mutated)
	if err != nil {
		t.Fatalf("re-mutate: %v", err)
	}
	if err := VerifyEnvelope(testSecret, header, reencoded, "org-1", testTolerance, testVerifyTime()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("downgraded record verified: err = %v, want ErrBadSignature", err)
	}
	// A single flipped byte fails identically.
	flipped := append([]byte(nil), body...)
	flipped[len(flipped)/2] ^= 0x01
	if err := VerifyEnvelope(testSecret, header, flipped, "org-1", testTolerance, testVerifyTime()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("flipped byte verified: err = %v, want ErrBadSignature", err)
	}
}

// TestEnvelopeAdversarialInjectedRecord: appending an extra record to
// the signed array (keeping the old signature) fails — even when the
// injected record is a legitimate record of the SAME org.
func TestEnvelopeAdversarialInjectedRecord(t *testing.T) {
	records := envelopeRecords(t)
	env, err := NewEnvelope("org-1", records, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	body, header := signForTest(t, testSecret, env)

	var mutated map[string]any
	if err := json.Unmarshal(body, &mutated); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	extra, err := MapEvent(fixture("policy.allow"))
	if err != nil {
		t.Fatalf("MapEvent: %v", err)
	}
	extraJSON, err := json.Marshal(extra)
	if err != nil {
		t.Fatalf("marshal extra: %v", err)
	}
	var extraAny any
	if err := json.Unmarshal(extraJSON, &extraAny); err != nil {
		t.Fatalf("re-decode extra: %v", err)
	}
	mutated["records"] = append(mutated["records"].([]any), extraAny)
	reencoded, err := json.Marshal(mutated)
	if err != nil {
		t.Fatalf("re-mutate: %v", err)
	}
	if err := VerifyEnvelope(testSecret, header, reencoded, "org-1", testTolerance, testVerifyTime()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("injected record verified: err = %v, want ErrBadSignature", err)
	}
}

// TestEnvelopeAdversarialKeyRotation: during the rotation window BOTH
// secrets are accepted (dual-key, verifyDualKey); after rotation only
// the new secret is. Envelopes signed with the outgoing secret stop
// verifying the moment it leaves the accepted set.
func TestEnvelopeAdversarialKeyRotation(t *testing.T) {
	const (
		oldSecret = "whsec_rotation_old" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
		newSecret = "whsec_rotation_new" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	)
	env, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	oldBody, oldHeader := signForTest(t, oldSecret, env)
	newBody, newHeader := signForTest(t, newSecret, env)

	dual := []string{oldSecret, newSecret}

	// Window: envelope under either key verifies against the accepted set.
	if err := verifyDualKey(dual, oldHeader, oldBody, "org-1", testTolerance, testVerifyTime()); err != nil {
		t.Fatalf("old-key envelope rejected during rotation window: %v", err)
	}
	if err := verifyDualKey(dual, newHeader, newBody, "org-1", testTolerance, testVerifyTime()); err != nil {
		t.Fatalf("new-key envelope rejected during rotation window: %v", err)
	}

	// After rotation: only the new set; the outgoing secret no longer
	// verifies anything.
	if err := verifyDualKey([]string{newSecret}, newHeader, newBody, "org-1", testTolerance, testVerifyTime()); err != nil {
		t.Fatalf("new-key envelope rejected after rotation: %v", err)
	}
	if err := verifyDualKey([]string{newSecret}, oldHeader, oldBody, "org-1", testTolerance, testVerifyTime()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("old-key envelope still accepted after rotation: err = %v, want ErrBadSignature", err)
	}
	// Cross-verification of single secrets never holds.
	if err := VerifyEnvelope(newSecret, oldHeader, oldBody, "org-1", testTolerance, testVerifyTime()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("old signature verified under new key: err = %v, want ErrBadSignature", err)
	}
}

// TestEnvelopeAdversarialCrossOrgRecord: an envelope carrying a record
// of another org is rejected — twice. At construction the single-org
// contract fires; at verification the org is bound into the envelope
// identity AND the HMAC input (the id is part of the signed body), so
// even a correctly re-signed envelope cannot smuggle a foreign record
// past an org-pinned verifier.
func TestEnvelopeAdversarialCrossOrgRecord(t *testing.T) {
	records := envelopeRecords(t)

	// 1. Construction: mixing orgs is an error.
	foreign := records[0]
	foreign.OrgID = "org-evil"
	if _, err := NewEnvelope("org-1", []NormalizedRecord{records[1], foreign}, testSignTime); !errors.Is(err, ErrCrossOrgRecord) {
		t.Fatalf("mixed-org envelope built: err = %v, want ErrCrossOrgRecord", err)
	}

	// 2. Verification against the wrong expected org: a legitimate
	// org-1 envelope fails an org-2 verifier (record org mismatch).
	env, err := NewEnvelope("org-1", records, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	body, header := signForTest(t, testSecret, env)
	if err := VerifyEnvelope(testSecret, header, body, "org-2", testTolerance, testVerifyTime()); !errors.Is(err, ErrCrossOrgRecord) {
		t.Fatalf("org-1 envelope accepted by org-2 verifier: err = %v, want ErrCrossOrgRecord", err)
	}

	// 3. Even a fully re-signed body (attacker holds the secret) cannot
	// carry org-2 records under an org-1 identity: the handcrafted id
	// does not match the records, and the records do not match the
	// expected org.
	org2rec := records[0]
	org2rec.OrgID = "org-2"
	org2env, err := NewEnvelope("org-2", []NormalizedRecord{org2rec}, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope(org-2): %v", err)
	}
	org2env.EnvelopeID = env.EnvelopeID // lie: org-1's id on org-2 records
	org2body, org2header := signForTest(t, testSecret, org2env)
	err = VerifyEnvelope(testSecret, org2header, org2body, "org-1", testTolerance, testVerifyTime())
	if !errors.Is(err, ErrCrossOrgRecord) && !errors.Is(err, ErrEnvelopeIDMismatch) {
		t.Fatalf("foreign-org records under a stolen id verified: err = %v, want ErrCrossOrgRecord or ErrEnvelopeIDMismatch", err)
	}
}

// TestEnvelopeAdversarialEnvelopeIDTamper: the identity itself is
// signed content — swapping it (with a valid signature over the edited
// body) fails the recomputation check.
func TestEnvelopeAdversarialEnvelopeIDTamper(t *testing.T) {
	env, err := NewEnvelope("org-1", envelopeRecords(t), testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	env.EnvelopeID = "env-" + strings.Repeat("ab", 32)
	body, header := signForTest(t, testSecret, env)
	if err := VerifyEnvelope(testSecret, header, body, "org-1", testTolerance, testVerifyTime()); !errors.Is(err, ErrEnvelopeIDMismatch) {
		t.Fatalf("swapped envelope_id verified: err = %v, want ErrEnvelopeIDMismatch", err)
	}
}

// TestEnvelopeAdversarialSchemaBypass: a body that passes HMAC (signed
// directly over the crafted bytes with a held secret) but violates the
// envelope schema still fails — verification composes authentication
// with validation, and neither alone is sufficient.
func TestEnvelopeAdversarialSchemaBypass(t *testing.T) {
	badBody := []byte(`{"schema_version":1,"envelope_id":"","issued_at":1,"records":null}`)
	tSig, sig := webhooks.Sign(testSecret, testSignTime, badBody)
	header := webhooks.SignatureHeader(tSig, sig)
	err := VerifyEnvelope(testSecret, header, badBody, "org-1", testTolerance, testVerifyTime())
	if err == nil || errors.Is(err, ErrBadSignature) {
		t.Fatalf("schema-invalid body with a valid HMAC must fail on the schema, got err = %v", err)
	}
}

// TestEnvelopeAdversarialEmptyBatchSignable: the explicit empty-export
// decision — 0 records round-trips sign→verify cleanly and is bound to
// its org (a foreign verifier rejects it through the identity).
func TestEnvelopeAdversarialEmptyBatchSignable(t *testing.T) {
	env, err := NewEnvelope("org-1", nil, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope(empty): %v", err)
	}
	body, header := signForTest(t, testSecret, env)
	if err := VerifyEnvelope(testSecret, header, body, "org-1", testTolerance, testVerifyTime()); err != nil {
		t.Fatalf("empty envelope failed verify: %v", err)
	}
	if err := VerifyEnvelope(testSecret, header, body, "org-2", testTolerance, testVerifyTime()); !errors.Is(err, ErrEnvelopeIDMismatch) {
		t.Fatalf("empty envelope accepted by wrong org: err = %v, want ErrEnvelopeIDMismatch", err)
	}
}
