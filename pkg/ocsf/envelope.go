package ocsf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/reireirei/yabanin/pkg/webhooks"
)

// Envelope is the delivery unit of the normalized export (W03-C01): a
// versioned batch of records with a deterministic identity, ready to be
// signed and handed to a transport (the connector side — E07-P02/E07-P03;
// this package never delivers).
//
// Field declaration order is the canonical JSON key order, mirroring the
// schema root (schema/export-v1.json): schema_version, envelope_id,
// issued_at, records, attempt. Do not reorder (the encoding must stay
// byte-deterministic — signature inputs are canonical bytes).
type Envelope struct {
	// SchemaVersion is the export-schema version (ExportSchemaVersion);
	// the fail-closed reader gate (validate.go) enforces it on receipt.
	SchemaVersion int `json:"schema_version"`
	// EnvelopeID is the deterministic content identity of the envelope:
	// a derivative of (org, schema_version, records) only — see
	// NewEnvelope. Re-exporting the same records (redelivery, retry)
	// re-derives the same id; issuing time and delivery attempts are
	// deliberately NOT part of it (they are instance attributes, not
	// content attributes).
	EnvelopeID string `json:"envelope_id"`
	// IssuedAt is the issue time in epoch milliseconds (OCSF
	// timestamp_t; the export contract is millisecond-granular).
	IssuedAt int64 `json:"issued_at"`
	// Records is the record batch. An empty batch is a valid, signable
	// envelope (an explicitly empty export — see envelope_adversarial_test
	// for the recorded decision); NewEnvelope always serializes it as []
	// (never null).
	Records []NormalizedRecord `json:"records"`
	// Attempt is the envelope-level delivery-attempt counter (W04
	// semantics): it grows only when a delivery of the envelope is
	// retried, never per record, and it is not part of EnvelopeID or any
	// ReplayID. Zero means "first issue, no retry" and is omitted from
	// the canonical encoding; the slot was reserved by W02-C01.
	Attempt int `json:"attempt,omitempty"`
}

// Envelope sentinels. Callers classify with errors.Is; wrapped variants
// name the offending record or field.
var (
	// ErrInvalidEnvelope: the envelope violates the construction
	// contract (empty org, zero/negative issued_at, record version
	// drift, missing dedup anchor).
	ErrInvalidEnvelope = errors.New("ocsf: invalid export envelope")
	// ErrCrossOrgRecord: an envelope is single-org by contract (the org
	// is an input of the envelope identity and the signature covers it
	// via the signed body); a record of another org cannot ride along.
	ErrCrossOrgRecord = errors.New("ocsf: envelope record belongs to another org")
	// ErrEnvelopeIDMismatch: the presented envelope_id does not match
	// the deterministic identity of the records it carries.
	ErrEnvelopeIDMismatch = errors.New("ocsf: envelope_id does not match its records")
	// ErrBadSignature: HMAC verification failed (missing, malformed,
	// wrong key, tampered body, or outside the tolerance window).
	ErrBadSignature = errors.New("ocsf: envelope signature verification failed")
	// ErrReplayIDMismatch (routed R2 hardening, batch-B review →
	// registry a47ba332): a record presents a replay_id that is not the
	// deterministic derivative of the verifier's org and the record's
	// own dedup anchor. The slot is optional (a W03-era record may
	// leave it empty), but a FILLED slot must re-derive exactly — a
	// replay id minted under another org or for another anchor never
	// rides a verified envelope, even with a valid signature over it.
	ErrReplayIDMismatch = errors.New("ocsf: record replay_id does not match its derivation")
	// ErrEmptySecret: signing or verifying with an empty secret is a
	// caller bug; it fails closed instead of producing a trivially
	// forgeable MAC.
	ErrEmptySecret = errors.New("ocsf: empty envelope signing secret")
)

// envelopeIDDomain separates the envelope-id derivation from other
// SHA-256 uses in the export stack (secevents event ids, replay ids).
const envelopeIDDomain = "yabanin-ocsf-envelope-id-v1"

// NewEnvelope builds an envelope for one org's records (W03-C01).
//
// Determinism contract: EnvelopeID is SHA-256 over the domain constant,
// the org id, the schema version and the canonical encoding of the
// records slice (json.Marshal of the struct — declaration-order keys, so
// byte-deterministic). Identical inputs always yield an identical id,
// which makes envelope identity replayable and diffable; issuedAt is
// intentionally excluded (content identity, not instance identity).
//
// The canonical form is derived from the decoded record structs, so
// additive unknown fields a future producer adds inside records do not
// shift the identity (they remain HMAC-covered by the signature over the
// full body, but identity comparison stays stable across schema
// additions — same tolerant-reader discipline as the versioning
// artifact).
func NewEnvelope(orgID string, records []NormalizedRecord, issuedAt time.Time) (Envelope, error) {
	if orgID == "" {
		return Envelope{}, fmt.Errorf("%w: org_id is empty", ErrInvalidEnvelope)
	}
	if issuedAt.IsZero() {
		return Envelope{}, fmt.Errorf("%w: issued_at is zero", ErrInvalidEnvelope)
	}
	if issuedAt.UnixMilli() < 0 {
		return Envelope{}, fmt.Errorf("%w: issued_at %d is before the epoch", ErrInvalidEnvelope, issuedAt.UnixMilli())
	}
	for i, rec := range records {
		if rec.OrgID == "" {
			return Envelope{}, fmt.Errorf("%w: record[%d] has no org_id", ErrInvalidEnvelope, i)
		}
		if rec.OrgID != orgID {
			return Envelope{}, fmt.Errorf("%w: record[%d] org %q, want %q", ErrCrossOrgRecord, i, rec.OrgID, orgID)
		}
		if rec.SchemaVersion != ExportSchemaVersion {
			return Envelope{}, fmt.Errorf("%w: record[%d] schema_version %d, want %d", ErrInvalidEnvelope, i, rec.SchemaVersion, ExportSchemaVersion)
		}
		if rec.FindingInfo.UID == "" {
			return Envelope{}, fmt.Errorf("%w: record[%d] has no finding_info.uid (dedup anchor)", ErrInvalidEnvelope, i)
		}
	}
	id, err := envelopeID(orgID, ExportSchemaVersion, records)
	if err != nil {
		return Envelope{}, err
	}
	// Defensive copy with non-nil slice: an empty batch must encode as
	// [] (schema type array), never null.
	out := make([]NormalizedRecord, len(records))
	copy(out, records)
	return Envelope{
		SchemaVersion: ExportSchemaVersion,
		EnvelopeID:    id,
		IssuedAt:      issuedAt.UnixMilli(),
		Records:       out,
	}, nil
}

// envelopeID derives the deterministic content identity. The records
// slice is marshaled in its canonical struct form (non-nil, so an empty
// batch hashes []).
func envelopeID(orgID string, schemaVersion int, records []NormalizedRecord) (string, error) {
	payload, err := envelopeRecordsCanonical(records)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(envelopeIDDomain))
	h.Write([]byte{0})
	h.Write([]byte(orgID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.Itoa(schemaVersion)))
	h.Write([]byte{0})
	h.Write(payload)
	return "env-" + hex.EncodeToString(h.Sum(nil)), nil
}

// EncodeEnvelope renders the envelope to its canonical JSON bytes: the
// byte string that is signed, verified and compared. Deterministic by
// construction (struct declaration order; records keep their slice
// order). Use the SAME bytes for SignEnvelope and VerifyEnvelope — a
// re-marshaled copy is byte-identical, but any semantic edit (even
// whitespace-preserving field reordering by a foreign encoder) changes
// the signature input.
func EncodeEnvelope(env Envelope) ([]byte, error) {
	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidEnvelope, err)
	}
	return data, nil
}

// SignEnvelope signs one envelope (W03-C01).
//
// Composition only — no new cryptographic primitive: the signature is
// the existing pkg/webhooks v2 scheme (Stripe-style
// "t=<unix-ts>,v1=<hex-hmac-sha256>" over "<t>.<body>"), built with
// webhooks.Sign + webhooks.SignatureHeader and checked with
// webhooks.VerifyAt through VerifyEnvelope. The secret follows the
// existing webhook secret-store pattern (opaque high-entropy string,
// e.g. "whsec_…", provisioned out-of-band); this package never stores,
// rotates or logs it. The signature timestamp is signedAt (callers pass
// the envelope issue time on first issue and a fresh time on each
// redelivery attempt, DLQ style — the attempt counter and the fresh
// signature travel together).
//
// Returns (canonicalBody, signatureHeader).
func SignEnvelope(secret string, env Envelope, signedAt time.Time) ([]byte, string, error) {
	if secret == "" {
		return nil, "", ErrEmptySecret
	}
	if signedAt.IsZero() {
		return nil, "", fmt.Errorf("%w: signing time is zero", ErrInvalidEnvelope)
	}
	body, err := EncodeEnvelope(env)
	if err != nil {
		return nil, "", err
	}
	t, sig := webhooks.Sign(secret, signedAt, body)
	return body, webhooks.SignatureHeader(t, sig), nil
}

// VerifyEnvelope authenticates and validates one envelope (W03-C01).
//
// Checks run fail-closed in authentication-first order:
//
//  1. HMAC over the exact body bytes (webhooks.VerifyAt — missing or
//     malformed signature, wrong key, tampered payload and signatures
//     outside the symmetric tolerance window all fail here);
//  2. the embedded-schema envelope validation, version gate first
//     (ValidateEnvelopeJSON);
//  3. the org contract: orgID is the verifier's expected tenant; every
//     record must belong to it (ErrCrossOrgRecord), and any assigned
//     replay_id must re-derive from (orgID, finding_info.uid)
//     (ErrReplayIDMismatch — routed R2 hardening: the id is a derived
//     value, not free text); even an empty envelope is org-bound
//     through its identity;
//  4. the integrity of EnvelopeID: recomputed from (orgID, version,
//     records), it must match (ErrEnvelopeIDMismatch) — the org rides
//     in the HMAC input transitively through the signed body.
//
// now is injectable so verification windows are testable and callers
// pin it to their clock; it must be non-zero. Verification is
// idempotent: the same (secret, header, body, orgID, now) always yields
// the same verdict, so re-verifying an envelope inside the tolerance
// window is safe (повтор/задержка — DISPATCH §8).
func VerifyEnvelope(secret, sigHeader string, body []byte, orgID string, tolerance time.Duration, now time.Time) error {
	if secret == "" {
		return ErrEmptySecret
	}
	if now.IsZero() {
		return fmt.Errorf("%w: verification time is zero", ErrInvalidEnvelope)
	}
	if orgID == "" {
		return fmt.Errorf("%w: expected org is empty", ErrInvalidEnvelope)
	}
	if err := webhooks.VerifyAt(secret, sigHeader, string(body), tolerance, now); err != nil {
		return fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if err := ValidateEnvelopeJSON(body); err != nil {
		return err
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrInvalidEnvelope, err)
	}
	if env.SchemaVersion != ExportSchemaVersion {
		return fmt.Errorf("%w: schema_version %d, want %d", ErrInvalidEnvelope, env.SchemaVersion, ExportSchemaVersion)
	}
	for i, rec := range env.Records {
		if rec.OrgID != orgID {
			return fmt.Errorf("%w: record[%d] org %q, want %q", ErrCrossOrgRecord, i, rec.OrgID, orgID)
		}
		if rec.ReplayID != "" {
			// Routed R2 hardening (batch-B review, registry a47ba332):
			// an assigned replay_id is a DERIVED value, not free text —
			// re-derive it from the verifier's expected org and the
			// record's own dedup anchor. The empty slot stays valid
			// (W03-era records), but any filled slot must match its
			// derivation exactly; a derivation that cannot even run
			// fails closed rather than skipping the check.
			want, err := ReplayID(orgID, rec.FindingInfo.UID)
			if err != nil {
				return fmt.Errorf("%w: record[%d]: %v", ErrReplayIDMismatch, i, err)
			}
			if rec.ReplayID != want {
				return fmt.Errorf("%w: record[%d] presented %q, derived %q", ErrReplayIDMismatch, i, rec.ReplayID, want)
			}
		}
	}
	expected, err := envelopeID(orgID, env.SchemaVersion, env.Records)
	if err != nil {
		return err
	}
	if env.EnvelopeID != expected {
		return fmt.Errorf("%w: presented %q, derived %q", ErrEnvelopeIDMismatch, env.EnvelopeID, expected)
	}
	return nil
}

// envelopeRecordsCanonical renders the exact record bytes an envelope
// identity is derived from (identity comparison and future audit
// tooling); a nil or empty slice canonicalizes to [].
func envelopeRecordsCanonical(records []NormalizedRecord) ([]byte, error) {
	recs := make([]NormalizedRecord, 0, len(records))
	recs = append(recs, records...)
	data, err := json.Marshal(recs)
	if err != nil {
		return nil, fmt.Errorf("%w: canonical records: %v", ErrInvalidEnvelope, err)
	}
	return data, nil
}
