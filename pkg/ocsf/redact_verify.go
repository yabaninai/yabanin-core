package ocsf

import (
	"time"

	"github.com/reireirei/yabanin/pkg/redact"
	"github.com/reireirei/yabanin/pkg/secevents"
)

// Export-boundary redaction verification (packet E07-P01, card W05-C01).
//
// The secevents pipeline already scrubs at its own durable boundaries
// (pkg/redact doc); this file closes the EXPORT boundary of the
// normalized form: every record leaving through an envelope can be
// passed through the SAME shared scrubber (one implementation, not a
// second regex set), so a smuggled credential — a producer gap, a
// future mapper bug, a poisoned summary or identity value — is replaced
// with RedactionMarker before the record reaches signing and delivery.
//
// Contract:
//
//   - total: EVERY string field of the record goes through
//     redact.ScrubSecrets, including enum-constrained ones. For
//     schema-valid values the scrubber is provably a no-op (the closed
//     vocabularies contain no credential-shaped content); applying it
//     anyway is defense in depth and keeps the rule free of carve-outs.
//   - defensive copy: the input record is never mutated; slices and
//     pointers (Evidence, Cost) are copied when present, and a record
//     without evidence keeps a nil Evidence (stays a nil-omitted field,
//     not an empty array).
//   - idempotent: scrubbing twice equals scrubbing once (the same
//     property pkg/redact guarantees), pinned by test.
//   - order: scrub BEFORE envelope construction. The sanctioned
//     pipeline is MapEvent → RedactRecord → AssignReplayIDs →
//     NewEnvelope → SignEnvelope. Scrubbing an already-signed envelope
//     changes the signed body, and verification fails closed by design
//     (tamper protection); RedactEnvelope rebuilds the identity over
//     the scrubbed batch so the result is signable again.
//   - evidence discipline is structural, not scrubbed-in: EvidenceRef
//     carries digests only (adapter.go evidence), so no content-bearing
//     evidence field exists to leak; the W05-C01 battery greps the
//     canonical JSON for fixture secret markers and for raw-content key
//     names to pin both layers.

// RedactionMarker is the replacement token the shared scrubber writes
// over credential-shaped content. It mirrors the pkg/redact replacement
// literal; the W05-C01 test pins the equality against the scrubber's
// actual output, so a future divergence fails the battery instead of
// drifting silently.
const RedactionMarker = "[REDACTED]"

// RedactRecord returns a defensive copy of rec with every string field
// scrubbed through the shared credential scrubber (pkg/redact). A clean
// record passes through byte-identically (pinned by test on the mapper
// corpus); a smuggled credential is replaced with RedactionMarker.
func RedactRecord(rec NormalizedRecord) NormalizedRecord {
	out := rec // string and value fields copy by value below; slices/pointers are re-built
	out.FindingInfo = RecordFindingInfo{
		UID:   redact.ScrubSecrets(rec.FindingInfo.UID),
		Title: redact.ScrubSecrets(rec.FindingInfo.Title),
	}
	out.Metadata = RecordMetadata{
		Version: redact.ScrubSecrets(rec.Metadata.Version),
		Product: RecordProduct{
			VendorName: redact.ScrubSecrets(rec.Metadata.Product.VendorName),
			Name:       redact.ScrubSecrets(rec.Metadata.Product.Name),
			Version:    redact.ScrubSecrets(rec.Metadata.Product.Version),
		},
		SecEventsSchemaVersion: rec.Metadata.SecEventsSchemaVersion,
	}
	out.OrgID = redact.ScrubSecrets(rec.OrgID)
	out.Identity = RecordIdentity{
		Agent:   scrubIDRef(rec.Identity.Agent),
		Session: scrubIDRef(rec.Identity.Session),
		Task:    scrubIDRef(rec.Identity.Task),
		Tool:    scrubIDRef(rec.Identity.Tool),
	}
	if rec.Evidence != nil {
		evidence := make([]secevents.EvidenceRef, len(rec.Evidence))
		for i, ref := range rec.Evidence {
			evidence[i] = scrubEvidenceRef(ref)
		}
		out.Evidence = evidence
	}
	if rec.Cost != nil {
		cost := *rec.Cost // copy the struct before touching it
		cost.State = redact.ScrubSecrets(cost.State)
		out.Cost = &cost
	}
	out.SourceEventType = redact.ScrubSecrets(rec.SourceEventType)
	out.ReplayID = redact.ScrubSecrets(rec.ReplayID)
	return out
}

// RedactEnvelope applies RedactRecord to every record of an already
// assembled batch and REBUILDS the envelope over the scrubbed records
// (NewEnvelope semantics: fresh deterministic identity over clean
// content), preserving the issue time and the delivery-attempt counter.
// It is the batch-side composition of the scrub-before-sign pipeline
// for producers that assemble first. orgID is explicit — an empty
// batch carries no records to recover the org from, and the org is an
// identity input, never an inference.
func RedactEnvelope(orgID string, env Envelope) (Envelope, error) {
	records := make([]NormalizedRecord, len(env.Records))
	for i := range env.Records {
		records[i] = RedactRecord(env.Records[i])
	}
	out, err := NewEnvelope(orgID, records, time.UnixMilli(env.IssuedAt))
	if err != nil {
		return Envelope{}, err
	}
	// Attempt is envelope-level delivery state, not record content: it
	// survives a scrub rebuild (a redelivered batch re-scrubs to the
	// same records; the attempt counter rides the envelope).
	out.Attempt = env.Attempt
	return out, nil
}

// scrubIDRef scrubs one identifier reference. State is a closed enum
// (IDKnown/IDUnknown/IDAbsent) — scrubbed like every other string for
// totality (IDState is a defined string type, so the scrubber applies);
// for valid states the scrubber is a provable no-op.
func scrubIDRef(ref secevents.IDRef) secevents.IDRef {
	return secevents.IDRef{
		Value: redact.ScrubSecrets(ref.Value),
		State: secevents.IDState(redact.ScrubSecrets(string(ref.State))),
	}
}

// scrubEvidenceRef scrubs one evidence reference (digests only by
// construction; Kind is a pattern-validated slug, Location an optional
// storage pointer — both scrubbed anyway, totality over carve-outs).
func scrubEvidenceRef(ref secevents.EvidenceRef) secevents.EvidenceRef {
	return secevents.EvidenceRef{
		Kind:     redact.ScrubSecrets(ref.Kind),
		Digest:   redact.ScrubSecrets(ref.Digest),
		Location: redact.ScrubSecrets(ref.Location),
	}
}
