package ocsf

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Replay identity (packet E07-P01, card W04-C01).
//
// A ReplayID is the stable cross-delivery identity of one exported
// record: the deterministic derivative of the tenant org and the
// secevents EventID (the record's dedup anchor, FindingInfo.UID). The
// secevents event_id itself already folds in (org, request, ts, policy,
// finding) — see pkg/secevents/adapter.go, EventID derivation — so the
// replay identity is anchored on the same collision-free base the
// ingest path dedups on (the org-scoped dedupKey precedent,
// pkg/secevents/ingest.go).
//
// Contract:
//
//   - same (org, EventID) ⇒ same ReplayID, forever and order-free: the
//     id depends only on its own record's inputs, never on batch
//     composition or position, so a consumer may dedup by ReplayID
//     without assuming any ordering across envelopes (the order-free
//     consumer contract of W04-C01);
//   - different orgs ⇒ different ReplayIDs even for a shared EventID
//     (org isolation; proven in W04-C03);
//   - the id is pure content derivation: no clock, no randomness, no
//     environment — pkg/ocsf stays stateless and deterministic.
//
// Delivery attempts are ENVELOPE-level state, never record state: a
// redelivery re-issues the same records byte-identically (same
// ReplayIDs, same envelope_id — attempt is not part of the envelope
// identity) and bumps Envelope.Attempt on a fresh signature. This is
// the DLQ precedent of pkg/eventpublisher/dlq.go (RetryCount rides the
// envelope; replayed payloads are untouched) applied to the export
// form.
//
// The record slot replay_id was reserved by W02-C01's schema; W04
// fills it (DISPATCH §4: «W03-C01 включает поле replay_id как
// зарезервированное; W04 его наполняет»). The value satisfies the slot
// constraints (string, 1..256: "replay-" + 64 hex = 71 chars).

// ErrEmptyReplayInput reports a replay identity derivation attempted
// without its anchor inputs (empty org or empty EventID). Deriving an
// id for an unanchored record would silently make every such record
// collide, so it fails closed.
var ErrEmptyReplayInput = errors.New("ocsf: replay identity input is empty")

// replayIDDomain separates the replay-id hash input from every other
// hash use of the same strings (envelope ids, signatures) — a domain
// tag, versioned so the derivation can evolve deliberately.
const replayIDDomain = "yabanin-ocsf-replay-id-v1"

// ReplayID derives the deterministic replay identity of one exported
// record from its tenant org and its secevents EventID. The result is
// "replay-" + 64 lowercase hex chars and is stable across re-exports,
// envelope compositions and delivery retries.
func ReplayID(orgID, eventID string) (string, error) {
	if orgID == "" || eventID == "" {
		return "", fmt.Errorf("%w: org_id=%q event_id=%q", ErrEmptyReplayInput, orgID, eventID)
	}
	h := sha256.New()
	h.Write([]byte(replayIDDomain))
	h.Write([]byte{0})
	h.Write([]byte(orgID))
	h.Write([]byte{0})
	h.Write([]byte(eventID))
	return "replay-" + hex.EncodeToString(h.Sum(nil)), nil
}

// AssignReplayIDs fills the ReplayID slot of every record in a batch
// from that record's own OrgID and FindingInfo.UID (the secevents
// EventID anchor). It is the batch-side entry point before
// NewEnvelope: an exported envelope carries replay-identified records.
//
// The assignment is idempotent and order-free: re-assigning (a
// re-export, a rollback replay) writes the same values, and per-record
// ids never depend on batch position. A record without its anchor
// (empty org or empty EventID) fails closed with
// ErrEmptyReplayInput — AssignReplayIDs returns on the first failure,
// leaving earlier assignments in place (they are deterministic
// recomputations, safe to overwrite on the next pass).
func AssignReplayIDs(records []NormalizedRecord) error {
	for i := range records {
		id, err := ReplayID(records[i].OrgID, records[i].FindingInfo.UID)
		if err != nil {
			return fmt.Errorf("record[%d] %q: %w", i, records[i].FindingInfo.UID, err)
		}
		records[i].ReplayID = id
	}
	return nil
}
