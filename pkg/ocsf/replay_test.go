package ocsf

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// W04-C01 acceptance: deterministic ReplayID derivation, stable across
// envelopes; attempt is envelope-level delivery state only; DLQ
// precedent documented in replay.go.

var replayIDShape = regexp.MustCompile(`^replay-[0-9a-f]{64}$`)

// TestReplayIDDeterministic: identical (org, event) re-derives the
// identical id; any input change changes the id; the shape is pinned.
func TestReplayIDDeterministic(t *testing.T) {
	a, err := ReplayID("org-1", "core-evt-1")
	if err != nil {
		t.Fatalf("ReplayID: %v", err)
	}
	b, err := ReplayID("org-1", "core-evt-1")
	if err != nil {
		t.Fatalf("ReplayID: %v", err)
	}
	if a != b {
		t.Fatalf("same inputs, different ids: %q vs %q", a, b)
	}
	if !replayIDShape.MatchString(a) {
		t.Fatalf("id shape = %q, want replay-<64 hex>", a)
	}

	other, err := ReplayID("org-1", "core-evt-2")
	if err != nil {
		t.Fatalf("ReplayID: %v", err)
	}
	if other == a {
		t.Fatalf("different events produced the same id")
	}
	if len(a) != len("replay-")+64 {
		t.Fatalf("id length = %d, want 71 (schema cap 256)", len(a))
	}
}

// TestReplayIDInputGuards: an unanchored derivation fails closed.
func TestReplayIDInputGuards(t *testing.T) {
	for _, tc := range [][2]string{
		{"", "core-evt-1"},
		{"org-1", ""},
		{"", ""},
	} {
		if _, err := ReplayID(tc[0], tc[1]); !errors.Is(err, ErrEmptyReplayInput) {
			t.Fatalf("ReplayID(%q,%q): err = %v, want ErrEmptyReplayInput", tc[0], tc[1], err)
		}
	}
}

// TestReplayAssignFillsSlot: AssignReplayIDs populates every record
// from its own anchor, and the assigned records still validate against
// the export schema with the replay_id slot consumed (the W02-C01
// reservation, filled by W04 per DISPATCH §4).
func TestReplayAssignFillsSlot(t *testing.T) {
	records := envelopeRecords(t)
	if err := AssignReplayIDs(records); err != nil {
		t.Fatalf("AssignReplayIDs: %v", err)
	}
	for i, rec := range records {
		if rec.ReplayID == "" {
			t.Fatalf("record[%d] left without replay id", i)
		}
		if !replayIDShape.MatchString(rec.ReplayID) {
			t.Fatalf("record[%d] replay id shape = %q", i, rec.ReplayID)
		}
		encoded := marshalMap(t, recordToMap(t, rec))
		if err := ValidateRecordJSON(encoded); err != nil {
			t.Fatalf("record[%d] with replay_id must validate: %v", i, err)
		}
		if !strings.Contains(string(encoded), `"replay_id":"`+rec.ReplayID+`"`) {
			t.Fatalf("record[%d] canonical bytes must carry the replay id", i)
		}
	}
}

// TestReplayAssignIdempotent: re-assignment (re-export after a
// rollback replay) writes the same values — no drift, no error.
func TestReplayAssignIdempotent(t *testing.T) {
	records := envelopeRecords(t)
	if err := AssignReplayIDs(records); err != nil {
		t.Fatalf("first assign: %v", err)
	}
	first := make([]string, len(records))
	for i, rec := range records {
		first[i] = rec.ReplayID
	}
	if err := AssignReplayIDs(records); err != nil {
		t.Fatalf("second assign: %v", err)
	}
	for i, rec := range records {
		if rec.ReplayID != first[i] {
			t.Fatalf("record[%d] replay id drifted on re-assign: %q vs %q", i, rec.ReplayID, first[i])
		}
	}
}

// TestReplayAssignAnchorless: a record without its dedup anchor fails
// closed instead of colliding every anchorless record onto one id.
func TestReplayAssignAnchorless(t *testing.T) {
	records := envelopeRecords(t)
	records[1].FindingInfo.UID = ""
	if err := AssignReplayIDs(records); !errors.Is(err, ErrEmptyReplayInput) {
		t.Fatalf("err = %v, want ErrEmptyReplayInput", err)
	}
	records[0].OrgID = ""
	if err := AssignReplayIDs(records); !errors.Is(err, ErrEmptyReplayInput) {
		t.Fatalf("err = %v, want ErrEmptyReplayInput", err)
	}
}

// TestReplayStableAcrossEnvelopes (AC): the same record in two
// different envelopes keeps the same ReplayID — batch composition,
// issue time and sibling records never leak into the per-record id.
func TestReplayStableAcrossEnvelopes(t *testing.T) {
	records := envelopeRecords(t)
	if err := AssignReplayIDs(records); err != nil {
		t.Fatalf("assign: %v", err)
	}
	solo := []NormalizedRecord{records[1]}
	if err := AssignReplayIDs(solo); err != nil {
		t.Fatalf("assign solo: %v", err)
	}
	if solo[0].ReplayID != records[1].ReplayID {
		t.Fatalf("same record in different batches got different ids: %q vs %q",
			solo[0].ReplayID, records[1].ReplayID)
	}

	first, err := NewEnvelope("org-1", records, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	second, err := NewEnvelope("org-1", solo, testSignTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewEnvelope solo: %v", err)
	}
	if first.Records[1].ReplayID != second.Records[0].ReplayID {
		t.Fatalf("envelopes lost the replay identity")
	}
}

// TestReplayAttemptEnvelopeLevelOnly (AC): attempt grows only at
// delivery, never at the record. A redelivery bumps Envelope.Attempt
// and re-signs, while the records — and therefore the envelope
// identity, which hashes records only — stay byte-stable. Record-side
// re-assignment never touches attempt.
func TestReplayAttemptEnvelopeLevelOnly(t *testing.T) {
	records := envelopeRecords(t)
	if err := AssignReplayIDs(records); err != nil {
		t.Fatalf("assign: %v", err)
	}
	original, err := NewEnvelope("org-1", records, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	redelivery, err := NewEnvelope("org-1", records, testSignTime)
	if err != nil {
		t.Fatalf("NewEnvelope redelivery: %v", err)
	}
	redelivery.Attempt = original.Attempt + 1 // delivery retry, DLQ-style

	if redelivery.EnvelopeID != original.EnvelopeID {
		t.Fatalf("delivery retry must not shift the envelope identity")
	}
	firstBody, firstHeader := signForTest(t, testSecret, original)
	retryBody, retryHeader := signForTest(t, testSecret, redelivery)
	if string(firstBody) == string(retryBody) {
		t.Fatalf("retry must be a distinct signed body (attempt counter)")
	}
	for _, delivered := range []struct {
		body         []byte
		header       string
		attemptLabel string
	}{{firstBody, firstHeader, "first"}, {retryBody, retryHeader, "retry"}} {
		if err := VerifyEnvelope(testSecret, delivered.header, delivered.body, "org-1", testTolerance, testVerifyTime()); err != nil {
			t.Fatalf("verify %s delivery: %v", delivered.attemptLabel, err)
		}
	}
	// And the record side of the discipline: re-assignment changes no
	// attempt anywhere (records have no attempt field at all).
	if redelivery.Records[0].ReplayID != original.Records[0].ReplayID {
		t.Fatalf("retry must reuse the same replay ids")
	}
}

// TestReplayOrderFree (order-free consumer contract): ids are
// position-independent — shuffling the batch (or delivering two
// interleaved batches) yields the same id set, so a consumer dedup
// table converges regardless of arrival order.
func TestReplayOrderFree(t *testing.T) {
	records := envelopeRecords(t)
	if err := AssignReplayIDs(records); err != nil {
		t.Fatalf("assign: %v", err)
	}
	byEvent := make(map[string]string, len(records))
	for _, rec := range records {
		byEvent[rec.FindingInfo.UID] = rec.ReplayID
	}

	shuffled := []NormalizedRecord{records[1], records[0]}
	if err := AssignReplayIDs(shuffled); err != nil {
		t.Fatalf("assign shuffled: %v", err)
	}
	for _, rec := range shuffled {
		if rec.ReplayID != byEvent[rec.FindingInfo.UID] {
			t.Fatalf("position changed the replay id of %q", rec.FindingInfo.UID)
		}
	}
}
