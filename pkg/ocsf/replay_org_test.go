package ocsf

import (
	"errors"
	"strings"
	"testing"
)

// W04-C03 cross-org / N/A battery (AC: явный тест — одинаковый EventID
// в двух org ⇒ РАЗНЫЕ ReplayID; ReplayID-коллизия между org невозможна
// по построению; таблица N/A-обоснований для схемных карточек).
//
// Precedent: the ingest path dedups on the org-scoped key
// OrgID + "\x00" + EventID (pkg/secevents/ingest.go, dedupKey) — the
// export form folds the same org scoping INTO the ReplayID hash, so a
// bare id is org-safe wherever it travels.

// TestReplayOrgIsolation: one EventID exported by two orgs derives two
// DIFFERENT ReplayIDs — and each org's id is stable across re-exports.
func TestReplayOrgIsolation(t *testing.T) {
	const sharedEvent = "core-shared-event"
	idOrg1, err := ReplayID("org-1", sharedEvent)
	if err != nil {
		t.Fatalf("ReplayID(org-1): %v", err)
	}
	idOrg2, err := ReplayID("org-2", sharedEvent)
	if err != nil {
		t.Fatalf("ReplayID(org-2): %v", err)
	}
	if idOrg1 == idOrg2 {
		t.Fatalf("same EventID in two orgs collided on one ReplayID: %q", idOrg1)
	}
	// Stability within each org.
	again, err := ReplayID("org-1", sharedEvent)
	if err != nil || again != idOrg1 {
		t.Fatalf("org-1 re-derivation drifted: %q vs %q (err %v)", again, idOrg1, err)
	}
	again2, err := ReplayID("org-2", sharedEvent)
	if err != nil || again2 != idOrg2 {
		t.Fatalf("org-2 re-derivation drifted: %q vs %q (err %v)", again2, idOrg2, err)
	}

	// End-to-end: identical source events of two orgs produce distinct
	// record ids inside their envelopes, and the envelopes themselves
	// are distinct (org is part of the envelope identity too).
	a := batteryEnv(t, "org-1", []string{sharedEvent}, testSignTime)
	b := batteryEnv(t, "org-2", []string{sharedEvent}, testSignTime)
	if a.Records[0].ReplayID == b.Records[0].ReplayID {
		t.Fatalf("cross-org envelopes carry one replay id")
	}
	if a.EnvelopeID == b.EnvelopeID {
		t.Fatalf("cross-org envelopes share one identity")
	}
}

// TestReplayOrgCollisionByConstruction: no (org, event) pair of a
// corpus collides cross-org while every same-org repeat matches — the
// construction guarantee (org is a hash input, ingest.go dedupKey
// precedent folded into the id).
func TestReplayOrgCollisionByConstruction(t *testing.T) {
	orgs := []string{"org-1", "org-2", "org-tenant-alpha", "org-tenant-beta", ""}
	events := []string{"core-evt-a", "core-evt-b", "shared", "x"}

	seen := make(map[string]string, len(orgs)*len(events)) // id → "org/event"
	for _, org := range orgs {
		for _, event := range events {
			id, err := ReplayID(org, event)
			if org == "" {
				if !errors.Is(err, ErrEmptyReplayInput) {
					t.Fatalf("empty org must fail closed, got %v", err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("ReplayID(%s,%s): %v", org, event, err)
			}
			owner := org + "/" + event
			if prior, dup := seen[id]; dup {
				t.Fatalf("collision: id %q derived for %s and %s", id, prior, owner)
			}
			seen[id] = owner
			again, err := ReplayID(org, event)
			if err != nil || again != id {
				t.Fatalf("same-org re-derivation drifted for %s", owner)
			}
		}
	}
	// Empty event id fails closed for every org as well.
	for _, org := range orgs {
		if _, err := ReplayID(org, ""); !errors.Is(err, ErrEmptyReplayInput) {
			t.Fatalf("empty event for org %q must fail closed, got %v", org, err)
		}
	}
}

// TestReplayOrgSmuggledRecordCaughtByReDerivation: a record whose
// OrgID says org-2 but whose ReplayID was derived for org-1 passes the
// JSON schema (schema has no org context — the N/A row below). The
// detection is RE-DERIVATION: ReplayID(rec.OrgID, rec.FindingInfo.UID)
// disagrees with the carried id. Producer pipelines cannot emit such a
// record (AssignReplayIDs derives from the record's own OrgID, so
// pipeline output is consistent by construction); a compromised
// producer holds the signing secret and is outside the tamper threat
// model proven in W03-C02.
func TestReplayOrgSmuggledRecordCaughtByReDerivation(t *testing.T) {
	records := envelopeRecords(t)
	if err := AssignReplayIDs(records); err != nil {
		t.Fatalf("assign: %v", err)
	}
	smuggled := records[0]   // org-1 record with its org-1 id
	smuggled.OrgID = "org-2" // org field flipped, id NOT re-derived

	// Schema alone: the record is shape-valid (org-blind by design) —
	// this is precisely the schema-cards N/A row.
	encoded := marshalMap(t, recordToMap(t, smuggled))
	if err := ValidateRecordJSON(encoded); err != nil {
		t.Fatalf("schema must not reject the smuggled record (org-blind by design): %v", err)
	}

	// Detection: one re-derivation call exposes the inconsistency.
	rederived, err := ReplayID(smuggled.OrgID, smuggled.FindingInfo.UID)
	if err != nil {
		t.Fatalf("ReplayID(org-2, anchor): %v", err)
	}
	if rederived == smuggled.ReplayID {
		t.Fatalf("org-1-derived id equals the org-2 re-derivation — isolation broken")
	}

	// Pipeline integrity: what AssignReplayIDs produces can never look
	// like the smuggled record — it derives from the record's own org.
	fresh := []NormalizedRecord{smuggled}
	if err := AssignReplayIDs(fresh); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if fresh[0].ReplayID != rederived {
		t.Fatalf("pipeline re-assignment must heal the id to the org-2 derivation")
	}
}

// TestReplayOrgSchemaNATable pins the N/A justification table for the
// schema-only cards of this packet (DISPATCH §8: «для чисто схемных
// карточек N/A "нет org-контекста у JSON Schema"»). It is data, not
// prose, so a reviewer greps one place.
func TestReplayOrgSchemaNATable(t *testing.T) {
	type naRow struct {
		card, scope, justification string
	}
	table := []naRow{
		{"E07-P01-W02-C01", "schema/export-v1.json + version.go",
			"N/A: JSON Schema has no org context — org isolation cannot be expressed in shape constraints; it is enforced by ReplayID derivation (org is a hash input) and by envelope org checks."},
		{"E07-P01-W02-C02", "validate.go + validate_test.go",
			"N/A: the validator is schema-driven (org-blind by construction); cross-org rejection is tested here and in the envelope battery instead."},
		{"E07-P01-W02-C03", "schema-versioning artifact",
			"N/A: versioning is org-independent; org discipline does not interact with the version band."},
		{"E07-P01-W03-C03", "transport design artifact",
			"N/A (design): transport delegates org pinning to VerifyEnvelope's expected-org parameter (see artifact §2.3); no org state exists at the transport layer."},
		{"E07-P01-W04-C01", "replay.go (this card's library half)",
			"NOT N/A — implemented: ReplayID(org, event) makes org isolation by construction; this file is its proof."},
		{"E07-P01-W04-C03", "replay_org_test.go",
			"NOT N/A — this table: cross-org proof + the schema-cards N/A justifications."},
	}
	for _, row := range table {
		if !strings.Contains(row.justification, "org") {
			t.Fatalf("%s: justification must name the org axis", row.card)
		}
		if row.card == "" || row.scope == "" {
			t.Fatalf("incomplete N/A row: %+v", row)
		}
	}
	if len(table) < 5 {
		t.Fatalf("N/A table must cover the schema cards, has %d rows", len(table))
	}
}
