// Reader→store projection (E06-P01 W01-C02).
//
// Project folds the events the org-bound Reader returned (Reader.Events,
// already org-homes-checked) into the incident store. It is the second
// half of the Trigger ② path: events stay durable and exactly-once in
// secevents_documents; the inbox is derived and rebuildable from them.
//
// Determinism law: Project sorts its own copy of the events by
// (occurred_at, event_id) — the reader's total order — so a replayed or
// out-of-order delivery folds identically. Each event becomes one upsert;
// equivalent findings merge on (org_id, group_key) inside the store
// (counts++ / last_seen forward — the W02-C02 replay acceptance, whose
// dedicated battery lands with that card).
//
// Org mapping law: security_inbox.org_id is a uuid (FK organizations),
// while the event wire carries the TEXT org key (0021). For a uuid-org
// deployment the TEXT key IS the uuid string, and Project enforces that
// identity per event — an event whose org key is not exactly the target
// org's uuid string is refused whole (the reader already guarantees row
// org == document org == bound org; this is the same homes law on the
// fold side, and it is airtight precisely because the FK makes the uuid
// the truth).

package inbox

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// provisional severity/confidence derivations. W01-C02 folds before the
// W03-C01 scoring card exists, so the derivation is deliberately minimal
// and deterministic; W03-C01 owns the real semantics (severity from
// finding verdicts, escalation = max; confidence from grouping quality).
// The store upsert always overwrites these with the latest draft, so a
// later, smarter derivation retroactively corrects rows on the next fold.
const (
	provisionalSeverity   = SeverityLow
	provisionalConfidence = 1.0
)

// Project folds events into the org's inbox. It returns after the first
// store refusal — a half-folded batch is safe (every upsert is atomic;
// the next delivery re-folds the remainder).
func Project(ctx context.Context, store *Store, orgID uuid.UUID, events []secevents.Event) error {
	if orgID == uuid.Nil {
		return ErrStoreOrgRequired
	}
	orgKey := orgID.String()
	sorted := make([]secevents.Event, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].OccurredAt.Equal(sorted[j].OccurredAt) {
			return sorted[i].EventID < sorted[j].EventID
		}
		return sorted[i].OccurredAt.Before(sorted[j].OccurredAt)
	})
	for _, e := range sorted {
		if e.OrgID != orgKey {
			return fmt.Errorf("inbox: project: event %s org key %q is not the target org %s (homes law)", e.EventID, e.OrgID, orgKey)
		}
		key, err := GroupKey(e)
		if err != nil {
			return fmt.Errorf("inbox: project: fold event %s: %w", e.EventID, err)
		}
		if _, err := store.Upsert(ctx, orgID, IncidentDraft{
			GroupKey:   key,
			Summary:    e.Summary,
			Severity:   provisionalSeverity,
			Confidence: provisionalConfidence,
			OccurredAt: e.OccurredAt,
			EventID:    e.EventID,
			Evidence:   e.Evidence,
		}); err != nil {
			return fmt.Errorf("inbox: project: fold event %s: %w", e.EventID, err)
		}
	}
	return nil
}

// ProjectReader pulls the bound org's events through the production
// reader and folds them — the full Trigger ② path in one call. The
// reader's org key must be the org's uuid string (see the org mapping
// law above); Project enforces it per event either way.
func ProjectReader(ctx context.Context, store *Store, orgID uuid.UUID, reader *Reader) error {
	events, err := reader.Events(ctx)
	if err != nil {
		return fmt.Errorf("inbox: project: read: %w", err)
	}
	return Project(ctx, store, orgID, events)
}
