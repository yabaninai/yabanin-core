// Operator state machine for the unified security inbox (E06-P01
// W04-C01).
//
// The transition table lives HERE, in code, as the single law:
//
//	new → acknowledged → in_progress → resolved | dismissed
//	resolved → acknowledged   (reopen)
//	dismissed → acknowledged  (reopen)
//
// plus the idempotency law: a same-state transition (self-loop) is legal
// and is a NO-OP — it neither errors nor moves updated_at. That is the
// store-side half of the W04-C02 same-state PATCH contract (200, nothing
// duplicated, nothing bumped); the handler journals it distinctly.
//
// ApplyOperatorPatch follows the store's writer law (store.go): Begin →
// bypass check → (pin only when the session is RLS-bound) → SELECT … FOR
// UPDATE → validate → UPDATE → Commit. Operator fields are the ONLY
// columns it writes; fold state (counts, seen bounds, event ids, evidence)
// is untouched — a reopen never loses history.

package inbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrInvalidTransition reports a transition the state machine refuses
// (including unknown states — the dictionary is part of the law).
var ErrInvalidTransition = errors.New("inbox: status: invalid transition")

// statusTransitions is the legal-edge table (self-loops excluded — they
// are legal by the idempotency law in ValidateTransition).
var statusTransitions = map[string]map[string]bool{
	StatusNew:          {StatusAcknowledged: true},
	StatusAcknowledged: {StatusInProgress: true},
	StatusInProgress:   {StatusResolved: true, StatusDismissed: true},
	StatusResolved:     {StatusAcknowledged: true}, // reopen
	StatusDismissed:    {StatusAcknowledged: true}, // reopen
}

// ValidateTransition applies the W04-C01 law to a from→to pair:
//
//   - from == to: legal no-op (idempotent same-state PATCH);
//   - a table edge: legal;
//   - anything else — including a word outside the status dictionary —
//     ErrInvalidTransition.
func ValidateTransition(from, to string) error {
	if _, ok := statusTransitions[from]; !ok {
		return fmt.Errorf("%w: unknown state %q", ErrInvalidTransition, from)
	}
	if _, ok := statusTransitions[to]; !ok {
		return fmt.Errorf("%w: unknown state %q", ErrInvalidTransition, to)
	}
	if from == to {
		return nil // idempotency law: self-loops are legal no-ops
	}
	if statusTransitions[from][to] {
		return nil
	}
	return fmt.Errorf("%w: %s → %s", ErrInvalidTransition, from, to)
}

// OperatorPatch is an operator's write to one incident. Absent fields are
// left untouched; AssigneeSet distinguishes "clear the assignee"
// (Assignee == uuid.Nil) from "don't touch" (AssigneeSet == false).
type OperatorPatch struct {
	Status      *string
	Assignee    uuid.UUID
	AssigneeSet bool
}

// validate checks the patch's own vocabulary (the transition's from-state
// comes from the row and is validated later, under the row lock).
func (p OperatorPatch) validate() error {
	if p.Status == nil {
		return nil
	}
	switch *p.Status {
	case StatusNew, StatusAcknowledged, StatusInProgress, StatusResolved, StatusDismissed:
		return nil
	default:
		return fmt.Errorf("%w: unknown state %q", ErrInvalidTransition, *p.Status)
	}
}

// storeLockSQL locks the incident row inside the org scope for the
// patch transaction (the writer law's statement order: lock, then decide,
// then write).
const storeLockSQL = `
SELECT id, org_id, group_key, summary, severity, confidence, status,
  assignee, first_seen, last_seen, event_count, first_event_id,
  last_event_id, evidence, created_at, updated_at
FROM security_inbox
WHERE org_id = $1 AND id = $2
FOR UPDATE`

// storePatchReturning is the RETURNING column list shared by the patch
// UPDATE (same shape as the store's other full-row statements).
const storePatchReturning = `
RETURNING id, org_id, group_key, summary, severity, confidence, status,
  assignee, first_seen, last_seen, event_count, first_event_id,
  last_event_id, evidence, created_at, updated_at`

// ApplyOperatorPatch applies an operator status/assignee change to one
// incident of one org and returns the resulting row. found=false (no
// error) when the incident does not exist in this org — foreign-org and
// unknown-id are indistinguishable by design (no existence leak).
//
// Semantics:
//
//   - ErrInvalidTransition when the requested status change is not a
//     legal edge (the row is left untouched; validated under the row
//     lock, so racing patches serialize on FOR UPDATE);
//   - a patch that changes NOTHING (same-state self-loop with the
//     assignee untouched or equal) is a legal no-op: the row returns
//     byte-identical, updated_at does not move, no UPDATE is issued;
//   - an effective patch writes ONLY status/assignee/updated_at.
func (s *Store) ApplyOperatorPatch(ctx context.Context, orgID, incidentID uuid.UUID, patch OperatorPatch) (Incident, bool, error) {
	if orgID == uuid.Nil {
		return Incident{}, false, ErrStoreOrgRequired
	}
	if err := patch.validate(); err != nil {
		return Incident{}, false, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Incident{}, false, fmt.Errorf("inbox: status: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	// Writer law: pin only when the session is RLS-bound.
	var bypass bool
	if err := tx.QueryRow(ctx, storeNeedsPinSQL).Scan(&bypass); err != nil {
		return Incident{}, false, fmt.Errorf("inbox: status: pin probe: %w", err)
	}
	if !bypass {
		if _, err := tx.Exec(ctx, readerPinSQL, orgID.String()); err != nil {
			return Incident{}, false, fmt.Errorf("inbox: status: pin: %w", err)
		}
	}

	var current Incident
	var evidence []byte
	err = tx.QueryRow(ctx, storeLockSQL, orgID, incidentID).Scan(
		&current.ID, &current.OrgID, &current.GroupKey, &current.Summary, &current.Severity,
		&current.Confidence, &current.Status, &current.Assignee, &current.FirstSeen,
		&current.LastSeen, &current.EventCount, &current.FirstEventID, &current.LastEventID,
		&evidence, &current.CreatedAt, &current.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Incident{}, false, nil
	}
	if err != nil {
		return Incident{}, false, fmt.Errorf("inbox: status: lock: %w", err)
	}
	if err := decodeIncidentEvidence(&current, evidence); err != nil {
		return Incident{}, false, err
	}

	// Transition law, under the row lock.
	nextStatus := current.Status
	statusChanged := false
	if patch.Status != nil {
		if err := ValidateTransition(current.Status, *patch.Status); err != nil {
			return Incident{}, false, err
		}
		if *patch.Status != current.Status {
			nextStatus = *patch.Status
			statusChanged = true
		}
	}
	assigneeChanged := patch.AssigneeSet && !sameAssignee(current.Assignee, patch.Assignee)
	if !statusChanged && !assigneeChanged {
		// Legal no-op: return the locked row untouched (no UPDATE, no
		// updated_at movement). The transaction commits the lock away.
		if err := tx.Commit(ctx); err != nil {
			return Incident{}, false, fmt.Errorf("inbox: status: commit noop: %w", err)
		}
		return current, true, nil
	}

	// Effective patch: write only the operator columns.
	var set []string
	args := []any{orgID, incidentID}
	if statusChanged {
		args = append(args, nextStatus)
		set = append(set, fmt.Sprintf("status = $%d", len(args)))
	}
	if assigneeChanged {
		var assigneeArg any
		if patch.Assignee != uuid.Nil {
			assigneeArg = patch.Assignee
		}
		args = append(args, assigneeArg)
		set = append(set, fmt.Sprintf("assignee = $%d", len(args)))
	}
	set = append(set, "updated_at = now()")
	sql := "UPDATE security_inbox SET " + strings.Join(set, ", ") +
		" WHERE org_id = $1 AND id = $2" + storePatchReturning

	var updated Incident
	if err := tx.QueryRow(ctx, sql, args...).Scan(
		&updated.ID, &updated.OrgID, &updated.GroupKey, &updated.Summary, &updated.Severity,
		&updated.Confidence, &updated.Status, &updated.Assignee, &updated.FirstSeen,
		&updated.LastSeen, &updated.EventCount, &updated.FirstEventID, &updated.LastEventID,
		&evidence, &updated.CreatedAt, &updated.UpdatedAt,
	); err != nil {
		return Incident{}, false, fmt.Errorf("inbox: status: update: %w", err)
	}
	if err := decodeIncidentEvidence(&updated, evidence); err != nil {
		return Incident{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Incident{}, false, fmt.Errorf("inbox: status: commit: %w", err)
	}
	return updated, true, nil
}

// sameAssignee compares an optional column value with a patch value
// (uuid.Nil in a patch means "clear", which equals a NULL column).
func sameAssignee(current *uuid.UUID, patch uuid.UUID) bool {
	if patch == uuid.Nil {
		return current == nil
	}
	return current != nil && *current == patch
}

// decodeIncidentEvidence decodes the evidence column into the incident
// (same contract as the store's inline unmarshal).
func decodeIncidentEvidence(inc *Incident, raw []byte) error {
	if err := json.Unmarshal(raw, &inc.Evidence); err != nil {
		return fmt.Errorf("inbox: status: unmarshal evidence: %w", err)
	}
	return nil
}
