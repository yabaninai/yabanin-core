// Incident model for the unified security inbox (E06-P01 W01-C02).
//
// An Incident is DERIVED state: it folds security events (the durable source
// of truth in secevents_documents, read through the org-bound Reader) into
// one operator-facing row per group of equivalent findings. The projection
// (projection.go) creates and advances incidents; operators (W04) advance
// status/assignee. The dictionaries are pinned by CHECK constraints in
// migration 0027 — this file mirrors them in Go so an invalid value is
// refused before it ever reaches the database.

package inbox

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// Severity vocabulary — the builtin detectors' dictionary
// (pkg/pipeline/builtins/params.go:12), pinned by security_inbox's
// severity CHECK. Severity answers "how bad" and is owned by the finding
// verdicts (escalation semantics land with W03-C01 scoring).
const (
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

// Incident status states — the W04-C01 state machine
// (new → acknowledged → in_progress → resolved | dismissed, plus reopen),
// pinned by security_inbox's status CHECK. The transition table itself is
// W04-C01's card; here only the vocabulary and the initial state exist.
const (
	StatusNew          = "new"
	StatusAcknowledged = "acknowledged"
	StatusInProgress   = "in_progress"
	StatusResolved     = "resolved"
	StatusDismissed    = "dismissed"
)

// MaxGroupKeyLen bounds group_key (a fingerprint hex string in practice,
// but the column contract is just bounded text).
const MaxGroupKeyLen = 128

// MaxEventIDLen mirrors the secevents event_id bound (256).
const MaxEventIDLen = 256

// Incident is one row of the security inbox for exactly one org.
type Incident struct {
	// ID identifies the incident (pagination keyset component).
	ID uuid.UUID
	// OrgID is the owning organization (RLS org_isolation key).
	OrgID uuid.UUID
	// GroupKey fingerprints the finding class this incident groups
	// (projection derivation; W02-C01 owns the full fingerprint law).
	GroupKey string
	// Summary is the latest folded event's human-readable summary.
	Summary string
	// Severity answers "how bad" (finding verdicts, dictionary above).
	Severity string
	// Confidence answers "how well grouped" (0..1, W03-C01 semantics).
	Confidence float64
	// Status is the operator state machine position.
	Status string
	// Assignee is the operator member id, nil when unassigned.
	Assignee *uuid.UUID
	// FirstSeen/LastSeen bound the folded events' occurred_at range
	// (LEAST/GREATEST invariants: FirstSeen <= LastSeen always).
	FirstSeen time.Time
	LastSeen  time.Time
	// EventCount is the number of folded events (>= 1).
	EventCount int64
	// FirstEventID/LastEventID reference the source events (secevents
	// event ids — provenance anchors into secevents_documents).
	FirstEventID string
	LastEventID  string
	// Evidence references the latest folded event's redacted evidence
	// (secevents.EvidenceRef — references only, never content).
	Evidence []secevents.EvidenceRef
	// CreatedAt/UpdatedAt are row bookkeeping (now() at write time).
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ErrInvalidIncident reports a model-level validation failure.
var ErrInvalidIncident = errors.New("inbox: invalid incident")

// Validate enforces the model contract mirrored from the 0027 CHECK
// constraints plus the fold invariants. Operator fields (Status/Assignee)
// are validated for vocabulary only.
func (i Incident) Validate() error {
	if i.OrgID == uuid.Nil {
		return fmt.Errorf("%w: org id is required", ErrInvalidIncident)
	}
	if i.GroupKey == "" || len(i.GroupKey) > MaxGroupKeyLen {
		return fmt.Errorf("%w: group key must be 1..%d chars", ErrInvalidIncident, MaxGroupKeyLen)
	}
	switch i.Severity {
	case SeverityLow, SeverityMedium, SeverityHigh:
	default:
		return fmt.Errorf("%w: severity %q not in the low|medium|high dictionary", ErrInvalidIncident, i.Severity)
	}
	if i.Confidence < 0 || i.Confidence > 1 {
		return fmt.Errorf("%w: confidence %f outside [0,1]", ErrInvalidIncident, i.Confidence)
	}
	switch i.Status {
	case StatusNew, StatusAcknowledged, StatusInProgress, StatusResolved, StatusDismissed:
	default:
		return fmt.Errorf("%w: status %q not in the state-machine dictionary", ErrInvalidIncident, i.Status)
	}
	if err := validEventRef(i.FirstEventID, "first"); err != nil {
		return err
	}
	if err := validEventRef(i.LastEventID, "last"); err != nil {
		return err
	}
	if i.EventCount < 1 {
		return fmt.Errorf("%w: event count %d < 1", ErrInvalidIncident, i.EventCount)
	}
	if i.FirstSeen.After(i.LastSeen) {
		return fmt.Errorf("%w: first_seen after last_seen (fold invariant violated)", ErrInvalidIncident)
	}
	return nil
}

func validEventRef(id, which string) error {
	if id == "" || len(id) > MaxEventIDLen {
		return fmt.Errorf("%w: %s event id must be 1..%d chars", ErrInvalidIncident, which, MaxEventIDLen)
	}
	return nil
}
