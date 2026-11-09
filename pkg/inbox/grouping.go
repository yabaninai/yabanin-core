// Grouping knobs (E06-P01 W02-C03): merge window, max group size,
// split-on-severity-change — code defaults plus the decision semantics,
// boundary-pinned in grouping_test.go.
//
// The knobs live at two layers, and the split matters:
//
//   - SplitOnSeverityChange is a KEY-LAW knob. Severity is an ingredient of
//     the group key (groupkey.go), so a severity change forks rows exactly
//     when the policy says so: with the knob ON the key carries the draft's
//     severity (verdict-based after W03-C01), with the knob OFF a constant
//     placeholder occupies the slot and verdict changes never fork. The
//     split therefore cannot be "half on": it is enforced by the (org_id,
//     group_key) unique row, the same lock the replay battery pins.
//
//   - MergeWindow and MaxGroupSize are ROW-STATE knobs. They compare the
//     incoming draft against the existing incident's fold coordinates, so
//     they cannot live in the (stateless) key; SplitsGroup below is their
//     pure decision function. The stateful wiring point is the fold that
//     knows the current row (the W05 trigger path, which resolves epoch
//     keys for a split); until then the defaults document the house law.
//
// Default choices (deliberate, pinned by tests):
//
//   - MergeWindow 24h: one operational day of a persistent finding folds
//     into one incident — the operator triage cadence. A finding that
//     comes back the next day is a NEW incident (fresh triage), not a
//     year-long megagroup.
//   - MaxGroupSize 500: one incident row caps at 500 folded events — a
//     runaway loop's blast radius is bounded per row and the inbox stays
//     readable; the events stay durable and re-derivable regardless.
//   - SplitOnSeverityChange ON: an escalation (low→high) must not hide
//     inside an old low incident — the operator sees a new row.

package inbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// GroupPolicy carries the grouping knobs. The zero value merges without
// bounds (no window, no cap, severity never forks) — every limit is
// opt-in, and DefaultGroupPolicy is the house posture.
type GroupPolicy struct {
	// MergeWindow folds an event into the existing incident when it
	// occurred strictly less than MergeWindow after the incident's
	// last_seen. Zero means no window.
	MergeWindow time.Duration
	// MaxGroupSize splits when the existing incident has already folded
	// MaxGroupSize events (the next event would exceed the cap). Zero
	// means no cap.
	MaxGroupSize int64
	// SplitOnSeverityChange puts the draft's severity into the group key
	// (see groupkey.go); a severity change then opens a new incident.
	SplitOnSeverityChange bool
}

// DefaultGroupPolicy is the house grouping posture (see the file comment
// for the reasoning behind each default).
func DefaultGroupPolicy() GroupPolicy {
	return GroupPolicy{
		MergeWindow:           24 * time.Hour,
		MaxGroupSize:          500,
		SplitOnSeverityChange: true,
	}
}

// severityPlaceholder occupies the key's severity slot when the policy
// does not split on severity changes — a constant, so any two severities
// key identically under that policy.
const severityPlaceholder = "-"

// GroupKeyFor derives the group key under an explicit policy; GroupKey is
// the default-policy shortcut. Everything else of the key law
// (groupkey.go) is unchanged: version prefix, category, resource digest,
// privacy (digests only), org isolation in the store.
func GroupKeyFor(p GroupPolicy, e secevents.Event, severity string) (string, error) {
	if e.EventType == "" {
		return "", ErrGroupKeyNoCategory
	}
	slot := severityPlaceholder
	if p.SplitOnSeverityChange {
		slot = severity
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		GroupKeyVersion,
		e.EventType,
		slot,
		ResourceDigest(e),
	}, "|")))
	return hex.EncodeToString(sum[:]), nil
}

// RowFoldState is the existing incident's fold coordinates — what the
// row-state knobs compare against. It is a read-side projection of the
// stored Incident, not a new source of truth.
type RowFoldState struct {
	LastSeen   time.Time
	EventCount int64
	Severity   string
}

// ErrSeverityRequired guards SplitsGroup callers that pass an empty draft
// severity: an unset severity cannot be compared, and inventing one would
// silently fork or merge groups on garbage.
var ErrSeverityRequired = errors.New("inbox: grouping: draft severity required")

// SplitsGroup reports whether an incoming draft must open a NEW incident
// instead of folding into the row described by st. A nil-state fold (no
// existing row) never splits. Precedence is fixed and documented: severity
// change first (usually already enforced at the key level), then the merge
// window, then the group size cap. The draft's OccurredAt at or beyond
// last_seen+MergeWindow splits — the boundary itself splits, one nanosecond
// before it merges. MaxGroupSize splits when the row is already at the cap
// (the next event would exceed it).
func (p GroupPolicy) SplitsGroup(st *RowFoldState, draft IncidentDraft) (bool, error) {
	if draft.Severity == "" {
		return false, ErrSeverityRequired
	}
	if st == nil {
		return false, nil // fresh fold: nothing to split from
	}
	if p.SplitOnSeverityChange && draft.Severity != st.Severity {
		return true, nil
	}
	if p.MergeWindow != 0 {
		if delta := draft.OccurredAt.Sub(st.LastSeen); delta >= p.MergeWindow {
			return true, nil
		}
	}
	if p.MaxGroupSize != 0 && st.EventCount >= p.MaxGroupSize {
		return true, nil
	}
	return false, nil
}
