package inbox

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// E06-P01 W02-C03: grouping knob boundaries. Exactly-on-the-boundary
// behavior is PINNED here — the merge window splits at its edge, the size
// cap splits when the row is at the cap, and the severity split is
// deterministic both as a decision and at the key/row level.

func TestGroupingDefaultsPinned(t *testing.T) {
	p := DefaultGroupPolicy()
	assert.Equal(t, 24*time.Hour, p.MergeWindow, "one operational day per incident")
	assert.Equal(t, int64(500), p.MaxGroupSize, "bounded blast radius per row")
	assert.True(t, p.SplitOnSeverityChange, "escalations must not hide inside old incidents")
}

func groupingDraft(occ time.Time, severity string) IncidentDraft {
	return IncidentDraft{
		GroupKey:   "k",
		Summary:    "s",
		Severity:   severity,
		Confidence: provisionalConfidence,
		OccurredAt: occ,
		EventID:    "evt-g",
	}
}

func TestGroupingMergeWindowBoundary(t *testing.T) {
	p := DefaultGroupPolicy()
	lastSeen := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	row := &RowFoldState{LastSeen: lastSeen, EventCount: 10, Severity: SeverityLow}

	cases := []struct {
		name  string
		occ   time.Time
		split bool
	}{
		{"one nanosecond before the window merges", lastSeen.Add(p.MergeWindow - 1), false},
		{"exactly at the window boundary splits", lastSeen.Add(p.MergeWindow), true},
		{"far past the window splits", lastSeen.Add(p.MergeWindow + time.Hour), true},
		{"delayed delivery before last_seen merges", lastSeen.Add(-time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			split, err := p.SplitsGroup(row, groupingDraft(tc.occ, SeverityLow))
			require.NoError(t, err)
			assert.Equal(t, tc.split, split)
		})
	}

	// Zero window = unlimited: any distance merges.
	noWindow := DefaultGroupPolicy()
	noWindow.MergeWindow = 0
	split, err := noWindow.SplitsGroup(row, groupingDraft(lastSeen.Add(365*24*time.Hour), SeverityLow))
	require.NoError(t, err)
	assert.False(t, split, "MergeWindow 0 means no window")
}

func TestGroupingMaxSizeBoundary(t *testing.T) {
	p := DefaultGroupPolicy() // MaxGroupSize 500
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	atCap := &RowFoldState{LastSeen: base, EventCount: p.MaxGroupSize, Severity: SeverityLow}
	oneBelow := &RowFoldState{LastSeen: base, EventCount: p.MaxGroupSize - 1, Severity: SeverityLow}

	split, err := p.SplitsGroup(oneBelow, groupingDraft(base.Add(time.Minute), SeverityLow))
	require.NoError(t, err)
	assert.False(t, split, "one below the cap folds up TO the cap")

	split, err = p.SplitsGroup(atCap, groupingDraft(base.Add(time.Minute), SeverityLow))
	require.NoError(t, err)
	assert.True(t, split, "a row at the cap splits the next event")

	// Zero cap = unlimited.
	noCap := DefaultGroupPolicy()
	noCap.MaxGroupSize = 0
	huge := &RowFoldState{LastSeen: base, EventCount: 1 << 40, Severity: SeverityLow}
	split, err = noCap.SplitsGroup(huge, groupingDraft(base.Add(time.Minute), SeverityLow))
	require.NoError(t, err)
	assert.False(t, split, "MaxGroupSize 0 means no cap")
}

func TestGroupingSeveritySplitDeterministic(t *testing.T) {
	p := DefaultGroupPolicy()
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	row := &RowFoldState{LastSeen: base, EventCount: 3, Severity: SeverityLow}

	// Knob ON: a severity change splits — always, regardless of window and
	// size distance (severity is checked first).
	split, err := p.SplitsGroup(row, groupingDraft(base, SeverityHigh))
	require.NoError(t, err)
	assert.True(t, split)
	split, err = p.SplitsGroup(row, groupingDraft(base.Add(p.MergeWindow+time.Hour), SeverityHigh))
	require.NoError(t, err)
	assert.True(t, split, "severity split outranks the window")

	// Same severity: no split from the severity knob.
	split, err = p.SplitsGroup(row, groupingDraft(base, SeverityLow))
	require.NoError(t, err)
	assert.False(t, split)

	// Knob OFF: a severity change does NOT split the row decision…
	off := DefaultGroupPolicy()
	off.SplitOnSeverityChange = false
	split, err = off.SplitsGroup(row, groupingDraft(base, SeverityHigh))
	require.NoError(t, err)
	assert.False(t, split)

	// …and it does not fork the KEY either (constant placeholder slot):
	// two severities, one row identity — the knob is enforced by the same
	// (org_id, group_key) lock as the replay battery.
	e := gkEvent("tool.deny", "agent-7", "sess-42", "s")
	keyLow, err := GroupKeyFor(off, e, SeverityLow)
	require.NoError(t, err)
	keyHigh, err := GroupKeyFor(off, e, SeverityHigh)
	require.NoError(t, err)
	assert.Equal(t, keyLow, keyHigh, "knob OFF: severity never enters the key")

	keyLowOn, err := GroupKeyFor(p, e, SeverityLow)
	require.NoError(t, err)
	keyHighOn, err := GroupKeyFor(p, e, SeverityHigh)
	require.NoError(t, err)
	assert.NotEqual(t, keyLowOn, keyHighOn, "knob ON: severity forks the key")
	assert.Equal(t, keyLowOn, gkKey(t, e), "default GroupKey == default-policy GroupKeyFor with the provisional severity")

	// Unknown/empty severity is refused, never silently keyed.
	_, err = p.SplitsGroup(row, groupingDraft(base, ""))
	assert.ErrorIs(t, err, ErrSeverityRequired)
}

func TestGroupingSeveritySplitMaterializesDistinctRows(t *testing.T) {
	// The severity split is not just a decision: under the default policy
	// the two severities carry different keys, so the store keeps TWO
	// incidents — deterministically across re-folds of the same drafts.
	_, app, org, _ := siFixture(t)
	ctx := WithOrg(context.Background(), org.String())
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	store := NewStore(app)
	p := DefaultGroupPolicy()
	e := siEvent(org.String(), fmt.Sprintf("gk3%x", time.Now().UnixNano()), "tool deny", base)

	fold := func(severity string) {
		t.Helper()
		key, err := GroupKeyFor(p, e, severity)
		require.NoError(t, err)
		_, err = store.Upsert(ctx, org, IncidentDraft{
			GroupKey:   key,
			Summary:    "escalation fold " + severity,
			Severity:   severity,
			Confidence: provisionalConfidence,
			OccurredAt: base,
			EventID:    e.EventID,
		})
		require.NoError(t, err)
	}
	fold(SeverityLow)
	fold(SeverityHigh)
	fold(SeverityLow)  // re-fold: idempotent row identity per key
	fold(SeverityHigh) // re-fold

	incs, err := store.List(ctx, org)
	require.NoError(t, err)
	require.Len(t, incs, 2, "severity change = two incidents under the default policy")
	sev := map[string]int64{}
	for _, inc := range incs {
		sev[inc.Severity] = inc.EventCount
	}
	assert.Equal(t, map[string]int64{SeverityLow: 2, SeverityHigh: 2}, sev,
		"each severity folds into its own row, re-folds merge — never a third row")
}
