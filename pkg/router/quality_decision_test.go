package router

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Deterministic gate stand: vN (model-a .60, model-b .90) and a vN+1 whose
// favorite improved (.93 → overlap_ok) or regressed (.82 → hold). Fixed
// timestamps — no now() input anywhere in the gate.
var gateNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func gateSnapshot(version string, createdAt time.Time, scores map[string]QualityScore) *QualitySnapshot {
	return &QualitySnapshot{Version: version, Source: "agenteval", CreatedAt: createdAt, Overall: scores}
}

func gatePrev() *QualitySnapshot {
	return gateSnapshot("run-v1", gateNow.Add(-48*time.Hour), map[string]QualityScore{
		"model-a": {Score: 0.60, Samples: 60},
		"model-b": {Score: 0.90, Samples: 60},
	})
}

func gateNextImproved() *QualitySnapshot {
	return gateSnapshot("run-v2", gateNow.Add(-time.Hour), map[string]QualityScore{
		"model-a": {Score: 0.70, Samples: 60},
		"model-b": {Score: 0.93, Samples: 60},
	})
}

func gateNextRegressed() *QualitySnapshot {
	return gateSnapshot("run-v2", gateNow.Add(-time.Hour), map[string]QualityScore{
		"model-a": {Score: 0.70, Samples: 60},
		"model-b": {Score: 0.82, Samples: 60}, // favorite drops .90 → .82
	})
}

// gateDecision builds the complete owner decision the recomputation must
// confirm for the given revision pair.
func gateDecision(orgID string, current, proposed *QualitySnapshot) *QualityRoutingDecision {
	return &QualityRoutingDecision{
		OrgID:               orgID,
		Basis:               QualityBasisImportedEval,
		TargetRevision:      proposed.Version,
		TargetDatasetDigest: proposed.DatasetDigest,
		Evidence:            CompareQualitySnapshots(current, proposed, 0),
		EvidenceSummary:     "imported run v2: favorite model-b improved on the v1 model overlap (owner-reviewed aggregates)",
		Limitations: "external import — not an independent Yabanin verification; single overall class split; " +
			"60 evaluated samples per arm; eval set and policy profile fixed at import time",
		AcknowledgesImport: true,
		ApprovedBy:         "owner",
		ApprovedAt:         gateNow,
	}
}

func TestAuthorizeQualityRoutingChange_AuthorizesValidDecisions(t *testing.T) {
	prev, next := gatePrev(), gateNextImproved()

	t.Run("first adoption records the no-baseline evidence", func(t *testing.T) {
		dec := gateDecision("org-1", nil, next)
		assert.False(t, dec.Evidence.ShiftAllowed)
		assert.Equal(t, "no_baseline_overlap", dec.Evidence.Reason)

		ev, err := AuthorizeQualityRoutingChange("org-1", nil, next, dec)
		require.NoError(t, err)
		assert.Equal(t, dec.Evidence, ev, "the returned evidence is the recomputation")
		assert.Equal(t, "run-v2", ev.NextVersion)
	})

	t.Run("version shift with overlap_ok evidence", func(t *testing.T) {
		dec := gateDecision("org-1", prev, next)
		assert.True(t, dec.Evidence.ShiftAllowed)

		ev, err := AuthorizeQualityRoutingChange("org-1", prev, next, dec)
		require.NoError(t, err)
		assert.True(t, ev.ShiftAllowed)
		assert.Equal(t, "overlap_ok", ev.Reason)
		assert.Equal(t, "run-v1", ev.PreviousVersion)
		assert.Equal(t, "run-v2", ev.NextVersion)
	})

	t.Run("re-authorization of the already applied revision", func(t *testing.T) {
		dec := gateDecision("org-1", next, next)

		ev, err := AuthorizeQualityRoutingChange("org-1", next, next, dec)
		require.NoError(t, err)
		assert.True(t, ev.ShiftAllowed)
	})

	t.Run("decision survives the owner-flow JSON round-trip", func(t *testing.T) {
		// The decision is produced out-of-band and serialized into the owner
		// registry; the gate must accept the exact recomputation after a
		// JSON round-trip (float64 evidence round-trips bit-exactly).
		dec := gateDecision("org-1", prev, next)
		raw, err := json.Marshal(dec)
		require.NoError(t, err)
		var back QualityRoutingDecision
		require.NoError(t, json.Unmarshal(raw, &back))

		_, err = AuthorizeQualityRoutingChange("org-1", prev, next, &back)
		require.NoError(t, err)
	})

	t.Run("decision wire form carries the required explanation", func(t *testing.T) {
		raw, err := json.Marshal(gateDecision("org-1", prev, next))
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		for _, key := range []string{
			"org_id", "basis", "target_revision", "evidence",
			"evidence_summary", "limitations", "acknowledges_import",
			"approved_by", "approved_at",
		} {
			assert.Contains(t, m, key, "decision JSON must carry %q", key)
		}
	})
}

// Every defect fails closed with a typed rejection wrapping
// ErrQualityRoutingChangeRejected: the caller keeps the current route and no
// evidence leaks out of a refusal.
func TestAuthorizeQualityRoutingChange_RejectsFailClosed(t *testing.T) {
	prev, next := gatePrev(), gateNextImproved()
	fresh := func(mutate func(d *QualityRoutingDecision)) *QualityRoutingDecision {
		d := gateDecision("org-1", prev, next)
		if mutate != nil {
			mutate(d)
		}
		return d
	}

	cases := []struct {
		name       string
		orgID      string
		current    *QualitySnapshot
		proposed   *QualitySnapshot
		dec        *QualityRoutingDecision
		wantReason string
	}{
		{
			name: "no decision recorded", orgID: "org-1", current: prev, proposed: next, dec: nil,
			wantReason: QualityRejectNoDecision,
		},
		{
			name: "decision issued for another org", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.OrgID = "org-2" }),
			wantReason: QualityRejectOrgMismatch,
		},
		{
			name: "decision without an org binding", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.OrgID = "" }),
			wantReason: QualityRejectOrgMismatch,
		},
		{
			name: "empty caller org", orgID: "", current: prev, proposed: next,
			dec:        fresh(nil),
			wantReason: QualityRejectOrgMismatch,
		},
		{
			name: "user feedback basis", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.Basis = "user_feedback" }),
			wantReason: QualityRejectUnknownBasis,
		},
		{
			name: "empty basis", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.Basis = "" }),
			wantReason: QualityRejectUnknownBasis,
		},
		{
			name: "import disclaimer not acknowledged", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.AcknowledgesImport = false }),
			wantReason: QualityRejectImportNotAcknowledged,
		},
		{
			name: "no recorded approver", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.ApprovedBy = "" }),
			wantReason: QualityRejectApprovalIncomplete,
		},
		{
			name: "no approval time", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.ApprovedAt = time.Time{} }),
			wantReason: QualityRejectApprovalIncomplete,
		},
		{
			name: "missing evidence summary", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.EvidenceSummary = "" }),
			wantReason: QualityRejectMissingEvidence,
		},
		{
			name: "missing limitations", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.Limitations = "" }),
			wantReason: QualityRejectMissingLimitations,
		},
		{
			name: "no proposed snapshot", orgID: "org-1", current: prev, proposed: nil,
			dec:        fresh(nil),
			wantReason: QualityRejectSnapshotUnusable,
		},
		{
			name: "decision without a target revision", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.TargetRevision = "" }),
			wantReason: QualityRejectRevisionMismatch,
		},
		{
			name: "unknown revision", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.TargetRevision = "run-v99" }),
			wantReason: QualityRejectRevisionMismatch,
		},
		{
			name: "proposed snapshot without a version", orgID: "org-1", current: prev,
			proposed:   gateSnapshot("", gateNow.Add(-time.Hour), map[string]QualityScore{"model-b": {Score: 0.9, Samples: 60}}),
			dec:        fresh(func(d *QualityRoutingDecision) { d.TargetRevision = "" }),
			wantReason: QualityRejectRevisionMismatch,
		},
		{
			name: "proposed snapshot without a creation time", orgID: "org-1", current: prev,
			proposed: func() *QualitySnapshot {
				p := gateNextImproved()
				p.CreatedAt = time.Time{}
				return p
			}(),
			dec:        fresh(nil),
			wantReason: QualityRejectSnapshotUnusable,
		},
		{
			name: "digest pinned but absent on the snapshot", orgID: "org-1", current: prev, proposed: next,
			dec:        fresh(func(d *QualityRoutingDecision) { d.TargetDatasetDigest = "sha256-imported" }),
			wantReason: QualityRejectDigestMismatch,
		},
		{
			name: "digest mismatch", orgID: "org-1",
			current: prev,
			proposed: func() *QualitySnapshot {
				p := gateNextImproved()
				p.DatasetDigest = "sha256-actual"
				return p
			}(),
			dec:        fresh(func(d *QualityRoutingDecision) { d.TargetDatasetDigest = "sha256-decided" }),
			wantReason: QualityRejectDigestMismatch,
		},
		{
			name: "forged shift allowance over a regression", orgID: "org-1",
			current:  prev,
			proposed: gateNextRegressed(),
			dec: func() *QualityRoutingDecision {
				d := gateDecision("org-1", prev, gateNextRegressed())
				d.Evidence.ShiftAllowed = true // tampered: the recomputation says hold
				return d
			}(),
			wantReason: QualityRejectEvidenceMismatch,
		},
		{
			name: "evidence recorded for different data", orgID: "org-1",
			current:    prev,
			proposed:   gateNextRegressed(), // same version string, different scores than the decision's pair
			dec:        gateDecision("org-1", prev, gateNextImproved()),
			wantReason: QualityRejectEvidenceMismatch,
		},
		{
			name: "faithful hold evidence cannot shift traffic", orgID: "org-1",
			current:    prev,
			proposed:   gateNextRegressed(),
			dec:        gateDecision("org-1", prev, gateNextRegressed()),
			wantReason: QualityRejectEvidenceHolds,
		},
		{
			name: "profile mismatch hold cannot be decided away", orgID: "org-1",
			current: func() *QualitySnapshot {
				p := gatePrev()
				p.PolicyProfile = "QUALITY_40"
				return p
			}(),
			proposed: func() *QualitySnapshot {
				p := gateNextImproved()
				p.PolicyProfile = "OTHER_PROFILE_10"
				return p
			}(),
			dec: func() *QualityRoutingDecision {
				p, n := gatePrev(), gateNextImproved()
				p.PolicyProfile, n.PolicyProfile = "QUALITY_40", "OTHER_PROFILE_10"
				return gateDecision("org-1", p, n)
			}(),
			wantReason: QualityRejectEvidenceHolds,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := AuthorizeQualityRoutingChange(tc.orgID, tc.current, tc.proposed, tc.dec)
			require.Error(t, err)
			assert.Zero(t, ev, "a rejection never leaks evidence")
			require.ErrorIs(t, err, ErrQualityRoutingChangeRejected)
			var rr *QualityRoutingRejection
			require.ErrorAs(t, err, &rr)
			assert.Equal(t, tc.wantReason, rr.Reason)
			assert.NotEmpty(t, rr.Message)
		})
	}
}

// The card's negative criterion, pinned structurally: user feedback can never
// authorize a routing change — not with shift-permitting numbers, not by
// borrowing an imported revision's identity — and the gate is a pure
// function: a refusal leaves every input byte-identical (no auto-apply, no
// state to corrupt).
func TestAuthorizeQualityRoutingChange_FeedbackNeverChangesRouting(t *testing.T) {
	prev, next := gatePrev(), gateNextImproved()
	dec := gateDecision("org-1", prev, next)
	dec.Basis = "user_feedback"
	dec.EvidenceSummary = "aggregate user feedback prefers model-b"

	feedbackSnap := gateNextImproved()
	feedbackSnap.Source = "user_feedback"

	before, err := json.Marshal([]any{prev, feedbackSnap, dec})
	require.NoError(t, err)

	_, err = AuthorizeQualityRoutingChange("org-1", prev, feedbackSnap, dec)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrQualityRoutingChangeRejected)
	var rr *QualityRoutingRejection
	require.ErrorAs(t, err, &rr)
	assert.Equal(t, QualityRejectUnknownBasis, rr.Reason)

	after, err := json.Marshal([]any{prev, feedbackSnap, dec})
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "the gate must not mutate snapshots or decisions")
}

func TestAuthorizeQualityRoutingChange_Deterministic(t *testing.T) {
	prev, next := gatePrev(), gateNextImproved()
	dec := gateDecision("org-1", prev, next)

	first, firstErr := AuthorizeQualityRoutingChange("org-1", prev, next, dec)
	require.NoError(t, firstErr)
	for i := 0; i < 10; i++ {
		ev, err := AuthorizeQualityRoutingChange("org-1", prev, next, dec)
		require.NoError(t, err, "iteration %d", i)
		assert.Equal(t, first, ev, "authorization must be deterministic (no RNG, no map order)")
	}
}
