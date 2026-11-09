package router

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// N09-P03-T04: rollback of quality routing over imported evaluation data.
//
// Stand: org-1 applied run-v1, then run-v2 (both revisions in the applied
// history), and now rolls back to run-v1. With the forward stand's snapshots
// the recomputed v2→v1 evidence HOLDS (v2's favorite measured higher than
// v1's) — exactly the situation a rollback exists for — and the gate must
// still authorize the manual, revision-bound return.
//
// No built-in runner, no LLM judge, no built-in model comparison (I64): the
// only evidence in play is the aggregate D4 overlap recomputation over
// imported results, established by T03.
//

func rollbackCurrent() *QualitySnapshot { return gateNextImproved() } // run-v2 (applied)
func rollbackTarget() *QualitySnapshot  { return gatePrev() }         // run-v1 (applied before)
func rollbackHistory() []string         { return []string{"run-v1", "run-v2"} }

// gateRollback builds the complete owner rollback decision the
// recomputation must confirm for the given revision pair.
func gateRollback(orgID string, current, target *QualitySnapshot) *QualityRoutingRollback {
	return &QualityRoutingRollback{
		OrgID:               orgID,
		Basis:               QualityBasisImportedEval,
		TargetRevision:      target.Version,
		TargetDatasetDigest: target.DatasetDigest,
		RollbackReason:      "run-v2 regressed against run-v1 measurements in production monitoring; returning to the last known-good imported revision",
		Evidence:            CompareQualitySnapshots(current, target, 0),
		EvidenceSummary:     "imported run v1 restored: the v2 favorite measured below the v1 baseline on the model overlap (owner-reviewed aggregates)",
		Limitations: "external import — not an independent Yabanin verification; single overall class split; " +
			"60 evaluated samples per arm; eval set and policy profile fixed at import time",
		AcknowledgesImport: true,
		ApprovedBy:         "owner",
		ApprovedAt:         gateNow,
	}
}

func TestAuthorizeQualityRoutingRollback_AuthorizesValidRollback(t *testing.T) {
	current, target := rollbackCurrent(), rollbackTarget()

	t.Run("revision-bound return to a previously applied revision", func(t *testing.T) {
		rb := gateRollback("org-1", current, target)

		ev, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), rb)
		require.NoError(t, err)
		assert.Equal(t, "run-v2", ev.PreviousVersion, "the route returns FROM the applied v2")
		assert.Equal(t, "run-v1", ev.NextVersion, "…TO the previously applied v1")
		assert.Equal(t, rb.Evidence, ev, "the returned evidence is the recomputation, for the audit log")
	})

	t.Run("hold verdict does not refuse a rollback", func(t *testing.T) {
		// A rollback is a safety action: the recomputed evidence typically
		// holds (the newer revision measured worse) and must not be able to
		// trap the org on it. This distinguishes the rollback gate from the
		// forward gate (evidence_holds).
		ev := CompareQualitySnapshots(current, target, 0)
		assert.False(t, ev.ShiftAllowed, "stand check: v2→v1 evidence holds (v1 favorite below v2 baseline)")
		assert.Equal(t, "favorite_regressed", ev.Reason)

		rb := gateRollback("org-1", current, target)
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), rb)
		require.NoError(t, err, "the forward gate's hold rule must not apply to rollbacks")
	})

	t.Run("decision survives the owner-flow JSON round-trip", func(t *testing.T) {
		rb := gateRollback("org-1", current, target)
		raw, err := json.Marshal(rb)
		require.NoError(t, err)
		var back QualityRoutingRollback
		require.NoError(t, json.Unmarshal(raw, &back))

		_, err = AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), &back)
		require.NoError(t, err)
	})

	t.Run("rollback wire form carries the required explanation", func(t *testing.T) {
		raw, err := json.Marshal(gateRollback("org-1", current, target))
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		for _, key := range []string{
			"org_id", "basis", "target_revision", "rollback_reason",
			"evidence", "evidence_summary", "limitations",
			"acknowledges_import", "approved_by", "approved_at",
		} {
			assert.Contains(t, m, key, "rollback JSON must carry %q", key)
		}
	})
}

// Every defect fails closed with a typed rejection wrapping
// ErrQualityRoutingChangeRejected: the caller keeps the current route, and a
// rollback never fires automatically or from damaged/foreign provenance.
func TestAuthorizeQualityRoutingRollback_RejectsFailClosed(t *testing.T) {
	current, target := rollbackCurrent(), rollbackTarget()
	fresh := func(mutate func(rb *QualityRoutingRollback)) *QualityRoutingRollback {
		rb := gateRollback("org-1", current, target)
		if mutate != nil {
			mutate(rb)
		}
		return rb
	}
	wantReason := func(t *testing.T, err error, reason string) {
		t.Helper()
		require.Error(t, err)
		require.ErrorIs(t, err, ErrQualityRoutingChangeRejected, "refusal %q must wrap the gate error", reason)
		var rej *QualityRoutingRejection
		require.ErrorAs(t, err, &rej, "refusal must be a *QualityRoutingRejection")
		assert.Equal(t, reason, rej.Reason)
	}

	t.Run("no decision never moves routing", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), nil)
		wantReason(t, err, QualityRejectNoDecision)
	})
	t.Run("decision issued for another org", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), fresh(func(rb *QualityRoutingRollback) { rb.OrgID = "org-2" }))
		wantReason(t, err, QualityRejectOrgMismatch)
	})
	t.Run("nothing applied to roll back from", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", nil, target, rollbackHistory(), fresh(nil))
		wantReason(t, err, QualityRejectRollbackNoCurrent)
	})
	t.Run("user feedback basis never rolls routing back", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), fresh(func(rb *QualityRoutingRollback) { rb.Basis = "user_feedback" }))
		wantReason(t, err, QualityRejectUnknownBasis)
	})
	t.Run("import disclaimer not acknowledged", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), fresh(func(rb *QualityRoutingRollback) { rb.AcknowledgesImport = false }))
		wantReason(t, err, QualityRejectImportNotAcknowledged)
	})
	t.Run("no recorded approver is not a manual approval", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), fresh(func(rb *QualityRoutingRollback) { rb.ApprovedBy = "" }))
		wantReason(t, err, QualityRejectApprovalIncomplete)
	})
	t.Run("zero approval time is not a manual approval", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), fresh(func(rb *QualityRoutingRollback) { rb.ApprovedAt = time.Time{} }))
		wantReason(t, err, QualityRejectApprovalIncomplete)
	})
	t.Run("rollback without a stated reason", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), fresh(func(rb *QualityRoutingRollback) { rb.RollbackReason = "" }))
		wantReason(t, err, QualityRejectRollbackReasonMissing)
	})
	t.Run("rollback without an evidence summary", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), fresh(func(rb *QualityRoutingRollback) { rb.EvidenceSummary = "" }))
		wantReason(t, err, QualityRejectMissingEvidence)
	})
	t.Run("rollback without limitations", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), fresh(func(rb *QualityRoutingRollback) { rb.Limitations = "" }))
		wantReason(t, err, QualityRejectMissingLimitations)
	})
	t.Run("no target snapshot", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", current, nil, rollbackHistory(), fresh(nil))
		wantReason(t, err, QualityRejectSnapshotUnusable)
	})
	t.Run("unknown revision — decision targets a version the snapshot does not carry", func(t *testing.T) {
		rb := fresh(func(rb *QualityRoutingRollback) { rb.TargetRevision = "run-v9" })
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), rb)
		wantReason(t, err, QualityRejectRevisionMismatch)
	})
	t.Run("empty target revision is never applied", func(t *testing.T) {
		rb := fresh(func(rb *QualityRoutingRollback) { rb.TargetRevision = "" })
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), rb)
		wantReason(t, err, QualityRejectRevisionMismatch)
	})
	t.Run("target snapshot without a creation time", func(t *testing.T) {
		bad := gateSnapshot(target.Version, time.Time{}, target.Overall)
		_, err := AuthorizeQualityRoutingRollback("org-1", current, bad, rollbackHistory(), fresh(nil))
		wantReason(t, err, QualityRejectSnapshotUnusable)
	})
	t.Run("digest pinned but absent on the target snapshot", func(t *testing.T) {
		rb := fresh(func(rb *QualityRoutingRollback) { rb.TargetDatasetDigest = "digest-tampered" })
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), rb)
		wantReason(t, err, QualityRejectDigestMismatch)
	})
	t.Run("target revision the org never applied", func(t *testing.T) {
		unknown := gateSnapshot("run-vX", gateNow.Add(-96*time.Hour), target.Overall)
		_, err := AuthorizeQualityRoutingRollback("org-1", current, unknown, rollbackHistory(), fresh(func(rb *QualityRoutingRollback) { rb.TargetRevision = "run-vX" }))
		wantReason(t, err, QualityRejectRollbackNotApplied)
	})
	t.Run("target equals the currently applied route", func(t *testing.T) {
		_, err := AuthorizeQualityRoutingRollback("org-1", current, current, rollbackHistory(), fresh(func(rb *QualityRoutingRollback) { rb.TargetRevision = current.Version }))
		wantReason(t, err, QualityRejectRollbackNoop)
	})
	t.Run("evidence recorded for different data", func(t *testing.T) {
		rb := fresh(func(rb *QualityRoutingRollback) {
			rb.Evidence = QualityOverlapEvidence{
				PreviousVersion: current.Version, NextVersion: target.Version,
				BestNextModel: "model-a", BestNextScore: 0.99,
				ShiftAllowed: true, Reason: "overlap_ok",
			}
		})
		_, err := AuthorizeQualityRoutingRollback("org-1", current, target, rollbackHistory(), rb)
		wantReason(t, err, QualityRejectEvidenceMismatch)
	})
}

// A rollback re-binds the route to a previously applied revision, but the
// freshness contract still governs steering: the restored snapshot's scores
// participate only while Fresh(maxAge, now) holds, and the router itself
// refuses any snapshot without provenance (UsableForRouting) — a rollback can
// never resurrect stale or unversioned scores as routing input.
func TestRollbackTargetServePathFreshnessContract(t *testing.T) {
	target := rollbackTarget() // run-v1, measured 48h before gateNow
	rb := gateRollback("org-1", rollbackCurrent(), target)
	_, err := AuthorizeQualityRoutingRollback("org-1", rollbackCurrent(), target, rollbackHistory(), rb)
	require.NoError(t, err)

	// Within the operator window the restored scores steer.
	assert.True(t, target.Fresh(72*time.Hour, gateNow))
	// Beyond it they do not — the caller's freshness gate degrades to the
	// classifier path with reason "stale_snapshot"; the rollback's validity
	// does not exempt the revision from staleness.
	assert.False(t, target.Fresh(24*time.Hour, gateNow), "a rolled-back revision cannot serve stale scores")
	// And a damaged provenance snapshot never steers at any age.
	damaged := &QualitySnapshot{Version: "run-v1", Overall: target.Overall}
	assert.False(t, damaged.UsableForRouting())
}
