package router

import (
	"time"
)

//
// Owner-approved ROLLBACK of quality routing over IMPORTED evaluation data
// (N09-P03-T04). The forward gate (AuthorizeQualityRoutingChange, T03) starts
// steering an org by a NEW imported revision; this file is the way back: an
// owner decision returns the org's production routing from the currently
// served imported revision to a specific PREVIOUSLY APPLIED imported
// revision. I64 forbids a built-in runner, an LLM judge or built-in model
// comparisons — a rollback, like every quality-routing change, rests only on
// imported external results and a manual owner decision.
//
// What distinguishes a rollback from a forward change:
//   - the target must be a revision this org ALREADY APPLIED (history
//     provided by the caller from the owner's application log). An unknown
//     version — anything the org never served — is rejected
//     (rollback_target_not_applied); a decision cannot invent a past.
//   - the recomputed D4 overlap evidence is RECORDED but NOT required to
//     allow the shift. A rollback is a safety action: it typically happens
//     exactly when the evidence holds (the newer revision regressed), and an
//     owner decision cannot be forced to re-prove "improvement" in order to
//     undo. The evidence must still be the honest recomputation for these
//     exact revisions — tampered or foreign evidence is corrupted provenance.
//
// Fail-closed invariants (card negative criteria — unchanged from T03):
//   - no decision → no change (imported scores never move routing by
//     themselves);
//   - corrupted provenance (digest mismatch, zero CreatedAt, tampered
//     evidence) → rejected, the caller keeps serving the current route;
//   - an unknown version (never applied, or a revision the target snapshot
//     does not carry) → never applied;
//   - user feedback (or any non-imported basis) → never a valid decision;
//   - nothing here mutates routing state: authorization is a pure function
//     and application is the caller's explicit, logged act.
//
// Serve-time note: authorization binds the route to the target revision, but
// the snapshot freshness contract still governs steering. A rolled-back-to
// revision older than the operator's freshness window degrades to the
// unchanged classifier path with reason "stale_snapshot" (QualitySnapshot.Fresh);
// a rollback can never resurrect stale scores as routing input. Rolling back
// to NO revision (leaving quality routing entirely) is not a decision this
// gate carries: removing the org's approval row in the owner registry is the
// documented path back to the classifier routing mode.
//

// Additional stable rejection reasons specific to the rollback gate. Every
// rejection wraps ErrQualityRoutingChangeRejected like the forward gate's.
const (
	QualityRejectRollbackNoCurrent     = "rollback_no_current_route"
	QualityRejectRollbackNotApplied    = "rollback_target_not_applied"
	QualityRejectRollbackNoop          = "rollback_target_is_current"
	QualityRejectRollbackReasonMissing = "missing_rollback_reason"
)

// QualityRoutingRollback is the owner's recorded decision to return one
// org's production routing from the currently served imported revision back
// to a specific previously applied imported revision. It is the artifact the
// owner flow produces when executing a rollback; the runtime only ever
// validates it (never creates or edits it).
type QualityRoutingRollback struct {
	OrgID          string `json:"org_id"`
	Basis          string `json:"basis"`
	TargetRevision string `json:"target_revision"`

	// TargetDatasetDigest, when recorded, pins the imported dataset content
	// hash the rollback targets. The applied target snapshot must carry the
	// same digest; anything else is corrupted provenance. Absent on both
	// sides is absence, not conflict (legacy runs without a dataset hash).
	TargetDatasetDigest string `json:"target_dataset_digest,omitempty"`

	// RollbackReason is the owner's own words for WHY the route returns to
	// the earlier revision. A rollback without a stated reason is not an
	// informed decision.
	RollbackReason string `json:"rollback_reason"`

	// Evidence is the D4 overlap evidence recomputed over the exact
	// current→target revisions and recorded for the audit trail. Unlike the
	// forward gate, ShiftAllowed is NOT required — but the recorded evidence
	// must still match the recomputation exactly.
	Evidence QualityOverlapEvidence `json:"evidence"`

	// EvidenceSummary and Limitations are the owner's own explanation of
	// what the evidence shows and what it does not cover. Both are REQUIRED.
	EvidenceSummary string `json:"evidence_summary"`
	Limitations     string `json:"limitations"`

	// AcknowledgesImport must be true: the rollback still acts over the
	// QualityImportDisclaimer — imported third-party results, not an
	// independent Yabanin verification.
	AcknowledgesImport bool `json:"acknowledges_import"`

	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
}

// AuthorizeQualityRoutingRollback is the fail-closed gate for rolling one
// org's quality-driven routing back to a previously applied imported
// revision. It returns the recomputed overlap evidence when the owner
// decision validly authorizes serving target for orgID in place of current,
// and a *QualityRoutingRejection (wrapping
// ErrQualityRoutingChangeRejected) when it does not — in which case the
// caller MUST keep the current route.
//
// current is the snapshot currently applied (there is nothing to roll back
// from without one). target is the previously applied revision being
// restored. appliedRevisions lists the revisions this org has applied
// (including the current one); it comes from the owner's application log,
// never from the decision itself.
//
// The recomputed evidence is returned with the authorization so the caller
// can log exactly what the rollback acted on.
func AuthorizeQualityRoutingRollback(orgID string, current, target *QualitySnapshot, appliedRevisions []string, rb *QualityRoutingRollback) (QualityOverlapEvidence, error) {
	if rb == nil {
		return QualityOverlapEvidence{}, reject(QualityRejectNoDecision,
			"no owner decision recorded — imported scores never change routing by themselves")
	}
	if orgID == "" || rb.OrgID == "" || rb.OrgID != orgID {
		return QualityOverlapEvidence{}, reject(QualityRejectOrgMismatch,
			"rollback is issued for org %q, not %q — a decision never applies across orgs", rb.OrgID, orgID)
	}
	if current == nil {
		return QualityOverlapEvidence{}, reject(QualityRejectRollbackNoCurrent,
			"no currently applied quality route for org %q — nothing to roll back from", orgID)
	}
	if rb.Basis != QualityBasisImportedEval {
		return QualityOverlapEvidence{}, reject(QualityRejectUnknownBasis,
			"rollback basis %q is not %q — user feedback and other non-imported signals never steer routing",
			rb.Basis, QualityBasisImportedEval)
	}
	if !rb.AcknowledgesImport {
		return QualityOverlapEvidence{}, reject(QualityRejectImportNotAcknowledged,
			"rollback must acknowledge: %s", QualityImportDisclaimer)
	}
	if rb.ApprovedBy == "" || rb.ApprovedAt.IsZero() {
		return QualityOverlapEvidence{}, reject(QualityRejectApprovalIncomplete,
			"rollback without a recorded approver or approval time is not a manual approval")
	}
	if rb.RollbackReason == "" {
		return QualityOverlapEvidence{}, reject(QualityRejectRollbackReasonMissing,
			"rollback must state why the route returns to the earlier revision")
	}
	if rb.EvidenceSummary == "" {
		return QualityOverlapEvidence{}, reject(QualityRejectMissingEvidence,
			"rollback must explain its evidence")
	}
	if rb.Limitations == "" {
		return QualityOverlapEvidence{}, reject(QualityRejectMissingLimitations,
			"rollback must state its limitations")
	}
	if target == nil {
		return QualityOverlapEvidence{}, reject(QualityRejectSnapshotUnusable,
			"no target snapshot to roll back to")
	}
	if rb.TargetRevision == "" || target.Version == "" || target.Version != rb.TargetRevision {
		return QualityOverlapEvidence{}, reject(QualityRejectRevisionMismatch,
			"rollback targets revision %q, target snapshot is %q — an unknown revision is never applied",
			rb.TargetRevision, target.Version)
	}
	if target.CreatedAt.IsZero() {
		return QualityOverlapEvidence{}, reject(QualityRejectSnapshotUnusable,
			"target snapshot %q has no creation time — provenance incomplete", target.Version)
	}
	if rb.TargetDatasetDigest != "" && target.DatasetDigest != rb.TargetDatasetDigest {
		return QualityOverlapEvidence{}, reject(QualityRejectDigestMismatch,
			"target snapshot dataset digest %q does not match the rollback-pinned %q — corrupted provenance",
			target.DatasetDigest, rb.TargetDatasetDigest)
	}
	applied := false
	for _, v := range appliedRevisions {
		if v == target.Version {
			applied = true
			break
		}
	}
	if !applied {
		return QualityOverlapEvidence{}, reject(QualityRejectRollbackNotApplied,
			"target revision %q is not in org %q's applied history — a rollback can only restore a revision the org served before",
			target.Version, orgID)
	}
	if target.Version == current.Version {
		return QualityOverlapEvidence{}, reject(QualityRejectRollbackNoop,
			"target revision %q is the currently applied route — nothing to roll back", target.Version)
	}

	// The recorded evidence must be the truth for these exact revisions
	// (honest audit trail). CompareQualitySnapshots is deterministic, so
	// recomputation over unchanged snapshots is bit-identical; divergence
	// means the rollback was recorded for different data or tampered with.
	// Unlike the forward gate a HOLD verdict does not refuse the rollback —
	// a rollback is precisely the response to a route that must be undone.
	ev := CompareQualitySnapshots(current, target, 0)
	if !sameEvidence(ev, rb.Evidence) {
		return QualityOverlapEvidence{}, reject(QualityRejectEvidenceMismatch,
			"recorded evidence (next=%q allowed=%v reason=%q) does not match the revisions (recomputed next=%q allowed=%v reason=%q)",
			rb.Evidence.NextVersion, rb.Evidence.ShiftAllowed, rb.Evidence.Reason,
			ev.NextVersion, ev.ShiftAllowed, ev.Reason)
	}
	return ev, nil
}
