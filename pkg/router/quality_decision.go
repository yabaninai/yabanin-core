package router

import (
	"errors"
	"fmt"
	"time"
)

//
// Owner-approved routing changes over IMPORTED evaluation data (N09-P03-T03).
//
// D2 already pins WHICH snapshot an org is served: the approvals registry
// (pkg/agenteval/results) binds the org to one imported run id, read-only at
// runtime. This file adds the gate for the routing CHANGE itself: an imported
// snapshot may start steering an org's traffic only through an explicit owner
// decision that
//   - is bound to the exact imported revision (snapshot Version) it applies;
//   - carries the D4 overlap evidence, which the gate RECOMPUTES over the
//     exact current/proposed snapshots — a decision recorded for different
//     data cannot be replayed (tampered or stale evidence is corrupted
//     provenance);
//   - explains the evidence (EvidenceSummary) and its limitations
//     (Limitations) in the owner's own words;
//   - acknowledges the basis is an IMPORTED external evaluation — it is never
//     presented as an independent Yabanin verification of model quality.
//
// Fail-closed invariants (card negative criteria):
//   - a corrupted approval or damaged provenance is rejected — the caller
//     keeps serving the current route;
//   - an unknown revision (decision targeting a version the proposed snapshot
//     does not carry) is never applied;
//   - user feedback (or any non-imported basis) can never form a valid
//     decision, so it cannot change production routing — not automatically,
//     and not manually through this gate;
//   - nothing here mutates routing state: authorization is a pure function
//     and application is the caller's explicit, logged act.
//

// QualityBasisImportedEval is the only decision basis this gate accepts: the
// evidence comes from an imported external evaluation run (owner decision
// I64). User feedback, internal dashboards or any other basis are rejected.
const QualityBasisImportedEval = "imported_eval"

// QualityImportDisclaimer is the mandatory disclosure every decision over
// imported scores must acknowledge: the import is third-party input, NOT an
// independent Yabanin verification of model quality.
const QualityImportDisclaimer = "imported external evaluation; not independently verified by Yabanin"

// Stable rejection reasons (for decision headers, logs and diagnosis). Every
// rejection wraps ErrQualityRoutingChangeRejected.
const (
	QualityRejectNoDecision            = "no_decision"
	QualityRejectOrgMismatch           = "org_mismatch"
	QualityRejectApprovalIncomplete    = "approval_incomplete"
	QualityRejectUnknownBasis          = "unknown_basis"
	QualityRejectImportNotAcknowledged = "import_not_acknowledged"
	QualityRejectMissingEvidence       = "missing_evidence_summary"
	QualityRejectMissingLimitations    = "missing_limitations"
	QualityRejectRevisionMismatch      = "revision_mismatch"
	QualityRejectSnapshotUnusable      = "snapshot_unusable"
	QualityRejectDigestMismatch        = "digest_mismatch"
	QualityRejectEvidenceMismatch      = "evidence_mismatch"
	QualityRejectEvidenceHolds         = "evidence_holds"
)

// ErrQualityRoutingChangeRejected wraps every gate refusal. Callers detect it
// with errors.Is and keep serving the current route.
var ErrQualityRoutingChangeRejected = errors.New("quality routing change rejected")

// QualityRoutingRejection explains why the gate refused a routing change.
type QualityRoutingRejection struct {
	Reason  string // one of the QualityReject* codes
	Message string // human-readable cause
}

func (e *QualityRoutingRejection) Error() string {
	return fmt.Sprintf("%s: %s (%s)", ErrQualityRoutingChangeRejected.Error(), e.Message, e.Reason)
}

func (e *QualityRoutingRejection) Unwrap() error { return ErrQualityRoutingChangeRejected }

func reject(reason, format string, args ...any) error {
	return &QualityRoutingRejection{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// QualityRoutingDecision is the owner's recorded decision to change one org's
// production routing to an imported evaluation revision. It is the artifact
// the owner flow produces when accepting a recommendation; the runtime only
// ever validates it (never creates or edits it).
type QualityRoutingDecision struct {
	OrgID          string `json:"org_id"`
	Basis          string `json:"basis"`
	TargetRevision string `json:"target_revision"`

	// TargetDatasetDigest, when recorded, pins the imported dataset content
	// hash the decision was made on. The applied snapshot must carry the same
	// digest; anything else is corrupted provenance. Absent on both sides is
	// absence, not conflict (legacy runs without a dataset hash).
	TargetDatasetDigest string `json:"target_dataset_digest,omitempty"`

	// Evidence is the D4 overlap evidence this decision is grounded in. The
	// gate recomputes it over the exact snapshots and refuses any divergence.
	Evidence QualityOverlapEvidence `json:"evidence"`

	// EvidenceSummary and Limitations are the owner's own explanation: what
	// the evidence shows and what it does not cover. Both are REQUIRED — a
	// decision that cannot explain its evidence and its constraints is not an
	// informed approval.
	EvidenceSummary string `json:"evidence_summary"`
	Limitations     string `json:"limitations"`

	// AcknowledgesImport must be true: the owner records that the basis is
	// QualityImportDisclaimer — imported third-party results, not an
	// independent Yabanin verification.
	AcknowledgesImport bool `json:"acknowledges_import"`

	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
}

// AuthorizeQualityRoutingChange is the fail-closed gate for applying a
// quality-driven routing change: it returns the recomputed overlap evidence
// when the owner decision validly authorizes serving proposed for orgID, and
// a *QualityRoutingRejection (wrapping ErrQualityRoutingChangeRejected) when
// it does not — in which case the caller MUST keep the current route.
//
// current is the snapshot currently applied (nil for first adoption — an
// org's switch from the classifier path to quality routing; that evidence is
// definitionally "no baseline overlap" and must be recorded as such).
//
// A version-to-version shift (current != nil) additionally requires the
// recomputed evidence to ALLOW the shift: an owner decision cannot override a
// hold verdict (regression, insufficient data, profile mismatch), it can only
// act on evidence that itself permits the change.
func AuthorizeQualityRoutingChange(orgID string, current, proposed *QualitySnapshot, dec *QualityRoutingDecision) (QualityOverlapEvidence, error) {
	if dec == nil {
		return QualityOverlapEvidence{}, reject(QualityRejectNoDecision,
			"no owner decision recorded — imported scores never change routing by themselves")
	}
	if orgID == "" || dec.OrgID == "" || dec.OrgID != orgID {
		return QualityOverlapEvidence{}, reject(QualityRejectOrgMismatch,
			"decision is issued for org %q, not %q — a decision never applies across orgs", dec.OrgID, orgID)
	}
	if dec.Basis != QualityBasisImportedEval {
		return QualityOverlapEvidence{}, reject(QualityRejectUnknownBasis,
			"decision basis %q is not %q — user feedback and other non-imported signals never steer routing",
			dec.Basis, QualityBasisImportedEval)
	}
	if !dec.AcknowledgesImport {
		return QualityOverlapEvidence{}, reject(QualityRejectImportNotAcknowledged,
			"decision must acknowledge: %s", QualityImportDisclaimer)
	}
	if dec.ApprovedBy == "" || dec.ApprovedAt.IsZero() {
		return QualityOverlapEvidence{}, reject(QualityRejectApprovalIncomplete,
			"decision without a recorded approver or approval time is not a manual approval")
	}
	if dec.EvidenceSummary == "" {
		return QualityOverlapEvidence{}, reject(QualityRejectMissingEvidence,
			"decision must explain its evidence")
	}
	if dec.Limitations == "" {
		return QualityOverlapEvidence{}, reject(QualityRejectMissingLimitations,
			"decision must state its limitations")
	}
	if proposed == nil {
		return QualityOverlapEvidence{}, reject(QualityRejectSnapshotUnusable,
			"no proposed snapshot to apply")
	}
	if dec.TargetRevision == "" || proposed.Version == "" || proposed.Version != dec.TargetRevision {
		return QualityOverlapEvidence{}, reject(QualityRejectRevisionMismatch,
			"decision targets revision %q, proposed snapshot is %q — an unknown revision is never applied",
			dec.TargetRevision, proposed.Version)
	}
	if proposed.CreatedAt.IsZero() {
		return QualityOverlapEvidence{}, reject(QualityRejectSnapshotUnusable,
			"proposed snapshot %q has no creation time — provenance incomplete", proposed.Version)
	}
	if dec.TargetDatasetDigest != "" && proposed.DatasetDigest != dec.TargetDatasetDigest {
		return QualityOverlapEvidence{}, reject(QualityRejectDigestMismatch,
			"proposed snapshot dataset digest %q does not match the decision-pinned %q — corrupted provenance",
			proposed.DatasetDigest, dec.TargetDatasetDigest)
	}

	// The recorded evidence must be the truth for these exact revisions.
	// CompareQualitySnapshots is deterministic (sorted iteration, alphabetical
	// tie-break), so recomputation over unchanged snapshots is bit-identical;
	// any divergence means the decision was made for different data or was
	// tampered with afterwards.
	ev := CompareQualitySnapshots(current, proposed, 0)
	if !sameEvidence(ev, dec.Evidence) {
		return QualityOverlapEvidence{}, reject(QualityRejectEvidenceMismatch,
			"recorded evidence (next=%q allowed=%v reason=%q) does not match the revisions (recomputed next=%q allowed=%v reason=%q)",
			dec.Evidence.NextVersion, dec.Evidence.ShiftAllowed, dec.Evidence.Reason,
			ev.NextVersion, ev.ShiftAllowed, ev.Reason)
	}
	if current != nil && !ev.ShiftAllowed {
		return QualityOverlapEvidence{}, reject(QualityRejectEvidenceHolds,
			"overlap evidence holds the shift (%s); a decision cannot act against a hold", ev.Reason)
	}
	// First adoption with faithfully recorded "hold-shaped" evidence
	// (no_baseline_overlap, or insufficient_data for an under-sampled run) is
	// valid: the decision honestly documents the absence of a baseline, the
	// snapshot stays revision-bound, and the serve-time QualityMinSamples
	// floor governs whether any model actually takes traffic.
	return ev, nil
}

// sameEvidence reports whether two evidence records are identical. Floats are
// compared exactly: both sides come from the same deterministic computation
// over the same snapshots, and encoding/json round-trips float64 values
// bit-exactly, so a decision that survived serialization still matches.
func sameEvidence(a, b QualityOverlapEvidence) bool {
	if a.PreviousVersion != b.PreviousVersion || a.NextVersion != b.NextVersion ||
		a.BestNextModel != b.BestNextModel || a.BestNextScore != b.BestNextScore ||
		a.Regression != b.Regression || a.ShiftAllowed != b.ShiftAllowed ||
		a.Reason != b.Reason || len(a.Compared) != len(b.Compared) {
		return false
	}
	for i := range a.Compared {
		if a.Compared[i] != b.Compared[i] {
			return false
		}
	}
	return true
}
