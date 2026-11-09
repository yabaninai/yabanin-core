package license

// Paid-module entitlement: a signed, offline-verifiable document that grants
// specific paid modules (owner answer I22: commercial licenses cover
// protection packs and Enterprise modules) to exactly ONE production
// deployment contour (owner answer I23).
//
// Scope semantics (I23), enforced by VerifyPaidModuleEntitlement:
//   - One entitlement names one DeploymentID. Every instance of that
//     production contour — HA replicas, the disaster-recovery contour and
//     test environments — presents the SAME DeploymentID, so one license
//     covers all of them; replica scaling and failover do not consume
//     additional licenses.
//   - An independent production contour carries a different DeploymentID and
//     therefore cannot verify against this entitlement: independent
//     production deployments are licensed and paid for separately.
//
// Term semantics (owner answers I24/I25, N11-P05-T03):
//   - The RUN right is perpetual for the signed module list on the signed
//     deployment contour: a paid production version keeps operating after
//     the maintenance term ends. Verification therefore performs NO
//     time-based rejection at all — there is deliberately no clock input —
//     so a maintenance date can never disable previously-paid protection,
//     internal-loop or history modules.
//   - MaintenanceEnd only separates the paid UPDATE/SUPPORT term from the
//     run right: after it, new versions, pack updates and support services
//     require renewal (see maintenance.go for the offline predicates).
//   - Critical security fixes for a still-supported purchased release line
//     are an I25 exception to renewal-only updates: ReleaseLines carries the
//     vendor-announced support windows so entitlement to those fixes is
//     verifiable offline and independent of MaintenanceEnd.
//   - TrialEnd (optional, additive in "2") is the explicit signed state of
//     an evaluation term, reported by TrialActiveAt. A trial is always
//     finite and strictly observational: it never extends, bounds or
//     substitutes the perpetual run right, the maintenance/update term or
//     the I25 critical-fix exception, and its end changes nothing about
//     previously-paid modules (I24).
//   - The activation-token GracePeriod (license.go, 7d clock-drift allowance
//     for activation state) is a DIFFERENT document with a DIFFERENT clock.
//     It is never consulted on this path and must never be used as a
//     substitute for the I24 continued-operation semantics.
//
// Boundary posture (unchanged from EntitlementSource): the document and its
// verification need no external server — signature checks are pure Ed25519.
// This type is the offline data layer a future enterprise-side
// EntitlementSource implementation would serve; core consumers keep a nil
// source and no core code derives any default grant from these types. Module
// identifiers are a vendor-issued list (e.g. "internal-loop" per I53,
// "media-persistence" per I62, conditional original-text retention per I63);
// the core defines no module catalog and grants nothing by default.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ModuleEntitlementVersion is the only entitlement document format this core
// understands. VerifyPaidModuleEntitlement fails closed on any other value
// so a future format change can never be silently half-accepted.
//
// Version history: "1" (N11-P05-T02) carried a hard document Expiry, which
// contradicts I24 — a paid version must keep running after its maintenance
// term ends. "2" (N11-P05-T03) replaces Expiry with MaintenanceEnd (update/
// support term only) plus ReleaseLines (I25 critical-fix windows). v1
// documents lack the maintenance split and are rejected by the version pin
// instead of being misread.
const ModuleEntitlementVersion = "2"

// ReleaseLine is a vendor-announced supported release line (I25): while the
// line is within SupportEnd, critical security fixes for the purchased
// release remain available without maintenance renewal when CriticalFixes is
// set. New features, protection-pack updates and support services are NOT
// covered by this exception (they follow MaintenanceEnd / the entitlement
// module list instead).
type ReleaseLine struct {
	// Line is the vendor-issued release-line identifier (exact string).
	Line string `json:"line"`
	// SupportEnd is the announced end of the line's support lifetime.
	SupportEnd time.Time `json:"se"`
	// CriticalFixes marks the I25 exception: critical security fixes ship
	// for this line without maintenance renewal while it is supported.
	CriticalFixes bool `json:"cf"`
}

// PaidModuleEntitlement is the vendor-signed grant of paid modules to one
// production deployment. The zero value grants nothing.
type PaidModuleEntitlement struct {
	Version string `json:"v"`
	// CustomerID is the paying customer the entitlement was issued to.
	CustomerID string `json:"c"`
	// DeploymentID is the licensed production contour identity (I23). All
	// HA/DR/test instances of that contour share it; an independent
	// production contour has its own identity and needs its own license.
	DeploymentID string `json:"d"`
	// Modules lists the granted paid-module identifiers (exact strings,
	// vendor-issued vocabulary). Membership is all a consumer may rely on;
	// the RUN right for these modules is perpetual (I24) — a module in this
	// list keeps working after MaintenanceEnd.
	Modules  []string  `json:"m"`
	IssuedAt time.Time `json:"i"`
	// MaintenanceEnd is the end of the paid update/support term (I24). It
	// is NOT a run-right bound: the paid version continues to operate after
	// it; new versions, pack updates and support require renewal.
	MaintenanceEnd time.Time `json:"me"`
	// TrialEnd is the OPTIONAL explicit end of a signed evaluation term
	// (zero = no trial exists — a definitive no-trial state, fail-closed).
	// It is observational metadata only (TrialActiveAt): a trial never
	// grants modules beyond the signed list, never bounds or extends the
	// perpetual run right (I24), the update/support term or the I25
	// critical-fix exception, and its termination is an explicit signed
	// state change, never a silent expiry of paid functionality.
	TrialEnd time.Time `json:"te,omitempty"`
	// ReleaseLines carries the vendor-announced supported release lines
	// (I25): the offline source for critical-security-fix eligibility.
	ReleaseLines []ReleaseLine `json:"rl,omitempty"`
	// Nonce makes each issued document unique for issuer-side audit and
	// revocation bookkeeping.
	Nonce string `json:"n"`
	// Signature is transport metadata, never meaningful inside a decoded
	// payload; it is always nil on a value returned by
	// VerifyPaidModuleEntitlement.
	Signature []byte `json:"sig,omitempty"`
}

// VerifyPaidModuleEntitlement verifies a module-entitlement token fully
// offline: Ed25519 signature against pub (normally VendorPublicKey), format
// version, structural validity and the I23 deployment binding. It returns
// the granted modules via the decoded document and fails closed on every
// mismatch; every error return carries the zero entitlement so a rejected
// document never exposes its grants. No external server is contacted.
//
// Deliberately ABSENT by design (I24, N11-P05-T03): any clock input. The run
// right for the signed module list is perpetual, so no time comparison can
// reject the document — a maintenance date can never disable previously-paid
// modules, and the activation-token GracePeriod can never leak into this
// decision (renewal/rollback and clock-skew policy stay with the explicit
// time predicates in maintenance.go and with future format revisions).
func VerifyPaidModuleEntitlement(token string, pub ed25519.PublicKey, runningDeploymentID string) (PaidModuleEntitlement, error) {
	var ent PaidModuleEntitlement
	if len(pub) != ed25519.PublicKeySize {
		return ent, fmt.Errorf("verify module entitlement: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		return ent, fmt.Errorf("verify module entitlement: invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return ent, fmt.Errorf("verify module entitlement: decode payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return ent, fmt.Errorf("verify module entitlement: decode sig: %w", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ent, fmt.Errorf("verify module entitlement: invalid entitlement signature")
	}
	if err := json.Unmarshal(payload, &ent); err != nil {
		// The stdlib may have partially populated ent before failing
		// (UnmarshalTypeError keeps already-decoded fields); a rejected
		// document must never expose grant metadata (review finding 1).
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: parse entitlement: %w", err)
	}
	// The signature over the payload already proves integrity; an embedded
	// self-reference is meaningless and is dropped (see Signature doc).
	ent.Signature = nil

	if ent.Version != ModuleEntitlementVersion {
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: unsupported version %q", ent.Version)
	}
	if ent.CustomerID == "" {
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: entitlement names no customer")
	}
	if ent.DeploymentID == "" {
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: entitlement names no deployment")
	}
	if runningDeploymentID == "" {
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: running deployment identity is not configured")
	}
	// I23 binding: the entitlement covers exactly the named production
	// contour. An independent production contour (different identity) can
	// never pass here and is not covered by this license.
	if ent.DeploymentID != runningDeploymentID {
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: entitlement is licensed for deployment %q, running deployment is %q", ent.DeploymentID, runningDeploymentID)
	}
	if len(ent.Modules) == 0 {
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: entitlement grants no modules")
	}
	for i, m := range ent.Modules {
		if strings.TrimSpace(m) == "" {
			return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: module[%d] is empty", i)
		}
		if strings.TrimSpace(m) != m {
			return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: module[%d] must not have leading/trailing whitespace", i)
		}
	}
	if ent.Nonce == "" {
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: entitlement has no nonce")
	}
	if ent.IssuedAt.IsZero() {
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: entitlement names no issued time")
	}
	if ent.MaintenanceEnd.IsZero() {
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: entitlement names no maintenance end")
	}
	if !ent.MaintenanceEnd.After(ent.IssuedAt) {
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: maintenance end %s must be after issued %s", ent.MaintenanceEnd.Format(time.RFC3339Nano), ent.IssuedAt.Format(time.RFC3339Nano))
	}
	if !ent.TrialEnd.IsZero() && !ent.TrialEnd.After(ent.IssuedAt) {
		return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: trial end %s must be after issued %s", ent.TrialEnd.Format(time.RFC3339Nano), ent.IssuedAt.Format(time.RFC3339Nano))
	}
	seenLines := make(map[string]bool, len(ent.ReleaseLines))
	for i, rl := range ent.ReleaseLines {
		if rl.Line == "" {
			return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: release line[%d] is empty", i)
		}
		if strings.TrimSpace(rl.Line) != rl.Line {
			return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: release line[%d] must not have leading/trailing whitespace", i)
		}
		if rl.SupportEnd.IsZero() {
			return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: release line[%d] (%s) names no support end", i, rl.Line)
		}
		if seenLines[rl.Line] {
			return PaidModuleEntitlement{}, fmt.Errorf("verify module entitlement: release line %q listed more than once", rl.Line)
		}
		seenLines[rl.Line] = true
	}
	return ent, nil
}

// HasModule reports whether id is exactly one of the granted paid modules.
// A module absent from the signed list has no entitlement — new packs never
// receive rights without an explicit grant (packet negative), before or
// after the maintenance term ends alike.
func (e PaidModuleEntitlement) HasModule(id string) bool {
	for _, m := range e.Modules {
		if m == id {
			return true
		}
	}
	return false
}

// TrialActiveAt reports the explicit state of the optional signed evaluation
// term at now: active through the exact TrialEnd instant (inclusive,
// matching the other time predicates), explicitly ended after it, and never
// active for a document without a trial (zero TrialEnd is a definitive
// no-trial state, not an open-ended one — trial end is always an explicit,
// vendor-signed state, never a silent condition).
//
// The trial is strictly observational: it must never be consulted as an
// enforcement input for the perpetual paid run right (HasModule, I24), the
// renewal-gated update/support right (UpdatesEntitledAt, maintenance.go) or
// the I25 critical-fix exception (CriticalFixEntitledAt) — none of those
// predicates read TrialEnd, and a trial ending never disables previously
// paid modules (pinned by TestPaidModuleEntitlement_TrialExplicitStateIsolation).
func (e PaidModuleEntitlement) TrialActiveAt(now time.Time) bool {
	if e.TrialEnd.IsZero() {
		return false
	}
	return !now.After(e.TrialEnd)
}
