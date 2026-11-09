package license

// Entitlement upgrade/downgrade transitions (E01-P05 card W05-C01,
// batch C).
//
// A transition is ONE in-place change to an ALREADY VERIFIED v2
// PaidModuleEntitlement: modules added or removed, vendor-announced
// release lines added or dropped (I25). The result is the NEXT UNSIGNED
// document; signing is performed outside Core with the issuer's existing
// vendor key — the transition API itself takes NO
// key material, so no re-issuance path for the signing secret exists here
// (the "secret is not re-issued" law of the card; a key rotation would be a
// vendor-side format event, not an entitlement transition).
//
// Invariants enforced by NextEntitlement, all fail closed:
//
//   - Identity stability (I23): CustomerID and DeploymentID are carried over
//     from the current document and the transition vocabulary cannot express
//     a change — a different production contour is a different license, a
//     different customer is a new sale. IsEntitlementSuccessor refuses any
//     hand-built "successor" that breaks identity.
//   - Monotone re-issue: the next document is issued strictly later than the
//     current one and under a fresh nonce, so a superseded (stale) base can
//     never produce a successor and a repeated presentation of an already
//     consumed token is refused (the replay arm of W05-C02's battery).
//   - Renewal gating (I24): an in-place transition is a document update, and
//     updates belong to the paid maintenance term — NextEntitlement refuses
//     unless the term is STRICTLY running at the transition instant. The
//     already-paid version keeps its perpetual run right with the OLD
//     document (maintenance.go); buying changes after the term ends is a
//     renewal (a new sale), not a transition. The exact-MaintenanceEnd
//     instant is refused as well: UpdatesEntitledAt is inclusive there, but
//     the re-issued document would need MaintenanceEnd strictly after its
//     own IssuedAt and the preserved term cannot satisfy that — the only
//     expressible rule is strictly-before.
//   - Term and trial preservation: MaintenanceEnd is carried over unchanged
//     (extending it is renewal, out of the transition vocabulary); TrialEnd
//     carries over while still live and is otherwise cleared — an observably
//     ended trial is re-recorded as the definitive no-trial state (the
//     explicit signed state change of module_entitlement.go), never extended.
//
// Determinism: every function is pure in its arguments; there is no wall
// clock, randomness or environment read. `now` is injectable everywhere, so
// proofs and consumers evaluate fixed instants.

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// EntitlementTransition describes one in-place change to a verified v2
// entitlement. The zero value is the identity transition and is refused:
// a re-issue must change the document (fresh IssuedAt/nonce alone do not
// justify a new signed artifact). All slices are applied in order; every
// named module or release line must not already be present (for adds) or
// absent (for removes) — a transition is exact, never drift.
type EntitlementTransition struct {
	// AddModules names paid modules to grant additionally (exact strings,
	// vendor-issued vocabulary; none may already be granted).
	AddModules []string
	// RemoveModules names granted modules to drop (none may be absent;
	// removing the last module is refused — termination is not a
	// transition, the old document simply keeps running).
	RemoveModules []string
	// AddReleaseLines announces additional supported release lines (I25);
	// no line id may already be present and every SupportEnd must be set.
	AddReleaseLines []ReleaseLine
	// DropReleaseLines removes release lines by exact line id (none may be
	// absent). Dropping a line ends its critical-fix exception window from
	// the NEXT document on; the signed window of the CURRENT document is
	// untouched (I24 run-right semantics keep verifying offline).
	DropReleaseLines []string
}

// NextEntitlement applies transition t to the VERIFIED current entitlement
// and returns the next UNSIGNED document for external signing at the same
// instant. now is the transition
// instant (also the next IssuedAt) and must be strictly after
// current.IssuedAt and strictly before current.MaintenanceEnd; nextNonce is
// the fresh issuer-side nonce (audit/revocation bookkeeping) and must differ
// from current.Nonce. The current document is not modified.
func NextEntitlement(current PaidModuleEntitlement, t EntitlementTransition, now time.Time, nextNonce string) (PaidModuleEntitlement, error) {
	var next PaidModuleEntitlement
	if current.Version != ModuleEntitlementVersion {
		return next, fmt.Errorf("entitlement transition: predecessor is not a v%s document — verify the current document first (downgrade arms of the battery pin this fail-closed)", ModuleEntitlementVersion)
	}
	if current.CustomerID == "" || current.DeploymentID == "" {
		return next, fmt.Errorf("entitlement transition: predecessor names no customer or deployment (verify the current document first)")
	}
	if current.IssuedAt.IsZero() {
		return next, fmt.Errorf("entitlement transition: predecessor names no issued time (verify the current document first)")
	}
	if current.MaintenanceEnd.IsZero() {
		return next, fmt.Errorf("entitlement transition: predecessor names no maintenance end (verify the current document first)")
	}
	if now.IsZero() {
		return next, fmt.Errorf("entitlement transition: transition instant is required")
	}
	// Monotone re-issue: the successor is strictly newer. Equality is the
	// same-instant replay of the original issuance and is refused alike.
	if !now.After(current.IssuedAt) {
		return next, fmt.Errorf("entitlement transition: stale predecessor (issued %s): transition instant %s is not strictly later", current.IssuedAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	}
	// I24 renewal gating, strict form (see the file comment for the exact
	// MaintenanceEnd instant).
	if !now.Before(current.MaintenanceEnd) {
		return next, fmt.Errorf("entitlement transition: maintenance term is not strictly running at %s (term ends %s) — renewal required, not a transition", now.Format(time.RFC3339Nano), current.MaintenanceEnd.Format(time.RFC3339Nano))
	}
	if nextNonce == "" {
		return next, fmt.Errorf("entitlement transition: nonce is required")
	}
	if nextNonce == current.Nonce {
		return next, fmt.Errorf("entitlement transition: nonce must change between re-issues")
	}
	if len(t.AddModules) == 0 && len(t.RemoveModules) == 0 && len(t.AddReleaseLines) == 0 && len(t.DropReleaseLines) == 0 {
		return next, fmt.Errorf("entitlement transition: empty transition (a re-issue must change the document)")
	}

	// Modules: exact set arithmetic against the ORIGINAL granted list
	// (order-stable: current order preserved, adds appended in transition
	// order). Adds must not collide with the original grants — nor removes
	// with its absences — so a transition naming the same module on both
	// sides is refused as inexact instead of silently netting to no-op.
	granted := make(map[string]bool, len(current.Modules))
	for _, m := range current.Modules {
		granted[m] = true
	}
	for i, m := range t.AddModules {
		if strings.TrimSpace(m) == "" {
			return PaidModuleEntitlement{}, fmt.Errorf("entitlement transition: add module[%d] is empty", i)
		}
		if strings.TrimSpace(m) != m {
			return PaidModuleEntitlement{}, fmt.Errorf("entitlement transition: add module[%d] must not have leading/trailing whitespace", i)
		}
		if granted[m] {
			return PaidModuleEntitlement{}, fmt.Errorf("entitlement transition: add module %q is already granted", m)
		}
	}
	for _, m := range t.RemoveModules {
		if !granted[m] {
			return PaidModuleEntitlement{}, fmt.Errorf("entitlement transition: remove module %q is not granted", m)
		}
	}
	next.Modules = make([]string, 0, len(current.Modules)+len(t.AddModules))
	for _, m := range current.Modules {
		if !slices.Contains(t.RemoveModules, m) {
			next.Modules = append(next.Modules, m)
		}
	}
	next.Modules = append(next.Modules, t.AddModules...)
	if len(next.Modules) == 0 {
		return PaidModuleEntitlement{}, fmt.Errorf("entitlement transition: removal leaves no modules — termination is not a transition (the current document keeps running)")
	}

	// Release lines (I25): same exactness — no duplicate ids, no unknown
	// drops, SupportEnd required on adds.
	lines := make(map[string]bool, len(current.ReleaseLines))
	for _, rl := range current.ReleaseLines {
		lines[rl.Line] = true
	}
	for i, rl := range t.AddReleaseLines {
		if rl.Line == "" {
			return PaidModuleEntitlement{}, fmt.Errorf("entitlement transition: add release line[%d] is empty", i)
		}
		if strings.TrimSpace(rl.Line) != rl.Line {
			return PaidModuleEntitlement{}, fmt.Errorf("entitlement transition: add release line[%d] must not have leading/trailing whitespace", i)
		}
		if rl.SupportEnd.IsZero() {
			return PaidModuleEntitlement{}, fmt.Errorf("entitlement transition: add release line[%d] (%s) names no support end", i, rl.Line)
		}
		if lines[rl.Line] {
			return PaidModuleEntitlement{}, fmt.Errorf("entitlement transition: add release line %q is already present", rl.Line)
		}
	}
	for _, id := range t.DropReleaseLines {
		if !lines[id] {
			return PaidModuleEntitlement{}, fmt.Errorf("entitlement transition: drop release line %q is not present", id)
		}
	}
	next.ReleaseLines = make([]ReleaseLine, 0, len(current.ReleaseLines)+len(t.AddReleaseLines))
	for _, rl := range current.ReleaseLines {
		if !slices.Contains(t.DropReleaseLines, rl.Line) {
			next.ReleaseLines = append(next.ReleaseLines, rl)
		}
	}
	for _, rl := range t.AddReleaseLines {
		normalized := rl
		normalized.SupportEnd = rl.SupportEnd.UTC()
		next.ReleaseLines = append(next.ReleaseLines, normalized)
	}
	if len(next.ReleaseLines) == 0 {
		next.ReleaseLines = nil
	}

	// Identity and term preservation (see the file comment).
	next.Version = ModuleEntitlementVersion
	next.CustomerID = current.CustomerID
	next.DeploymentID = current.DeploymentID
	next.MaintenanceEnd = current.MaintenanceEnd.UTC()
	// A still-live trial carries over verbatim; an observably ended trial
	// is re-recorded as the definitive no-trial state (zero), never
	// extended. TrialEnd in (now, ...) keeps the issue-time invariant
	// TrialEnd > IssuedAt satisfied for the successor.
	switch {
	case current.TrialEnd.IsZero():
		next.TrialEnd = time.Time{}
	case current.TrialEnd.After(now):
		next.TrialEnd = current.TrialEnd.UTC()
	default:
		next.TrialEnd = time.Time{}
	}
	next.IssuedAt = now.UTC()
	next.Nonce = nextNonce
	next.Signature = nil
	return next, nil
}

// IsEntitlementSuccessor reports whether next is a legal in-place successor
// of prev on the SAME licensed contour: same format version, same customer,
// same deployment (I23), issued STRICTLY later under a DIFFERENT nonce. A
// consumer holding prev uses this to refuse stale presentations — a replay
// of prev itself, an older document or a same-instant re-issue all fail.
// Structural validity of either document is VerifyPaidModuleEntitlement's
// job; this check is purely about succession order and identity.
func IsEntitlementSuccessor(prev, next PaidModuleEntitlement) error {
	if prev.CustomerID == "" || prev.DeploymentID == "" {
		return fmt.Errorf("entitlement successor: predecessor names no customer or deployment (verify it first)")
	}
	if next.Version != prev.Version {
		return fmt.Errorf("entitlement successor: format version changed (%q -> %q)", prev.Version, next.Version)
	}
	if next.CustomerID != prev.CustomerID {
		return fmt.Errorf("entitlement successor: customer changed (%q -> %q)", prev.CustomerID, next.CustomerID)
	}
	if next.DeploymentID != prev.DeploymentID {
		return fmt.Errorf("entitlement successor: deployment changed: %q -> %q — an independent contour is a different license, not a successor", prev.DeploymentID, next.DeploymentID)
	}
	if !next.IssuedAt.After(prev.IssuedAt) {
		return fmt.Errorf("entitlement successor: stale presentation (prev issued %s, presented issued %s) — a successor must be strictly newer", prev.IssuedAt.Format(time.RFC3339Nano), next.IssuedAt.Format(time.RFC3339Nano))
	}
	if next.Nonce == prev.Nonce {
		return fmt.Errorf("entitlement successor: nonce did not change between re-issues")
	}
	return nil
}
