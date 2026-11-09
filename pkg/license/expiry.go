// Expiry machine (E01-P05 card W04-C01, batch B).
//
// One place answers the packet expiry law: «истечение НЕ открывает
// запрещённых действий и НЕ блокирует экспорт данных/core» — expiry never
// OPENS a forbidden action and never BLOCKS data export or core operation.
//
// Two planes, never conflated (maintenance.go):
//
//   - the ACTIVATION plane (Claims/State/StateFromClaims, license.go:66/:80):
//     the 7-day GracePeriod clock-drift allowance lives HERE and only here.
//     ExpiryPostureAt is its injectable-clock form — StateFromClaims reads
//     the wall clock, proofs and consumers that must evaluate a fixed or
//     future instant use ExpiryPostureAt.
//
//   - the ENTITLEMENT plane (PaidModuleEntitlement + maintenance.go gates):
//     I24/I25 semantics — perpetual run right, renewal-gated updates, the
//     critical-fix exception. The machine DELEGATES to the maintenance
//     predicates; it never re-derives them, so the two can never diverge.
//
// The law is encoded by construction:
//
//   - CoreAllowed and DataExportAllowed are constant true in every posture
//     the constructors return — expiry may degrade enterprise features, it
//     may never take the deployment's core or its data away.
//   - EnterpriseAllowed fails closed at every boundary: it is exactly the
//     activation plane's Active (now strictly before ExpiresAt+GracePeriod)
//     and is monotone non-increasing in now (pinned adversarially in
//     expiry_adversarial_test.go, W04-C03).
//
// Boundary semantics (total partition — no dead zone, fail closed):
//
//   - PhaseActive covers (-∞, ExpiresAt]: at the exact ExpiresAt instant the
//     term is still running (inclusive expiry, the strict-After convention
//     of the whole package).
//   - PhaseGrace covers (ExpiresAt, ExpiresAt+GracePeriod): the 7-day
//     clock-drift allowance, both bounds strict.
//   - PhaseHardExpired covers [ExpiresAt+GracePeriod, +∞). At the exact
//     grace-end instant StateFromClaims reports all three booleans false
//     (the known dead-zone instant of license.go:83–88 — Active is strict
//     Before, HardExpired is strict After). The machine totalizes that
//     instant as HARD-EXPIRED: the ambiguous instant fails closed, which
//     also makes EnterpriseAllowed exactly (Phase != PhaseHardExpired).
//
// The zero ExpiresAt (no activation token exists at all — the feature-dark
// contour) hard-expires: enterprise closed, core and export still allowed.
package license

import "time"

// ExpiryPhase is the activation timeline partition at some instant.
type ExpiryPhase string

const (
	// PhaseActive is the running term: through the exact ExpiresAt instant.
	PhaseActive ExpiryPhase = "active"
	// PhaseGrace is past ExpiresAt but within the 7-day clock-drift
	// allowance, up to (exclusive) the grace-end instant.
	PhaseGrace ExpiryPhase = "grace"
	// PhaseHardExpired is past grace: degraded mode, enterprise closed.
	PhaseHardExpired ExpiryPhase = "hard-expired"
)

// GraceEnd returns the first HARD-EXPIRED instant for an activation term
// ending at expiresAt: ExpiresAt+GracePeriod (the fail-closed totalization
// of StateFromClaims's dead-zone instant — see the boundary semantics).
func GraceEnd(expiresAt time.Time) time.Time {
	return expiresAt.Add(GracePeriod)
}

// ExpiryPhaseAt partitions the activation timeline at now. Total and
// monotone in now: every instant belongs to exactly one phase and later
// instants never move backwards to an earlier phase.
func ExpiryPhaseAt(expiresAt, now time.Time) ExpiryPhase {
	switch {
	case !now.After(expiresAt):
		return PhaseActive
	case now.Before(GraceEnd(expiresAt)):
		return PhaseGrace
	default:
		return PhaseHardExpired
	}
}

// ExpiryPosture is the packet-law answer for the activation plane at one
// instant. Treat the fields as read-only; the only constructors are
// ExpiryPostureAt and ExpiryPostureFromState, and they always return
// CoreAllowed=true and DataExportAllowed=true — that constancy IS the law.
type ExpiryPosture struct {
	// Phase is the timeline partition at the evaluated instant.
	Phase ExpiryPhase
	// EnterpriseAllowed reports whether enterprise (paid-feature) gating
	// may stay open. Exactly the activation plane's Active: false from the
	// exact grace-end instant (fail closed), never re-opened by a later
	// instant.
	EnterpriseAllowed bool
	// CoreAllowed reports whether core operation is allowed. ALWAYS true:
	// expiry never blocks the core of a deployment.
	CoreAllowed bool
	// DataExportAllowed reports whether data export is allowed. ALWAYS
	// true: a deployment can always take its data out, expired or not.
	DataExportAllowed bool
	// ExpiresAt mirrors the term end (diagnostics; the zero time means no
	// activation document exists — feature-dark, hard-expired posture).
	ExpiresAt time.Time
}

// ExpiryPostureAt is the injectable-clock posture: the evaluation instant is
// explicit, so fixed past/present/future proofs and consumers never depend
// on the wall clock.
func ExpiryPostureAt(expiresAt, now time.Time) ExpiryPosture {
	return ExpiryPosture{
		Phase:             ExpiryPhaseAt(expiresAt, now),
		EnterpriseAllowed: now.Before(GraceEnd(expiresAt)),
		CoreAllowed:       true,
		DataExportAllowed: true,
		ExpiresAt:         expiresAt,
	}
}

// ExpiryPostureFromState derives the posture from a SERVED State (the
// StateFromClaims output the license Server exposes). The state machine's
// dead-zone instant (all booleans false — possible only exactly at grace
// end, or the zero State of an unconfigured contour) fails closed to the
// hard-expired posture; a CONTRADICTORY shape (Active∧HardExpired — never
// produced by StateFromClaims, but a hand-built State could carry it) also
// fails closed: HardExpired wins over Active. Core and data export stay
// allowed in every case.
func ExpiryPostureFromState(st State) ExpiryPosture {
	phase := PhaseHardExpired
	switch {
	case st.HardExpired:
		phase = PhaseHardExpired
	case st.Expired:
		phase = PhaseGrace
	case st.Active:
		phase = PhaseActive
	}
	return ExpiryPosture{
		Phase:             phase,
		EnterpriseAllowed: st.Active && !st.HardExpired,
		CoreAllowed:       true,
		DataExportAllowed: true,
	}
}

// RunRight reports the perpetual run right for one paid module (I24): it
// reads ONLY the signed module list — there is deliberately no clock input,
// so no maintenance date, no expiry and no clock manipulation can ever
// disable a previously-paid module. The formal parameter is the entitlement
// alone; the clock-freedom is the contract (pinned in
// expiry_adversarial_test.go: identical at every instant).
func RunRight(ent PaidModuleEntitlement, module string) bool {
	return ent.HasModule(module)
}

// UpdateRightAt delegates to the renewal-gated update/support predicate
// (maintenance.go:45): updates and support services are included exactly
// while the paid maintenance term runs, inclusive at the exact
// MaintenanceEnd instant.
func UpdateRightAt(ent PaidModuleEntitlement, now time.Time) bool {
	return ent.UpdatesEntitledAt(now)
}

// CriticalFixRightAt delegates to the I25 exception predicate
// (maintenance.go:60): critical security fixes for a purchased, still
// supported release line remain available WITHOUT maintenance renewal —
// independent of MaintenanceEnd, inclusive at the exact SupportEnd instant,
// fail closed for unknown lines, flag-off lines and expired support.
func CriticalFixRightAt(ent PaidModuleEntitlement, line string, now time.Time) bool {
	return ent.CriticalFixEntitledAt(line, now)
}
