package license

// Offline maintenance semantics (owner answers I24 and I25, card
// N11-P05-T03). The entitlement splits three rights that must never be
// conflated:
//
//  1. RUN (perpetual, I24): modules signed into the entitlement keep
//     operating on the licensed contour forever — protection packs, the
//     internal loop (I53) and history features (I62/I63) included. There is
//     no clock input anywhere in this path: HasModule is the only run-right
//     predicate, and VerifyPaidModuleEntitlement never rejects on time.
//  2. UPDATES/SUPPORT (paid term, I24): new versions, pack updates and
//     support services are included only while the maintenance term is
//     running (UpdatesEntitledAt). After MaintenanceEnd these require
//     renewal, but the already-paid version keeps running.
//  3. CRITICAL SECURITY FIXES (I25 exception): for a purchased release line
//     within its announced support lifetime, critical fixes remain
//     available WITHOUT maintenance renewal (CriticalFixEntitledAt). This
//     is independent of MaintenanceEnd — it can outlive it — and never
//     implies renewed support services or new-feature rights.
//
// Every predicate is a pure function of (document, now): deterministic,
// offline, no external server, and the 7-day activation GracePeriod
// (license.go) is unreachable from here — it governs activation-token clock
// drift only and is never a maintenance/renewal extension.

import "time"

// MaintenanceEndedAt reports whether the paid update/support term (I24) has
// ended at now. The boundary is inclusive: the term is still running at the
// exact MaintenanceEnd instant. A zero-valued entitlement (never verified)
// reports ended=false — the zero value grants nothing, so callers must not
// read ended=false alone as an update right; use UpdatesEntitledAt.
func (e PaidModuleEntitlement) MaintenanceEndedAt(now time.Time) bool {
	if e.MaintenanceEnd.IsZero() {
		return false
	}
	return now.After(e.MaintenanceEnd)
}

// UpdatesEntitledAt reports whether new versions, pack updates and support
// services (I24 renewal-gated rights) are included at now: exactly while the
// paid maintenance term is running. A zero-valued entitlement grants no
// update right.
func (e PaidModuleEntitlement) UpdatesEntitledAt(now time.Time) bool {
	if e.MaintenanceEnd.IsZero() {
		return false
	}
	return !now.After(e.MaintenanceEnd)
}

// CriticalFixEntitledAt reports whether critical security fixes are
// available for the named release line at now (I25): the line must be
// announced in the signed entitlement with the critical-fix exception flag
// and still within its announced support lifetime. Maintenance status is
// deliberately irrelevant here — the exception exists precisely for
// deployments whose maintenance term already ended. Unknown lines, lines
// without the flag, zero-valued entitlements and expired support windows
// all fail closed.
func (e PaidModuleEntitlement) CriticalFixEntitledAt(line string, now time.Time) bool {
	for _, rl := range e.ReleaseLines {
		if rl.Line != line {
			continue
		}
		if !rl.CriticalFixes || rl.SupportEnd.IsZero() {
			return false
		}
		// Inclusive boundary: entitled through the exact SupportEnd instant.
		return !now.After(rl.SupportEnd)
	}
	return false
}
