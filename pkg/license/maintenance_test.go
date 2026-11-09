package license

// N11-P05-T03 acceptance and negative tests: the offline I24/I25 maintenance
// semantics. Layer split under test:
//   - RUN right: perpetual for the signed module list — the maintenance date
//     can never disable previously-paid protection packs, the internal loop
//     (I53) or history features (I62/I63).
//   - UPDATES/SUPPORT: gated by MaintenanceEnd only (renewal-gated, I24).
//   - CRITICAL FIXES: gated by the signed release-line support windows
//     (I25 exception) — independent of MaintenanceEnd.
//   - The 7-day activation GracePeriod (license.go) never substitutes for
//     any of these.
//
// Everything is table-driven over a fixed clock and a fixed-seed key — fully
// deterministic and offline.

import (
	"testing"
	"time"
)

// maintenanceFixture issues the packet's canonical paid grant: protection
// pack + internal loop (I53) + media persistence (I62) + conditional
// original-text retention (I63) for prod-eu-1, maintenance ending 2026-10-01,
// release line 1.4 supported (with the I25 critical-fix exception) through
// 2027-06-30 — i.e. line support outlives the maintenance term.
var maintenanceFixture = struct {
	deploy         string
	modules        []string
	issued         time.Time
	maintenanceEnd time.Time
	line           string
	lineSupportEnd time.Time
	newPack        string
}{
	deploy: "prod-eu-1",
	modules: []string{
		"protection-pack-av",                  // protection pack (I22/I25 vocabulary)
		"internal-loop",                       // Enterprise internal loop (I53)
		"media-persistence",                   // history media persistence (I62)
		"conditional-original-text-retention", // history original retention (I63)
	},
	issued:         time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
	maintenanceEnd: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	line:           "1.4",
	lineSupportEnd: time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC),
	newPack:        "protection-pack-nextgen", // never signed into the grant
}

func issueMaintenanceFixture(t *testing.T) (PaidModuleEntitlement, string) {
	t.Helper()
	pub, priv := moduleEntitlementTestKey()
	ent := PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   maintenanceFixture.deploy,
		Modules:        maintenanceFixture.modules,
		IssuedAt:       maintenanceFixture.issued,
		MaintenanceEnd: maintenanceFixture.maintenanceEnd,
		Nonce:          "maintenance-0001",
		ReleaseLines: []ReleaseLine{
			{Line: maintenanceFixture.line, SupportEnd: maintenanceFixture.lineSupportEnd, CriticalFixes: true},
		},
	}
	token, err := fixturePaidModuleEntitlement(priv, ent, maintenanceFixture.issued)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	verified, err := VerifyPaidModuleEntitlement(token, pub, maintenanceFixture.deploy)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return verified, token
}

// TestMaintenance_RunRightSurvivesMaintenanceEnd is the I24 acceptance core:
// one second past MaintenanceEnd — and years past it — the paid version
// keeps working: the document still verifies and every previously-paid
// module (protection, internal loop, history) still reports entitled. The
// maintenance date never disables previously-paid protection / internal
// loop / history (packet negative).
func TestMaintenance_RunRightSurvivesMaintenanceEnd(t *testing.T) {
	ent, _ := issueMaintenanceFixture(t)

	afterPoints := []struct {
		name string
		now  time.Time
	}{
		{"one ns past maintenance", maintenanceFixture.maintenanceEnd.Add(time.Nanosecond)},
		{"one day past maintenance", maintenanceFixture.maintenanceEnd.Add(24 * time.Hour)},
		{"past line support end too", maintenanceFixture.lineSupportEnd.Add(24 * time.Hour)},
		{"ten years past maintenance", maintenanceFixture.maintenanceEnd.Add(10 * 365 * 24 * time.Hour)},
	}
	for _, at := range afterPoints {
		for _, m := range maintenanceFixture.modules {
			if !ent.HasModule(m) {
				t.Fatalf("%s: paid module %q lost after maintenance end — I24 run right violated", at.name, m)
			}
		}
		if ended := ent.MaintenanceEndedAt(at.now); !ended {
			t.Fatalf("%s: MaintenanceEndedAt = false, want true", at.name)
		}
		if ent.UpdatesEntitledAt(at.now) {
			t.Fatalf("%s: update/support right must require renewal after maintenance end (I24)", at.name)
		}
	}
}

// TestMaintenance_RunRightUnaffectedWhileWithinMaintenance: inside the paid
// term everything is entitled AND updates flow; the run right is identical
// inside and after the term (same predicate, no clock input).
func TestMaintenance_RunRightUnaffectedWhileWithinMaintenance(t *testing.T) {
	ent, _ := issueMaintenanceFixture(t)

	within := []struct {
		name string
		now  time.Time
	}{
		{"at issue", maintenanceFixture.issued},
		{"one ns before maintenance end", maintenanceFixture.maintenanceEnd.Add(-time.Nanosecond)},
		{"at exact maintenance end", maintenanceFixture.maintenanceEnd},
	}
	for _, at := range within {
		if !ent.UpdatesEntitledAt(at.now) {
			t.Fatalf("%s: update/support must be included in the paid term (I24)", at.name)
		}
		if ent.MaintenanceEndedAt(at.now) {
			t.Fatalf("%s: MaintenanceEndedAt = true inside the paid term", at.name)
		}
		for _, m := range maintenanceFixture.modules {
			if !ent.HasModule(m) {
				t.Fatalf("%s: paid module %q not entitled inside the paid term", at.name, m)
			}
		}
	}
}

// TestMaintenance_NewPackNeedsEntitlement pins the packet negative across the
// whole timeline: a pack absent from the signed list never gains rights —
// not inside the paid term, not after maintenance end, not because the
// release line is still supported. Renewal or a new signed document are the
// only paths to new content.
func TestMaintenance_NewPackNeedsEntitlement(t *testing.T) {
	ent, _ := issueMaintenanceFixture(t)

	points := []struct {
		name string
		now  time.Time
	}{
		{"inside paid term", maintenanceFixture.issued.Add(24 * time.Hour)},
		{"past maintenance end", maintenanceFixture.maintenanceEnd.Add(24 * time.Hour)},
		{"past line support end", maintenanceFixture.lineSupportEnd.Add(24 * time.Hour)},
	}
	for _, at := range points {
		if ent.HasModule(maintenanceFixture.newPack) {
			t.Fatalf("%s: unsigned pack %q gained rights without entitlement (packet negative)", at.name, maintenanceFixture.newPack)
		}
		if ent.CriticalFixEntitledAt(maintenanceFixture.newPack, at.now) {
			t.Fatalf("%s: unsigned pack %q treated as a critical-fix release line", at.name, maintenanceFixture.newPack)
		}
	}

	// The only legitimate path: a NEW signed document naming the pack in its
	// module list (a pack is never a release line — grants live in Modules).
	pub, priv := moduleEntitlementTestKey()
	renewalAt := maintenanceFixture.maintenanceEnd.Add(24 * time.Hour)
	renewed, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   maintenanceFixture.deploy,
		Modules:        append(append([]string{}, maintenanceFixture.modules...), maintenanceFixture.newPack),
		IssuedAt:       renewalAt,
		MaintenanceEnd: renewalAt.Add(365 * 24 * time.Hour),
		Nonce:          "renewal-0002",
		ReleaseLines: []ReleaseLine{
			{Line: maintenanceFixture.line, SupportEnd: maintenanceFixture.lineSupportEnd, CriticalFixes: true},
		},
	}, renewalAt)
	if err != nil {
		t.Fatalf("issue renewal: %v", err)
	}
	verified, err := VerifyPaidModuleEntitlement(renewed, pub, maintenanceFixture.deploy)
	if err != nil {
		t.Fatalf("verify renewal: %v", err)
	}
	if !verified.HasModule(maintenanceFixture.newPack) {
		t.Fatal("renewed document naming the pack must grant it")
	}
}

// TestMaintenance_CriticalFixEntitled is the I25 exception table: critical
// security fixes for the supported purchased line remain available after the
// maintenance term ends, exactly through the announced support lifetime,
// while new features/packs/support do NOT follow this exception.
func TestMaintenance_CriticalFixEntitled(t *testing.T) {
	ent, _ := issueMaintenanceFixture(t)

	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"inside maintenance, line supported", maintenanceFixture.issued.Add(24 * time.Hour), true},
		{"at maintenance end, line supported", maintenanceFixture.maintenanceEnd, true},
		{"past maintenance, line supported (the I25 case)", maintenanceFixture.maintenanceEnd.Add(90 * 24 * time.Hour), true},
		{"at line support end", maintenanceFixture.lineSupportEnd, true},
		{"one ns past line support end", maintenanceFixture.lineSupportEnd.Add(time.Nanosecond), false},
		{"years past everything", maintenanceFixture.lineSupportEnd.Add(365 * 24 * time.Hour), false},
	}
	for _, tc := range cases {
		if got := ent.CriticalFixEntitledAt(maintenanceFixture.line, tc.now); got != tc.want {
			t.Fatalf("%s: CriticalFixEntitledAt(%q) = %v, want %v", tc.name, maintenanceFixture.line, got, tc.want)
		}
	}

	// The exception is per-line and flag-gated: an unflagged line and an
	// unknown line never qualify, whatever the clock says.
	if ent.CriticalFixEntitledAt("0.9", maintenanceFixture.issued.Add(time.Hour)) {
		t.Fatal("unknown release line entitled to critical fixes, want fail-closed")
	}
	noFlag := PaidModuleEntitlement{
		Modules:        []string{"internal-loop"},
		MaintenanceEnd: maintenanceFixture.maintenanceEnd,
		ReleaseLines:   []ReleaseLine{{Line: "1.4", SupportEnd: maintenanceFixture.lineSupportEnd, CriticalFixes: false}},
	}
	if noFlag.CriticalFixEntitledAt("1.4", maintenanceFixture.issued.Add(time.Hour)) {
		t.Fatal("line without the critical-fix flag entitled, want fail-closed")
	}
	// Zero-valued entitlement grants no critical-fix right.
	var zero PaidModuleEntitlement
	if zero.CriticalFixEntitledAt(maintenanceFixture.line, time.Now()) {
		t.Fatal("zero entitlement entitled to critical fixes, want fail-closed")
	}
}

// TestMaintenance_CriticalFixExceptionDoesNotRenewSupport: the I25 exception
// covers critical fixes ONLY — it must not resurrect the renewal-gated
// update/support right past MaintenanceEnd, and must not grant new packs.
func TestMaintenance_CriticalFixExceptionDoesNotRenewSupport(t *testing.T) {
	ent, _ := issueMaintenanceFixture(t)

	after := maintenanceFixture.maintenanceEnd.Add(90 * 24 * time.Hour)
	if !ent.CriticalFixEntitledAt(maintenanceFixture.line, after) {
		t.Fatal("fixture precondition lost: critical-fix exception must be active after maintenance end")
	}
	if ent.UpdatesEntitledAt(after) {
		t.Fatal("critical-fix exception leaked into update/support rights — I25 does not renew support")
	}
	if ent.HasModule(maintenanceFixture.newPack) {
		t.Fatal("critical-fix exception granted an unsigned pack")
	}
}

// TestMaintenance_GracePeriodNeverSubstitutesI24 pins the packet negative
// explicitly: the legacy 7-day activation GracePeriod (license.go) and the
// I24 maintenance semantics are disjoint mechanisms. If I24 were (wrongly)
// modeled as a grace extension, run rights would die 7 days after
// MaintenanceEnd and update rights would silently extend to MaintenanceEnd
// +7d — neither happens. And the two document types never cross: an
// activation token hard-expired beyond its own grace confers no module
// rights, while the module entitlement's validity ignores activation state
// entirely.
func TestMaintenance_GracePeriodNeverSubstitutesI24(t *testing.T) {
	ent, token := issueMaintenanceFixture(t)

	justPastGrace := maintenanceFixture.maintenanceEnd.Add(GracePeriod).Add(time.Nanosecond)

	// Run rights outlive any grace window: the run right has NO clock at all
	// (HasModule takes no time — nothing time-derived can gate it), so the
	// same grant holds just past the grace horizon and years later
	// (TestMaintenance_RunRightSurvivesMaintenanceEnd pins the far horizon).
	for _, m := range maintenanceFixture.modules {
		if !ent.HasModule(m) {
			t.Fatalf("paid module %q lost past the grace horizon — grace must not bound I24", m)
		}
	}
	// Nor does grace extend the renewal-gated rights: 7 days + 1ns after
	// MaintenanceEnd the update/support term is over.
	if ent.UpdatesEntitledAt(justPastGrace) {
		t.Fatal("update/support right extended by the 7d grace — grace must not substitute for renewal (I24)")
	}
	if !ent.MaintenanceEndedAt(justPastGrace) {
		t.Fatal("maintenance must read as ended past the grace horizon")
	}

	// Disjoint documents: an activation token 1ns past its own grace is
	// hard-rejected (activation clock-drift allowance exhausted), yet the
	// paid-module entitlement for the same deployment verifies and keeps its
	// run rights at the same instant — grace semantics never substitute for
	// (or leak into) I24.
	entPub, entPriv := moduleEntitlementTestKey()
	oldVendorKey := VendorPublicKey
	VendorPublicKey = entPub
	defer func() { VendorPublicKey = oldVendorKey }()
	expiredActivation := makeToken(t, entPriv, map[string]interface{}{
		"org_id":     "cust_acme",
		"expires_at": maintenanceFixture.maintenanceEnd.Add(-GracePeriod).Add(-time.Nanosecond).Format(time.RFC3339),
		"issued_at":  maintenanceFixture.issued.Format(time.RFC3339),
	})
	if _, err := Verify(expiredActivation); err == nil {
		t.Fatal("activation token past its grace verified — activation grace is finite")
	}
	// The entitlement document is verified by explicit signature+binding, so
	// activation state cannot revoke it: re-verify and re-check run rights at
	// the same instant the activation token died.
	reVerified, err := VerifyPaidModuleEntitlement(token, entPub, maintenanceFixture.deploy)
	if err != nil {
		t.Fatalf("module entitlement must verify independently of activation state: %v", err)
	}
	if !reVerified.HasModule("internal-loop") || !reVerified.HasModule("protection-pack-av") {
		t.Fatal("activation expiry leaked into the module run right — grace must not govern I24")
	}
}

// TestMaintenance_ZeroEntitlementGrantsNothing: the zero value never becomes
// an implicit grant — no run right, no update right, no maintenance verdict.
func TestMaintenance_ZeroEntitlementGrantsNothing(t *testing.T) {
	var zero PaidModuleEntitlement
	now := maintenanceFixture.maintenanceEnd.Add(time.Hour)
	for _, m := range maintenanceFixture.modules {
		if zero.HasModule(m) {
			t.Fatalf("zero entitlement grants %q", m)
		}
	}
	if zero.UpdatesEntitledAt(now) {
		t.Fatal("zero entitlement grants update/support right")
	}
	if zero.MaintenanceEndedAt(now) {
		t.Fatal("zero entitlement reports a maintenance verdict")
	}
	if zero.CriticalFixEntitledAt(maintenanceFixture.line, now) {
		t.Fatal("zero entitlement grants critical-fix right")
	}
}
