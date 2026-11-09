package license

// N11-P05-T05 negative-semantics pins (adjacent tests-only card on top of the
// delivered T03 entitlement layer and the T04 verification layer — patterns
// consumed, no fork, zero production changes). The card's negative scenario:
//
//   1. a maintenance date must never disable previously-paid protection,
//      internal-loop or history modules (I24);
//   2. new packs never gain rights without an explicit signed grant —
//      membership is EXACT, so identity games (case, trim, prefix, suffix,
//      NUL) cannot smuggle an unsigned pack in;
//   3. the legacy 7-day activation GracePeriod (license.go) never
//      substitutes for I24 — not by arithmetic (the update term ends at
//      MaintenanceEnd, not MaintenanceEnd+7d) and not by reference (the
//      entitlement path never mentions the constant, audited here).
//
// Every row records (cause → expected result): the negative scenario is
// reproducible and must not produce a false success (a grant) or a false
// failure (a revoked paid module). Fixed anchors only (moduleEntitlementNow /
// maintenanceFixture) — no wall clock anywhere in this file.

import (
	"go/ast"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNegative_NewPacksNeedExplicitGrant_MembershipIsExact pins the packet
// negative at the matching layer: HasModule is exact string membership over
// the signed list. No normalization exists in either direction — a drifted
// query never matches a signed id, and a legally-signed drifted id never
// grants its canonical neighbor. Any "friendly" matching (case folding,
// trimming, prefix/suffix/contains) would hand an unsigned pack its signed
// sibling's rights and fails this pin.
func TestNegative_NewPacksNeedExplicitGrant_MembershipIsExact(t *testing.T) {
	ent, _ := issueMaintenanceFixture(t)

	// Drift queries around every signed id: all must stay ungranted.
	for _, m := range maintenanceFixture.modules {
		drifts := []string{
			m + " ",                       // trailing space is a different id
			" " + m,                       // leading space is a different id
			"\t" + m,                      // tab padding is a different id
			stringsToUpper(m),             // case is significant
			stringsToUpper(m[:1]) + m[1:], // only the first letter uppercased
			m + "2",                       // suffix extension (protection-pack-av2)
			"x" + m,                       // prefix extension
			m + "\x00",                    // NUL-terminated games
			m[:len(m)-1],                  // truncation
		}
		for _, d := range drifts {
			if d == m {
				continue // guard the guard: skip degenerate rows
			}
			assert.Falsef(t, ent.HasModule(d),
				"drifted module id %q must not match signed %q: membership is exact, no normalization (packet negative)", d, m)
		}
		// The exact id stays granted — a normalization "fix" that rewrites
		// both sides into canonical buckets would break real grants too.
		assert.Truef(t, ent.HasModule(m), "exact signed id %q must stay granted", m)
	}

	// A legally-signable drifted document (case and extension variants pass
	// issue validation — only emptiness/whitespace are rejected) verifies
	// fine but grants NOTHING canonical: the vendor must sign exact
	// vendor-issued ids; drift is a grant of the drifted string, never of
	// the canonical pack.
	pub, _ := moduleEntitlementTestKey()
	driftedList := []string{"INTERNAL-LOOP", "protection-pack-av2", "internal-loop\x00"}
	drToken, _, _ := issueModuleToken(t, maintenanceFixture.deploy, driftedList,
		moduleEntitlementNow, moduleEntitlementNow.Add(365*24*time.Hour))
	drEnt, err := VerifyPaidModuleEntitlement(drToken, pub, maintenanceFixture.deploy)
	require.NoError(t, err, "a structurally valid document with drifted ids still verifies — drift is a signing-time property, not a verify-time rejection")
	for _, canonical := range []string{"internal-loop", "protection-pack-av"} {
		assert.Falsef(t, drEnt.HasModule(canonical),
			"drifted signed id %q must not grant canonical %q — no normalization in either direction", driftedList, canonical)
	}
	for _, signed := range driftedList {
		assert.Truef(t, drEnt.HasModule(signed),
			"the document grants exactly what it signed: %q", signed)
	}

	// Mixed list: one drifted entry must not dilute the exact entries. The
	// canonical history spelling is dropped and its uppercase drift signed
	// instead — the drifted entry must grant only itself.
	var mixedList []string
	for _, m := range maintenanceFixture.modules {
		if m != "media-persistence" {
			mixedList = append(mixedList, m)
		}
	}
	mixedList = append(mixedList, "MEDIA-PERSISTENCE")
	mixedToken, _, _ := issueModuleToken(t, maintenanceFixture.deploy, mixedList,
		moduleEntitlementNow, moduleEntitlementNow.Add(365*24*time.Hour))
	require.NoError(t, err)
	mixedEnt, err := VerifyPaidModuleEntitlement(mixedToken, pub, maintenanceFixture.deploy)
	require.NoError(t, err)
	assert.False(t, mixedEnt.HasModule("media-persistence"),
		"the drifted uppercase entry must not grant the canonical history module (I62)")
	assert.True(t, mixedEnt.HasModule("MEDIA-PERSISTENCE"),
		"the drifted entry grants exactly the drifted string — membership reflects the signed list verbatim")
	for _, m := range mixedList {
		assert.Truef(t, mixedEnt.HasModule(m), "exact entries in a mixed list stay granted: %q", m)
	}
}

// stringsToUpper is a tiny ASCII helper so the drift table above reads as
// data, not as a strings import dance. It intentionally covers ASCII only:
// module ids in this packet are ASCII vendor vocabulary.
func stringsToUpper(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'a' && c <= 'z' {
			out[i] = c - 'a' + 'A'
		}
	}
	return string(out)
}

// TestNegative_GracePeriodNeverReferencedOnEntitlementPath pins the
// "старый grace 7d не подменяет I24" negative at the source level: the
// entitlement path files never reference the activation GracePeriod constant
// (or any time.Since/time.Until clock helper) — the 7-day activation window
// cannot be spliced into the maintenance semantics by construction, only by
// writing a new reference, which fails this audit loudly. Complements T04's
// NoClockInputByConstruction (which pins time.Now; a grace substitution
// needs no time.Now at all — `now.After(end.Add(GracePeriod))` would slip
// past it) and T03's behavioral grace pin (which checks the past-grace
// horizon; see TestNegative_MaintenanceDateNeverDisablesPaidModules for the
// inside-grace arithmetic that closes that blind spot).
func TestNegative_GracePeriodNeverReferencedOnEntitlementPath(t *testing.T) {
	for _, name := range []string{"module_entitlement.go", "maintenance.go"} {
		f := parsePackageFile(t, name)

		var idents []string
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				idents = append(idents, id.Name)
			}
			return true
		})
		// Liveness guard: the audit must see the real file, not an empty
		// parse — a broken/false pass here must be loud.
		require.NotEmpty(t, idents, "%s parsed to no identifiers — the audit is blind, fix the scan first", name)
		require.Containsf(t, idents, "PaidModuleEntitlement",
			"%s audit lost sight of the entitlement type — the scan is broken, not the code", name)

		for _, id := range idents {
			assert.NotEqualf(t, "GracePeriod", id,
				"%s references the activation GracePeriod — the 7d window must never substitute for I24 maintenance semantics", name)
		}
		// Clock-helper family beyond time.Now (T04's pin): time.Since and
		// time.Until are equally clock reads.
		for _, ref := range selectorRefs(t, f) {
			assert.NotContainsf(t, []string{"time.Since", "time.Until"}, ref,
				"%s references %q — the entitlement path must stay clock-free", name, ref)
		}
	}
}

// TestNegative_MaintenanceDateNeverDisablesPaidModules is the card's
// reproducible negative decision table with (cause → expected result)
// recorded per row: across the maintenance boundary, the activation-grace
// horizon and the I25 line-support boundary, every previously-paid module
// (protection, internal loop, history ×2) keeps running, the update/support
// right flips exactly once at MaintenanceEnd (no false success inside the
// grace window either), and the trial/maintenance negatives stack without
// ever producing a grant or a revocation. Fixed anchors only.
//
// The inside-grace rows are the ones T03's grace pin cannot see: at
// MaintenanceEnd+24h the update right must ALREADY be renewal-gated, even
// though the activation grace window (7d) is still nominally open. A
// mutation extending the term by GracePeriod passes the T03 horizon check
// (which only tests after end+7d) but fails this table here.
func TestNegative_MaintenanceDateNeverDisablesPaidModules(t *testing.T) {
	ent, _ := issueMaintenanceFixture(t)
	end := maintenanceFixture.maintenanceEnd
	lineEnd := maintenanceFixture.lineSupportEnd
	day := 24 * time.Hour

	// name, now, updatesEntitled, maintenanceEnded, criticalFixLine, cause
	rows := []struct {
		name    string
		now     time.Time
		updates bool
		ended   bool
		critFix bool
		cause   string
	}{
		{"one ns before end", end.Add(-time.Nanosecond), true, false, true,
			"inside the paid term updates flow and maintenance is not ended"},
		{"exactly at end (inclusive)", end, true, false, true,
			"the term runs through its exact signed end instant"},
		{"one ns past end", end.Add(time.Nanosecond), false, true, true,
			"renewal-gated immediately past the term — no grace slack (I24)"},
		{"end + 1 day (inside activation grace)", end.Add(day), false, true, true,
			"the 7d activation grace is a DIFFERENT document's window: it must not extend the update term by even one day"},
		{"end + grace − 1ns", end.Add(GracePeriod).Add(-time.Nanosecond), false, true, true,
			"the last instant a GracePeriod-extended term would still grant — must already be renewal-gated"},
		{"end + grace + 1ns", end.Add(GracePeriod).Add(time.Nanosecond), false, true, true,
			"past any grace horizon the update right stays closed (matches T03's pin)"},
		{"at line support end (inclusive)", lineEnd, false, true, true,
			"the I25 critical-fix window runs through its exact signed end, independent of maintenance"},
		{"line support end + 1ns", lineEnd.Add(time.Nanosecond), false, true, false,
			"the I25 window closes on its own clock; the RUN right is untouched — only the fix exception ends"},
		{"ten years past everything", end.Add(10 * 365 * day), false, true, false,
			"the perpetual run right outlives every signed window (I24)"},
	}
	for _, m := range maintenanceFixture.modules {
		t.Run("module:"+m, func(t *testing.T) {
			for _, row := range rows {
				assert.Truef(t, ent.HasModule(m),
					"%s: paid module %q must keep running — %s (I24)", row.name, m, row.cause)
			}
		})
	}

	for _, row := range rows {
		assert.Equalf(t, row.updates, ent.UpdatesEntitledAt(row.now),
			"%s: update/support verdict wrong — %s", row.name, row.cause)
		assert.Equalf(t, row.ended, ent.MaintenanceEndedAt(row.now),
			"%s: maintenance-ended verdict wrong — %s", row.name, row.cause)
		assert.Equalf(t, row.critFix, ent.CriticalFixEntitledAt(maintenanceFixture.line, row.now),
			"%s: critical-fix verdict for line %q wrong — %s", row.name, maintenanceFixture.line, row.cause)
		assert.Falsef(t, ent.HasModule(maintenanceFixture.newPack),
			"%s: the unsigned pack %q must stay ungranted — %s", row.name, maintenanceFixture.newPack, row.cause)
	}

	// Stacked negative: a trial that already ended adds neither a disable
	// nor an extension — inside the paid term (past trial end) everything
	// still flows; past the term both observational states read honestly.
	pub, priv := moduleEntitlementTestKey()
	stackToken, err := fixturePaidModuleEntitlement(priv, PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   maintenanceFixture.deploy,
		Modules:        maintenanceFixture.modules,
		IssuedAt:       maintenanceFixture.issued,
		MaintenanceEnd: end,
		TrialEnd:       end.Add(-30 * day), // trial ended 30d before maintenance end
		Nonce:          "negative-stack-0001",
	}, maintenanceFixture.issued)
	require.NoError(t, err)
	stackEnt, err := VerifyPaidModuleEntitlement(stackToken, pub, maintenanceFixture.deploy)
	require.NoError(t, err)

	stackRows := []struct {
		name string
		now  time.Time
	}{
		{"just past trial end, inside term", end.Add(-29 * day)},
		{"one ns before maintenance end", end.Add(-time.Nanosecond)},
		{"one ns past maintenance end", end.Add(time.Nanosecond)},
	}
	for _, sr := range stackRows {
		assert.Falsef(t, stackEnt.TrialActiveAt(sr.now),
			"%s: the ended trial must read as ended — an explicit signed state, never a silent gate", sr.name)
		assert.Falsef(t, stackEnt.HasModule(maintenanceFixture.newPack),
			"%s: the ended trial must not smuggle the unsigned pack in", sr.name)
		for _, m := range maintenanceFixture.modules {
			assert.Truef(t, stackEnt.HasModule(m),
				"%s: trial end + maintenance negatives stacked — paid module %q must still run (I24)", sr.name, m)
		}
	}
	assert.True(t, stackEnt.UpdatesEntitledAt(end.Add(-29*day)),
		"past trial end but inside the term, updates still flow — trial end is not a renewal event")
	assert.False(t, stackEnt.UpdatesEntitledAt(end.Add(time.Nanosecond)),
		"past the term, updates are renewal-gated exactly as without any trial — no false success")
}
