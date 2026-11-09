// Entitlement transition tests (E01-P05 card W05-C01, batch C).
//
// Card variants: add module; remove module; release-line add/drop (I25);
// DeploymentID stable across every transition kind; secret NOT re-issued.
//
// The secret law is pinned structurally and behaviorally: NextEntitlement
// takes no key material at all, and re-signing goes through the standing
// fixturePaidModuleEntitlement — old and new tokens therefore verify against
// the SAME vendor public key (the runtime keypair stands in for it; no
// private key material lives in the tree). N/A key re-issuance: there is no
// rotation or re-issue path in the transition vocabulary to cover — a vendor
// key event would be a format-level change, out of this card's scope.
//
// All instants are fixed offsets from the corpus anchor (2026-11-08T00:00:00Z,
// entitlement_verify_test.go): issuance at the anchor, transitions at
// anchor+30d inside the anchor+180d maintenance term. No wall clock.
package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upgradeFixtures is one deterministic scenario: a runtime vendor keypair
// plus the baseline CURRENT document (issued at the anchor, two modules, one
// supported release line, 180d maintenance term).
type upgradeFixtures struct {
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	current PaidModuleEntitlement
}

func newUpgradeFixtures(t *testing.T) upgradeFixtures {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return upgradeFixtures{
		priv: priv,
		pub:  pub,
		current: PaidModuleEntitlement{
			Version:        ModuleEntitlementVersion,
			CustomerID:     "cust-upgrade",
			DeploymentID:   corpusDeployment,
			Modules:        []string{"internal-loop", "media-persistence"},
			IssuedAt:       corpusAnchor,
			MaintenanceEnd: corpusAnchor.Add(180 * 24 * time.Hour),
			ReleaseLines: []ReleaseLine{
				{Line: "2026.1", SupportEnd: corpusAnchor.Add(365 * 24 * time.Hour), CriticalFixes: true},
			},
			Nonce: "nonce-1",
		},
	}
}

// at is a fixed offset from the corpus anchor (deterministic instants only).
func at(days int) time.Time { return corpusAnchor.Add(time.Duration(days) * 24 * time.Hour) }

// signUpgrade issues next with the standing vendor key and re-verifies it
// against the SAME public key — the round-trip every accepted transition in
// this file must survive.
func signUpgrade(t *testing.T, f upgradeFixtures, next PaidModuleEntitlement, now time.Time) PaidModuleEntitlement {
	t.Helper()
	token, err := fixturePaidModuleEntitlement(f.priv, next, now)
	require.NoError(t, err, "a transition result must be issuable")
	verified, err := VerifyPaidModuleEntitlement(token, f.pub, corpusDeployment)
	require.NoError(t, err, "the re-issued token must verify offline against the SAME key")
	return verified
}

func TestNextEntitlement_AddModule(t *testing.T) {
	f := newUpgradeFixtures(t)
	next, err := NextEntitlement(f.current, EntitlementTransition{AddModules: []string{"protection-pack"}}, at(30), "nonce-2")
	require.NoError(t, err)

	assert.Equal(t, []string{"internal-loop", "media-persistence", "protection-pack"}, next.Modules,
		"adds append after the preserved current order")
	assert.Equal(t, corpusAnchor.Add(180*24*time.Hour), next.MaintenanceEnd, "the term carries over unchanged")
	assert.Equal(t, at(30), next.IssuedAt, "the transition instant becomes IssuedAt")
	assert.Equal(t, "nonce-2", next.Nonce)

	// Secret law: old and new tokens verify against the SAME public key.
	currentToken, err := fixturePaidModuleEntitlement(f.priv, f.current, corpusAnchor)
	require.NoError(t, err)
	_, err = VerifyPaidModuleEntitlement(currentToken, f.pub, corpusDeployment)
	require.NoError(t, err, "the OLD token keeps verifying under the same key")
	verified := signUpgrade(t, f, next, at(30))
	assert.True(t, verified.HasModule("protection-pack"))
	require.NoError(t, IsEntitlementSuccessor(f.current, verified))

	// Exactness refusals.
	_, err = NextEntitlement(f.current, EntitlementTransition{AddModules: []string{"internal-loop"}}, at(30), "nonce-2")
	require.ErrorContains(t, err, "already granted", "re-adding a granted module is refused")
	_, err = NextEntitlement(f.current, EntitlementTransition{AddModules: []string{"  padded"}}, at(30), "nonce-2")
	require.ErrorContains(t, err, "leading/trailing whitespace")
	_, err = NextEntitlement(f.current, EntitlementTransition{AddModules: []string{""}}, at(30), "nonce-2")
	require.ErrorContains(t, err, "is empty")
	_, err = NextEntitlement(f.current, EntitlementTransition{
		AddModules:    []string{"protection-pack"},
		RemoveModules: []string{"protection-pack"},
	}, at(30), "nonce-2")
	require.ErrorContains(t, err, "not granted",
		"a module named on both sides validates against the ORIGINAL grant set — no silent netting")
}

func TestNextEntitlement_RemoveModule(t *testing.T) {
	f := newUpgradeFixtures(t)
	next, err := NextEntitlement(f.current, EntitlementTransition{RemoveModules: []string{"media-persistence"}}, at(30), "nonce-2")
	require.NoError(t, err)
	assert.Equal(t, []string{"internal-loop"}, next.Modules)
	verified := signUpgrade(t, f, next, at(30))
	assert.False(t, verified.HasModule("media-persistence"), "the removed module is gone from the signed grant")
	assert.True(t, verified.HasModule("internal-loop"), "the kept module survives (I24 perpetual run right)")

	_, err = NextEntitlement(f.current, EntitlementTransition{RemoveModules: []string{"ghost"}}, at(30), "nonce-2")
	require.ErrorContains(t, err, "not granted", "removing an absent module is refused")
	_, err = NextEntitlement(f.current, EntitlementTransition{RemoveModules: []string{"internal-loop", "media-persistence"}}, at(30), "nonce-2")
	require.ErrorContains(t, err, "removal leaves no modules",
		"termination is not a transition — the old document simply keeps running")

	// The current document is never mutated by a transition.
	assert.Equal(t, []string{"internal-loop", "media-persistence"}, f.current.Modules)
}

func TestNextEntitlement_ReleaseLines(t *testing.T) {
	f := newUpgradeFixtures(t)
	newLine := ReleaseLine{Line: "2027.0", SupportEnd: at(720), CriticalFixes: true}

	next, err := NextEntitlement(f.current, EntitlementTransition{
		AddReleaseLines:  []ReleaseLine{newLine},
		DropReleaseLines: []string{"2026.1"},
	}, at(30), "nonce-2")
	require.NoError(t, err)
	require.Len(t, next.ReleaseLines, 1, "one dropped, one added")
	assert.Equal(t, "2027.0", next.ReleaseLines[0].Line)
	verified := signUpgrade(t, f, next, at(30))
	assert.False(t, verified.CriticalFixEntitledAt("2026.1", at(60)),
		"the dropped line's I25 window is closed from the NEXT document on")
	assert.True(t, verified.CriticalFixEntitledAt("2027.0", at(60)),
		"the added line's I25 window is open")
	// The CURRENT document is untouched by its successor's line changes.
	currentVerified := signUpgrade(t, f, f.current, corpusAnchor)
	assert.True(t, currentVerified.CriticalFixEntitledAt("2026.1", at(60)),
		"the old signed window keeps verifying offline (I24 run-right semantics)")

	_, err = NextEntitlement(f.current, EntitlementTransition{DropReleaseLines: []string{"9.9"}}, at(30), "nonce-2")
	require.ErrorContains(t, err, "not present", "dropping an absent line is refused")
	_, err = NextEntitlement(f.current, EntitlementTransition{AddReleaseLines: []ReleaseLine{{Line: "2026.1", SupportEnd: at(400)}}}, at(30), "nonce-2")
	require.ErrorContains(t, err, "already present", "re-adding a present line id is refused")
	_, err = NextEntitlement(f.current, EntitlementTransition{AddReleaseLines: []ReleaseLine{{Line: "2028.0"}}}, at(30), "nonce-2")
	require.ErrorContains(t, err, "names no support end")

	// Dropping the last line without adds leaves the nil (omitempty) shape,
	// which must still be issuable.
	dropAll, err := NextEntitlement(f.current, EntitlementTransition{DropReleaseLines: []string{"2026.1"}}, at(30), "nonce-2")
	require.NoError(t, err)
	assert.Nil(t, dropAll.ReleaseLines)
	signUpgrade(t, f, dropAll, at(30))

	// SupportEnd normalization: a non-UTC input is stored in UTC (the same
	// instant), and a non-UTC transition instant normalizes the same way.
	tokyo := time.FixedZone("stand-in", 3*3600)
	nonUTC, err := NextEntitlement(f.current, EntitlementTransition{AddReleaseLines: []ReleaseLine{{
		Line: "2027.1", SupportEnd: at(400).In(tokyo), CriticalFixes: true,
	}}}, at(30).In(tokyo), "nonce-2")
	require.NoError(t, err)
	require.Len(t, nonUTC.ReleaseLines, 2, "the current line is kept and the add appended")
	assert.Equal(t, "2027.1", nonUTC.ReleaseLines[1].Line)
	assert.True(t, nonUTC.ReleaseLines[1].SupportEnd.Equal(at(400)),
		"the support end keeps its instant")
	_, offset := nonUTC.ReleaseLines[1].SupportEnd.Zone()
	assert.Zero(t, offset, "the support end is stored in UTC")
	assert.Equal(t, at(30), nonUTC.IssuedAt, "the transition instant keeps its instant in UTC")
	signUpgrade(t, f, nonUTC, at(30).In(tokyo))
}

func TestNextEntitlement_IdentityStable(t *testing.T) {
	f := newUpgradeFixtures(t)
	kinds := []EntitlementTransition{
		{AddModules: []string{"protection-pack"}},
		{RemoveModules: []string{"media-persistence"}},
		{DropReleaseLines: []string{"2026.1"}},
		{AddReleaseLines: []ReleaseLine{{Line: "2027.0", SupportEnd: at(500)}}},
		{AddModules: []string{"protection-pack"}, RemoveModules: []string{"media-persistence"},
			AddReleaseLines: []ReleaseLine{{Line: "2027.0", SupportEnd: at(500)}}, DropReleaseLines: []string{"2026.1"}},
	}
	for i, tr := range kinds {
		next, err := NextEntitlement(f.current, tr, at(30), "nonce-2")
		require.NoError(t, err, "kind %d", i)
		// DeploymentID (:98) stability across every transition kind.
		assert.Equal(t, f.current.DeploymentID, next.DeploymentID, "kind %d: deployment is stable (I23)", i)
		assert.Equal(t, f.current.CustomerID, next.CustomerID, "kind %d: customer is stable", i)
		assert.Equal(t, ModuleEntitlementVersion, next.Version, "kind %d: the v2 pin carries over", i)
		require.NoError(t, IsEntitlementSuccessor(f.current, next), "kind %d", i)
	}

	// Hand-built successors that break identity are refused.
	hijacked := f.current
	hijacked.DeploymentID = "other-contour"
	hijacked.IssuedAt = at(31)
	hijacked.Nonce = "nonce-3"
	require.ErrorContains(t, IsEntitlementSuccessor(f.current, hijacked), "deployment changed",
		"a cross-contour successor is impossible (I23: an independent contour is a different license)")
	resold := f.current
	resold.CustomerID = "cust-other"
	resold.IssuedAt = at(31)
	resold.Nonce = "nonce-3"
	require.ErrorContains(t, IsEntitlementSuccessor(f.current, resold), "customer changed")
	reforked := f.current
	reforked.Version = "3"
	reforked.IssuedAt = at(31)
	reforked.Nonce = "nonce-3"
	require.ErrorContains(t, IsEntitlementSuccessor(f.current, reforked), "format version changed")
}

func TestNextEntitlement_MaintenanceTermRule(t *testing.T) {
	f := newUpgradeFixtures(t)
	tr := EntitlementTransition{AddModules: []string{"protection-pack"}}

	_, err := NextEntitlement(f.current, tr, at(181), "nonce-2")
	require.ErrorContains(t, err, "renewal required",
		"after the term ends an in-place transition is refused (I24: changes are renewal-gated)")

	_, err = NextEntitlement(f.current, tr, corpusAnchor.Add(180*24*time.Hour), "nonce-2")
	require.ErrorContains(t, err, "renewal required",
		"the exact MaintenanceEnd instant is refused too: UpdatesEntitledAt is inclusive there, but the re-issued document would need MaintenanceEnd strictly after its own IssuedAt")

	next, err := NextEntitlement(f.current, tr, corpusAnchor.Add(180*24*time.Hour).Add(-time.Nanosecond), "nonce-2")
	require.NoError(t, err, "one nanosecond before the term end the transition is expressible")
	signUpgrade(t, f, next, corpusAnchor.Add(180*24*time.Hour).Add(-time.Nanosecond))

	next, err = NextEntitlement(f.current, tr, at(1), "nonce-2")
	require.NoError(t, err, "deep inside the term the transition is expressible")
	signUpgrade(t, f, next, at(1))
}

func TestNextEntitlement_MonotonicityAndNonce(t *testing.T) {
	f := newUpgradeFixtures(t)
	tr := EntitlementTransition{AddModules: []string{"protection-pack"}}

	_, err := NextEntitlement(f.current, tr, corpusAnchor, "nonce-2")
	require.ErrorContains(t, err, "stale predecessor", "a same-instant re-issue replays the original issuance")
	_, err = NextEntitlement(f.current, tr, at(-1), "nonce-2")
	require.ErrorContains(t, err, "stale predecessor", "backdating below the current issuance is refused")
	_, err = NextEntitlement(f.current, tr, time.Time{}, "nonce-2")
	require.ErrorContains(t, err, "transition instant is required")
	_, err = NextEntitlement(f.current, EntitlementTransition{}, at(30), "nonce-2")
	require.ErrorContains(t, err, "empty transition", "a re-issue must change the document")
	_, err = NextEntitlement(f.current, tr, at(30), "")
	require.ErrorContains(t, err, "nonce is required")
	_, err = NextEntitlement(f.current, tr, at(30), f.current.Nonce)
	require.ErrorContains(t, err, "nonce must change")
	_, err = NextEntitlement(PaidModuleEntitlement{}, tr, at(30), "nonce-2")
	require.ErrorContains(t, err, "verify the current document first",
		"an unverified zero predecessor must not produce successors")

	// A foreign-version predecessor (the v1 legacy corpus shape) is refused
	// outright: no v2 successor may be derived from downgrade-era claims.
	v1Legacy := loadCorpusEntitlement(t, "version_skew_v1.json")
	_, err = NextEntitlement(v1Legacy, tr, at(30), "nonce-2")
	require.ErrorContains(t, err, "not a v2 document",
		"a v1 predecessor cannot produce a v2 successor (fail closed, battery D2 arm)")

	// Replay of the old token against the held successor is refused (the
	// consumer-side stale arm; the battery in upgrade_battery_test.go walks
	// the full corpus with it).
	next, err := NextEntitlement(f.current, tr, at(30), "nonce-2")
	require.NoError(t, err)
	require.ErrorContains(t, IsEntitlementSuccessor(next, f.current), "stale presentation",
		"once the successor is held, re-presenting the old token is refused")
	require.ErrorContains(t, IsEntitlementSuccessor(f.current, f.current), "stale presentation",
		"presenting the held document as its own successor is refused")
}

func TestNextEntitlement_TrialCarryOver(t *testing.T) {
	f := newUpgradeFixtures(t)
	tr := EntitlementTransition{AddModules: []string{"protection-pack"}}

	// A live trial carries over verbatim.
	withTrial := f.current
	withTrial.TrialEnd = at(60)
	next, err := NextEntitlement(withTrial, tr, at(30), "nonce-2")
	require.NoError(t, err)
	assert.Equal(t, at(60), next.TrialEnd, "a still-live trial is preserved, never extended")

	// An observably ended trial is re-recorded as the definitive no-trial
	// state (an explicit signed state change), because the carried value
	// would violate TrialEnd > IssuedAt on the successor.
	ended := f.current
	ended.TrialEnd = at(10)
	next, err = NextEntitlement(ended, tr, at(30), "nonce-2")
	require.NoError(t, err)
	assert.True(t, next.TrialEnd.IsZero(), "the ended trial is cleared to the definitive no-trial state")
	signUpgrade(t, f, next, at(30))

	// No trial in, no trial out.
	next, err = NextEntitlement(f.current, tr, at(30), "nonce-2")
	require.NoError(t, err)
	assert.True(t, next.TrialEnd.IsZero())
}

func TestIsEntitlementSuccessor_Ordering(t *testing.T) {
	f := newUpgradeFixtures(t)
	first, err := NextEntitlement(f.current, EntitlementTransition{AddModules: []string{"protection-pack"}}, at(30), "nonce-2")
	require.NoError(t, err)
	second, err := NextEntitlement(first, EntitlementTransition{AddModules: []string{"history-retention"}}, at(60), "nonce-3")
	require.NoError(t, err)

	require.NoError(t, IsEntitlementSuccessor(f.current, first), "a strictly newer same-identity document is a successor")
	require.NoError(t, IsEntitlementSuccessor(first, second), "the chain composes")
	require.ErrorContains(t, IsEntitlementSuccessor(second, first), "stale presentation",
		"the ordering is asymmetric (a fork is not a rollback)")

	// Equal instants and nonce reuse fail even with strictly valid documents.
	sameInstant := first
	sameInstant.Nonce = "nonce-3"
	sameInstant.Modules = append([]string(nil), first.Modules...)
	sameInstant.Modules = append(sameInstant.Modules, "history-retention")
	require.ErrorContains(t, IsEntitlementSuccessor(first, sameInstant), "stale presentation",
		"equal issuance instants are refused (same-instant fork)")
	nonceReuse := second
	nonceReuse.Nonce = first.Nonce
	require.ErrorContains(t, IsEntitlementSuccessor(first, nonceReuse), "nonce did not change")
	require.ErrorContains(t, IsEntitlementSuccessor(PaidModuleEntitlement{}, first), "verify it first")
}
