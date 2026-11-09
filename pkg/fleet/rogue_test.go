// Rogue battery (E03-P01 card W05-C02, batch C): end-to-end adversarial
// story arcs over the packet's seams — «rogue-зачисление отказано;
// отозванная повторная попытка отказана; секреты не получены end-to-end
// (отказ ВЫДАЧИ); delayed replay; rollback» — plus the routed rider (a)
// of the batch-A review: a REFUSED cross-org presentation does NOT
// consume the nonce (the journal writes only after every refusal,
// enroll.go:287 / health.go:311 — pinned here behaviorally, both refusal
// sides, with a negative control that the journal still bites).
//
// Framing law: the batch-A/batteries pin unit edges; these arcs walk a
// whole adversary STORY through the real seams (issue → present →
// registry → gate), asserting after every step that the rogue received
// nothing and the registry learned nothing. Fixed seeds and clocks:
// deterministic (no rand/env; determinism law).
//
// N/A rows (in-file justification, per the card's «Обязательные
// варианты» rule and the W05-C01 threat model §8):
//
//   - STORE-plane arms (revoked-caps-refresh through UpsertCaps, RLS
//     isolation, fake rows): the PG/Docker environment belongs to the
//     W03-C03 battery (caps_store_test.go, real PG) — the SQL-layer
//     terminality twin is pinned there (TestCapsStore_RevokedIsTerminal);
//     disjunct by environment, not by law.
//   - NETWORK branches: pkg/fleet has no network code — verification is
//     pure Ed25519 over local bytes (offline by construction,
//     TestIdentityVerify_OfflineByConstruction).
//   - PHYSICAL clock manipulation: every clock is an injected parameter;
//     "attacker controls the clock" is modeled as hostile VALUES exactly
//     as in the rollback/delayed arms below (batch-A precedent).
//   - OCSP/CRL external authorities: revocation is registry-LOCAL
//     membership (revoke.go); no external authority exists to spoof.
package fleet

import (
	"crypto/ed25519"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rogNow is the fixed rogue-battery clock.
var rogNow = time.Date(2026, 11, 8, 16, 0, 0, 0, time.UTC)

// Fixed test-only seeds: the vendor (trusted issuer) and an independent
// rogue operator with their own key material.
var (
	rogVendorSeed = []byte("yabanin-e03-p01-rogue-vendor-001") // 32 bytes, test-only
	rogRogueSeed  = []byte("yabanin-e03-p01-rogue-attacker01") // 32 bytes, test-only
)

func rogVendorPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(rogVendorSeed)
	return priv.Public().(ed25519.PublicKey), priv
}

func rogRoguePair() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(rogRogueSeed)
	return priv.Public().(ed25519.PublicKey), priv
}

// rogEnrollDoc issues a vendor-signed enrollment document.
func rogEnrollDoc(t *testing.T, priv ed25519.PrivateKey, org, deployment, nonce string, issued time.Time) string {
	t.Helper()
	token, err := IssueEnrollment(priv, EnrollmentRecord{
		OrgID: org, DeploymentID: deployment, Nonce: nonce, IssuedAt: issued,
	}, issued)
	require.NoError(t, err)
	return token
}

// rogBeatDoc issues a vendor-signed heartbeat document.
func rogBeatDoc(t *testing.T, priv ed25519.PrivateKey, org, deployment, nonce string, issued time.Time) string {
	t.Helper()
	token, err := IssueHeartbeat(priv, HeartbeatRecord{
		OrgID: org, DeploymentID: deployment, Nonce: nonce, IssuedAt: issued,
	}, issued)
	require.NoError(t, err)
	return token
}

// rogEnrolled walks the REAL seams to one enrolled installation.
func rogEnrolled(t *testing.T, reg *Registry, pub ed25519.PublicKey, priv ed25519.PrivateKey, org, deployment, nonce string, at time.Time) Installation {
	t.Helper()
	token := rogEnrollDoc(t, priv, org, deployment, nonce, at)
	ins, err := reg.ApplyEnrollment(token, pub, org, at, DefaultEnrollmentWindow)
	require.NoError(t, err)
	return ins
}

// TestRogue_ForeignSignedEnrollmentEndToEnd — «rogue-зачисление
// отказано», the whole story: a rogue operator (own key) spends every
// seam — enrollment of a rogue deployment, heartbeat for the ghost,
// issuance gate — and receives NOTHING at any of them; two independent
// registries (stateless verifier twin) refuse identically; neither
// registry learns a single coordinate.
func TestRogue_ForeignSignedEnrollmentEndToEnd(t *testing.T) {
	vendorPub, _ := rogVendorPair()
	_, roguePriv := rogRoguePair()
	regA, regB := NewRegistry(), NewRegistry()

	// The rogue's own enrollment document for their deployment.
	rogueToken := rogEnrollDoc(t, roguePriv, "org-acme", "deploy-rogue-01", "rog-nonce-0001", rogNow)
	for name, reg := range map[string]*Registry{"warm": regA, "fresh-twin": regB} {
		_, err := reg.ApplyEnrollment(rogueToken, vendorPub, "org-acme", rogNow, DefaultEnrollmentWindow)
		require.ErrorIs(t, err, ErrEnrollmentSignature, "%s registry: a foreign-signed document never enrolls", name)
		_, ok := reg.Lookup("deploy-rogue-01")
		assert.False(t, ok, "%s registry: the rogue identity was never learned", name)
	}

	// The ghost heartbeat: signature fails before any state question.
	rogueBeat := rogBeatDoc(t, roguePriv, "org-acme", "deploy-rogue-01", "rog-nonce-0002", rogNow)
	_, err := regA.ApplyHeartbeat(rogueBeat, vendorPub, "org-acme", rogNow, DefaultFatigueWindow)
	require.ErrorIs(t, err, ErrHeartbeatSignature)

	// And the packet's own verdict: the ghost receives no secrets.
	err = regA.AuthorizeSecretIssuance("deploy-rogue-01")
	require.ErrorIs(t, err, ErrNotEnrolled, "unknown identity: nothing at all, fail-closed")
	err = regA.AuthorizeSecretIssuance("")
	require.ErrorIs(t, err, ErrNotEnrolled)
}

// TestRogue_RevokedReEnrollmentRefusedEndToEnd — «отозванная повторная
// попытка отказана», the whole lifecycle arc: enroll → heartbeat
// (active) → revoke → every re-entry attempt (fresh re-enrollment,
// heartbeat, clock games, re-revocation) fails or preserves the first
// fact; the installation stays terminal and unissueable end-to-end.
func TestRogue_RevokedReEnrollmentRefusedEndToEnd(t *testing.T) {
	pub, priv := rogVendorPair()
	reg := NewRegistry()
	const deploy = "deploy-acme-prod-01"
	rogEnrolled(t, reg, pub, priv, "org-acme", deploy, "rog-nonce-0010", rogNow)

	// Active through the real health seam.
	beatAt := rogNow.Add(time.Minute)
	_, err := reg.ApplyHeartbeat(rogBeatDoc(t, priv, "org-acme", deploy, "rog-nonce-0011", beatAt), pub, "org-acme", beatAt, DefaultFatigueWindow)
	require.NoError(t, err)

	// Revocation (the operator's containment action).
	revokedAt := rogNow.Add(time.Hour)
	require.NoError(t, reg.Revoke(deploy, "breach containment", revokedAt))

	// Re-entry 1: a FRESH, correctly signed, transport-fresh enrollment
	// document issued AFTER the revocation — refused, terminal.
	reAt := revokedAt.Add(time.Minute)
	reToken := rogEnrollDoc(t, priv, "org-acme", deploy, "rog-nonce-0012", reAt)
	_, err = reg.ApplyEnrollment(reToken, pub, "org-acme", reAt, DefaultEnrollmentWindow)
	require.ErrorIs(t, err, ErrRevoked, "a revoked identity never re-enters through enrollment")

	// Re-entry 2: heartbeat revival — refused, record untouched.
	before, _ := reg.Lookup(deploy)
	_, err = reg.ApplyHeartbeat(rogBeatDoc(t, priv, "org-acme", deploy, "rog-nonce-0013", reAt), pub, "org-acme", reAt, DefaultFatigueWindow)
	require.ErrorIs(t, err, ErrRevoked)
	after, _ := reg.Lookup(deploy)
	assert.Equal(t, before.LastHeartbeatAt, after.LastHeartbeatAt, "revoked record untouched by the refused beat")

	// Re-entry 3: re-revocation is idempotent and launders nothing — the
	// FIRST instant and reason survive a rolled-back second Revoke.
	require.NoError(t, reg.Revoke(deploy, "laundering attempt", revokedAt.Add(-24*time.Hour)))
	ins, _ := reg.Lookup(deploy)
	assert.True(t, ins.RevokedAt.Equal(revokedAt), "first revocation instant preserved")
	assert.Equal(t, "breach containment", ins.RevocationReason)

	// Hostile evaluation clocks change nothing: membership and status
	// consult no clock for a revoked installation.
	hostileClocks := []time.Time{
		{},
		rogNow.Add(-72 * time.Hour),
		revokedAt,
		rogNow.Add(365 * 24 * time.Hour),
	}
	for _, at := range hostileClocks {
		assert.True(t, reg.IsRevoked(deploy), "membership takes no clock (at %v)", at)
		status, err := HealthStatus(ins, at, DefaultFatigueWindow)
		require.NoError(t, err, "revoked asks no clock question (at %v)", at)
		assert.Equal(t, StateRevoked, status)
		require.ErrorIs(t, reg.AuthorizeSecretIssuance(deploy), ErrRevoked, "issuance refused at %v", at)
	}
}

// TestRogue_SecretsNeverIssuedEndToEnd — the PACKET LAW end-to-end
// («отозванная установка не получает секреты», отказ ВЫДАЧИ): one arc
// walks every lifecycle phase through its REAL transition and probes
// the issuance gate at each step — unknown refuses, live phases issue,
// ONLY revocation refuses — and pins the structural half of the law:
// no record anywhere in the registry model carries secret material, so
// there is nothing to steal even before the gate refuses.
func TestRogue_SecretsNeverIssuedEndToEnd(t *testing.T) {
	pub, priv := rogVendorPair()
	reg := NewRegistry()
	const deploy = "deploy-acme-prod-02"

	// Phase 1: unknown — nothing at all.
	require.ErrorIs(t, reg.AuthorizeSecretIssuance(deploy), ErrNotEnrolled)

	// Phase 2: enrolled (real seam) — issuable.
	rogEnrolled(t, reg, pub, priv, "org-acme", deploy, "rog-nonce-0020", rogNow)
	require.NoError(t, reg.AuthorizeSecretIssuance(deploy))

	// Phase 3: active (real heartbeat) — issuable.
	beatAt := rogNow.Add(time.Minute)
	_, err := reg.ApplyHeartbeat(rogBeatDoc(t, priv, "org-acme", deploy, "rog-nonce-0021", beatAt), pub, "org-acme", beatAt, DefaultFatigueWindow)
	require.NoError(t, err)
	require.NoError(t, reg.AuthorizeSecretIssuance(deploy))

	// Phase 4: stale (real fatigue expiry) — the status is EXPLICIT and
	// still issuable: staleness is observability, not punishment (the
	// W04-C01-owned policy, SM-6 of the threat model; only revocation
	// punishes).
	staleAt := beatAt.Add(DefaultFatigueWindow + time.Minute)
	ins, _ := reg.Lookup(deploy)
	status, err := HealthStatus(ins, staleAt, DefaultFatigueWindow)
	require.NoError(t, err)
	require.Equal(t, StateStale, status, "stale is explicit before the gate question")
	require.NoError(t, reg.AuthorizeSecretIssuance(deploy), "stale stays issuable — the disclosed policy")

	// Phase 5: revoked — THE refusal. The packet's punishment is refusal
	// of ISSUANCE, never a stored secret to lose.
	require.NoError(t, reg.Revoke(deploy, "contract terminated", staleAt))
	err = reg.AuthorizeSecretIssuance(deploy)
	require.ErrorIs(t, err, ErrRevoked)
	require.Contains(t, err.Error(), "contract terminated", "the refusal carries the audit trail")

	// Structural half: the registry records carry no key material — the
	// identity-model §2 law, pinned reflectively for BOTH record shapes
	// (in-memory Installation and the store twin StoredInstallation) so a
	// future secret-bearing field addition fails HERE first.
	for _, typ := range []reflect.Type{reflect.TypeOf(Installation{}), reflect.TypeOf(StoredInstallation{})} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			assert.NotEqual(t, reflect.Slice, f.Type.Kind(), "%s.%s must not be a slice (no raw key bytes)", typ.Name(), f.Name)
			name := f.Type.String() + " " + f.Name
			assert.NotContains(t, strings.ToLower(name), "ed25519", "%s.%s must not carry key material", typ.Name(), f.Name)
			assert.NotContains(t, strings.ToLower(name), "private", "%s.%s must not carry key material", typ.Name(), f.Name)
			assert.NotContains(t, strings.ToLower(name), "secret", "%s.%s must not carry key material", typ.Name(), f.Name)
		}
	}
}

// TestRogue_DelayedReplayEndToEnd — «повтор/задержка события», both
// domains end-to-end: captured enrollment and heartbeat documents come
// back late (outside the transport window — stateless refusal on warm
// AND fresh registries), on time (in-window duplicate — the nonce
// journal refuses), and cross-domain (an enrollment token re-used at
// the heartbeat seam and vice versa — the document-type law refuses);
// the original installation is untouched after every attempt.
func TestRogue_DelayedReplayEndToEnd(t *testing.T) {
	pub, priv := rogVendorPair()
	reg, freshReg := NewRegistry(), NewRegistry()
	const deploy = "deploy-acme-prod-03"

	// The legitimate capture: one enrollment + one heartbeat document.
	enrollTok := rogEnrollDoc(t, priv, "org-acme", deploy, "rog-nonce-0030", rogNow)
	_, err := reg.ApplyEnrollment(enrollTok, pub, "org-acme", rogNow, DefaultEnrollmentWindow)
	require.NoError(t, err)
	beatTok := rogBeatDoc(t, priv, "org-acme", deploy, "rog-nonce-0031", rogNow)
	_, err = reg.ApplyHeartbeat(beatTok, pub, "org-acme", rogNow, DefaultFatigueWindow)
	require.NoError(t, err)

	// Late enrollment replay: stateless window refusal, warm registry…
	late := rogNow.Add(DefaultEnrollmentWindow + time.Hour)
	_, err = reg.ApplyEnrollment(enrollTok, pub, "org-acme", late, DefaultEnrollmentWindow)
	require.ErrorIs(t, err, ErrStaleEnrollment, "window-expired enrollment is stale against a warm registry")
	// …and the fresh-registry twin (no journal — cross-process story).
	_, err = freshReg.ApplyEnrollment(enrollTok, pub, "org-acme", late, DefaultEnrollmentWindow)
	require.ErrorIs(t, err, ErrStaleEnrollment, "…and anywhere else: the refusal is stateless")

	// Late heartbeat replay: same law on the health seam.
	_, err = reg.ApplyHeartbeat(beatTok, pub, "org-acme", rogNow.Add(DefaultFatigueWindow+time.Hour), DefaultFatigueWindow)
	require.ErrorIs(t, err, ErrStaleHeartbeat)

	// On-time duplicate: the nonce journal layer refuses in-window repeats.
	soon := rogNow.Add(DefaultEnrollmentWindow - time.Second)
	_, err = reg.ApplyEnrollment(enrollTok, pub, "org-acme", soon, DefaultEnrollmentWindow)
	require.ErrorIs(t, err, ErrReplay, "in-window re-presentation hits the nonce journal")

	// Cross-domain re-use: an enrollment token is not a heartbeat…
	_, err = reg.ApplyHeartbeat(enrollTok, pub, "org-acme", rogNow, DefaultFatigueWindow)
	require.ErrorIs(t, err, ErrInvalidHeartbeat, "document-type law: enrollment ≠ heartbeat")
	// …and a heartbeat is not an enrollment token.
	_, err = reg.ApplyEnrollment(beatTok, pub, "org-acme", rogNow, DefaultEnrollmentWindow)
	require.ErrorIs(t, err, ErrInvalidEnrollment, "document-type law: heartbeat ≠ enrollment")

	// The original survived every attempt: still enrolled-and-beat, nothing
	// rewound, no second record.
	ins, ok := reg.Lookup(deploy)
	require.True(t, ok)
	assert.Equal(t, StateActive, ins.State)
	require.NotNil(t, ins.LastHeartbeatAt)
	assert.True(t, ins.LastHeartbeatAt.Equal(rogNow))
	assert.Len(t, reg.installations, 1)
}

// TestRogue_ClockRollbackEndToEnd — «rollback», three hostile-clock
// stories: (a) a rolled-back fresh enrollment document cannot revive a
// revoked installation; (b) a rolled-back (older IssuedAt) heartbeat,
// however transport-fresh, cannot rewind the monotone liveness clock —
// the stale-visibility clock keeps ticking from the LAST accepted beat;
// (c) a PRE-ISSUED heartbeat from beyond the future edge of the
// symmetric window is refused — the rogue cannot stockpile future
// liveness (the SM-3 pin; the enrollment side of the window is pinned
// to the nanosecond in both directions by enroll_test.go:224-228).
func TestRogue_ClockRollbackEndToEnd(t *testing.T) {
	pub, priv := rogVendorPair()
	reg := NewRegistry()
	const deploy = "deploy-acme-prod-04"
	rogEnrolled(t, reg, pub, priv, "org-acme", deploy, "rog-nonce-0040", rogNow)

	// (a) Rollback does not revive the revoked.
	revokedAt := rogNow.Add(time.Hour)
	require.NoError(t, reg.Revoke(deploy, "breach containment", revokedAt))
	// Document issued BEFORE the revocation instant, presented while still
	// transport-fresh (the window would accept it): terminality refuses —
	// ordering does not save the attacker (freshness :207 passes, the
	// revoked re-entry check :279 refuses).
	freshRolledBack := revokedAt.Add(-time.Minute)
	rolledBack := rogEnrollDoc(t, priv, "org-acme", deploy, "rog-nonce-0041", freshRolledBack)
	_, err := reg.ApplyEnrollment(rolledBack, pub, "org-acme", revokedAt.Add(time.Minute), DefaultEnrollmentWindow)
	require.ErrorIs(t, err, ErrRevoked, "a rolled-back document cannot revive the revoked")

	// (b) Monotone liveness: an older-but-fresh beat never rewinds time.
	reg2 := NewRegistry()
	rogEnrolled(t, reg2, pub, priv, "org-acme", "deploy-acme-prod-05", "rog-nonce-0042", rogNow)
	t2 := rogNow.Add(10 * time.Minute)
	_, err = reg2.ApplyHeartbeat(rogBeatDoc(t, priv, "org-acme", "deploy-acme-prod-05", "rog-nonce-0043", t2), pub, "org-acme", t2, DefaultFatigueWindow)
	require.NoError(t, err)
	// A second beat issued EARLIER (t2-5m), delivered late but inside the
	// transport window: accepted as a signal, powerless to rewind.
	older := t2.Add(-5 * time.Minute)
	_, err = reg2.ApplyHeartbeat(rogBeatDoc(t, priv, "org-acme", "deploy-acme-prod-05", "rog-nonce-0044", older), pub, "org-acme", t2.Add(time.Minute), DefaultFatigueWindow)
	require.NoError(t, err, "an older transport-fresh beat is a valid signal")
	ins, _ := reg2.Lookup("deploy-acme-prod-05")
	require.NotNil(t, ins.LastHeartbeatAt)
	assert.True(t, ins.LastHeartbeatAt.Equal(t2), "liveness was not rewound")
	// Stale visibility follows the LAST accepted beat, not the attacker's
	// rolled-back instant: the status is computed from t2.
	status, err := HealthStatus(ins, t2.Add(DefaultFatigueWindow+time.Second), DefaultFatigueWindow)
	require.NoError(t, err)
	assert.Equal(t, StateStale, status, "staleness derives from the monotone clock — rollback cannot mask it")

	// (c) Pre-issued liveness from the future: beyond the future edge of
	// the symmetric window the document is stale — no stockpiled beats.
	future := rogNow.Add(2 * DefaultFatigueWindow)
	_, err = reg2.ApplyHeartbeat(rogBeatDoc(t, priv, "org-acme", "deploy-acme-prod-05", "rog-nonce-0045", future), pub, "org-acme", rogNow, DefaultFatigueWindow)
	require.ErrorIs(t, err, ErrStaleHeartbeat, "a future-dated heartbeat beyond the window is refused (symmetric window)")
}

// TestRogue_CrossOrgNonceJournalUntouched — RIDER (a) of the batch-A
// review: a REFUSED cross-org presentation does NOT consume the nonce
// (the journal writes only after every refusal). Three refusal classes:
// verifier-side enrollment (enroll.go:196), verifier-side heartbeat
// (health.go:213) and registry-side heartbeat (health.go:301-305, the
// token verified against the serving org but the installation belongs
// to another). After each refusal the same nonce must still be usable
// at the RIGHTFUL boundary — the document is not burned by the
// attacker's failed presentation. Negative control: at the rightful
// boundary the journal DOES consume (a genuine duplicate still refuses
// with ErrReplay) — the property is precision, not a dead journal.
func TestRogue_CrossOrgNonceJournalUntouched(t *testing.T) {
	pub, priv := rogVendorPair()

	// Part 1 — enrollment, verifier-side refusal. A document for org-b
	// presented at the org-a verifier boundary.
	const nonce1 = "rog-nonce-0050"
	orgBDoc := rogEnrollDoc(t, priv, "org-b", "deploy-acme-prod-06", nonce1, rogNow)
	regA := NewRegistry()
	_, err := regA.ApplyEnrollment(orgBDoc, pub, "org-a", rogNow, DefaultEnrollmentWindow)
	require.ErrorIs(t, err, ErrCrossOrg)
	_, ok := regA.Lookup("deploy-acme-prod-06")
	assert.False(t, ok, "cross-org presentation enrolled nothing at the wrong boundary")

	// The same token at the RIGHTFUL boundary: success — the refused
	// presentation consumed nothing.
	regB := NewRegistry()
	_, err = regB.ApplyEnrollment(orgBDoc, pub, "org-b", rogNow, DefaultEnrollmentWindow)
	require.NoError(t, err, "rider (a): a refused cross-org presentation must not burn the nonce")
	// Negative control: the journal works — the same nonce again refuses.
	_, err = regB.ApplyEnrollment(orgBDoc, pub, "org-b", rogNow.Add(time.Second), DefaultEnrollmentWindow)
	require.ErrorIs(t, err, ErrReplay, "control: a genuine duplicate is still refused by the journal")

	// Part 2 — heartbeat, verifier-side refusal. org-b's beat at the
	// org-a verifier. (deploy-acme-prod-06 is already live in regB from
	// Part 1's rightful-boundary success.)
	const nonce2 = "rog-nonce-0051"
	beatB := rogBeatDoc(t, priv, "org-b", "deploy-acme-prod-06", nonce2, rogNow)
	_, err = regB.ApplyHeartbeat(beatB, pub, "org-a", rogNow, DefaultFatigueWindow)
	require.ErrorIs(t, err, ErrCrossOrg, "verifier-side cross-org heartbeat refused")
	// Same token at the rightful boundary: accepted — nonce intact.
	_, err = regB.ApplyHeartbeat(beatB, pub, "org-b", rogNow, DefaultFatigueWindow)
	require.NoError(t, err, "rider (a): the refused cross-org beat did not consume its nonce")

	// Part 3 — heartbeat, REGISTRY-side refusal (the deepest arm): the
	// heartbeat names org-a and VERIFIES against the org-a boundary, but
	// the deployment belongs to org-b — the registry refuses to migrate
	// coordinates (health.go:301-305) AFTER the journal read and BEFORE
	// the journal write, leaving the nonce consumable for the rightful
	// presentation.
	const nonce3 = "rog-nonce-0053"
	crossBeat := rogBeatDoc(t, priv, "org-a", "deploy-acme-prod-06", nonce3, rogNow.Add(time.Minute))
	_, err = regB.ApplyHeartbeat(crossBeat, pub, "org-a", rogNow.Add(time.Minute), DefaultFatigueWindow)
	require.ErrorIs(t, err, ErrCrossOrg, "registry-side cross-org heartbeat refused (coordinates never migrate)")
	ins, _ := regB.Lookup("deploy-acme-prod-06")
	assert.Equal(t, "org-b", ins.OrgID, "the installation stayed where it was enrolled")
	// A DIFFERENT valid heartbeat with the SAME nonce for the rightful
	// org succeeds: the refused presentation left the journal untouched.
	rightful := rogBeatDoc(t, priv, "org-b", "deploy-acme-prod-06", nonce3, rogNow.Add(2*time.Minute))
	_, err = regB.ApplyHeartbeat(rightful, pub, "org-b", rogNow.Add(2*time.Minute), DefaultFatigueWindow)
	require.NoError(t, err, "rider (a): the registry-side refusal did not burn the nonce either")
}
