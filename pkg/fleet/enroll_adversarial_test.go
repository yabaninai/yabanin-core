// Adversarial enrollment battery (E03-P01 card W02-C03, batch A): the
// card's mandatory vectors — повтор/задержка (delayed replay); подмена
// идентичности (identity substitution); rollback часов не оживляет
// отозванную (clock rollback cannot revive a revoked installation); plus
// the N/A rows justified in-file. Fixed seeds and clocks: deterministic.
//
// N/A rows (justified here per the card «N/A неприменимых веток»):
//
//   - NETWORK branches: there is no network code in pkg/fleet — enrollment
//     verification is pure Ed25519 over local bytes and the registry is an
//     in-memory structure (persistence is W03-C03). No dial/DNS/HTTP
//     surface exists to attack from this battery; MITM/TLS-hardening rows
//     are vacuous at this seam.
//   - ONLINE revocation sources (OCSP/CRL distribution points): the
//     packet's revocation law is registry-LOCAL membership (revoke.go,
//     crl.go precedent adapted); no external revocation authority is
//     consulted, so spoofing one is not a reachable branch.
//   - PHYSICAL clock manipulation: the code under test takes every clock
//     as an injected parameter (determinism law), so "attacker controls
//     the clock" is modeled exactly as the rollback/delayed-replay arms
//     below — passing hostile values, with the fail-closed refusal pinned.
//   - PERSISTENCE attacks (registry swap, DB tampering): out of scope until
//     migration 0024 lands (W03-C03, batch B); the in-memory registry has
//     no such surface in batch A.
package fleet

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// advNow is the fixed adversarial test clock.
var advNow = time.Date(2026, 11, 8, 14, 0, 0, 0, time.UTC)

var advSeed = []byte("yabanin-e03-p01-advrsrl-seed-001") // 32 bytes, test-only

func advKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(advSeed)
	return priv.Public().(ed25519.PublicKey), priv
}

// advAttackerSeed is an independent attacker key (32 bytes, test-only).
var advAttackerSeed = []byte("yabanin-e03-p01-advrsrl-attacker")

func advAttackerPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(advAttackerSeed)
	return priv.Public().(ed25519.PublicKey), priv
}

// advIssue issues a deterministic enrollment token with the vendor key.
func advIssue(t *testing.T, deployment, org, nonce string, issued time.Time) string {
	t.Helper()
	_, priv := advKeyPair()
	token, err := IssueEnrollment(priv, EnrollmentRecord{
		OrgID:        org,
		DeploymentID: deployment,
		Nonce:        nonce,
		IssuedAt:     issued,
	}, issued)
	require.NoError(t, err)
	return token
}

// TestAdversarial_ImmediateReplay — «повтор»: the very same token, re-
// presented immediately (inside the freshness window, fresh signature,
// fresh nonce — a textbook replay), is refused, and the refusal does not
// disturb the original installation.
func TestAdversarial_ImmediateReplay(t *testing.T) {
	token := advIssue(t, "deploy-acme-prod-01", "org-acme", "adv-nonce-0001", advNow)
	pub, _ := advKeyPair()
	reg := NewRegistry()

	_, err := reg.ApplyEnrollment(token, pub, "org-acme", advNow, DefaultEnrollmentWindow)
	require.NoError(t, err)
	_, err = reg.ApplyEnrollment(token, pub, "org-acme", advNow.Add(time.Second), DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrReplay)

	ins, ok := reg.Lookup("deploy-acme-prod-01")
	require.True(t, ok)
	assert.Equal(t, StateEnrolled, ins.State, "original installation untouched")
}

// TestAdversarial_DelayedReplay — «задержка (delayed replay)»: the token
// comes back AFTER its freshness window. The refusal is pinned on BOTH
// surfaces with the composition order disclosed: ApplyEnrollment verifies
// FIRST (pure, stateless — the window refuses the document regardless of
// any journal state), so a window-expired replay is ErrStaleEnrollment
// against a warm registry AND against a fresh one; the nonce journal is
// the second layer for IN-WINDOW duplicates (the immediate-replay and
// nonce-reuse arms). Neither layer alone is trusted to carry the refusal.
func TestAdversarial_DelayedReplay(t *testing.T) {
	token := advIssue(t, "deploy-acme-prod-01", "org-acme", "adv-nonce-0002", advNow)
	pub, _ := advKeyPair()
	late := advNow.Add(DefaultEnrollmentWindow + time.Hour)
	reg := NewRegistry()
	_, err := reg.ApplyEnrollment(token, pub, "org-acme", advNow, DefaultEnrollmentWindow)
	require.NoError(t, err)

	// Warm registry (journal remembers the nonce): the pure window check
	// runs first and refuses — freshness precedes journal consultation.
	_, err = reg.ApplyEnrollment(token, pub, "org-acme", late, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrStaleEnrollment, "a window-expired document is stale, warm registry or not")

	// Fresh registry (no journal — the cross-process story): same refusal,
	// same class, statelessly.
	freshReg := NewRegistry()
	_, err = freshReg.ApplyEnrollment(token, pub, "org-acme", late, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrStaleEnrollment, "a window-expired document cannot enroll anywhere")

	// And the pure verifier agrees statelessly.
	_, err = VerifyEnrollment(token, pub, "org-acme", late, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrStaleEnrollment)

	// The journal layer stays armed for in-window duplicates: re-present
	// the same token while STILL inside the window (the delayed arm's
	// boundary case — delayed, but not yet stale).
	soon := advNow.Add(DefaultEnrollmentWindow - time.Second)
	_, err = reg.ApplyEnrollment(token, pub, "org-acme", soon, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrReplay, "in-window re-presentation hits the nonce journal")
}

// TestAdversarial_IdentitySubstitution — «подмена идентичности»: the
// attacker takes a validly signed document and swaps the deployment
// coordinate inside the payload. The signature check fails FIRST (the
// substituted coordinates are never trusted), and re-signing with the
// attacker's own key fails against the trusted vendor key. Neither
// canonical-Malleability nor key confusion opens an enrollment.
func TestAdversarial_IdentitySubstitution(t *testing.T) {
	token := advIssue(t, "deploy-acme-prod-01", "org-acme", "adv-nonce-0003", advNow)
	pub, _ := advKeyPair()

	// Payload surgery: decode, swap identity, re-encode, keep old sig.
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	require.True(t, ok)
	raw, err := base64.RawURLEncoding.DecodeString(payloadB64)
	require.NoError(t, err)
	swapped := strings.Replace(string(raw), "deploy-acme-prod-01", "deploy-victim-01", 1)
	require.NotEqual(t, string(raw), swapped, "fixture sanity")
	substituted := base64.RawURLEncoding.EncodeToString([]byte(swapped)) + "." + sigB64

	reg := NewRegistry()
	_, err = reg.ApplyEnrollment(substituted, pub, "org-acme", advNow, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEnrollmentSignature, "signature fails before any substituted coordinate is read")

	// The registry never learned the victim identity.
	_, ok = reg.Lookup("deploy-victim-01")
	assert.False(t, ok)
	_, ok = reg.Lookup("deploy-acme-prod-01")
	assert.False(t, ok, "the mangled document enrolled nobody")

	// Self-signed substitution: attacker re-issues the document for the
	// victim identity under the ATTACKER key.
	_, atkPriv := advAttackerPair()
	atkToken, err := IssueEnrollment(atkPriv, EnrollmentRecord{
		OrgID:        "org-acme",
		DeploymentID: "deploy-victim-01",
		Nonce:        "adv-nonce-0003",
		IssuedAt:     advNow,
	}, advNow)
	require.NoError(t, err)
	_, err = reg.ApplyEnrollment(atkToken, pub, "org-acme", advNow, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEnrollmentSignature, "a foreign-signed document never enrolls")
	_, ok = reg.Lookup("deploy-victim-01")
	assert.False(t, ok)
}

// TestAdversarial_CrossOrgSubstitution — identity substitution across the
// org boundary: a valid document for org-other presented with the victim
// org's verifier boundary is refused with ErrCrossOrg BEFORE any registry
// mutation (the cross-org arm of W02-C01, restated adversarially with a
// substituted expectedOrg — the document's own org stays signed and
// untampered; only the PRESENTATION boundary lies).
func TestAdversarial_CrossOrgSubstitution(t *testing.T) {
	token := advIssue(t, "deploy-acme-prod-01", "org-other", "adv-nonce-0004", advNow)
	pub, _ := advKeyPair()
	reg := NewRegistry()

	_, err := reg.ApplyEnrollment(token, pub, "org-acme", advNow, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCrossOrg)

	_, ok := reg.Lookup("deploy-acme-prod-01")
	assert.False(t, ok, "cross-org presentation enrolled nothing")
}

// TestAdversarial_ClockRollbackDoesNotRevive — «rollback часов не оживляет
// отозванную»: after revocation, hostile clock values (past-side rollback,
// future-side jump, pre-enrollment instants) cannot restore enrollment,
// issuance rights or re-entry. IsRevoked and the issuance gate consult NO
// clock at all — membership is a set fact, not a time comparison — and the
// revocation audit trail keeps its first instant even when a later Revoke
// carries a rolled-back clock.
func TestAdversarial_ClockRollbackDoesNotRevive(t *testing.T) {
	token := advIssue(t, "deploy-acme-prod-01", "org-acme", "adv-nonce-0005", advNow)
	pub, _ := advKeyPair()
	reg := NewRegistry()
	_, err := reg.ApplyEnrollment(token, pub, "org-acme", advNow, DefaultEnrollmentWindow)
	require.NoError(t, err)
	revokedAt := advNow.Add(time.Hour)
	require.NoError(t, reg.Revoke("deploy-acme-prod-01", "breach containment", revokedAt))

	// Hostile clocks, past to future.
	for _, at := range []time.Time{
		{},
		advNow.Add(-48 * time.Hour), // long before enrollment
		advNow,                      // before revocation
		revokedAt.Add(-time.Nanosecond),
		revokedAt,
		revokedAt.Add(365 * 24 * time.Hour), // far future
	} {
		// Membership: clock-free by construction.
		assert.True(t, reg.IsRevoked("deploy-acme-prod-01"), "IsRevoked takes no clock — rollback is impossible at %v", at)
		// Issuance: refused at every hostile instant.
		err := reg.AuthorizeSecretIssuance("deploy-acme-prod-01")
		require.Error(t, err, "at %v", at)
		require.ErrorIs(t, err, ErrRevoked, "at %v", at)
	}

	// Re-entry with a rolled-back issued-at: the window would accept the
	// OLD document as fresh (it was issued at advNow), revocation still
	// refuses it — the journal remembers the nonce AND the identity is
	// terminal.
	_, err = reg.ApplyEnrollment(token, pub, "org-acme", advNow.Add(time.Minute), DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrReplay)

	// A brand-new rolled-back document (fresh nonce, issued in the past
	// inside the window): revocation terminality refuses it regardless.
	newDoc := advIssue(t, "deploy-acme-prod-01", "org-acme", "adv-nonce-0006", advNow)
	_, err = reg.ApplyEnrollment(newDoc, pub, "org-acme", advNow.Add(time.Minute), DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRevoked, "a revoked identity never re-enters, whatever the clock says")

	// Rolled-back re-revocation cannot launder the audit trail.
	require.NoError(t, reg.Revoke("deploy-acme-prod-01", "laundering attempt", advNow.Add(-24*time.Hour)))
	ins, _ := reg.Lookup("deploy-acme-prod-01")
	assert.True(t, ins.RevokedAt.Equal(revokedAt), "first revocation instant survives the rollback")
	assert.Equal(t, "breach containment", ins.RevocationReason)
}

// TestAdversarial_ConcurrencyNoWindowOpens — the entry seam and the
// revocation seam race: concurrent ApplyEnrollment/Revoke/IsRevoked/
// AuthorizeSecretIssuance never open a window where a revoked installation
// is issuable or an identity enrolls twice (the registry mutex is the
// single serialization point; this battery is what -race actually loads).
// The race phase asserts only TRUE invariants (exactly one enrollment
// success; no revoked-but-allowed observation); which interleaving wins is
// deliberately free, so terminality is re-asserted deterministically after
// the join.
func TestAdversarial_ConcurrencyNoWindowOpens(t *testing.T) {
	pub, _ := advKeyPair()
	reg := NewRegistry()

	const routines = 16
	done := make(chan struct{}, routines*2)
	var enrollOK int64

	// Half the routines race to enroll the SAME identity with the SAME
	// token: exactly one may succeed.
	token := advIssue(t, "deploy-acme-prod-01", "org-acme", "adv-nonce-0007", advNow)
	for i := 0; i < routines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			if _, err := reg.ApplyEnrollment(token, pub, "org-acme", advNow, DefaultEnrollmentWindow); err == nil {
				atomic.AddInt64(&enrollOK, 1)
			}
		}()
	}
	// The other half revokes concurrently and probes the gate; every probe
	// must see either a refusal or a pre-revocation allow — never a
	// revoked-but-allowed inconsistency.
	for i := 0; i < routines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_ = reg.Revoke("deploy-acme-prod-01", "concurrent revocation", advNow.Add(time.Hour))
			if err := reg.AuthorizeSecretIssuance("deploy-acme-prod-01"); err == nil {
				if ins, ok := reg.Lookup("deploy-acme-prod-01"); ok && ins.State == StateRevoked {
					t.Error("issuance allowed while state is revoked")
				}
			}
		}()
	}
	for i := 0; i < routines*2; i++ {
		<-done
	}

	assert.EqualValues(t, 1, atomic.LoadInt64(&enrollOK), "exactly one enrollment may succeed")

	// Deterministic terminality after the race (Revoke is idempotent, so
	// this lands regardless of which racing revocation — if any — won).
	require.NoError(t, reg.Revoke("deploy-acme-prod-01", "post-race revocation", advNow.Add(2*time.Hour)))
	assert.True(t, reg.IsRevoked("deploy-acme-prod-01"), "the revocation won")
	require.ErrorIs(t, reg.AuthorizeSecretIssuance("deploy-acme-prod-01"), ErrRevoked)
}
