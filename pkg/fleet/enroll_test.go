// Signed enrollment battery (E03-P01 card W02-C01, batch A): the card's
// mandatory variants — валидное зачисление; повтор (replay) отказ; forged
// подпись; cross-org попытка отказана; пустой org = отказ — plus the
// freshness window and registry-composition arms. Fixed seed, fixed clock:
// deterministic (determinism law; no time.Now/rand/env anywhere here).
package fleet

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enrNow is the fixed enrollment test clock.
var enrNow = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

// enrSeed derives the deterministic vendor test key (test-only).
var enrSeed = []byte("yabanin-e03-p01-enroll-seed-0001")

func enrKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(enrSeed)
	return priv.Public().(ed25519.PublicKey), priv
}

// enrToken issues a deterministic enrollment token for the standard
// fixture contour.
func enrToken(t *testing.T, deployment, org, nonce string, issued time.Time) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv := enrKeyPair()
	token, err := IssueEnrollment(priv, EnrollmentRecord{
		OrgID:        org,
		DeploymentID: deployment,
		Nonce:        nonce,
		IssuedAt:     issued,
	}, enrNow)
	require.NoError(t, err)
	return token, pub
}

// TestEnrollment_ValidRoundTrip — «валидное зачисление»: issue → verify →
// apply; the installation lands enrolled with the exact public coordinates.
func TestEnrollment_ValidRoundTrip(t *testing.T) {
	token, pub := enrToken(t, "deploy-acme-prod-01", "org-acme", "nonce-0001", enrNow)

	rec, err := VerifyEnrollment(token, pub, "org-acme", enrNow, DefaultEnrollmentWindow)
	require.NoError(t, err)
	assert.Equal(t, EnrollmentVersion, rec.Version)
	assert.Equal(t, "deploy-acme-prod-01", rec.DeploymentID)
	assert.Equal(t, "org-acme", rec.OrgID)
	assert.Equal(t, "nonce-0001", rec.Nonce)
	assert.True(t, rec.IssuedAt.Equal(enrNow))

	reg := NewRegistry()
	ins, err := reg.ApplyEnrollment(token, pub, "org-acme", enrNow, DefaultEnrollmentWindow)
	require.NoError(t, err)
	assert.Equal(t, StateEnrolled, ins.State)
	assert.Equal(t, "deploy-acme-prod-01", ins.DeploymentID)
	assert.Equal(t, "org-acme", ins.OrgID)
	assert.True(t, ins.EnrolledAt.Equal(enrNow))
}

// TestEnrollment_ReplayRefused — «повтор (replay) отказ»: the same token
// presented twice is refused the second time (nonce journal), and a SECOND
// valid token reusing the same nonce is refused as well.
func TestEnrollment_ReplayRefused(t *testing.T) {
	token, pub := enrToken(t, "deploy-acme-prod-01", "org-acme", "nonce-0001", enrNow)
	reg := NewRegistry()
	_, err := reg.ApplyEnrollment(token, pub, "org-acme", enrNow, DefaultEnrollmentWindow)
	require.NoError(t, err)

	_, err = reg.ApplyEnrollment(token, pub, "org-acme", enrNow.Add(time.Second), DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrReplay)

	// Same nonce, different (would-be valid) document: still a replay.
	reused, err := IssueEnrollment(func() ed25519.PrivateKey {
		_, priv := enrKeyPair()
		return priv
	}(), EnrollmentRecord{
		OrgID:        "org-acme",
		DeploymentID: "deploy-acme-prod-02",
		Nonce:        "nonce-0001",
		IssuedAt:     enrNow,
	}, enrNow)
	require.NoError(t, err)
	_, err = reg.ApplyEnrollment(reused, pub, "org-acme", enrNow, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrReplay)
}

// TestEnrollment_ForgedSignature — «forged подпись»: payload tampering and
// a foreign signer are both refused by the signature check before any
// coordinates are trusted.
func TestEnrollment_ForgedSignature(t *testing.T) {
	token, pub := enrToken(t, "deploy-acme-prod-01", "org-acme", "nonce-0001", enrNow)

	// Foreign key: independently signed, otherwise identical document.
	_, attacker := foreignKey()
	forged, err := IssueEnrollment(attacker, EnrollmentRecord{
		OrgID:        "org-acme",
		DeploymentID: "deploy-acme-prod-01",
		Nonce:        "nonce-0001",
		IssuedAt:     enrNow,
	}, enrNow)
	require.NoError(t, err)
	_, err = VerifyEnrollment(forged, pub, "org-acme", enrNow, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEnrollmentSignature)

	// Garbage token forms fail closed too.
	for _, bad := range []string{"", "not-a-token", "aaaa.bbbb", "!!!!.****", token + "x"} {
		_, err := VerifyEnrollment(bad, pub, "org-acme", enrNow, DefaultEnrollmentWindow)
		require.Error(t, err, "token %q", bad)
	}
}

// TestEnrollment_CrossOrgRefused — «cross-org попытка отказана»: a document
// signed for org A presented to org B's verifier is refused with
// ErrCrossOrg, even though it is fresh and correctly signed.
func TestEnrollment_CrossOrgRefused(t *testing.T) {
	token, pub := enrToken(t, "deploy-acme-prod-01", "org-acme", "nonce-0001", enrNow)
	_, err := VerifyEnrollment(token, pub, "org-other", enrNow, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCrossOrg)

	reg := NewRegistry()
	_, err = reg.ApplyEnrollment(token, pub, "org-other", enrNow, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCrossOrg)
}

// TestEnrollment_EmptyOrgRefused — «пустой org = отказ»: empty org on the
// document side AND on the verifier side are both refused.
func TestEnrollment_EmptyOrgRefused(t *testing.T) {
	_, priv := enrKeyPair()
	_, err := IssueEnrollment(priv, EnrollmentRecord{
		OrgID:        "",
		DeploymentID: "deploy-acme-prod-01",
		Nonce:        "nonce-0001",
		IssuedAt:     enrNow,
	}, enrNow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOrg)

	token, pub := enrToken(t, "deploy-acme-prod-01", "org-acme", "nonce-0002", enrNow)
	_, err = VerifyEnrollment(token, pub, "", enrNow, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidEnrollment)
}

// TestEnrollment_IssuanceValidation — the issuer fails closed on malformed
// documents (bad version, invalid coordinates, empty/padded nonce, zero
// clock), so a malformed document cannot even exist.
func TestEnrollment_IssuanceValidation(t *testing.T) {
	_, priv := enrKeyPair()
	base := EnrollmentRecord{
		OrgID:        "org-acme",
		DeploymentID: "deploy-acme-prod-01",
		Nonce:        "nonce-0001",
		IssuedAt:     enrNow,
	}

	badVersion := base
	badVersion.Version = "2"
	_, err := IssueEnrollment(priv, badVersion, enrNow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidEnrollment)

	badDeploy := base
	badDeploy.DeploymentID = " padded"
	_, err = IssueEnrollment(priv, badDeploy, enrNow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidDeploymentID)

	badNonce := base
	badNonce.Nonce = " "
	_, err = IssueEnrollment(priv, badNonce, enrNow)
	require.Error(t, err)

	emptyNonce := base
	emptyNonce.Nonce = ""
	_, err = IssueEnrollment(priv, emptyNonce, enrNow)
	require.Error(t, err)

	noClock := base
	noClock.IssuedAt = time.Time{}
	_, err = IssueEnrollment(priv, noClock, time.Time{})
	require.Error(t, err)

	badKey := make([]byte, 8)
	_, err = IssueEnrollment(badKey, base, enrNow)
	require.Error(t, err)

	// Version defaults and IssuedAt defaults are the only leniency, and
	// both are pinned: defaulted doc verifies.
	defaulted, err := IssueEnrollment(priv, EnrollmentRecord{
		OrgID:        "org-acme",
		DeploymentID: "deploy-acme-prod-01",
		Nonce:        "nonce-0003",
	}, enrNow)
	require.NoError(t, err)
	pub, _ := enrKeyPair()
	_, err = VerifyEnrollment(defaulted, pub, "org-acme", enrNow, DefaultEnrollmentWindow)
	require.NoError(t, err)
}

// TestEnrollment_FreshnessWindow — the injectable-clock window: inside is
// accepted (both skew directions, to the nanosecond bound); outside is
// stale; zero/non-positive windows and a zero verification clock are
// refused outright.
func TestEnrollment_FreshnessWindow(t *testing.T) {
	token, pub := enrToken(t, "deploy-acme-prod-01", "org-acme", "nonce-0001", enrNow)
	window := DefaultEnrollmentWindow

	for _, tc := range []struct {
		at   time.Time
		ok   bool
		note string
	}{
		{enrNow, true, "exact issue instant"},
		{enrNow.Add(window - time.Nanosecond), true, "last nanosecond of the window"},
		{enrNow.Add(window), true, "the exact window edge (inclusive)"},
		{enrNow.Add(window + time.Nanosecond), false, "one nanosecond past the window is stale"},
		{enrNow.Add(-window), true, "full past-side skew (inclusive)"},
		{enrNow.Add(-window - time.Minute), false, "beyond past-side skew is stale"},
	} {
		rec, err := VerifyEnrollment(token, pub, "org-acme", tc.at, window)
		if tc.ok {
			require.NoError(t, err, tc.note)
			assert.Equal(t, "deploy-acme-prod-01", rec.DeploymentID, tc.note)
		} else {
			require.Error(t, err, tc.note)
			require.ErrorIs(t, err, ErrStaleEnrollment, tc.note)
		}
	}

	_, err := VerifyEnrollment(token, pub, "org-acme", time.Time{}, window)
	require.Error(t, err)
	_, err = VerifyEnrollment(token, pub, "org-acme", enrNow, 0)
	require.Error(t, err)
	_, err = VerifyEnrollment(token, pub, "org-acme", enrNow, -time.Minute)
	require.Error(t, err)
}

// TestEnrollment_RegistryDuplicateRefused — a live identity cannot enroll
// twice: the second, independently valid document for the same contour is
// refused with ErrAlreadyEnrolled; the registry keeps the first
// enrollment (the record-level check of that fact is revoke_test.go's
// Lookup arm — Lookup arrives with W02-C02).
func TestEnrollment_RegistryDuplicateRefused(t *testing.T) {
	token, pub := enrToken(t, "deploy-acme-prod-01", "org-acme", "nonce-0001", enrNow)
	reg := NewRegistry()
	_, err := reg.ApplyEnrollment(token, pub, "org-acme", enrNow, DefaultEnrollmentWindow)
	require.NoError(t, err)

	second, _ := enrToken(t, "deploy-acme-prod-01", "org-acme", "nonce-0002", enrNow)
	_, err = reg.ApplyEnrollment(second, pub, "org-acme", enrNow, DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAlreadyEnrolled)
}

// TestEnrollment_ZeroRegistryFailsClosed — the zero Registry is an EMPTY
// registry: enrollment works (lazy init) and every unknown-identity
// question is refused (revoke.go arms cover the specifics).
func TestEnrollment_ZeroRegistryFailsClosed(t *testing.T) {
	var reg Registry
	token, pub := enrToken(t, "deploy-acme-prod-01", "org-acme", "nonce-0001", enrNow)
	ins, err := reg.ApplyEnrollment(token, pub, "org-acme", enrNow, DefaultEnrollmentWindow)
	require.NoError(t, err)
	assert.Equal(t, StateEnrolled, ins.State)
}

// foreignKey is an independent deterministic key that signs nothing the
// verifier trusts (the forged-signature arm's attacker).
func foreignKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed([]byte("yabanin-e03-p01-enroll-attacker1")) // 32 bytes, test-only
	return priv.Public().(ed25519.PublicKey), priv
}
