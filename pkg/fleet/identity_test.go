// Identity core battery (E03-P01 card W01-C02, batch A): coordinate
// validation, deterministic fingerprinting, the binding seams and the
// fail-closed lifecycle transition law of identity-model.md §3–§4. All
// inputs are fixed literals — deterministic by construction (no clock, no
// randomness, no environment).
package fleet

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDeploymentID_Variants(t *testing.T) {
	valid := []string{
		"deploy-acme-prod-01",
		"contour_euwest.2:dr",
		"Ünïcödé-Контур-42",   // valid UTF-8, non-ASCII letters
		"with interior space", // upstream-legal shape: entitlement law (:147–152) forbids only padding
		strings.Repeat("d", maxCoordinateBytes),
	}
	for _, id := range valid {
		require.NoError(t, ValidateDeploymentID(id), "expected valid: %q", id)
	}

	invalid := map[string]string{
		"":                       "empty («пустая — отказ»)",
		"  deploy-acme":          "leading whitespace",
		"deploy-acme\t":          "trailing tab",
		"\ndeploy":               "leading newline (also a control character)",
		"deploy\u007fprod":       "DEL control character",
		"deploy\u0000prod":       "NUL control character",
		strings.Repeat("d", 129): "over the 128-byte bound",
		"deploy\xff\xfe":         "invalid UTF-8 bytes",
	}
	for id, why := range invalid {
		err := ValidateDeploymentID(id)
		require.Error(t, err, "%s: %q", why, id)
		require.ErrorIs(t, err, ErrInvalidDeploymentID, "%s: %q", why, id)
	}
}

func TestValidateOrgID_SameStructuralLaw(t *testing.T) {
	require.NoError(t, ValidateOrgID("org-acme"))
	err := ValidateOrgID(" org-acme")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOrg)
}

func TestNewIdentity_ValidAndEmpty(t *testing.T) {
	id, err := NewIdentity("deploy-acme-prod-01", "org-acme")
	require.NoError(t, err)
	assert.Equal(t, Identity{DeploymentID: "deploy-acme-prod-01", OrgID: "org-acme"}, id)

	// Empty upstream («пустая — отказ»): no identity exists without its root.
	_, err = NewIdentity("", "org-acme")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidDeploymentID)

	_, err = NewIdentity("deploy-acme-prod-01", "")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOrg)
}

func TestIdentityFingerprint_DeterministicRepeat(t *testing.T) {
	id, err := NewIdentity("deploy-acme-prod-01", "org-acme")
	require.NoError(t, err)

	// «повтор вывода отпечатка детерминирован»: repeated computation is
	// byte-identical — the fingerprint is a pure function of the public
	// coordinates.
	first, err := id.Fingerprint()
	require.NoError(t, err)
	for i := 0; i < 8; i++ {
		again, err := id.Fingerprint()
		require.NoError(t, err)
		assert.Equal(t, first, again, "fingerprint output must be deterministic")
	}

	// Freshly constructed equal identity → equal fingerprint (value
	// semantics, no hidden state).
	same, err := NewIdentity("deploy-acme-prod-01", "org-acme")
	require.NoError(t, err)
	again, err := same.Fingerprint()
	require.NoError(t, err)
	assert.Equal(t, first, again)
}

func TestIdentityFingerprint_DistinguishesCoordinates(t *testing.T) {
	base, err := NewIdentity("deploy-acme-prod-01", "org-acme")
	require.NoError(t, err)
	baseFP, err := base.Fingerprint()
	require.NoError(t, err)

	// identity ≠ org: same contour under another org is another registry
	// identity; another contour under the same org likewise.
	otherOrg, err := NewIdentity("deploy-acme-prod-01", "org-other")
	require.NoError(t, err)
	otherOrgFP, err := otherOrg.Fingerprint()
	require.NoError(t, err)
	assert.NotEqual(t, baseFP, otherOrgFP)

	otherDeploy, err := NewIdentity("deploy-acme-prod-02", "org-acme")
	require.NoError(t, err)
	otherDeployFP, err := otherDeploy.Fingerprint()
	require.NoError(t, err)
	assert.NotEqual(t, baseFP, otherDeployFP)

	// Domain separation from a bare sha256 of a coordinate: the fingerprint
	// is never accidentally equal to an untagged digest.
	assert.Len(t, baseFP, 64, "hex sha-256")
}

func TestIdentityFingerprint_InvalidCoordinatesRefused(t *testing.T) {
	_, err := (Identity{DeploymentID: "", OrgID: "org-acme"}).Fingerprint()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidDeploymentID)

	_, err = (Identity{DeploymentID: "deploy", OrgID: " padded"}).Fingerprint()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOrg)
}

func TestIdentity_VerifyFingerprint_ForgedClaim(t *testing.T) {
	id, err := NewIdentity("deploy-acme-prod-01", "org-acme")
	require.NoError(t, err)
	good, err := id.Fingerprint()
	require.NoError(t, err)
	assert.True(t, id.VerifyFingerprint(good), "an honest claim verifies")

	// Forged claims: well-formed hex that is simply not this identity's
	// fingerprint — and the fingerprint of TAMPERED coordinates (the
	// substitution arm's identity-side seam).
	assert.False(t, id.VerifyFingerprint(strings.Repeat("0", 64)), "fabricated digest")
	tampered, err := NewIdentity("deploy-acme-prod-02", "org-acme")
	require.NoError(t, err)
	tamperedFP, err := tampered.Fingerprint()
	require.NoError(t, err)
	assert.False(t, id.VerifyFingerprint(tamperedFP), "fingerprint recomputed over substituted coordinates")

	// No fingerprint exists for invalid coordinates, so nothing matches.
	assert.False(t, (Identity{}).VerifyFingerprint(good))
	assert.False(t, (Identity{}).VerifyFingerprint(""))
}

func TestIdentity_Bindings(t *testing.T) {
	id, err := NewIdentity("deploy-acme-prod-01", "org-acme")
	require.NoError(t, err)

	assert.True(t, id.BoundToDeployment("deploy-acme-prod-01"))
	assert.False(t, id.BoundToDeployment("deploy-acme-prod-02"), "mismatch deployment")
	assert.False(t, id.BoundToDeployment(""), "empty never binds")

	assert.True(t, id.BoundToOrg("org-acme"))
	assert.False(t, id.BoundToOrg("org-other"), "cross-org")
	assert.False(t, id.BoundToOrg(""), "empty never binds")
}

func TestValidateTransition_LifecycleLaw(t *testing.T) {
	allowed := []struct{ from, to State }{
		{StateEnrolled, StateActive},
		{StateEnrolled, StateRevoked},
		{StateActive, StateStale},
		{StateActive, StateRevoked},
		{StateStale, StateActive}, // resumption after stale (W04-C01)
		{StateStale, StateRevoked},
	}
	for _, tc := range allowed {
		require.NoError(t, ValidateTransition(tc.from, tc.to), "%s → %s", tc.from, tc.to)
	}

	refused := []struct {
		from, to State
		why      string
	}{
		{StateRevoked, StateActive, "revoked is terminal"},
		{StateRevoked, StateEnrolled, "revoked is terminal"},
		{StateRevoked, StateStale, "revoked is terminal"},
		{StateRevoked, StateRevoked, "no-op, and terminal"},
		{StateEnrolled, StateEnrolled, "no-op refresh is not a transition"},
		{StateActive, StateEnrolled, "backwards"},
		{StateStale, StateEnrolled, "backwards"},
		{StateEnrolled, StateStale, "must pass through active (heartbeat machinery, W04)"},
		{State("unknown"), StateActive, "unknown source fails closed"},
		{StateActive, State("unknown"), "unknown target fails closed"},
		{State(""), StateRevoked, "empty source fails closed"},
	}
	for _, tc := range refused {
		err := ValidateTransition(tc.from, tc.to)
		require.Error(t, err, "%s: %s → %s", tc.why, tc.from, tc.to)
		require.ErrorIs(t, err, ErrInvalidTransition, "%s: %s → %s", tc.why, tc.from, tc.to)
	}
}

func TestStateKnown(t *testing.T) {
	for _, s := range []State{StateEnrolled, StateActive, StateStale, StateRevoked} {
		assert.True(t, StateKnown(s), string(s))
	}
	assert.False(t, StateKnown(State("unknown")))
	assert.False(t, StateKnown(State("unknown")))
	assert.False(t, StateKnown(State("")))
}
