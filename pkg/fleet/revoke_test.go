// Revocation battery (E03-P01 card W02-C02, batch A): the card's mandatory
// variants — отзыв; повторный отзыв идемпотентен; отозванная установка не
// получает секреты (отказ ВЫДАЧИ — the packet law, as an issuance refusal);
// stale→revoked переход виден — plus the fail-closed refusal arms and the
// no-clock-membership property (rollback arms live in W02-C03's adversarial
// battery). Fixed clock; deterministic.
package fleet

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rvNow is the fixed revocation test clock.
var rvNow = time.Date(2026, 11, 8, 13, 0, 0, 0, time.UTC)

// rvEnrolled registers one enrolled installation via the real entry seam.
func rvEnrolled(t *testing.T, deployment string) (*Registry, func()) {
	t.Helper()
	reg := NewRegistry()
	pub, priv := rvKeyPair()
	token, err := IssueEnrollment(priv, EnrollmentRecord{
		OrgID:        "org-acme",
		DeploymentID: deployment,
		Nonce:        "rv-nonce-" + deployment,
		IssuedAt:     rvNow,
	}, rvNow)
	require.NoError(t, err)
	_, err = reg.ApplyEnrollment(token, pub, "org-acme", rvNow, DefaultEnrollmentWindow)
	require.NoError(t, err)
	return reg, func() {}
}

var rvSeed = []byte("yabanin-e03-p01-revoke-seed-0001") // 32 bytes, test-only

func rvKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(rvSeed)
	return priv.Public().(ed25519.PublicKey), priv
}

// TestRevoke_LiveToRevoked — «отзыв»: a live installation revokes, the
// state is terminal, the audit trail is recorded, and the record is
// visible through Lookup (a copy — mutation through it must not stick).
func TestRevoke_LiveToRevoked(t *testing.T) {
	reg, _ := rvEnrolled(t, "deploy-acme-prod-01")

	require.NoError(t, reg.Revoke("deploy-acme-prod-01", "contract terminated", rvNow.Add(time.Hour)))

	assert.True(t, reg.IsRevoked("deploy-acme-prod-01"))
	ins, ok := reg.Lookup("deploy-acme-prod-01")
	require.True(t, ok)
	assert.Equal(t, StateRevoked, ins.State)
	assert.True(t, ins.RevokedAt.Equal(rvNow.Add(time.Hour)))
	assert.Equal(t, "contract terminated", ins.RevocationReason)

	// Lookup returns a copy: mutating it cannot corrupt registry state.
	ins.State = StateActive
	again, _ := reg.Lookup("deploy-acme-prod-01")
	assert.Equal(t, StateRevoked, again.State)
}

// TestRevoke_IdempotentRerevoke — «повторный отзыв идемпотентен»: a second
// Revoke succeeds (nil) and preserves the FIRST instant and reason, even
// when the second call carries a different clock and reason.
func TestRevoke_IdempotentRerevoke(t *testing.T) {
	reg, _ := rvEnrolled(t, "deploy-acme-prod-01")
	firstAt := rvNow.Add(2 * time.Hour)

	require.NoError(t, reg.Revoke("deploy-acme-prod-01", "contract terminated", firstAt))
	// Second revoke: earlier clock (a rollback of the audit input) and a
	// different reason — both must be ignored in favor of the first fact.
	require.NoError(t, reg.Revoke("deploy-acme-prod-01", "other reason", firstAt.Add(-time.Hour)))

	ins, _ := reg.Lookup("deploy-acme-prod-01")
	assert.True(t, ins.RevokedAt.Equal(firstAt), "first revocation instant preserved")
	assert.Equal(t, "contract terminated", ins.RevocationReason, "first reason preserved")
	assert.True(t, reg.IsRevoked("deploy-acme-prod-01"))
}

// TestRevoke_StaleToRevokedVisible — «stale→revoked переход виден»: an
// installation whose state is stale (set here directly: batch A has no
// heartbeat machinery yet — W04 owns the window that produces stale
// legitimately; the transition LAW is this packet's) revokes, and the
// change is visible in state, membership and the issuance gate at once.
func TestRevoke_StaleToRevokedVisible(t *testing.T) {
	reg, _ := rvEnrolled(t, "deploy-acme-prod-01")
	setState(t, reg, "deploy-acme-prod-01", StateStale)

	assert.False(t, reg.IsRevoked("deploy-acme-prod-01"), "stale is NOT revoked — statuses stay distinct")
	require.NoError(t, reg.Revoke("deploy-acme-prod-01", "stale beyond policy", rvNow.Add(72*time.Hour)))

	assert.True(t, reg.IsRevoked("deploy-acme-prod-01"))
	ins, _ := reg.Lookup("deploy-acme-prod-01")
	assert.Equal(t, StateRevoked, ins.State, "the stale→revoked transition is visible in the record")
	require.ErrorIs(t, reg.AuthorizeSecretIssuance("deploy-acme-prod-01"), ErrRevoked)
}

// TestRevoke_RefusalArms — fail-closed request validation: unknown
// deployment, invalid identity shape, empty/padded reason, zero clock.
func TestRevoke_RefusalArms(t *testing.T) {
	reg, _ := rvEnrolled(t, "deploy-acme-prod-01")

	err := reg.Revoke("deploy-ghost-01", "reason", rvNow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRevocationRejected)
	require.ErrorIs(t, err, ErrNotEnrolled, "unknown deployment is named explicitly")

	for _, badID := range []string{"", " padded", "deploy\u0000x"} {
		require.Error(t, reg.Revoke(badID, "reason", rvNow), "identity %q", badID)
	}
	for _, badReason := range []string{"", "   ", "\t"} {
		err := reg.Revoke("deploy-acme-prod-01", badReason, rvNow)
		require.Error(t, err, "reason %q", badReason)
		require.ErrorIs(t, err, ErrRevocationRejected)
	}
	require.Error(t, reg.Revoke("deploy-acme-prod-01", "reason", time.Time{}))

	// No refusal above mutated anything.
	ins, _ := reg.Lookup("deploy-acme-prod-01")
	assert.Equal(t, StateEnrolled, ins.State)
	assert.True(t, ins.RevokedAt.IsZero())
}

// TestSecretIssuanceGate_PacketLaw — «отозванная установка не получает
// секреты» as an ISSUANCE refusal: revoked → ErrRevoked; not enrolled →
// ErrNotEnrolled; enrolled/active/stale → nil (stale stays issuable in
// batch A — staleness is an explicit health status owned by W04, not a
// revocation; disclosed in the card record).
func TestSecretIssuanceGate_PacketLaw(t *testing.T) {
	reg, _ := rvEnrolled(t, "deploy-acme-prod-01")
	reg2, _ := rvEnrolled(t, "deploy-acme-prod-02")

	// Enrolled: issuable.
	require.NoError(t, reg.AuthorizeSecretIssuance("deploy-acme-prod-01"))

	// Revoked: refused — the issuance, never a stored secret (the registry
	// has no secret field anywhere to begin with).
	require.NoError(t, reg.Revoke("deploy-acme-prod-01", "breach containment", rvNow.Add(time.Minute)))
	err := reg.AuthorizeSecretIssuance("deploy-acme-prod-01")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRevoked)

	// Active and stale: issuable in batch A (explicit W04 handoff).
	setState(t, reg2, "deploy-acme-prod-02", StateActive)
	require.NoError(t, reg2.AuthorizeSecretIssuance("deploy-acme-prod-02"))
	setState(t, reg2, "deploy-acme-prod-02", StateStale)
	require.NoError(t, reg2.AuthorizeSecretIssuance("deploy-acme-prod-02"))

	// Unknown: nothing at all (fail-closed default).
	err = reg.AuthorizeSecretIssuance("deploy-ghost-01")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNotEnrolled)
	err = reg.AuthorizeSecretIssuance("")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNotEnrolled)
}

// TestRevoke_RevokedNeverReentersThroughEnrollment — terminality at the
// entry seam: a fresh, correctly signed enrollment for a revoked contour
// is refused with ErrRevoked (the rogue re-enrollment vector, W05-C02 will
// replay this end-to-end).
func TestRevoke_RevokedNeverReentersThroughEnrollment(t *testing.T) {
	reg, _ := rvEnrolled(t, "deploy-acme-prod-01")
	require.NoError(t, reg.Revoke("deploy-acme-prod-01", "contract terminated", rvNow.Add(time.Hour)))

	pub, priv := rvKeyPair()
	token, err := IssueEnrollment(priv, EnrollmentRecord{
		OrgID:        "org-acme",
		DeploymentID: "deploy-acme-prod-01",
		Nonce:        "rv-reenter-nonce-0002",
		IssuedAt:     rvNow.Add(2 * time.Hour),
	}, rvNow.Add(2*time.Hour))
	require.NoError(t, err)
	_, err = reg.ApplyEnrollment(token, pub, "org-acme", rvNow.Add(2*time.Hour), DefaultEnrollmentWindow)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRevoked)

	ins, _ := reg.Lookup("deploy-acme-prod-01")
	assert.Equal(t, StateRevoked, ins.State, "revocation survives the re-entry attempt")
	assert.Equal(t, "rv-nonce-deploy-acme-prod-01", ins.Nonce, "original enrollment record intact")
}

// setState is a test seam over the registry's internal record: batch A has
// no heartbeat machinery (W04 owns producing active/stale legitimately),
// so the transition-law tests install the source state directly. Same
// package, single seam, used only to reach otherwise-unreachable lawful
// source states — every state it installs is a legal registry state.
func setState(t *testing.T, reg *Registry, deploymentID string, s State) {
	t.Helper()
	reg.mu.Lock()
	defer reg.mu.Unlock()
	ins, ok := reg.installations[deploymentID]
	require.True(t, ok, "setState: installation must exist")
	ins.State = s
}
