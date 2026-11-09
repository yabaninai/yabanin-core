// Health battery (E03-P01 card W04-C01, batch B): the heartbeat envelope
// and the fatigue window against the card's four arms — fresh heartbeat,
// EXPLICIT stale (window expired), resumption after stale, forged
// heartbeat rejected — plus the domain-separation, replay, terminality,
// monotone-liveness and pure-status arms of the packet law.
package fleet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hbFixture builds the vendor keypair, a fresh registry and one enrolled
// installation of org/deploy, with the deterministic injected clock.
func hbFixture(t *testing.T) (pub ed25519.PublicKey, priv ed25519.PrivateKey, reg *Registry, org, deploy string, base time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	reg = NewRegistry()
	org, deploy = "hborg", "deploy-ha"
	base = time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
	token, err := IssueEnrollment(priv, EnrollmentRecord{
		OrgID: org, DeploymentID: deploy, Nonce: "enroll-nonce-1",
	}, base)
	require.NoError(t, err)
	_, err = reg.ApplyEnrollment(token, pub, org, base, DefaultEnrollmentWindow)
	require.NoError(t, err)
	return pub, priv, reg, org, deploy, base
}

func hbBeat(t *testing.T, priv ed25519.PrivateKey, org, deploy, nonce string, at time.Time) string {
	t.Helper()
	token, err := IssueHeartbeat(priv, HeartbeatRecord{
		OrgID: org, DeploymentID: deploy, Nonce: nonce, IssuedAt: at,
	}, at)
	require.NoError(t, err)
	return token
}

func TestHealth_FreshHeartbeatActivates(t *testing.T) {
	pub, priv, reg, org, deploy, base := hbFixture(t)
	window := DefaultFatigueWindow

	// Pre-beat: enrolled, no liveness claimed.
	inst, ok := reg.installations[deploy]
	require.True(t, ok)
	require.Nil(t, inst.LastHeartbeatAt)
	status, err := HealthStatus(*inst, base, window)
	require.NoError(t, err)
	assert.Equal(t, StateEnrolled, status, "no heartbeat yet: enrolled, not stale")

	// Fresh heartbeat: active, liveness recorded, explicit status.
	beatAt := base.Add(time.Minute)
	_, err = reg.ApplyHeartbeat(hbBeat(t, priv, org, deploy, "hb-1", beatAt), pub, org, beatAt, window)
	require.NoError(t, err)
	inst = reg.installations[deploy]
	require.NotNil(t, inst.LastHeartbeatAt)
	assert.True(t, inst.LastHeartbeatAt.Equal(beatAt))
	assert.Equal(t, StateActive, inst.State)
	status, err = HealthStatus(*inst, beatAt, window)
	require.NoError(t, err)
	assert.Equal(t, StateActive, status)

	// Just inside the window: still active (boundary is > window).
	status, err = HealthStatus(*inst, beatAt.Add(window), window)
	require.NoError(t, err)
	assert.Equal(t, StateActive, status, "window edge is inclusive-fresh")
}

func TestHealth_StaleIsExplicit(t *testing.T) {
	pub, priv, reg, org, deploy, base := hbFixture(t)
	window := DefaultFatigueWindow

	beatAt := base.Add(time.Minute)
	_, err := reg.ApplyHeartbeat(hbBeat(t, priv, org, deploy, "hb-1", beatAt), pub, org, beatAt, window)
	require.NoError(t, err)

	// The fatigue window expires: the status is EXPLICITLY stale — never
	// a silent default, never an absence of row (packet law).
	later := beatAt.Add(window + time.Second)
	inst := reg.installations[deploy]
	status, err := HealthStatus(*inst, later, window)
	require.NoError(t, err)
	assert.Equal(t, StateStale, status, "fatigue window expired: stale is EXPLICIT")

	// The lifecycle model allows active→stale as an edge; the stored
	// state stays whatever the last accepted beat reported until a
	// transition records otherwise — HealthStatus computes truth.
	require.NoError(t, ValidateTransition(StateActive, StateStale))

	// Staleness is observability, not punishment: nothing here blocks
	// issuance; the twin law lives in the drift/read seams (W04-C02/C03).
}

func TestHealth_ResumptionAfterStale(t *testing.T) {
	pub, priv, reg, org, deploy, base := hbFixture(t)
	window := DefaultFatigueWindow

	beat1 := base.Add(time.Minute)
	_, err := reg.ApplyHeartbeat(hbBeat(t, priv, org, deploy, "hb-1", beat1), pub, org, beat1, window)
	require.NoError(t, err)
	staleAt := beat1.Add(window + 5*time.Minute)
	status, err := HealthStatus(*reg.installations[deploy], staleAt, window)
	require.NoError(t, err)
	require.Equal(t, StateStale, status)

	// Resumption: a fresh verified heartbeat returns the installation to
	// active and moves the monotone clock.
	beat2 := staleAt.Add(time.Minute)
	got, err := reg.ApplyHeartbeat(hbBeat(t, priv, org, deploy, "hb-2", beat2), pub, org, beat2, window)
	require.NoError(t, err)
	assert.Equal(t, StateActive, got.State)
	require.NotNil(t, got.LastHeartbeatAt)
	assert.True(t, got.LastHeartbeatAt.Equal(beat2))
	status, err = HealthStatus(got, beat2, window)
	require.NoError(t, err)
	assert.Equal(t, StateActive, status)

	// Monotone liveness: a late but transport-fresh OLDER heartbeat never
	// rewinds the clock (the max wins) and never de-activates.
	older := beat2.Add(-30 * time.Second)
	got, err = reg.ApplyHeartbeat(hbBeat(t, priv, org, deploy, "hb-3", older), pub, org, beat2, window)
	require.NoError(t, err)
	assert.True(t, got.LastHeartbeatAt.Equal(beat2), "older heartbeat must not rewind liveness")
	assert.Equal(t, StateActive, got.State)
}

func TestHealth_ForgedAndCrossDomainRefused(t *testing.T) {
	pub, priv, reg, org, deploy, base := hbFixture(t)
	window := DefaultFatigueWindow
	now := base.Add(time.Minute)

	// Forged: signed by a foreign key.
	_, foreignPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	forged := hbBeat(t, foreignPriv, org, deploy, "hb-f", now)
	_, err = reg.ApplyHeartbeat(forged, pub, org, now, window)
	require.ErrorIs(t, err, ErrHeartbeatSignature)

	// Tampered payload under a valid signature: re-sign the payload with
	// flipped org, present against the real verifier boundary.
	tampered := hbBeat(t, priv, "otherrg", deploy, "hb-t", now)
	_, err = reg.ApplyHeartbeat(tampered, pub, org, now, window)
	require.ErrorIs(t, err, ErrCrossOrg)

	// Domain separation: a perfectly valid ENROLLMENT token is not a
	// heartbeat — the document-type law refuses it before any state.
	enrollTok, err := IssueEnrollment(priv, EnrollmentRecord{
		OrgID: org, DeploymentID: deploy, Nonce: "hb-domain-1",
	}, now)
	require.NoError(t, err)
	_, err = reg.ApplyHeartbeat(enrollTok, pub, org, now, window)
	require.ErrorIs(t, err, ErrInvalidHeartbeat)

	// And the mirror arm: a heartbeat document cannot be re-used as an
	// enrollment token.
	hbTok := hbBeat(t, priv, org, deploy, "hb-domain-2", now)
	_, err = reg.ApplyEnrollment(hbTok, pub, org, now, DefaultEnrollmentWindow)
	require.ErrorIs(t, err, ErrInvalidEnrollment)

	// Forged-by-hand payload: strip the signature to garbage.
	payloadB64, _, ok := strings.Cut(hbTok, ".")
	require.True(t, ok)
	_, err = reg.ApplyHeartbeat(payloadB64+".AAAA", pub, org, now, window)
	require.ErrorIs(t, err, ErrHeartbeatSignature)

	// Structural refusals of the envelope itself: bad version, wrong
	// type tag, missing nonce — refused at issue time, so build by hand.
	bad := HeartbeatRecord{Version: "9", Type: heartbeatDocType, OrgID: org, DeploymentID: deploy, Nonce: "x", IssuedAt: now}
	_, err = IssueHeartbeat(priv, bad, now)
	require.ErrorIs(t, err, ErrInvalidHeartbeat)
	bad = HeartbeatRecord{Version: HealthVersion, Type: "fleet.enrollment", OrgID: org, DeploymentID: deploy, Nonce: "x", IssuedAt: now}
	_, err = IssueHeartbeat(priv, bad, now)
	require.ErrorIs(t, err, ErrInvalidHeartbeat)
	bad = HeartbeatRecord{Version: HealthVersion, Type: heartbeatDocType, OrgID: org, DeploymentID: deploy, IssuedAt: now}
	_, err = IssueHeartbeat(priv, bad, now)
	require.ErrorIs(t, err, ErrInvalidHeartbeat)

	// None of the refused arms touched the registry: still enrolled, no
	// liveness claimed, journal unchanged except nothing consumed.
	inst := reg.installations[deploy]
	assert.Equal(t, StateEnrolled, inst.State)
	assert.Nil(t, inst.LastHeartbeatAt)
}

func TestHealth_ReplayAndTransportWindow(t *testing.T) {
	pub, priv, reg, org, deploy, base := hbFixture(t)
	window := DefaultFatigueWindow

	beat := hbBeat(t, priv, org, deploy, "hb-once", base)
	_, err := reg.ApplyHeartbeat(beat, pub, org, base, window)
	require.NoError(t, err)

	// Same token again: nonce already consumed — replay refused.
	_, err = reg.ApplyHeartbeat(beat, pub, org, base.Add(time.Second), window)
	require.ErrorIs(t, err, ErrReplay)

	// A transport-stale document is refused at verification: a liveness
	// signal arriving too old proves nothing (distinct from the stale
	// STATUS, which HealthStatus reports explicitly).
	old := hbBeat(t, priv, org, deploy, "hb-old", base.Add(-2*window))
	_, err = reg.ApplyHeartbeat(old, pub, org, base, window)
	require.ErrorIs(t, err, ErrStaleHeartbeat)

	// Degenerate window / clock inputs fail closed.
	_, err = reg.ApplyHeartbeat(hbBeat(t, priv, org, deploy, "hb-w", base), pub, org, base, 0)
	require.ErrorIs(t, err, ErrInvalidHeartbeat)
	_, err = reg.ApplyHeartbeat(hbBeat(t, priv, org, deploy, "hb-z", base), pub, org, time.Time{}, window)
	require.ErrorIs(t, err, ErrInvalidHeartbeat)
	_, err = reg.ApplyHeartbeat(hbBeat(t, priv, org, deploy, "hb-o", base), pub, "", base, window)
	require.ErrorIs(t, err, ErrInvalidHeartbeat)
}

func TestHealth_UnknownAndRevokedRefused(t *testing.T) {
	pub, priv, reg, org, deploy, base := hbFixture(t)
	window := DefaultFatigueWindow
	now := base.Add(time.Minute)

	// Unknown deployment: fail-closed registry question.
	_, err := reg.ApplyHeartbeat(hbBeat(t, priv, org, "deploy-ghost", "hb-g", now), pub, org, now, window)
	require.ErrorIs(t, err, ErrNotEnrolled)

	// Revoked is terminal: a heartbeat neither revives nor mutates the
	// record; the refused beat leaves liveness untouched.
	require.NoError(t, reg.Revoke(deploy, "operator audit", base))
	revoked, ok := reg.Lookup(deploy)
	require.True(t, ok)
	require.Equal(t, StateRevoked, revoked.State)
	before := revoked.LastHeartbeatAt
	_, err = reg.ApplyHeartbeat(hbBeat(t, priv, org, deploy, "hb-r", now), pub, org, now, window)
	require.ErrorIs(t, err, ErrRevoked)
	after, _ := reg.Lookup(deploy)
	assert.Equal(t, before, after.LastHeartbeatAt, "revoked record untouched")

	// HealthStatus: revoked verdicts without reading the clock (terminal
	// law; no window input participates).
	status, err := HealthStatus(after, now, 0)
	require.NoError(t, err, "revoked needs no window")
	assert.Equal(t, StateRevoked, status)

	// Unknown state never becomes a status verdict.
	_, err = HealthStatus(Installation{State: "zombie"}, now, window)
	require.ErrorIs(t, err, ErrInvalidTransition)
}

func TestHealth_StatusRequiresSaneInputs(t *testing.T) {
	// Pure HealthStatus input law: zero clock and degenerate windows are
	// refused for live installations (enrolled-no-beat and revoked stay
	// total — no clock question is asked).
	at := time.Date(2026, 11, 8, 9, 30, 0, 0, time.UTC)
	beat := at
	_, err := HealthStatus(Installation{State: StateActive, LastHeartbeatAt: &beat}, time.Time{}, DefaultFatigueWindow)
	require.ErrorIs(t, err, ErrInvalidHeartbeat)
	_, err = HealthStatus(Installation{State: StateActive, LastHeartbeatAt: &beat}, at, 0)
	require.ErrorIs(t, err, ErrInvalidHeartbeat)
	_, err = HealthStatus(Installation{State: StateEnrolled}, at, 0)
	require.NoError(t, err, "enrolled-without-beat asks no clock question")
	_, err = HealthStatus(Installation{State: StateRevoked}, at, -time.Minute)
	require.NoError(t, err, "revoked asks no clock question")
}

func TestHealth_EnvelopeShapeIsDistinct(t *testing.T) {
	// The signed payload carries the explicit type tag inside the signed
	// bytes: stripping or swapping it breaks verification. Pin the wire
	// shape so a future rename is a conscious version bump, not drift.
	_, priv, _, org, deploy, base := hbFixture(t)
	tok := hbBeat(t, priv, org, deploy, "hb-shape", base)
	payloadB64, _, ok := strings.Cut(tok, ".")
	require.True(t, ok, "token must be payload.sig")
	raw, err := base64.RawURLEncoding.DecodeString(payloadB64)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	assert.Equal(t, HealthVersion, doc["v"])
	assert.Equal(t, "fleet.heartbeat", doc["t"], "document type rides inside the signed bytes")
	assert.Equal(t, org, doc["o"])
	assert.Equal(t, deploy, doc["d"])
	assert.Equal(t, "hb-shape", doc["n"])
	require.Contains(t, doc, "i")
}
