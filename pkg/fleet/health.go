// Health envelope (E03-P01 card W04-C01, batch B): the installation
// heartbeat and the fatigue window. A heartbeat is signed under the SAME
// Ed25519 license PKI as enrollment (IssueEnrollment precedent) but is a
// DISTINCT signed document: the payload carries an explicit document-type
// tag, so an enrollment token replayed as a heartbeat (or vice versa)
// fails at the payload law, not by luck of field overlap — domain
// separation at the document layer.
//
// Laws (packet dispatch §1 + card W04-C01):
//   - «устаревший статус явно видим»: staleness is an EXPLICIT status
//     (StateStale), computed by HealthStatus — never a silent default and
//     never inferred from absence of a row;
//   - staleness is observability: it does NOT block secret issuance — only
//     revocation does (identity.go ErrRevoked law; the drift seam W04-C02
//     and the read API W04-C03 surface it, they do not punish it);
//   - revoked is terminal: a heartbeat never revives a revoked
//     installation and never mutates its record;
//   - liveness is monotone: a late-arriving older heartbeat never rewinds
//     the observed liveness clock;
//   - fail-closed verification: signature precedes payload trust, the org
//     boundary is enforced on both sides, the transport window is
//     symmetric (a too-old heartbeat proves nothing and is refused), and
//     the nonce journal refuses replays.
//
// Determinism law (identity.go): every clock value is an injected
// parameter; no wall clock, no randomness, no environment input.
package fleet

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// HealthVersion is the only heartbeat document format this core
// understands; verification fails closed on any other value.
const HealthVersion = "1"

// heartbeatDocType is the explicit document-type tag inside the signed
// payload. It is what makes the heartbeat domain distinct from the
// enrollment domain under the same key: a verifier accepts ONLY this
// exact tag, so a valid enrollment signature can never be re-used as a
// heartbeat (its payload names a different document type).
const heartbeatDocType = "fleet.heartbeat"

// DefaultFatigueWindow is the standard freshness window: a heartbeat is
// fresh for this long, after which HealthStatus reports the EXPLICIT
// stale state. Callers should pass their deployment's operational policy;
// VerifyHeartbeat and HealthStatus refuse non-positive windows instead of
// silently accepting everything (DefaultEnrollmentWindow discipline).
const DefaultFatigueWindow = 15 * time.Minute

// Health errors (sentinels; sites wrap concrete context).
var (
	// ErrInvalidHeartbeat: the document is structurally invalid or was
	// issued malformed (bad token shape, bad version, wrong document
	// type, missing fields, degenerate window or clock).
	ErrInvalidHeartbeat = errors.New("fleet: invalid heartbeat")
	// ErrHeartbeatSignature: the signature check failed (forged or
	// foreign-signed document).
	ErrHeartbeatSignature = errors.New("fleet: heartbeat signature mismatch")
	// ErrStaleHeartbeat: the heartbeat document itself is outside the
	// transport window at verification time — a liveness signal that
	// arrives too old proves nothing and is refused (this is NOT the
	// stale status; the status is HealthStatus' explicit verdict).
	ErrStaleHeartbeat = errors.New("fleet: stale heartbeat refused")
	// ErrCrossOrg, ErrReplay, ErrRevoked and ErrNotEnrolled are shared
	// with the enrollment seam (enroll.go) and the lifecycle law
	// (identity.go).
)

// HeartbeatRecord is the signed heartbeat document: one deployment
// contour of one org reports liveness. JSON tags follow the enrollment
// token's compact style; the Type tag rides inside the signed bytes so it
// cannot be stripped or swapped. It carries NO secrets (identity-model
// §2).
type HeartbeatRecord struct {
	Version      string    `json:"v"`
	Type         string    `json:"t"`
	OrgID        string    `json:"o"`
	DeploymentID string    `json:"d"`
	Nonce        string    `json:"n"`
	IssuedAt     time.Time `json:"i"`
}

// IssueHeartbeat validates rec, signs it with the vendor private key and
// returns the token form base64url(payload JSON) + "." + base64url(sig) —
// the enrollment token shape (enroll.go :76). IssuedAt defaults to now
// when zero; times are normalized to UTC so the signed bytes are
// reproducible.
func IssueHeartbeat(priv ed25519.PrivateKey, rec HeartbeatRecord, now time.Time) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("issue heartbeat: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	if rec.Version == "" {
		rec.Version = HealthVersion
	}
	if rec.Version != HealthVersion {
		return "", fmt.Errorf("issue heartbeat: unsupported version %q (want %q): %w", rec.Version, HealthVersion, ErrInvalidHeartbeat)
	}
	if rec.Type == "" {
		rec.Type = heartbeatDocType
	}
	if rec.Type != heartbeatDocType {
		return "", fmt.Errorf("issue heartbeat: document type %q is not a heartbeat: %w", rec.Type, ErrInvalidHeartbeat)
	}
	if err := ValidateOrgID(rec.OrgID); err != nil {
		return "", fmt.Errorf("issue heartbeat: %w", err)
	}
	if err := ValidateDeploymentID(rec.DeploymentID); err != nil {
		return "", fmt.Errorf("issue heartbeat: %w", err)
	}
	if rec.Nonce == "" {
		return "", fmt.Errorf("issue heartbeat: nonce is required: %w", ErrInvalidHeartbeat)
	}
	if strings.TrimSpace(rec.Nonce) != rec.Nonce {
		return "", fmt.Errorf("issue heartbeat: nonce must not have leading/trailing whitespace: %w", ErrInvalidHeartbeat)
	}
	if rec.IssuedAt.IsZero() {
		if now.IsZero() {
			return "", fmt.Errorf("issue heartbeat: issued time is required (neither IssuedAt nor now set): %w", ErrInvalidHeartbeat)
		}
		rec.IssuedAt = now
	}
	rec.IssuedAt = rec.IssuedAt.UTC()

	payload, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("issue heartbeat: encode payload: %w", err)
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyHeartbeat verifies a heartbeat token fully offline against the
// vendor public key and the org boundary the verifier serves. Pure
// function (no registry state); replay protection is the caller's
// journal (Registry.ApplyHeartbeat composes both). Fails closed on every
// arm: malformed token, bad signature, wrong version, wrong document
// type (the enrollment-token-as-heartbeat domain attack), empty org on
// either side, cross-org presentation, zero now, non-positive window and
// documents outside the symmetric transport window.
//
// The signature is checked BEFORE the payload is trusted — a forged
// document never exposes its (possibly malicious) coordinates
// (VerifyEnrollment ordering precedent, enroll.go :125).
func VerifyHeartbeat(token string, pub ed25519.PublicKey, expectedOrg string, now time.Time, window time.Duration) (HeartbeatRecord, error) {
	var zero HeartbeatRecord
	if len(pub) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("verify heartbeat: public key must be %d bytes, got %d: %w", ed25519.PublicKeySize, len(pub), ErrInvalidHeartbeat)
	}
	if expectedOrg == "" {
		return zero, fmt.Errorf("verify heartbeat: serving org is not configured: %w", ErrInvalidHeartbeat)
	}
	if now.IsZero() {
		return zero, fmt.Errorf("verify heartbeat: verification time is required: %w", ErrInvalidHeartbeat)
	}
	if window <= 0 {
		return zero, fmt.Errorf("verify heartbeat: window must be positive, got %s: %w", window, ErrInvalidHeartbeat)
	}

	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		return zero, fmt.Errorf("verify heartbeat: invalid token format: %w", ErrInvalidHeartbeat)
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return zero, fmt.Errorf("verify heartbeat: decode payload: %w: %v", ErrInvalidHeartbeat, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return zero, fmt.Errorf("verify heartbeat: decode sig: %w: %v", ErrInvalidHeartbeat, err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return zero, ErrHeartbeatSignature
	}

	var rec HeartbeatRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		// A rejected document never exposes its coordinates.
		return zero, fmt.Errorf("verify heartbeat: parse heartbeat: %w: %v", ErrInvalidHeartbeat, err)
	}
	if rec.Version != HealthVersion {
		return zero, fmt.Errorf("verify heartbeat: unsupported version %q: %w", rec.Version, ErrInvalidHeartbeat)
	}
	// The domain law: only heartbeat documents verify here. A perfectly
	// signed enrollment token fails this check — its payload is a
	// different document type.
	if rec.Type != heartbeatDocType {
		return zero, fmt.Errorf("verify heartbeat: document type %q is not a heartbeat: %w", rec.Type, ErrInvalidHeartbeat)
	}
	if rec.OrgID == "" {
		return zero, fmt.Errorf("verify heartbeat: heartbeat names no org: %w", ErrInvalidHeartbeat)
	}
	if err := ValidateOrgID(rec.OrgID); err != nil {
		return zero, fmt.Errorf("verify heartbeat: %w", err)
	}
	if err := ValidateDeploymentID(rec.DeploymentID); err != nil {
		return zero, fmt.Errorf("verify heartbeat: %w", err)
	}
	if rec.Nonce == "" {
		return zero, fmt.Errorf("verify heartbeat: heartbeat has no nonce: %w", ErrInvalidHeartbeat)
	}
	if rec.IssuedAt.IsZero() {
		return zero, fmt.Errorf("verify heartbeat: heartbeat names no issued time: %w", ErrInvalidHeartbeat)
	}
	// Cross-org presentation is refused before any freshness decision.
	if rec.OrgID != expectedOrg {
		return zero, fmt.Errorf("%w: heartbeat is for org %q, verifier serves %q", ErrCrossOrg, rec.OrgID, expectedOrg)
	}
	// Symmetric transport window (bounded skew tolerance, the enrollment
	// transport law applied to heartbeats). Note the split: a document
	// too old is REFUSED here, while an installation whose last accepted
	// heartbeat has aged out is reported STALE by HealthStatus — refusal
	// of a signal is not the same thing as the explicit stale status.
	issued := rec.IssuedAt.UTC()
	age := now.UTC().Sub(issued)
	if age < 0 {
		age = -age
	}
	if age > window {
		return zero, fmt.Errorf("%w: issued %s, verified %s, window %s", ErrStaleHeartbeat, issued.Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano), window)
	}
	return rec, nil
}

// HealthStatus reports the EXPLICIT lifecycle status of an installation
// at now, given the fatigue window. Pure and total:
//
//	revoked            → revoked (terminal; no clock input participates)
//	enrolled, no beat  → enrolled (liveness was never claimed)
//	last beat + window ≥ now → active
//	last beat + window < now  → stale — EXPLICITLY, the packet law
//	«устаревший статус явно видим»
//
// Staleness is observability: callers surface it (drift seam W04-C02,
// read API W04-C03); they must not refuse secret issuance for it — only
// revocation does that.
func HealthStatus(inst Installation, now time.Time, window time.Duration) (State, error) {
	if !StateKnown(inst.State) {
		// Fail-closed: an unknown state never becomes a status verdict.
		return "", fmt.Errorf("%w: unknown state %q", ErrInvalidTransition, inst.State)
	}
	if inst.State == StateRevoked {
		return StateRevoked, nil
	}
	if inst.LastHeartbeatAt == nil {
		return StateEnrolled, nil
	}
	if window <= 0 {
		return "", fmt.Errorf("health status: window must be positive, got %s: %w", window, ErrInvalidHeartbeat)
	}
	if now.IsZero() {
		return "", fmt.Errorf("health status: evaluation time is required: %w", ErrInvalidHeartbeat)
	}
	if now.UTC().Sub(inst.LastHeartbeatAt.UTC()) > window {
		return StateStale, nil
	}
	// Fresh liveness: the status is computed from the clock, not
	// remembered — even an installation whose stored state predates the
	// health seam reports the derived truth, active.
	return StateActive, nil
}

// ApplyHeartbeat is the composite health seam on the in-memory registry:
// verify the token offline (pure VerifyHeartbeat), enforce the org
// boundary and the lifecycle law, consume the nonce in the replay
// journal, then update the installation's liveness. Fail-closed arms:
// unknown deployment (ErrNotEnrolled), revoked deployment (terminal — a
// heartbeat never revives it and never mutates its record), replayed
// nonce. On success the installation is ACTIVE with the monotone
// liveness clock: LastHeartbeatAt only ever moves forward (a late but
// transport-fresh older heartbeat updates neither the clock nor rewinds
// liveness). Every failure leaves the registry unchanged.
func (r *Registry) ApplyHeartbeat(token string, pub ed25519.PublicKey, expectedOrg string, now time.Time, window time.Duration) (Installation, error) {
	rec, err := VerifyHeartbeat(token, pub, expectedOrg, now, window)
	if err != nil {
		return Installation{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureLocked()

	// One journal for the whole registry: a nonce consumed by an
	// enrollment document is consumed, full stop — cross-protocol
	// cross-reuse is refused too (fail-closed; the payload type tag
	// already makes such reuse fail verification, this is the second
	// lock on the same door).
	if _, seen := r.nonces[rec.Nonce]; seen {
		return Installation{}, fmt.Errorf("%w: nonce already consumed", ErrReplay)
	}
	existing, ok := r.installations[rec.DeploymentID]
	if !ok {
		return Installation{}, fmt.Errorf("%w: heartbeat for unknown deployment %q", ErrNotEnrolled, rec.DeploymentID)
	}
	if existing.OrgID != rec.OrgID {
		// Registry-side twin of the verifier-side cross-org law: the
		// token verified against the serving org, but the installation
		// belongs to another org — refuse, never migrate coordinates.
		return Installation{}, fmt.Errorf("%w: deployment %q belongs to org %q, heartbeat names %q", ErrCrossOrg, rec.DeploymentID, existing.OrgID, rec.OrgID)
	}
	if existing.State == StateRevoked {
		return Installation{}, fmt.Errorf("%w: heartbeat on revoked deployment %q refused (terminal)", ErrRevoked, rec.DeploymentID)
	}

	r.nonces[rec.Nonce] = struct{}{}
	// Monotone liveness: the clock takes the max, never a rewind.
	if existing.LastHeartbeatAt == nil || rec.IssuedAt.UTC().After(existing.LastHeartbeatAt.UTC()) {
		t := rec.IssuedAt.UTC()
		existing.LastHeartbeatAt = &t
	}
	// Health updates REPORT state without transitioning to it
	// (identity.go allowedTransitions comment): a fresh verified
	// heartbeat means active — from enrolled (first beat), from active
	// (refresh) and from stale (resumption after the fatigue window).
	existing.State = StateActive
	return *existing, nil
}
