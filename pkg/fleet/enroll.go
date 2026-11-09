// Signed enrollment (E03-P01 card W02-C01, batch A): the registry's entry
// seam. An enrollment document is signed under the SAME Ed25519 license
// PKI that issues entitlements (precedent Issue/VerifyPaidModuleEntitlement,
// pkg/license/module_entitlement.go:134/:226): the vendor key binds one
// deployment contour identity (identity-model.md) to one org, the document
// carries a nonce, and replay is refused.
//
// Determinism law: every clock value is an injected parameter; the package
// reads no wall clock, no randomness and no environment. Fail-closed
// defaults: signature check precedes payload trust, an empty org on either
// side is refused, a cross-org presentation is refused, a stale or replayed
// document is refused, and an unknown deployment never enters the registry.
package fleet

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// EnrollmentVersion is the only enrollment document format this core
// understands; verification fails closed on any other value (the
// ModuleEntitlementVersion discipline, applied to the enrollment seam).
const EnrollmentVersion = "1"

// DefaultEnrollmentWindow is the standard freshness window a verifier may
// pass when it has no deployment-specific policy. Callers may choose
// tighter windows; VerifyEnrollment refuses non-positive windows instead
// of silently accepting everything.
const DefaultEnrollmentWindow = 5 * time.Minute

// Enrollment errors (sentinels; sites wrap concrete context).
var (
	// ErrInvalidEnrollment: the document is structurally invalid or was
	// issued malformed.
	ErrInvalidEnrollment = errors.New("fleet: invalid enrollment")
	// ErrEnrollmentSignature: the signature check failed (forged or
	// foreign-signed document).
	ErrEnrollmentSignature = errors.New("fleet: enrollment signature mismatch")
	// ErrCrossOrg: the document was presented to the wrong org boundary.
	ErrCrossOrg = errors.New("fleet: cross-org enrollment refused")
	// ErrStaleEnrollment: the document is outside the freshness window.
	ErrStaleEnrollment = errors.New("fleet: stale enrollment refused")
	// ErrReplay: the nonce was already consumed — a replayed document.
	ErrReplay = errors.New("fleet: enrollment replay refused")
	// ErrAlreadyEnrolled: the deployment identity is already live in this
	// registry (duplicate enrollment is refused; updates flow through the
	// later caps/health seams, not re-enrollment).
	ErrAlreadyEnrolled = errors.New("fleet: deployment already enrolled")
	// ErrRevoked and ErrNotEnrolled live in identity.go with the lifecycle
	// law they express.
)

// EnrollmentRecord is the signed enrollment document: one deployment
// contour joins one org. JSON tags follow the entitlement token's compact
// style. It carries NO secrets — only public coordinates plus the anti-
// replay nonce (identity-model.md §2).
type EnrollmentRecord struct {
	Version      string    `json:"v"`
	OrgID        string    `json:"o"`
	DeploymentID string    `json:"d"`
	Nonce        string    `json:"n"`
	IssuedAt     time.Time `json:"i"`
}

// IssueEnrollment validates rec, signs it with the vendor private key and
// returns the token form base64url(payload JSON) + "." + base64url(sig) —
// the entitlement token shape (module_entitlement.go:210). IssuedAt
// defaults to now when zero; times are normalized to UTC so the signed
// bytes are reproducible.
func IssueEnrollment(priv ed25519.PrivateKey, rec EnrollmentRecord, now time.Time) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("issue enrollment: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	if rec.Version == "" {
		rec.Version = EnrollmentVersion
	}
	if rec.Version != EnrollmentVersion {
		return "", fmt.Errorf("issue enrollment: unsupported version %q (want %q): %w", rec.Version, EnrollmentVersion, ErrInvalidEnrollment)
	}
	if err := ValidateOrgID(rec.OrgID); err != nil {
		return "", fmt.Errorf("issue enrollment: %w", err)
	}
	if err := ValidateDeploymentID(rec.DeploymentID); err != nil {
		return "", fmt.Errorf("issue enrollment: %w", err)
	}
	if rec.Nonce == "" {
		return "", fmt.Errorf("issue enrollment: nonce is required: %w", ErrInvalidEnrollment)
	}
	if strings.TrimSpace(rec.Nonce) != rec.Nonce {
		return "", fmt.Errorf("issue enrollment: nonce must not have leading/trailing whitespace: %w", ErrInvalidEnrollment)
	}
	if rec.IssuedAt.IsZero() {
		if now.IsZero() {
			return "", fmt.Errorf("issue enrollment: issued time is required (neither IssuedAt nor now set): %w", ErrInvalidEnrollment)
		}
		rec.IssuedAt = now
	}
	rec.IssuedAt = rec.IssuedAt.UTC()

	payload, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("issue enrollment: encode payload: %w", err)
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyEnrollment verifies an enrollment token fully offline against the
// vendor public key and the org boundary the verifier serves. It is a pure
// function (no registry state): replay protection is the caller's journal
// (Registry.ApplyEnrollment composes both). Fails closed on every arm:
// malformed token, bad signature, wrong version, empty org on either side,
// cross-org presentation, zero now, non-positive window and documents
// outside [now-window, now+window].
//
// The signature is checked BEFORE the payload is trusted — a forged
// document never exposes its (possibly malicious) coordinates, mirroring
// the verify-then-use ordering of VerifyPaidModuleEntitlement (:243–250).
func VerifyEnrollment(token string, pub ed25519.PublicKey, expectedOrg string, now time.Time, window time.Duration) (EnrollmentRecord, error) {
	var zero EnrollmentRecord
	if len(pub) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("verify enrollment: public key must be %d bytes, got %d: %w", ed25519.PublicKeySize, len(pub), ErrInvalidEnrollment)
	}
	if expectedOrg == "" {
		return zero, fmt.Errorf("verify enrollment: serving org is not configured: %w", ErrInvalidEnrollment)
	}
	if now.IsZero() {
		return zero, fmt.Errorf("verify enrollment: verification time is required: %w", ErrInvalidEnrollment)
	}
	if window <= 0 {
		return zero, fmt.Errorf("verify enrollment: window must be positive, got %s: %w", window, ErrInvalidEnrollment)
	}

	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		return zero, fmt.Errorf("verify enrollment: invalid token format: %w", ErrInvalidEnrollment)
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return zero, fmt.Errorf("verify enrollment: decode payload: %w: %v", ErrInvalidEnrollment, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return zero, fmt.Errorf("verify enrollment: decode sig: %w: %v", ErrInvalidEnrollment, err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return zero, ErrEnrollmentSignature
	}

	var rec EnrollmentRecord
	// Strict decode: unknown payload fields are refused, not ignored.
	// This is the enrollment side of the document-domain law: a
	// heartbeat (health.go) carries an explicit type tag inside its
	// signed bytes, so without strictness a valid heartbeat token would
	// ALSO parse as a valid enrollment (its extra field silently
	// dropped). Fail-closed: a document of another domain never enters
	// the registry through lenient parsing.
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		// A rejected document never exposes its coordinates (the same
		// zero-on-error discipline as the entitlement verifier :246–251).
		return zero, fmt.Errorf("verify enrollment: parse enrollment: %w: %v", ErrInvalidEnrollment, err)
	}
	if rec.Version != EnrollmentVersion {
		return zero, fmt.Errorf("verify enrollment: unsupported version %q: %w", rec.Version, ErrInvalidEnrollment)
	}
	// Empty org = refusal on BOTH sides: an upstream-empty coordinate and
	// an unconfigured verifier boundary are equally invalid («пустой org =
	// отказ»).
	if rec.OrgID == "" {
		return zero, fmt.Errorf("verify enrollment: enrollment names no org: %w", ErrInvalidEnrollment)
	}
	if err := ValidateOrgID(rec.OrgID); err != nil {
		return zero, fmt.Errorf("verify enrollment: %w", err)
	}
	if err := ValidateDeploymentID(rec.DeploymentID); err != nil {
		return zero, fmt.Errorf("verify enrollment: %w", err)
	}
	if rec.Nonce == "" {
		return zero, fmt.Errorf("verify enrollment: enrollment has no nonce: %w", ErrInvalidEnrollment)
	}
	if rec.IssuedAt.IsZero() {
		return zero, fmt.Errorf("verify enrollment: enrollment names no issued time: %w", ErrInvalidEnrollment)
	}
	// Cross-org presentation is refused before any freshness decision: the
	// document may be perfectly fresh and perfectly signed for ANOTHER org.
	if rec.OrgID != expectedOrg {
		return zero, fmt.Errorf("%w: enrollment is for org %q, verifier serves %q", ErrCrossOrg, rec.OrgID, expectedOrg)
	}
	// Freshness window (injectable clock; symmetric to tolerate bounded
	// skew, the GracePeriod-style allowance of the license world applied
	// to enrollment transport).
	issued := rec.IssuedAt.UTC()
	age := now.UTC().Sub(issued)
	if age < 0 {
		age = -age
	}
	if age > window {
		return zero, fmt.Errorf("%w: issued %s, verified %s, window %s", ErrStaleEnrollment, issued.Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano), window)
	}
	return rec, nil
}

// Installation is the registry's bookkeeping record for one enrolled
// deployment contour. It stores NO secrets (identity-model.md §2): the
// revocation law (revoke.go) punishes revoked installations by refusing
// secret ISSUANCE, so there is nothing here to steal.
type Installation struct {
	DeploymentID string
	OrgID        string
	Nonce        string
	State        State
	EnrolledAt   time.Time
	// LastHeartbeatAt is the monotone liveness clock (health.go): nil
	// until the first verified heartbeat, then only ever forward.
	LastHeartbeatAt *time.Time
	// RevokedAt is the FIRST revocation instant; idempotent re-revocation
	// never overwrites it. Reason is the audit trail entry.
	RevokedAt        time.Time
	RevocationReason string
}

// Registry is the in-memory fleet registry core: verified enrollments,
// their nonce journal and revocation bookkeeping. Persistence (migration
// 0024_fleet_registry + RLS) is W03-C03 (batch B); the zero Registry
// lazily initializes to an EMPTY registry, which fails closed — nothing is
// enrolled, so every secret-issuance question is refused until a verified
// enrollment says otherwise.
type Registry struct {
	mu            sync.Mutex
	installations map[string]*Installation
	nonces        map[string]struct{}
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		installations: make(map[string]*Installation),
		nonces:        make(map[string]struct{}),
	}
}

// ensureLocked lazily initializes the zero Registry (fail-closed empty).
func (r *Registry) ensureLocked() {
	if r.installations == nil {
		r.installations = make(map[string]*Installation)
	}
	if r.nonces == nil {
		r.nonces = make(map[string]struct{})
	}
}

// ApplyEnrollment is the composite entry seam: verify the token offline
// (pure VerifyEnrollment), consume its nonce in the replay journal, refuse
// duplicate or revoked identities, then insert the installation in the
// enrolled state. Every failure leaves the registry unchanged.
func (r *Registry) ApplyEnrollment(token string, pub ed25519.PublicKey, expectedOrg string, now time.Time, window time.Duration) (Installation, error) {
	rec, err := VerifyEnrollment(token, pub, expectedOrg, now, window)
	if err != nil {
		return Installation{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureLocked()

	if _, seen := r.nonces[rec.Nonce]; seen {
		return Installation{}, fmt.Errorf("%w: nonce already consumed", ErrReplay)
	}
	if existing, ok := r.installations[rec.DeploymentID]; ok {
		if existing.State == StateRevoked {
			// A revoked identity never re-enters through enrollment
			// (the W05 rogue re-enrollment arm; revocation is terminal).
			return Installation{}, fmt.Errorf("%w: deployment %q is revoked", ErrRevoked, rec.DeploymentID)
		}
		return Installation{}, fmt.Errorf("%w: deployment %q is already live", ErrAlreadyEnrolled, rec.DeploymentID)
	}

	r.nonces[rec.Nonce] = struct{}{}
	ins := &Installation{
		DeploymentID: rec.DeploymentID,
		OrgID:        rec.OrgID,
		Nonce:        rec.Nonce,
		State:        StateEnrolled,
		EnrolledAt:   rec.IssuedAt.UTC(),
	}
	r.installations[rec.DeploymentID] = ins
	return *ins, nil
}
