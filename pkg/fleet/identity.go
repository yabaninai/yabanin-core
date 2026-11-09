// Package fleet is the managed-installation registry core (E03-P01,
// batch A): installation identity, signed enrollment and revocation.
//
// Laws carried from the packet dispatch (DISPATCH-2026-11-07.md §1):
//   - the registry is an open SPI in core-Apache territory; it stores NO
//     secrets — a revoked installation is punished by refusing secret
//     ISSUANCE (W02-C02), never by holding key material;
//   - identity is derived from the licensed deployment contour
//     (PaidModuleEntitlement.DeploymentID, pkg/license/module_entitlement.go:98)
//     and is NOT org membership: one org may run many contours, one contour
//     is shared by all its HA/DR/test instances (I23);
//   - determinism: non-test code in this package takes every time value as
//     an injected parameter and uses no randomness and no environment
//     input;
//   - fail-closed defaults: unknown identities, empty coordinates, unknown
//     states and terminal-state exits are all refused.
//
// Persistence (migration 0024_fleet_registry, RLS posture) is W03-C03
// (batch B); this file is the pure identity layer those cards build on.
package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// IdentityModelVersion tags the identity model (coordinates + fingerprint
// domain separator + lifecycle) so a future format change is visible in
// stored/derived artifacts instead of being silently misread — the same
// discipline as ModuleEntitlementVersion in pkg/license.
const IdentityModelVersion = "1"

// maxCoordinateBytes bounds both identity coordinates. Generous against any
// vendor-issued DeploymentID, small enough to keep registry keys sane.
const maxCoordinateBytes = 128

// State is the identity lifecycle state (identity-model.md §4). Batch A
// materializes enrolled and revoked; active/stale become observable when
// the W04 heartbeat machinery lands later in the packet — the transition
// law here is already the full model.
type State string

const (
	// StateEnrolled means a verified enrollment was applied; no heartbeat
	// observed yet.
	StateEnrolled State = "enrolled"
	// StateActive means a fresh heartbeat inside the fatigue window (W04).
	StateActive State = "active"
	// StateStale means the fatigue window expired; the status is EXPLICIT
	// (packet law «устаревший статус явно видим», machinery in W04).
	StateStale State = "stale"
	// StateRevoked means terminal. Set-membership fact (crl.go:37
	// precedent); no clock input participates, so rollback cannot
	// un-revoke.
	StateRevoked State = "revoked"
)

// Identity-lifecycle errors. Sentinels so callers (and W02/W05 batteries)
// can errors.Is them; wrapped context is added at each site.
var (
	// ErrInvalidDeploymentID: the deployment coordinate fails structural
	// validation (empty, padded, oversized, malformed).
	ErrInvalidDeploymentID = errors.New("fleet: invalid deployment identity")
	// ErrInvalidOrg: the org coordinate fails structural validation.
	ErrInvalidOrg = errors.New("fleet: invalid org identity")
	// ErrInvalidTransition: the requested lifecycle transition is not in
	// the allowed set (fail-closed: includes revoked→anything).
	ErrInvalidTransition = errors.New("fleet: invalid lifecycle transition")
	// ErrRevoked: the deployment identity is revoked — the registry refuses
	// the action (enrollment, secret issuance) because revocation is
	// terminal. Defined here, beside the lifecycle law it comes from, so
	// the enrollment seam (enroll.go) and the revocation machinery
	// (revoke.go) share one error surface.
	ErrRevoked = errors.New("fleet: deployment is revoked")
	// ErrNotEnrolled: the deployment identity is unknown to the registry —
	// fail-closed default for every registry question about it.
	ErrNotEnrolled = errors.New("fleet: deployment is not enrolled")
)

// allowedTransitions is the full lifecycle law (identity-model.md §4).
// revoked is terminal (empty set). Same-state "transitions" are absent on
// purpose: a refresh is not a lifecycle change; health updates (W04) report
// state without transitioning to it.
var allowedTransitions = map[State]map[State]bool{
	StateEnrolled: {StateActive: true, StateRevoked: true},
	StateActive:   {StateStale: true, StateRevoked: true},
	StateStale:    {StateActive: true, StateRevoked: true},
	StateRevoked:  {},
}

// StateKnown reports whether s is one of the four model states. Unknown
// states fail closed everywhere else via ValidateTransition.
func StateKnown(s State) bool {
	_, ok := allowedTransitions[s]
	return ok
}

// ValidateTransition enforces the lifecycle law: from and to must be known
// states, from ≠ to, and the edge must exist. Every refusal is ErrInvalidTransition
// with concrete context; the terminality of revoked is expressed by its empty
// edge set, not by a special case.
func ValidateTransition(from, to State) error {
	if !StateKnown(from) {
		return fmt.Errorf("%w: unknown source state %q", ErrInvalidTransition, from)
	}
	if !StateKnown(to) {
		return fmt.Errorf("%w: unknown target state %q", ErrInvalidTransition, to)
	}
	if from == to {
		return fmt.Errorf("%w: %q → %q is a no-op, not a transition", ErrInvalidTransition, from, to)
	}
	if !allowedTransitions[from][to] {
		return fmt.Errorf("%w: %q → %q", ErrInvalidTransition, from, to)
	}
	return nil
}

// validateCoordinate applies the shared structural law of identity-model.md
// §3 to one coordinate: non-empty, no leading/trailing whitespace, no
// control characters, valid UTF-8, at most maxCoordinateBytes. It accepts
// every structurally valid entitlement DeploymentID (whose own law is
// exactly non-empty + no surrounding whitespace, module_entitlement.go
// :147–152) and rejects garbage — a deliberate structural superset, not a
// charset allowlist (vendor-issued identifiers keep their own vocabulary;
// interior spaces stay upstream-legal rather than silently redefining what
// a licensed contour may be called).
func validateCoordinate(kind ErrKind, v string) error {
	if v == "" {
		return fmt.Errorf("%w: %s is empty", kind.Err(), kind.What())
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("%w: %s is not valid UTF-8", kind.Err(), kind.What())
	}
	if strings.TrimSpace(v) != v {
		return fmt.Errorf("%w: %s must not have leading/trailing whitespace", kind.Err(), kind.What())
	}
	if len(v) > maxCoordinateBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", kind.Err(), kind.What(), maxCoordinateBytes)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s must not contain control characters", kind.Err(), kind.What())
		}
	}
	return nil
}

// ErrKind selects which sentinel a coordinate failure reports.
type ErrKind struct {
	err  error
	what string
}

// Err returns the wrapped sentinel.
func (k ErrKind) Err() error { return k.err }

// What returns the human name of the coordinate.
func (k ErrKind) What() string { return k.what }

var (
	kindDeployment = ErrKind{err: ErrInvalidDeploymentID, what: "deployment identity"}
	kindOrg        = ErrKind{err: ErrInvalidOrg, what: "org identity"}
)

// ValidateDeploymentID validates a deployment contour identity coordinate
// (identity-model.md §3). The empty value is invalid: an identity never
// exists without its root (the «пустая — отказ» variant).
func ValidateDeploymentID(id string) error {
	return validateCoordinate(kindDeployment, id)
}

// ValidateOrgID validates the org coordinate with the same structural law.
func ValidateOrgID(id string) error {
	return validateCoordinate(kindOrg, id)
}

// Identity is one installation's public coordinates. It carries no secrets
// by construction (identity-model.md §2): no key material, no tokens, no
// credentials ever live here or in the registry.
type Identity struct {
	// DeploymentID is the licensed production contour identity (I23),
	// inherited from PaidModuleEntitlement.DeploymentID (:98) through a
	// verified enrollment.
	DeploymentID string
	// OrgID is the tenant boundary the installation was enrolled under.
	OrgID string
}

// NewIdentity builds an Identity after validating both coordinates
// (fail-closed: no zero-value identity with invalid coordinates).
func NewIdentity(deploymentID, orgID string) (Identity, error) {
	if err := ValidateDeploymentID(deploymentID); err != nil {
		return Identity{}, err
	}
	if err := ValidateOrgID(orgID); err != nil {
		return Identity{}, err
	}
	return Identity{DeploymentID: deploymentID, OrgID: orgID}, nil
}

// fingerprintDomain separates the identity fingerprint from every other
// hex-sha256 artifact in the system; the model version rides in the domain
// so a future coordinate set cannot collide with today's fingerprints.
const fingerprintDomain = "fleet-identity-v" + IdentityModelVersion

// Fingerprint returns the deterministic identity fingerprint: hex(sha256(
// domain ‖ NUL ‖ OrgID ‖ NUL ‖ DeploymentID)). It is a pure function —
// identical coordinates always yield the identical fingerprint (the
// «повтор вывода отпечатка детерминирован» arm) — and it hashes ONLY public
// coordinates (identity-model.md §2/§3).
func (i Identity) Fingerprint() (string, error) {
	if err := ValidateDeploymentID(i.DeploymentID); err != nil {
		return "", err
	}
	if err := ValidateOrgID(i.OrgID); err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(fingerprintDomain))
	h.Write([]byte{0})
	h.Write([]byte(i.OrgID))
	h.Write([]byte{0})
	h.Write([]byte(i.DeploymentID))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyFingerprint reports whether claimed is exactly the fingerprint of
// i. A forged or recomputed-over-tampered-coordinates claim is false; this
// is the identity-side twin of the verify-then-use ordering law (a claim is
// never trusted because it looks well-formed).
func (i Identity) VerifyFingerprint(claimed string) bool {
	want, err := i.Fingerprint()
	if err != nil {
		// Invalid coordinates have no fingerprint, so nothing can match.
		return false
	}
	return claimed == want
}

// BoundToDeployment reports whether the identity's contour is exactly
// deploymentID (the mismatch-deployment variant's identity-side seam; the
// document-side binding is VerifyPaidModuleEntitlement :271).
func (i Identity) BoundToDeployment(deploymentID string) bool {
	return i.DeploymentID != "" && i.DeploymentID == deploymentID
}

// BoundToOrg reports whether the identity was enrolled under orgID.
func (i Identity) BoundToOrg(orgID string) bool {
	return i.OrgID != "" && i.OrgID == orgID
}
