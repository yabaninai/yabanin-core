// Revocation (E03-P01 card W02-C02, batch A): the packet's revocation law
// over the in-memory registry. Precedent: the license CRL
// (pkg/license/crl.go:11 RevokeIntermediate, :37 IsRevoked) — revocation is
// set membership, addition is idempotent, membership is a pure lookup. The
// registry form drops the CRL's filesystem I/O (persistence arrives with
// migration 0024_fleet_registry, W03-C03 batch B) and keeps the semantics.
//
// PACKET LAW (DISPATCH §3 W02-C02, identity-model.md §2): a revoked
// installation receives NO secrets — the refusal is one of ISSUANCE, never
// one of storage. The registry stores no key material at all; there is no
// secret to withdraw, only issuance decisions to refuse. KMS integration
// is explicitly out of scope (DISPATCH §2 anchor table).
//
// Determinism: revocation takes the clock as an injected parameter (for
// the audit trail) and consults NO time value in any membership decision —
// a clock rollback therefore cannot un-revoke (the W02-C03 arm).
package fleet

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrRevocationRejected means the revocation request itself is malformed
// (unknown deployment, empty reason, zero clock). Re-revoking an already
// revoked installation is NOT an error — it is the idempotent success the
// CRL precedent defines (crl.go:24–27).
var ErrRevocationRejected = errors.New("fleet: revocation rejected")

// Revoke marks the enrolled deployment revoked. Fail-closed contract:
//
//   - unknown deployment → ErrNotEnrolled wrapped in ErrRevocationRejected
//     (an auditor cannot revoke what the registry never accepted);
//   - empty/padded reason → refused (the audit trail never records a
//     why-less revocation);
//   - zero clock → refused (a revocation without a timestamp would be an
//     unauditable mutation of terminal state);
//   - already revoked → nil, and the FIRST RevokedAt/Reason are preserved
//     (idempotence, crl.go precedent);
//   - live (enrolled/active/stale) → the ValidateTransition law moves it to
//     StateRevoked — including the stale→revoked edge the card names
//     («stale→revoked переход виден»).
func (r *Registry) Revoke(deploymentID string, reason string, now time.Time) error {
	if err := ValidateDeploymentID(deploymentID); err != nil {
		return fmt.Errorf("%w: %v", ErrRevocationRejected, err)
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: reason is required", ErrRevocationRejected)
	}
	if now.IsZero() {
		return fmt.Errorf("%w: revocation time is required", ErrRevocationRejected)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureLocked()

	ins, ok := r.installations[deploymentID]
	if !ok {
		return fmt.Errorf("%w: %w", ErrRevocationRejected, ErrNotEnrolled)
	}
	if ins.State == StateRevoked {
		// Idempotent: the first revocation stands, byte for byte.
		return nil
	}
	if err := ValidateTransition(ins.State, StateRevoked); err != nil {
		// Unreachable for the four model states (every live state has the
		// revoked edge); the guard keeps the law the single source of
		// truth if states are ever added.
		return fmt.Errorf("%w: %v", ErrRevocationRejected, err)
	}
	ins.State = StateRevoked
	ins.RevokedAt = now.UTC()
	ins.RevocationReason = reason
	return nil
}

// IsRevoked reports membership in the revocation set (crl.go:37 form).
// Unknown deployments are not "revoked" — they are NOT ENROLLED, and the
// issuance gate refuses them on that basis; conflating the two would hide
// registry drift behind a revocation answer.
func (r *Registry) IsRevoked(deploymentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureLocked()
	ins, ok := r.installations[deploymentID]
	return ok && ins.State == StateRevoked
}

// Lookup returns a copy of the installation record (callers can never
// mutate registry state through it).
func (r *Registry) Lookup(deploymentID string) (Installation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureLocked()
	ins, ok := r.installations[deploymentID]
	if !ok {
		return Installation{}, false
	}
	return *ins, true
}

// AuthorizeSecretIssuance is the packet law as an enforceable seam: may
// this installation be ISSUED secrets right now?
//
//   - revoked → ErrRevoked: the issuance is refused. (The registry holds no
//     secrets; the refusal happens at issuance time, by design.)
//   - not enrolled → ErrNotEnrolled: unknown identities receive nothing
//     (fail-closed default).
//   - live (enrolled/active/stale) → nil. Stale installations remain
//     issuable in batch A: staleness is an EXPLICIT health status (W04's
//     law «устаревший статус явно видим»), not a revocation, and silently
//     coupling it to issuance here would pre-empt W04's window policy —
//     disclosed in the card record, decided where the window lives.
func (r *Registry) AuthorizeSecretIssuance(deploymentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureLocked()
	ins, ok := r.installations[deploymentID]
	if !ok {
		return fmt.Errorf("%w: %q", ErrNotEnrolled, deploymentID)
	}
	if ins.State == StateRevoked {
		return fmt.Errorf("%w: secret issuance refused for %q (revoked %s: %s)",
			ErrRevoked, deploymentID, ins.RevokedAt.Format(time.RFC3339Nano), ins.RevocationReason)
	}
	return nil
}
