package adminstore

// N01-P04-T03/T06 rotation runbook pinned at the CREDENTIAL seam
// (org provider API keys — the same contract shape covers the mcpcreds and
// per-model upstream key columns, which share the encryptOrgCredentialKey /
// decryptOrgCredentialKey pattern):
//
//   - dual trust: rows written under the old key stay readable while the old
//     key is still configured (the rollback window);
//   - cross-key failure is loud and material-free: the new key refuses the
//     old row and the old key refuses the re-encrypted row (no silent
//     fallback, no plaintext downgrade, no key/plaintext in errors);
//   - the runbook (decrypt-with-old → re-encrypt-with-new per credential)
//     converges: after the re-save, only the new key reads the row — that is
//     the documented "old secret revoked per contract" step for this seam;
//   - the no-stop property: all of the above happens on live Store objects
//     without any restart or traffic pause — the two encryptors are simply
//     two key versions of the same seam.
//
// This is a mock-grade unit scenario (no database); the envelope format and
// keyring lifecycle they sit on are covered exhaustively in pkg/kms.

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/encryption"
)

const rotProbeKey = "sk-rotation-probe-0123456789abcdef-SECRET" // #nosec G101 -- test probe value

// rotationStore builds a store keyed by an independent random 32-byte key
// (each call = one key version of the seam).
func rotationStore(t *testing.T) *Store {
	t.Helper()
	return newForTest(&mockDB{}, newTestLogger(), encryption.MustNew(encryption.EncodeKey()))
}

func TestOrgCredential_RotationRunbook_NoStop(t *testing.T) {
	oldStore := rotationStore(t)
	newStore := rotationStore(t)

	// Pre-rotation: the old key writes and reads its own envelope.
	ctOld, last4, err := oldStore.encryptOrgCredentialKey(context.Background(), rotProbeKey)
	if err != nil {
		t.Fatalf("encrypt under old key: %v", err)
	}
	if last4 != "CRET" {
		t.Fatalf("last4 = %q", last4)
	}
	if got, err := oldStore.decryptOrgCredentialKey(context.Background(), ctOld); err != nil || got != rotProbeKey {
		t.Fatalf("old key must read its own row: %q, %v", got, err)
	}

	// Dual trust: during the window, the OLD key still serves the row (the
	// rollback window) — no restart, no pause, just a second key version
	// configured alongside.
	if got, err := oldStore.decryptOrgCredentialKey(context.Background(), ctOld); err != nil || got != rotProbeKey {
		t.Fatalf("dual-trust window violated: %q, %v", got, err)
	}

	// Cross-key read BEFORE migration must fail closed: the new key refuses
	// the old row loudly (never an empty credential, never plaintext).
	got, err := newStore.decryptOrgCredentialKey(context.Background(), ctOld)
	if err == nil {
		t.Fatalf("the new key decrypted a pre-rotation row: %q", got)
	}
	if got != "" {
		t.Fatalf("cross-key decrypt returned a value alongside the error: %q", got)
	}
	if strings.Contains(err.Error(), rotProbeKey) {
		t.Fatalf("cross-key error carried the plaintext: %q", err.Error())
	}

	// The runbook: decrypt-with-old → re-encrypt-with-new (per credential,
	// lazily or by sweep — traffic never stops).
	plain, err := oldStore.decryptOrgCredentialKey(context.Background(), ctOld)
	if err != nil {
		t.Fatalf("runbook decrypt: %v", err)
	}
	ctNew, _, err := newStore.encryptOrgCredentialKey(context.Background(), plain)
	if err != nil {
		t.Fatalf("runbook re-encrypt: %v", err)
	}
	if ctNew == ctOld {
		t.Fatal("re-encryption must produce a fresh envelope")
	}
	if got, err := newStore.decryptOrgCredentialKey(context.Background(), ctNew); err != nil || got != rotProbeKey {
		t.Fatalf("the new key must read the migrated row: %q, %v", got, err)
	}

	// Old secret revoked per contract: after the re-save, the OLD key
	// refuses the new row (and the new key still refuses the old artifact).
	if got, err := oldStore.decryptOrgCredentialKey(context.Background(), ctNew); err == nil {
		t.Fatalf("the old key read a rotated row: %q", got)
	} else if strings.Contains(err.Error(), rotProbeKey) {
		t.Fatalf("post-rotation refusal carried the plaintext: %q", err.Error())
	}

	// Rollback window end-to-end: the old row remains readable by the old
	// key until the operator drops that key version.
	if got, err := oldStore.decryptOrgCredentialKey(context.Background(), ctOld); err != nil || got != rotProbeKey {
		t.Fatalf("rollback window violated: %q, %v", got, err)
	}
}

// TestOrgCredential_RotationRefusalsStayLoud pins the seam's fail-closed
// negatives that bound the rotation: a wrong-shaped envelope, an encrypted
// row with no encryptor configured, and a plaintext write without a key all
// refuse instead of degrading.
func TestOrgCredential_RotationRefusalsStayLoud(t *testing.T) {
	noKey := newForTest(&mockDB{}, newTestLogger(), nil)

	// An encrypted row with no configured encryptor is a hard error, never
	// an empty credential or a passthrough.
	if got, err := noKey.decryptOrgCredentialKey(context.Background(), "enc:AAAA"); err == nil {
		t.Fatalf("encrypted row without an encryptor = %q, want refusal", got)
	}

	// A plaintext write without an encryptor is refused under the production
	// policy (the dev escape hatch is explicitly overridden here).
	restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
	defer restore()
	if ct, last4, err := noKey.encryptOrgCredentialKey(context.Background(), rotProbeKey); err == nil {
		t.Fatalf("plaintext credential write = %q/%q, want refusal", ct, last4)
	}
}
