package kms

// Decrypt-with-old → re-encrypt-with-new. The boundary
// evidence pins a foreign key failing closed on one ciphertext; what was
// missing is the scenario contract around a rotation: the runbook
// re-encryption must preserve data end-to-end, the OLD key must fail closed
// on NEW ciphertext (no silent fallback — this is exactly why rotating
// without re-encrypting orphans every row, per docs/ops/secrets-rotation.md),
// the NEW key must fail closed on OLD ciphertext until the re-encrypt lands,
// the old ciphertext stays readable for the rollback window, and every
// refusal names no payload or ciphertext material. Both providers with key
// material on disk are covered: LocalKMS (raw master key) and FileKMS
// (KEK file + wrapped-DEK envelopes).

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// TestLocalKMS_MasterKeyRotation_ReencryptRunbook: the LocalKMS rotation
// lifecycle — old ct readable, re-encrypt preserves the payload, both
// cross-key decryptions fail closed with material-free errors, and the old
// ciphertext stays readable for rollback.
func TestLocalKMS_MasterKeyRotation_ReencryptRunbook(t *testing.T) {
	payload := []byte("kms-rotation-lifecycle-payload")
	oldKMS, err := NewLocalKMS(masterKey(0x30))
	if err != nil {
		t.Fatalf("NewLocalKMS(old): %v", err)
	}
	newKMS, err := NewLocalKMS(masterKey(0xC0))
	if err != nil {
		t.Fatalf("NewLocalKMS(new): %v", err)
	}

	ctOld, err := oldKMS.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("Encrypt(old): %v", err)
	}

	// Pre-rotation state: the old key reads its own ciphertext.
	got, err := oldKMS.Decrypt(context.Background(), ctOld)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("old key must read its own ciphertext: %q, %v", got, err)
	}

	// The runbook rotation: decrypt-with-old → encrypt-with-new.
	plain, err := oldKMS.Decrypt(context.Background(), ctOld)
	if err != nil {
		t.Fatalf("runbook decrypt: %v", err)
	}
	ctNew, err := newKMS.Encrypt(context.Background(), plain)
	if err != nil {
		t.Fatalf("runbook re-encrypt: %v", err)
	}

	// Data survives the rotation.
	got, err = newKMS.Decrypt(context.Background(), ctNew)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("the re-encrypted payload must round-trip under the new key: %q, %v", got, err)
	}

	ctNewB64 := base64.StdEncoding.EncodeToString(ctNew)
	// The old key must NOT decrypt the new ciphertext (no silent fallback —
	// rotation without re-encryption must break loudly, never serve
	// anything).
	got, err = oldKMS.Decrypt(context.Background(), ctNew)
	if err == nil {
		t.Fatalf("the old key decrypted the rotated ciphertext: %q", got)
	}
	if got != nil {
		t.Errorf("the cross-key decrypt returned a payload alongside the error: %q", got)
	}
	if strings.Contains(err.Error(), string(payload)) || strings.Contains(err.Error(), ctNewB64) {
		t.Errorf("the cross-key error carried material: %q", err.Error())
	}

	// The new key must NOT decrypt the pre-rotation ciphertext either
	// (fail-closed until the re-encrypt lands).
	got, err = newKMS.Decrypt(context.Background(), ctOld)
	if err == nil {
		t.Fatalf("the new key decrypted a pre-rotation ciphertext: %q", got)
	}
	if got != nil {
		t.Errorf("the cross-key decrypt returned a payload alongside the error: %q", got)
	}
	if strings.Contains(err.Error(), string(payload)) {
		t.Errorf("the cross-key error carried material: %q", err.Error())
	}

	// Rollback window: the old key still reads its own ciphertext.
	got, err = oldKMS.Decrypt(context.Background(), ctOld)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("the old key must keep reading its own ciphertext during the rollback window: %q, %v", got, err)
	}
}

// TestFileKMS_KEKRotation_ReencryptRunbook: the same rotation lifecycle over
// the ops-facing KEK-file provider, where an envelope is (ciphertext, wrapped
// DEK) and the runbook is decrypt-under-old-KEK → re-encrypt-under-new-KEK.
func TestFileKMS_KEKRotation_ReencryptRunbook(t *testing.T) {
	payload := []byte("file-kms-rotation-lifecycle-payload")
	oldKMS, err := NewFileKMS(writeKEKFile(t, "kek-rotation-old"), "eu")
	if err != nil {
		t.Fatalf("NewFileKMS(old): %v", err)
	}
	newKMS, err := NewFileKMS(writeKEKFile(t, "kek-rotation-new"), "eu")
	if err != nil {
		t.Fatalf("NewFileKMS(new): %v", err)
	}

	ctOld, wrappedOld, err := oldKMS.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("Encrypt(old): %v", err)
	}

	// Pre-rotation state: the old KEK reads its own envelope.
	got, err := oldKMS.Decrypt(context.Background(), ctOld, wrappedOld)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("old KEK must read its own envelope: %q, %v", got, err)
	}

	// The runbook rotation: decrypt-under-old → encrypt-under-new.
	plain, err := oldKMS.Decrypt(context.Background(), ctOld, wrappedOld)
	if err != nil {
		t.Fatalf("runbook decrypt: %v", err)
	}
	ctNew, wrappedNew, err := newKMS.Encrypt(context.Background(), plain)
	if err != nil {
		t.Fatalf("runbook re-encrypt: %v", err)
	}

	// Data survives the rotation.
	got, err = newKMS.Decrypt(context.Background(), ctNew, wrappedNew)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("the re-encrypted envelope must round-trip under the new KEK: %q, %v", got, err)
	}

	// Cross-KEK decryptions fail closed in both directions, carrying no
	// payload, ciphertext, or wrapped-DEK material.
	for _, tc := range []struct {
		name    string
		kek     *FileKMS
		ct      string
		wrapped string
	}{
		{"old kek on new envelope", oldKMS, ctNew, wrappedNew},
		{"new kek on old envelope", newKMS, ctOld, wrappedOld},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.kek.Decrypt(context.Background(), tc.ct, tc.wrapped)
			if err == nil {
				t.Fatalf("%s must fail closed, got %q", tc.name, got)
			}
			if got != nil {
				t.Errorf("%s returned a payload alongside the error: %q", tc.name, got)
			}
			for _, material := range []string{string(payload), tc.ct, tc.wrapped} {
				if strings.Contains(err.Error(), material) {
					t.Errorf("%s error carried material: %q", tc.name, err.Error())
				}
			}
		})
	}

	// Rollback window: the old KEK still reads its own envelope.
	got, err = oldKMS.Decrypt(context.Background(), ctOld, wrappedOld)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("the old KEK must keep reading its own envelope during the rollback window: %q, %v", got, err)
	}
}
