//go:build integration

package kms

// boundary — the master key lives in an on-disk file read through the
// production factory (the Docker/K8s _FILE secret convention), and every
// "restart" is a fresh provider instance constructed from that file. The
// the deployment contract: key material survives a restart, rotation through
// the factory keeps data readable only after the runbook re-encrypt, a
// revoked/foreign key fails closed in BOTH directions, missing key material
// refuses to start, and no error names payload or ciphertext material.

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeMasterKeyFile writes 32 raw key bytes to a temp file (the K8s secret
// mount posture) and returns the path.
func writeMasterKeyFile(t *testing.T, name string, key []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("write master key file: %v", err)
	}
	return path
}

// TestKMS_Factory_KeyFileLifecycle_RestartRotateRevoke: issue (factory reads
// the key file) → restart (a fresh instance reads the same file) → rotate
// (new key file; runbook re-encrypt; cross-key decryptions fail closed) →
// revoke (no key material = no provider at all).
func TestKMS_Factory_KeyFileLifecycle_RestartRotateRevoke(t *testing.T) {
	const payload = "kms-factory-lifecycle-payload"
	keyA := writeMasterKeyFile(t, "kms.key.a", masterKey(0x11))
	keyB := writeMasterKeyFile(t, "kms.key.b", masterKey(0x22))
	ctx := context.Background()

	// Issue: the factory builds the provider from the mounted key file.
	t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", keyA)
	t.Setenv("YABANIN_KMS_LOCAL_KEY", "")
	old, err := New("local", "")
	if err != nil {
		t.Fatalf("New(local, keyA): %v", err)
	}
	ctOld, err := old.Encrypt(ctx, []byte(payload))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Restart: a fresh factory instance from the same on-disk material
	// reads the pre-restart ciphertext (persistence across the process
	// boundary).
	t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", keyA)
	restarted, err := New("local", "")
	if err != nil {
		t.Fatalf("New(local, keyA restart): %v", err)
	}
	if got, err := restarted.Decrypt(ctx, ctOld); err != nil || string(got) != payload {
		t.Fatalf("the restarted provider must read pre-restart ciphertext: %q, %v", got, err)
	}

	// Rotate: swap the mounted file, rebuild through the factory, run the
	// decrypt-with-old → re-encrypt-with-new runbook.
	t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", keyB)
	current, err := New("local", "")
	if err != nil {
		t.Fatalf("New(local, keyB): %v", err)
	}
	plain, err := old.Decrypt(ctx, ctOld)
	if err != nil {
		t.Fatalf("runbook decrypt: %v", err)
	}
	ctNew, err := current.Encrypt(ctx, plain)
	if err != nil {
		t.Fatalf("runbook re-encrypt: %v", err)
	}
	if got, err := current.Decrypt(ctx, ctNew); err != nil || string(got) != payload {
		t.Fatalf("the rotated key must read re-encrypted data: %q, %v", got, err)
	}

	// Cross-key decryptions fail closed in both directions, carrying no
	// payload or ciphertext material.
	ctNewB64 := base64.StdEncoding.EncodeToString(ctNew)
	for _, tc := range []struct {
		name string
		kms  interface {
			Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
		}
		ct []byte
	}{
		{"revoked key on rotated ciphertext", old, ctNew},
		{"rotated key on pre-rotation ciphertext", current, ctOld},
	} {
		got, err := tc.kms.Decrypt(ctx, tc.ct)
		if err == nil {
			t.Fatalf("%s must fail closed, got %q", tc.name, got)
		}
		if got != nil {
			t.Errorf("%s returned a payload alongside the error: %q", tc.name, got)
		}
		for _, material := range []string{payload, ctNewB64} {
			if strings.Contains(err.Error(), material) {
				t.Errorf("%s error carried material: %q", tc.name, err.Error())
			}
		}
	}

	// Rollback window: the revoked key still reads its own ciphertext.
	if got, err := old.Decrypt(ctx, ctOld); err != nil || string(got) != payload {
		t.Fatalf("the old key must keep reading its own ciphertext: %q, %v", got, err)
	}

	// Revoke: no key material at all — the factory refuses to start (no
	// silent default, no unencrypted fallback).
	t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", "")
	t.Setenv("YABANIN_KMS_LOCAL_KEY", "")
	if p, err := New("local", ""); err == nil {
		t.Fatalf("a stand without key material must not start, got %T", p)
	}
}

// TestFileKMS_KEKRestart_CorruptionAndForeignKEKFailClosed: the ops-facing
// KEK file across a restart (fresh NewFileKMS from the same mounted path),
// plus the corruption and foreign-KEK refusal postures on the real file
// boundary.
func TestFileKMS_KEKRestart_CorruptionAndForeignKEKFailClosed(t *testing.T) {
	const payload = "file-kms-restart-payload"
	kekPath := writeKEKFile(t, "kek-intlc-restart")
	f1, err := NewFileKMS(kekPath, "eu")
	if err != nil {
		t.Fatalf("NewFileKMS: %v", err)
	}
	ct, wrapped, err := f1.Encrypt(context.Background(), []byte(payload))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Restart: a fresh instance built from the same mounted KEK reads the
	// pre-restart envelope.
	restarted, err := NewFileKMS(kekPath, "eu")
	if err != nil {
		t.Fatalf("NewFileKMS restart: %v", err)
	}
	if got, err := restarted.Decrypt(context.Background(), ct, wrapped); err != nil || string(got) != payload {
		t.Fatalf("the restarted FileKMS must read pre-restart envelopes: %q, %v", got, err)
	}

	// Corruption: a tampered wrapped DEK fails closed with no material.
	mutated := []byte(wrapped)
	mutated[3] ^= 0xFF
	if got, err := restarted.Decrypt(context.Background(), ct, string(mutated)); err == nil {
		t.Fatalf("a corrupted envelope must fail closed, got %q", got)
	} else {
		for _, material := range []string{payload, ct, wrapped} {
			if strings.Contains(err.Error(), material) {
				t.Errorf("corruption error carried material: %q", err.Error())
			}
		}
	}

	// Foreign KEK: a different mounted file decrypts nothing.
	foreign, err := NewFileKMS(writeKEKFile(t, "kek-intlc-foreign"), "eu")
	if err != nil {
		t.Fatalf("NewFileKMS foreign: %v", err)
	}
	if got, err := foreign.Decrypt(context.Background(), ct, wrapped); err == nil {
		t.Fatalf("a foreign KEK must fail closed, got %q", got)
	} else if strings.Contains(err.Error(), payload) {
		t.Errorf("foreign-KEK error carried material: %q", err.Error())
	}
}
