package lineage

// plaintext key material for storage in production (dev/test keeps the
// historical passthrough with a warning), and the migration helpers must be
// no-ops without an encryptor or a database.

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/encryption"
)

func TestKeyStore_Encrypt_RefusesPlaintextInProduction(t *testing.T) {
	restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
	defer restore()

	ks := NewKeyStore(nil, nil)
	_, err := ks.Encrypt("base64-private-key-material")
	if err == nil {
		t.Fatal("expected production refusal to store plaintext lineage key, got nil")
	}
	if !strings.Contains(err.Error(), "plaintext") {
		t.Errorf("expected 'plaintext' in error, got: %v", err)
	}
}

func TestKeyStore_Encrypt_PassthroughInDevTest(t *testing.T) {
	ks := NewKeyStore(nil, nil)
	got, err := ks.Encrypt("base64-private-key-material")
	if err != nil {
		t.Fatalf("dev/test passthrough must succeed, got: %v", err)
	}
	if got != "base64-private-key-material" {
		t.Errorf("expected plaintext passthrough in dev/test, got %q", got)
	}
}

func TestKeyStore_Encrypt_PrefixWithEncryptor(t *testing.T) {
	ks := NewKeyStore(nil, mustEncryptor(t))
	ct, err := ks.Encrypt("base64-private-key-material")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !encryption.IsEncrypted(ct) {
		t.Fatalf("expected enc:-prefixed ciphertext, got %q", ct)
	}
}

// The no-encryptor no-op (0, nil) on a real pool is covered by the
// integration suite; without a pool the migration reports an error.
func TestKeyStore_MigratePlaintextKeys_NilPoolErrors(t *testing.T) {
	ks := NewKeyStore(nil, mustEncryptor(t))
	if _, err := ks.MigratePlaintextKeys(context.Background()); err == nil {
		t.Fatal("expected error for nil pool, got nil")
	}
}

func mustEncryptor(t *testing.T) *encryption.Encryptor {
	t.Helper()
	e, err := encryption.New(encryption.EncodeKey())
	if err != nil {
		t.Fatalf("build encryptor: %v", err)
	}
	return e
}
