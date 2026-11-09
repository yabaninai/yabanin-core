package kms

// failure/boundary tests: decryption failures and misconfiguration
// must stay diagnosable without ever carrying key material in the error
// strings, and every non-local or wrong-key path must fail closed. FileKMS
// had no coverage at all before this file; its unwrap/decrypt errors are the
// last boundary where ciphertext/DEK material could surface.

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/encryption"
)

// masterKey builds a deterministic AES-256 key (not a real credential).
func masterKey(seed byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

// TestLocalKMS_WrongMasterKeyFailsClosed: a foreign master key decrypts
// nothing, and the failure names no material.
func TestLocalKMS_WrongMasterKeyFailsClosed(t *testing.T) {
	plaintext := []byte("boundary-plaintext-r034")
	owner, err := NewLocalKMS(masterKey(0x10))
	if err != nil {
		t.Fatalf("NewLocalKMS(owner): %v", err)
	}
	foreign, err := NewLocalKMS(masterKey(0x80))
	if err != nil {
		t.Fatalf("NewLocalKMS(foreign): %v", err)
	}

	ct, err := owner.Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := foreign.Decrypt(context.Background(), ct)
	if err == nil {
		t.Fatalf("a foreign master key decrypted owner ciphertext: %q", got)
	}
	if got != nil {
		t.Errorf("foreign decrypt returned payload alongside the error: %q", got)
	}
	if strings.Contains(err.Error(), string(plaintext)) || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(ct)) {
		t.Errorf("decrypt error carried material: %q", err.Error())
	}
}

// TestLocalKMS_DecryptFailureErrorsCarryNoMaterial: every malformed-ciphertext
// refusal keeps the plaintext AND the ciphertext out of the error string.
func TestLocalKMS_DecryptFailureErrorsCarryNoMaterial(t *testing.T) {
	plaintext := []byte("boundary-plaintext-r034-secret")
	k, err := NewLocalKMS(masterKey(0x20))
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}
	ct, err := k.Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ctB64 := base64.StdEncoding.EncodeToString(ct)

	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xFF

	tests := []struct {
		name string
		ct   []byte
	}{
		{"tampered", tampered},
		{"truncated to nonce", ct[:8]},
		{"empty", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := k.Decrypt(context.Background(), tc.ct)
			if err == nil {
				t.Fatalf("malformed ciphertext (%s) must fail, got %q", tc.name, got)
			}
			if strings.Contains(err.Error(), string(plaintext)) {
				t.Errorf("error carried the plaintext: %q", err.Error())
			}
			if strings.Contains(err.Error(), ctB64) {
				t.Errorf("error carried the ciphertext: %q", err.Error())
			}
		})
	}
}

// TestNewLocalKMS_RejectsInvalidKeyMaterial: wrong key sizes are refused
// with a size-only diagnosis; the key bytes never appear in the error.
func TestNewLocalKMS_RejectsInvalidKeyMaterial(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", []byte("too-short-key")},
		{"odd", make([]byte, 31)},
		{"oversized", make([]byte, 64)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k, err := NewLocalKMS(tc.key)
			if err == nil {
				t.Fatalf("NewLocalKMS(%s) = %v, want error", tc.name, k)
			}
			if k != nil {
				t.Errorf("NewLocalKMS(%s) returned a provider alongside the error", tc.name)
			}
			if len(tc.key) > 0 && strings.Contains(err.Error(), string(tc.key)) {
				t.Errorf("error echoed the key material: %q", err.Error())
			}
		})
	}
}

// writeKEKFile writes a valid random hex KEK (encryption.New grade) to a
// temp file and returns the path.
func writeKEKFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(encryption.EncodeKey()), 0o600); err != nil {
		t.Fatalf("write kek: %v", err)
	}
	return path
}

// TestFileKMS_RoundTrip covers the previously untested FileKMS happy path.
func TestFileKMS_RoundTrip(t *testing.T) {
	f, err := NewFileKMS(writeKEKFile(t, "kek"), "eu")
	if err != nil {
		t.Fatalf("NewFileKMS: %v", err)
	}
	if f.Name() != "file" || f.Region() != "eu" {
		t.Errorf("provider identity = %s/%s, want file/eu", f.Name(), f.Region())
	}

	payload := []byte("file-kms-boundary-payload")
	ct, wrapped, err := f.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !encryption.IsEncrypted(ct) || !encryption.IsEncrypted(wrapped) {
		t.Fatalf("envelope outputs must be enc:-prefixed, got ct=%t wrapped=%t", encryption.IsEncrypted(ct), encryption.IsEncrypted(wrapped))
	}
	got, err := f.Decrypt(context.Background(), ct, wrapped)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("round-trip mismatch: %q", got)
	}
}

// TestFileKMS_WrongKEKAndCorruptionFailClosed: a foreign KEK or a tampered
// wrapped DEK refuses with a diagnosable error that carries no DEK, wrapped
// DEK, or payload material.
func TestFileKMS_WrongKEKAndCorruptionFailClosed(t *testing.T) {
	owner, err := NewFileKMS(writeKEKFile(t, "kek-owner"), "eu")
	if err != nil {
		t.Fatalf("NewFileKMS(owner): %v", err)
	}
	foreign, err := NewFileKMS(writeKEKFile(t, "kek-foreign"), "eu")
	if err != nil {
		t.Fatalf("NewFileKMS(foreign): %v", err)
	}

	payload := []byte("file-kms-boundary-payload-2")
	ct, wrapped, err := owner.Encrypt(context.Background(), payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Foreign KEK: the wrapped DEK is unreadable → fail closed.
	got, err := foreign.Decrypt(context.Background(), ct, wrapped)
	if err == nil {
		t.Fatalf("a foreign KEK unwrapped the DEK: %q", got)
	}
	if got != nil {
		t.Errorf("foreign decrypt returned payload alongside the error: %q", got)
	}

	// Tampered wrapped DEK (valid enc: framing, flipped payload byte).
	raw, dErr := base64.StdEncoding.DecodeString(wrapped[len("enc:"):])
	if dErr != nil {
		t.Fatalf("decode wrapped: %v", dErr)
	}
	raw[len(raw)-1] ^= 0xFF
	tampered := "enc:" + base64.StdEncoding.EncodeToString(raw)

	tests := []struct {
		name    string
		kek     *FileKMS
		wrapped string
	}{
		{"wrong kek", foreign, wrapped},
		{"tampered wrapped dek", owner, tampered},
		{"non-enc wrapped dek", owner, "plaintext-dek"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.kek.Decrypt(context.Background(), ct, tc.wrapped)
			if err == nil {
				t.Fatalf("%s must fail closed, got %q", tc.name, got)
			}
			for _, material := range []string{string(payload), ct, wrapped, tampered} {
				if material != "" && strings.Contains(err.Error(), material) {
					t.Errorf("%s error carried material: %q", tc.name, err.Error())
				}
			}
		})
	}
}

// TestFileKMS_MissingKEKPathRejected: an empty or unreadable kek_path fails
// construction (no silently unencrypted provider).
func TestFileKMS_MissingKEKPathRejected(t *testing.T) {
	if f, err := NewFileKMS("", "eu"); err == nil {
		t.Fatalf("empty kek_path = %v, want error", f)
	}
	if f, err := NewFileKMS(filepath.Join(t.TempDir(), "absent"), "eu"); err == nil {
		t.Fatalf("missing kek file = %v, want error", f)
	}
	// A text-shaped "key" (password-like) must be rejected by the KEK policy.
	weak := filepath.Join(t.TempDir(), "weak")
	if err := os.WriteFile(weak, []byte("hunter2-hunter2-hunter2-hunter2!"), 0o600); err != nil {
		t.Fatalf("write weak kek: %v", err)
	}
	if f, err := NewFileKMS(weak, "eu"); err == nil {
		t.Fatalf("password-like KEK = %v, want error", f)
	}
}

// TestAWSKMS_StubFailsClosedWithoutEcho: the stub provider never encrypts,
// never decrypts, and never passes material through in either direction.
func TestAWSKMS_StubFailsClosedWithoutEcho(t *testing.T) {
	plaintext := []byte("aws-stub-boundary-payload")
	aws := NewAWSKMS("alias/boundary")

	ct, err := aws.Encrypt(context.Background(), plaintext)
	if err == nil {
		t.Fatalf("the stub must never encrypt, got %q", ct)
	}
	if strings.Contains(err.Error(), string(plaintext)) {
		t.Errorf("stub encrypt error echoed the plaintext: %q", err.Error())
	}
	if _, err := aws.Decrypt(context.Background(), plaintext); err == nil {
		t.Fatal("the stub must never decrypt")
	}
	if err := aws.Validate(); err == nil {
		t.Fatal("the stub must never validate")
	}
}

// TestNew_FactoryLocalKeyBoundaries: hermetic factory checks — key sizes are
// diagnosed by length only, a 16-byte AES-128 key is accepted, and unknown
// providers are refused.
func TestNew_FactoryLocalKeyBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"missing", "", true},
		{"short raw key", "0123456789abcde", true},
		{"aes-128 raw key", "0123456789abcdef", false},
		{"aes-256 raw key", "0123456789abcdef0123456789abcdef", false},
		{"oversized", "0123456789abcdef0123456789abcdef0", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", "")
			t.Setenv("YABANIN_KMS_LOCAL_KEY", tc.key)
			p, err := New("local", "")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("New(local, key %q) = %v, want error", tc.name, p)
				}
				if tc.key != "" && strings.Contains(err.Error(), tc.key) {
					t.Errorf("factory error echoed the key material: %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("New(local): %v", err)
			}
			if p == nil {
				t.Fatal("New(local) returned a nil provider")
			}
		})
	}

	t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", "")
	t.Setenv("YABANIN_KMS_LOCAL_KEY", "0123456789abcdef0123456789abcdef")
	if p, err := New("gcp", ""); err == nil {
		t.Fatalf("unknown provider = %v, want error", p)
	}
}
