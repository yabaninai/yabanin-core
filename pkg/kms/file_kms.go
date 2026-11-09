package kms

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/reireirei/yabanin/pkg/encryption"
)

// FileKMS reads a KEK from a file path (typically a K8s secret mounted
// read-only at /etc/yabanin/kek). Data keys are generated locally and
// envelope-encrypted via AES-GCM (pkg/encryption). No network — air-gap safe.
type FileKMS struct {
	kek    *encryption.Encryptor
	region string
}

// NewFileKMS reads the KEK from kekPath. The file content may be a 64-hex-char
// key or a password string; encryption.New handles both.
func NewFileKMS(kekPath, region string) (*FileKMS, error) {
	if kekPath == "" {
		return nil, fmt.Errorf("file kms: kek_path is required")
	}
	//nolint:gosec // KEK path is injected via K8s secret mount, not user-controlled
	kekBytes, err := os.ReadFile(kekPath)
	if err != nil {
		return nil, fmt.Errorf("file kms: read kek %s: %w", kekPath, err)
	}
	enc, err := encryption.New(string(kekBytes))
	if err != nil {
		return nil, fmt.Errorf("file kms: build kek: %w", err)
	}
	return &FileKMS{kek: enc, region: region}, nil
}

// Name returns the provider name for this KMS implementation.
func (f *FileKMS) Name() string { return "file" }

// Region returns the deployment region for this KMS instance.
func (f *FileKMS) Region() string { return f.region }

// Encrypt generates a random DEK, encrypts plaintext with it, and wraps the DEK with KEK.
func (f *FileKMS) Encrypt(_ context.Context, plaintext []byte) (string, string, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return "", "", fmt.Errorf("file kms: gen dek: %w", err)
	}
	dekHex := fmt.Sprintf("%x", dek)
	dekEnc, err := encryption.New(dekHex)
	if err != nil {
		return "", "", fmt.Errorf("file kms: build dek: %w", err)
	}
	ciphertext, err := dekEnc.Encrypt(string(plaintext))
	if err != nil {
		return "", "", fmt.Errorf("file kms: encrypt payload: %w", err)
	}
	wrapped, err := f.kek.Encrypt(dekHex)
	if err != nil {
		return "", "", fmt.Errorf("file kms: wrap dek: %w", err)
	}
	return ciphertext, wrapped, nil
}

// Decrypt unwraps a DEK with KEK and decrypts the payload.
func (f *FileKMS) Decrypt(_ context.Context, ciphertextB64, wrappedDEK string) ([]byte, error) {
	dekHex, err := f.kek.Decrypt(wrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("file kms: unwrap dek: %w", err)
	}
	dekEnc, err := encryption.New(dekHex)
	if err != nil {
		return nil, fmt.Errorf("file kms: build dek: %w", err)
	}
	pt, err := dekEnc.Decrypt(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("file kms: decrypt payload: %w", err)
	}
	return []byte(pt), nil
}
