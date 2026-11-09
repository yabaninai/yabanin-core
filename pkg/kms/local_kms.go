package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// LocalKMS is a no-op envelope encryption provider using in-process AES-GCM.
// Suitable for development and air-gapped deployments where a cloud KMS is
// unavailable. Keys are derived from the provided master key material.
type LocalKMS struct {
	aead cipher.AEAD
}

// NewLocalKMS creates an AES-GCM AEAD from the given 32-byte master key.
func NewLocalKMS(masterKey []byte) (*LocalKMS, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("local kms: create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("local kms: create GCM: %w", err)
	}
	return &LocalKMS{aead: aead}, nil
}

// Encrypt encrypts plaintext with AES-GCM. Returns ciphertext with nonce prepended.
func (k *LocalKMS) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("local kms: generate nonce: %w", err)
	}
	ciphertext := k.aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts ciphertext that was produced by Encrypt. Expects nonce prepended.
func (k *LocalKMS) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	nonceSize := k.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("local kms: ciphertext too short")
	}
	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := k.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("local kms: decrypt: %w", err)
	}
	return plaintext, nil
}
