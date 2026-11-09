// Package kms provides envelope encryption with per-region keys.
// The factory selects the implementation based on config.KMSProvider.
package kms

import (
	"context"
)

// Provider is the interface for envelope encryption operations.
type Provider interface {
	// Encrypt encrypts plaintext and returns ciphertext + metadata.
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	// Decrypt decrypts ciphertext produced by Encrypt.
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}
