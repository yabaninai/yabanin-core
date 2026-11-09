//go:build integration

package integration

import (
	"context"

	"github.com/reireirei/yabanin/pkg/kms"
)

// integrationTestKMS is a no-op KMS provider for integration tests: it passes
// bytes through untouched. It exists only so the integration suite can construct
// a RunGatewayServer argument after the kms.Provider parameter was added; tests
// do not exercise real envelope encryption.
type integrationTestKMS struct{}

var _ kms.Provider = integrationTestKMS{}

func (integrationTestKMS) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (integrationTestKMS) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}
