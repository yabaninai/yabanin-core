package kms

import (
	"context"
	"fmt"
)

// AWSKMS wraps the AWS KMS API for envelope encryption. The actual AWS SDK
// import is deferred to avoid requiring AWS credentials in dev environments.
// This stub satisfies the Provider interface for compilation when AWS is not
// available; production code should wire a real aws-sdk-go-v2 client.
type AWSKMS struct {
	keyID string
}

// NewAWSKMS creates an AWS KMS provider for envelope encryption.
func NewAWSKMS(keyID string) *AWSKMS {
	return &AWSKMS{keyID: keyID}
}

// Encrypt encrypts plaintext using the wrapped KMS data key (stub).
func (k *AWSKMS) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	// Stub: this provider is not yet implemented. It must NOT be used in production —
	// doing so would store data in plaintext with no encryption at all.
	return nil, fmt.Errorf("kms: aws provider is not implemented; use local or file KMS instead")
}

// Decrypt decrypts ciphertext using the wrapped KMS data key (stub).
func (k *AWSKMS) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	// Stub: this provider is not yet implemented. Returning ciphertext as plaintext would
	// silently break encryption integrity and leak data.
	return nil, fmt.Errorf("kms: aws provider is not implemented; use local or file KMS instead")
}

// Validate always fails — the AWS KMS stub must never be selected in production.
func (k *AWSKMS) Validate() error {
	return fmt.Errorf("kms: aws provider is a stub and must not be used; implement with aws-sdk-go-v2 or use local/file KMS")
}
