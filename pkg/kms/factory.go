package kms

import (
	"bytes"
	"fmt"
	"os"

	"github.com/reireirei/yabanin/pkg/config"
)

// Supported providers: "local" (env/file master key — wired and tested) and
// "file" (same key material from a path). The "aws" provider is a FAIL-CLOSED
// STUB: Encrypt/Decrypt/Validate return errors. Do not enable it until it is
// implemented against aws-sdk-go-v2 with an integration test — do not wire the
// SDK "for the checkbox" without one.

// masterKeyEnv is the environment variable that must hold a 32-byte AES-256 key for LocalKMS.
const masterKeyEnv = "YABANIN_KMS_LOCAL_KEY"

// ReadKeyFromEnv reads KMS key from YABANIN_KMS_LOCAL_KEY_FILE or YABANIN_KMS_LOCAL_KEY env vars.
// It supports the Docker/Kubernetes _FILE convention: if YABANIN_KMS_LOCAL_KEY_FILE is set,
// its value is treated as a file path whose contents are read as the key. Otherwise,
// YABANIN_KMS_LOCAL_KEY is used directly (convenient for local development).
func ReadKeyFromEnv() ([]byte, error) {
	env := config.KMSLocalFromEnv()
	// Try _FILE variant first (Docker secret convention)
	if env.KeyFile != "" {
		data, err := os.ReadFile(env.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read kms key file %s: %w", env.KeyFile, err)
		}
		key := bytes.TrimSpace(data)
		if len(key) == 0 {
			return nil, fmt.Errorf("kms key file %s is empty", env.KeyFile)
		}
		return key, nil
	}

	// Fallback to direct env var (for dev)
	if env.Key != "" {
		return []byte(env.Key), nil
	}

	return nil, fmt.Errorf("neither %s_FILE nor %s is set", masterKeyEnv, masterKeyEnv)
}

// New creates a KMS provider based on the given provider name and key ID.
//
// Configuration matrix (unsupported combinations fail loudly — never a
// silent default):
//   - Legacy single-key config: YABANIN_KMS_LOCAL_KEY(_FILE) with no keyset
//     file → the classic unversioned LocalKMS (backward compatible).
//   - Explicit versioned config: YABANIN_KMS_KEYSET_FILE alone → a
//     VersionedKMS ring (envelopes carry the key version; rotation is
//     online — see versioned.go).
//   - Both key sources at once → error: an ambiguous key source must not
//     start.
//   - The "aws" provider remains a fail-closed stub regardless of key
//     source.
func New(provider, keyID string) (Provider, error) {
	switch provider {
	case "local", "":
		keysetPath := os.Getenv(keysetFileEnv)
		if keysetPath != "" {
			env := config.KMSLocalFromEnv()
			if env.KeyFile != "" || env.Key != "" {
				return nil, fmt.Errorf("kms: unsupported configuration: %s and %s/%s are mutually exclusive; choose one key source", keysetFileEnv, masterKeyEnv+"_FILE", masterKeyEnv)
			}
			return NewVersionedFromEnv()
		}
		key, err := ReadKeyFromEnv()
		if err != nil {
			return nil, fmt.Errorf("kms: %w", err)
		}
		if len(key) != 32 && len(key) != 16 {
			return nil, fmt.Errorf("kms: %s must be 16 (AES-128) or 32 (AES-256) bytes, got %d", masterKeyEnv, len(key))
		}
		return NewLocalKMS(key)
	case "aws":
		// Fail-closed stub: AWSKMS.Validate always returns an error until a
		// real aws-sdk-go-v2 implementation lands (see aws_kms.go).
		return nil, (&AWSKMS{keyID: keyID}).Validate()
	default:
		return nil, fmt.Errorf("kms: unknown provider %q", provider)
	}
}
