package license

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/reireirei/yabanin/pkg/config"
)

// VerifyLicenseChain verifies a license end-to-end:
// 1. Parse root public key and validate length
// 2. Parse license token
// 3. Check expiry and customer binding
// 4. Load intermediate cert and verify its root signature
// 5. Verify license signature against intermediate pubkey
// 6. Check CRL for revoked intermediates
func VerifyLicenseChain(licensePath string, rootPubHex string, crlPath string) error {
	return verifyLicenseChainInternal(licensePath, rootPubHex, crlPath, "")
}

// verifyLicenseChainInternal is the internal implementation that accepts an
// optional intermediate cert path override. This is used by the CLI to wire
// the --intermediate-cert flag.
func verifyLicenseChainInternal(licensePath string, rootPubHex string, crlPath string, intermediateCertOverride string) error {
	// Parse root public key with length validation
	rootPubBytes, err := hex.DecodeString(rootPubHex)
	if err != nil {
		return fmt.Errorf("parse root pub: %w", err)
	}
	if len(rootPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("root public key must be exactly 32 bytes, got %d", len(rootPubBytes))
	}
	rootPub := ed25519.PublicKey(rootPubBytes)

	// Read license token
	licenseData, err := readLocalFile(licensePath)
	if err != nil {
		return fmt.Errorf("read license file: %w", err)
	}

	var token Token
	if err := json.Unmarshal(licenseData, &token); err != nil {
		return fmt.Errorf("parse license: %w", err)
	}

	// Check expiry
	if time.Now().After(token.Expiry) {
		return fmt.Errorf("license expired at %s", token.Expiry.Format(time.RFC3339))
	}

	// Load intermediate cert (optionally override path via env var or flag)
	interCert, err := loadIntermediateCert(intermediateCertOverride)
	if err != nil {
		return fmt.Errorf("load intermediate: %w", err)
	}

	// Verify intermediate was signed by root
	if err := VerifyIntermediate(interCert, rootPub); err != nil {
		return fmt.Errorf("intermediate verification: %w", err)
	}

	// Check CRL for revoked intermediates
	if crlPath != "" {
		if err := checkCRL(crlPath, interCert.Serial); err != nil {
			return fmt.Errorf("crl check: %w", err)
		}
	}

	// Verify license signature against intermediate pubkey
	if err := VerifyLicense(&token, interCert.PubKey); err != nil {
		return fmt.Errorf("license verification: %w", err)
	}

	return nil
}

// loadIntermediateCert loads the intermediate certificate from file.
// If overridePath is non-empty it takes precedence over the env var default.
func loadIntermediateCert(overridePath string) (*IntermediateCert, error) {
	var path string
	if overridePath != "" {
		path = overridePath
	} else {
		path = config.LicenseFromEnv().IntermediateCert
	}
	if path == "" {
		path = "deploy/license/intermediate.json"
	}

	data, err := readLocalFile(path)
	if err != nil {
		return nil, fmt.Errorf("read intermediate cert: %w", err)
	}

	var cert IntermediateCert
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil, fmt.Errorf("parse intermediate cert: %w", err)
	}

	return &cert, nil
}

func checkCRL(crlPath string, interSerial string) error {
	data, err := readLocalFile(crlPath)
	if err != nil {
		return fmt.Errorf("read crl: %w", err)
	}

	var crl CRL
	if err := json.Unmarshal(data, &crl); err != nil {
		return fmt.Errorf("parse crl: %w", err)
	}

	for _, revoked := range crl.RevokedSerials {
		if revoked == interSerial {
			return fmt.Errorf("intermediate cert serial %s is revoked", interSerial)
		}
	}

	return nil
}
