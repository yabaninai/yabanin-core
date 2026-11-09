package license

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// VerifyIntermediate checks that an intermediate cert was signed by the given root key.
func VerifyIntermediate(cert *IntermediateCert, rootPub ed25519.PublicKey) error {
	if time.Now().After(cert.Expiry) {
		return fmt.Errorf("intermediate cert expired")
	}

	payload := []byte(fmt.Sprintf("%s|%s|", cert.Version, cert.Serial))
	payload = append(payload, cert.PubKey...)

	if !ed25519.Verify(rootPub, payload, cert.RootSig) {
		return fmt.Errorf("intermediate cert signature invalid")
	}

	return nil
}

// VerifyLicense checks that a license token was signed by the given intermediate key.
func VerifyLicense(token *Token, interPub ed25519.PublicKey) error {
	if time.Now().After(token.Expiry) {
		return fmt.Errorf("license expired")
	}

	payload := []byte(fmt.Sprintf("%s|%s|%s|%s|%s",
		token.Version,
		token.CustomerID,
		token.Serial,
		token.Expiry.Format(time.RFC3339),
		token.Intermediate,
	))

	if !ed25519.Verify(interPub, payload, token.Signature) {
		return fmt.Errorf("license signature invalid")
	}

	return nil
}
