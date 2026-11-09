package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// These signing helpers create disposable verification fixtures only.
// fixtureRootKeyPair generates a new root Ed25519 keypair for the PKI.
func fixtureRootKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate root key: %w", err)
	}
	return pub, priv, nil
}

// fixtureIntermediate creates an intermediate cert and key signed by the root.
func fixtureIntermediate(rootPriv ed25519.PrivateKey, validity time.Duration) (*IntermediateCert, ed25519.PrivateKey, error) {
	interPub, interPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate intermediate key: %w", err)
	}

	serial := fixtureSerial()
	cert := &IntermediateCert{
		Version:  "1",
		Serial:   serial,
		PubKey:   interPub,
		Expiry:   time.Now().Add(validity),
		IssuedAt: time.Now(),
	}

	payload := []byte(fmt.Sprintf("%s|%s|", cert.Version, cert.Serial))
	payload = append(payload, interPub...)
	cert.RootSig = ed25519.Sign(rootPriv, payload)

	return cert, interPriv, nil
}

// fixtureLicense creates a new license token signed by the intermediate key.
func fixtureLicense(interPriv ed25519.PrivateKey, interSerial string, customerID string, expiry time.Time) (*Token, error) {
	serial := fixtureSerial()
	token := &Token{
		Version:      "1",
		CustomerID:   customerID,
		Expiry:       expiry,
		Serial:       serial,
		Intermediate: interSerial,
		IssuedAt:     time.Now(),
	}

	payload := []byte(fmt.Sprintf("%s|%s|%s|%s|%s",
		token.Version,
		token.CustomerID,
		token.Serial,
		token.Expiry.Format(time.RFC3339),
		interSerial,
	))
	token.Signature = ed25519.Sign(interPriv, payload)

	return token, nil
}

func fixtureSerial() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
