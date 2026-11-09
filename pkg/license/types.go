package license

import "time"

// Token represents an issued license signed by an intermediate key.
type Token struct {
	Version      string    `json:"v"`
	CustomerID   string    `json:"c"`
	Expiry       time.Time `json:"e"`
	Serial       string    `json:"s"`
	IssuedAt     time.Time `json:"i"`
	Intermediate string    `json:"intermediate_id"`
	Signature    []byte    `json:"sig"`
}

// IntermediateCert represents a certificate for an intermediate signing key.
type IntermediateCert struct {
	Version  string    `json:"v"`
	Serial   string    `json:"s"`
	PubKey   []byte    `json:"pub"`
	RootSig  []byte    `json:"root_sig"`
	Expiry   time.Time `json:"e"`
	IssuedAt time.Time `json:"i"`
}

// CRL represents a certificate revocation list.
type CRL struct {
	RevokedSerials []string  `json:"revoked_serials"`
	UpdatedAt      time.Time `json:"updated_at"`
}
