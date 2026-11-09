package run

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/reireirei/yabanin/pkg/license"
)

// fixtureSignedModuleEntitlement signs disposable test input without validation.
// Tests exercise the production verifier, including correctly signed bad claims.
func fixtureSignedModuleEntitlement(priv ed25519.PrivateKey, ent license.PaidModuleEntitlement, now time.Time) (string, error) {
	if ent.Version == "" {
		ent.Version = license.ModuleEntitlementVersion
	}
	if ent.IssuedAt.IsZero() {
		ent.IssuedAt = now
	}
	ent.IssuedAt = ent.IssuedAt.UTC()
	ent.MaintenanceEnd = ent.MaintenanceEnd.UTC()
	ent.TrialEnd = ent.TrialEnd.UTC()
	ent.Signature = nil
	payload, err := json.Marshal(ent)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload)), nil
}
