package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Test-only signing support; no issuance API is included in the runtime package.
// fixturePaidModuleEntitlement validates ent, signs it with the vendor private
// key and returns the token form:
// base64url(payload JSON) + "." + base64url(Ed25519 signature).
// IssuedAt defaults to now when zero; both times are normalized to UTC so
// the signed bytes are reproducible.
func fixturePaidModuleEntitlement(priv ed25519.PrivateKey, ent PaidModuleEntitlement, now time.Time) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("issue module entitlement: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	if ent.Version == "" {
		ent.Version = ModuleEntitlementVersion
	}
	if ent.Version != ModuleEntitlementVersion {
		return "", fmt.Errorf("issue module entitlement: unsupported version %q (want %q)", ent.Version, ModuleEntitlementVersion)
	}
	if ent.CustomerID == "" {
		return "", fmt.Errorf("issue module entitlement: customer is required")
	}
	if ent.DeploymentID == "" {
		return "", fmt.Errorf("issue module entitlement: deployment is required")
	}
	if strings.TrimSpace(ent.DeploymentID) != ent.DeploymentID {
		return "", fmt.Errorf("issue module entitlement: deployment must not have leading/trailing whitespace")
	}
	if len(ent.Modules) == 0 {
		return "", fmt.Errorf("issue module entitlement: at least one module is required")
	}
	for i, m := range ent.Modules {
		if strings.TrimSpace(m) == "" {
			return "", fmt.Errorf("issue module entitlement: module[%d] is empty", i)
		}
		if strings.TrimSpace(m) != m {
			return "", fmt.Errorf("issue module entitlement: module[%d] must not have leading/trailing whitespace", i)
		}
	}
	if ent.Nonce == "" {
		return "", fmt.Errorf("issue module entitlement: nonce is required")
	}
	if ent.IssuedAt.IsZero() {
		if now.IsZero() {
			return "", fmt.Errorf("issue module entitlement: issued time is required (neither IssuedAt nor now set)")
		}
		ent.IssuedAt = now
	}
	ent.IssuedAt = ent.IssuedAt.UTC()
	ent.MaintenanceEnd = ent.MaintenanceEnd.UTC()
	if ent.MaintenanceEnd.IsZero() {
		return "", fmt.Errorf("issue module entitlement: maintenance end is required")
	}
	if !ent.MaintenanceEnd.After(ent.IssuedAt) {
		return "", fmt.Errorf("issue module entitlement: maintenance end %s must be after issued %s", ent.MaintenanceEnd.Format(time.RFC3339Nano), ent.IssuedAt.Format(time.RFC3339Nano))
	}
	ent.TrialEnd = ent.TrialEnd.UTC()
	if !ent.TrialEnd.IsZero() && !ent.TrialEnd.After(ent.IssuedAt) {
		return "", fmt.Errorf("issue module entitlement: trial end %s must be after issued %s", ent.TrialEnd.Format(time.RFC3339Nano), ent.IssuedAt.Format(time.RFC3339Nano))
	}
	seenLines := make(map[string]bool, len(ent.ReleaseLines))
	for i, rl := range ent.ReleaseLines {
		if rl.Line == "" {
			return "", fmt.Errorf("issue module entitlement: release line[%d] is empty", i)
		}
		if strings.TrimSpace(rl.Line) != rl.Line {
			return "", fmt.Errorf("issue module entitlement: release line[%d] must not have leading/trailing whitespace", i)
		}
		if rl.SupportEnd.IsZero() {
			return "", fmt.Errorf("issue module entitlement: release line[%d] (%s) names no support end", i, rl.Line)
		}
		if seenLines[rl.Line] {
			return "", fmt.Errorf("issue module entitlement: release line %q listed more than once", rl.Line)
		}
		seenLines[rl.Line] = true
	}
	// The signature never covers itself (and the struct tag omits it when
	// nil); clear it defensively so re-issuing a decoded value is stable.
	ent.Signature = nil

	payload, err := json.Marshal(ent)
	if err != nil {
		return "", fmt.Errorf("issue module entitlement: encode payload: %w", err)
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
