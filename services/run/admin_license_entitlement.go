package run

// Offline paid-module entitlement wiring (N11-P05-T03) at the admin entry
// point — the license-specific seam named by the packet contract. Scope and
// posture:
//
//   - FULLY OFFLINE: the entitlement token is read from a local file and
//     verified against the build-embedded vendor public key
//     (license.VendorPublicKey). No external server is contacted — there is
//     no phone-home, no fetch, no online revocation on this path.
//   - OPT-IN, FAIL-CLOSED: an unconfigured contour (both env vars unset)
//     runs enterprise-free with no enforcement and no failure; a
//     half-configured or invalid entitlement refuses startup — enforcement
//     never half-starts (same posture as the activation chain gate).
//   - I24 PERPETUAL RUN RIGHT: verification has no maintenance gate. A
//     deployment whose maintenance term ended still loads its paid
//     entitlement and keeps every paid module; MaintenanceEnd only decides
//     the update/support status reported at startup. The 7-day activation
//     GracePeriod (pkg/license GracePeriod) is never consulted here.
//   - NO DEFAULT GRANTS: resolving the document grants no feature by
//     itself. Core defines no module catalog (owner answers I53/I62/I63 are
//     vendor-issued ids); consumers gate through the signed module list
//     (HasModule) or the core EntitlementSource boundary, never through
//     this loader.

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/license"
)

const (
	// licenseModuleEntitlementFileEnv names the local file holding the
	// vendor-signed paid-module entitlement token
	// (base64url(payload).base64url(sig)).
	licenseModuleEntitlementFileEnv = "YABANIN_LICENSE_MODULE_ENTITLEMENT_FILE"
	// licenseModuleEntitlementDeploymentEnv names the running production
	// contour (I23): one entitlement covers the contour's HA/DR/test
	// instances; independent production contours present their own identity
	// and need their own license.
	licenseModuleEntitlementDeploymentEnv = "YABANIN_LICENSE_DEPLOYMENT_ID"
)

// resolveModuleEntitlement loads and verifies the offline paid-module
// entitlement configured for this contour. Returns (nil, nil) when the
// deployment carries no entitlement (enterprise-free core contour); returns
// an error when the configuration is incomplete or the document fails the
// offline checks — callers must refuse startup in that case.
func resolveModuleEntitlement() (*license.PaidModuleEntitlement, error) {
	tokenFile := strings.TrimSpace(os.Getenv(licenseModuleEntitlementFileEnv))
	deploymentID := strings.TrimSpace(os.Getenv(licenseModuleEntitlementDeploymentEnv))

	if tokenFile == "" && deploymentID == "" {
		return nil, nil //nolint:nilnil // unconfigured contour is enterprise-free (I22): absence is the explicit non-error "no entitlement" state, callers branch on ent==nil
	}
	if tokenFile == "" {
		return nil, fmt.Errorf("module entitlement env incomplete: %s is required when %s is set",
			licenseModuleEntitlementFileEnv, licenseModuleEntitlementDeploymentEnv)
	}
	if deploymentID == "" {
		return nil, fmt.Errorf("module entitlement env incomplete: %s is required when %s is set",
			licenseModuleEntitlementDeploymentEnv, licenseModuleEntitlementFileEnv)
	}

	// Operator/config-chosen local path (same trust boundary as the
	// activation license file; see pkg/license/localfile.go).
	data, err := os.ReadFile(tokenFile) //nolint:gosec // G304: operator-configured path, same trust boundary as YABANIN_LICENSE_FILE
	if err != nil {
		return nil, fmt.Errorf("read module entitlement file: %w", err)
	}

	ent, err := license.VerifyPaidModuleEntitlement(strings.TrimSpace(string(data)), license.VendorPublicKey, deploymentID)
	if err != nil {
		return nil, err
	}
	return &ent, nil
}

// logModuleEntitlementStatus reports the offline I24/I25 standing at startup:
// the perpetual run right is implicit (the entitlement verified), while the
// renewal-gated status is derived locally from the signed MaintenanceEnd —
// visible, offline-verifiable metadata per I24, never an enforcement input.
// The optional signed evaluation term (TrialEnd) is reported as the explicit
// state it is (active/ended/no trial) — never as a run-right bound.
func logModuleEntitlementStatus(logger *slog.Logger, ent *license.PaidModuleEntitlement) {
	if ent == nil {
		return
	}
	now := time.Now()
	fields := []any{
		"deployment", ent.DeploymentID,
		"modules", len(ent.Modules),
		"maintenance_end", ent.MaintenanceEnd.Format(time.RFC3339),
		"maintenance_ended", ent.MaintenanceEndedAt(now),
		"updates_entitled", ent.UpdatesEntitledAt(now),
	}
	if !ent.TrialEnd.IsZero() {
		fields = append(fields,
			"trial_end", ent.TrialEnd.Format(time.RFC3339),
			"trial_active", ent.TrialActiveAt(now),
		)
	}
	logger.Info("paid-module entitlement verified (offline)", fields...)
}
