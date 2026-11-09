package run

// N11-P05-T05 negative-semantics pins at the admin entry point seam
// (adjacent tests-only card; T03/T04 wiring helpers consumed, no fork, zero
// production changes). The card's negative scenario, made reproducible at
// the wiring layer:
//
//   1. a maintenance date that already ended — stacked with an already
//      ended trial — must neither fail startup (false failure) nor fake
//      success: the paid modules keep running and the single startup line
//      reports the honest renewal/trial states;
//   2. the activation chain (a DIFFERENT document class with its own 7d
//      GracePeriod clock) is never consulted by the module-entitlement
//      resolver: a stale/hard-expired activation environment cannot
//      substitute for, revoke, or create a paid-module entitlement (I24).
//
// Day-scale margins around time.Now() follow the shipped wiring pattern
// (production reads the wall clock at resolve/report time; assertions are
// clock-free or carry multi-day margins). No wall-clock anchors.

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestModuleEntitlementNegative_MaintenanceAndTrialEnded_ReportedHonestly
// reproduces the card's headline negative at the entry point: the contour's
// maintenance ended 40 days ago AND its evaluation trial ended 10 days ago.
// Expected results, pinned verbatim:
//   - startup succeeds (a maintenance date is never a startup failure — I24);
//   - every previously-paid module (protection / internal loop / history)
//     stays granted, the unsigned pack stays ungranted;
//   - the report says maintenance_ended=true, updates_entitled=false (no
//     false success), trial_active=false (explicit signed end state) and
//     still counts all four paid modules (never a silent drop).
func TestModuleEntitlementNegative_MaintenanceAndTrialEnded_ReportedHonestly(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	day := 24 * time.Hour
	modules := []string{
		"protection-pack-av",
		"internal-loop",
		"media-persistence",
		"conditional-original-text-retention",
	}
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
	t.Setenv(licenseModuleEntitlementFileEnv, writeEntitlementTokenWithTrial(t, priv, modules,
		now.Add(-400*day), now.Add(-40*day) /* maintenance ended */, now.Add(-10*day) /* trial ended */))

	ent, err := resolveModuleEntitlement()
	require.NoError(t, err, "a maintenance date must never fail startup — negative scenario must not produce a false failure (I24)")
	require.NotNil(t, ent)
	for _, m := range modules {
		assert.Truef(t, ent.HasModule(m),
			"paid module %q must keep running after maintenance AND trial end — neither date disables paid functionality (I24)", m)
	}
	assert.False(t, ent.HasModule("protection-pack-nextgen"),
		"the unsigned pack gains no rights from the ended-trial/ended-maintenance state")
	assert.True(t, ent.MaintenanceEndedAt(now), "the maintenance state reads honestly as ended")
	assert.False(t, ent.UpdatesEntitledAt(now), "the update right reads honestly as renewal-gated — no false success (I24)")
	assert.False(t, ent.TrialActiveAt(now), "the ended trial reads honestly as ended — an explicit signed state")

	// The single startup line must report the same honesty an operator can
	// act on — including the exact signed maintenance instant.
	var buf bytes.Buffer
	logModuleEntitlementStatus(slog.New(slog.NewTextHandler(&buf, nil)), ent)
	out := buf.String()
	assert.Contains(t, out, "paid-module entitlement verified (offline)",
		"the offline posture is stated even in the all-negative state")
	assert.Contains(t, out, "maintenance_ended=true")
	assert.Contains(t, out, "updates_entitled=false", "no false success in the operator-visible status (I24)")
	assert.Contains(t, out, "trial_active=false", "the ended trial is reported as the explicit state it is")
	assert.Contains(t, out, "modules=4", "the report still counts every paid module — a maintenance date never drops history/protection/loop")
	assert.Contains(t, out, "maintenance_end="+ent.MaintenanceEnd.Format(time.RFC3339),
		"the report names the exact signed maintenance instant — cause and expected result are operator-visible")
}

// TestModuleEntitlementNegative_ActivationChainNeverConsulted pins the
// "старый grace 7d не подменяет I24" negative at the wiring: the activation
// chain (license.go Verify/State — the document class that owns the 7-day
// GracePeriod) is a different mechanism on a different clock. The module
// entitlement resolver must produce byte-identical results whether the
// activation environment is absent or points at a long-hard-expired
// activation token (an activation document from 2019/2020 would be years
// past any 7d grace IF consulted). Activation presence alone must not
// create module enforcement either — no implicit grant from the other
// document class.
func TestModuleEntitlementNegative_ActivationChainNeverConsulted(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	day := 24 * time.Hour
	modules := []string{"protection-pack-av", "internal-loop"}

	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
	t.Setenv(licenseModuleEntitlementFileEnv, writeEntitlementToken(t, priv, modules,
		now.Add(-24*time.Hour), now.Add(365*day)))

	// Baseline: activation environment completely absent.
	baseline, err := resolveModuleEntitlement()
	require.NoError(t, err)
	require.NotNil(t, baseline)

	// Stale activation environment: a hard-expired activation-shaped token
	// file (fixed literal, deterministic) plus the admin startup key pair —
	// state that, if consulted, would be rejected years beyond any grace.
	staleActivationPath := filepath.Join(t.TempDir(), "stale-activation.token")
	staleActivation := "eyJvcmc_unused-since-2019.sig.deadbeef" // fixed literal; must NEVER be parsed on this path
	require.NoError(t, os.WriteFile(staleActivationPath, []byte(staleActivation+"\n"), 0o600))
	t.Setenv("YABANIN_LICENSE_FILE", staleActivationPath)
	t.Setenv("YABANIN_LICENSE_ROOT_PUBKEY", "ab00")

	withStale, err := resolveModuleEntitlement()
	require.NoError(t, err, "the stale activation environment must not perturb module-entitlement resolution — different document class")
	require.NotNil(t, withStale)
	assert.Equal(t, baseline, withStale,
		"module entitlement resolves byte-identically with and without a hard-expired activation environment: the 7d grace clock is never consulted (I24)")
	for _, m := range modules {
		assert.Truef(t, withStale.HasModule(m), "paid module %q unaffected by activation state (I24)", m)
	}

	// Activation configuration ALONE (no entitlement envs) must not create
	// an entitlement or an error: an activation grant is not a module grant,
	// and the resolver stays in its explicit unconfigured state (I22).
	pinEntitlementEnvClean(t)
	t.Setenv("YABANIN_LICENSE_FILE", staleActivationPath)
	t.Setenv("YABANIN_LICENSE_ROOT_PUBKEY", "ab00")

	entOnlyActivation, err := resolveModuleEntitlement()
	require.NoError(t, err, "activation state must not be read as module enforcement input")
	assert.Nil(t, entOnlyActivation,
		"no entitlement object may materialize from activation configuration alone — the module grant needs its own signed document (I24)")

	// And the fail-closed half-configured state (deployment set, entitlement
	// document missing) stays fail-closed with the activation environment
	// present: a stale activation token must never be accepted as a
	// substitute for the missing entitlement document (I24; the 7d grace
	// window belongs to that other document class and cannot backfill it).
	pinEntitlementEnvClean(t)
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
	t.Setenv("YABANIN_LICENSE_FILE", staleActivationPath)
	t.Setenv("YABANIN_LICENSE_ROOT_PUBKEY", "ab00")

	_, err = resolveModuleEntitlement()
	require.Error(t, err, "a missing entitlement document stays a configuration error even with activation state present")
	assert.Contains(t, err.Error(), licenseModuleEntitlementFileEnv+" is required",
		"the error must name the MISSING entitlement document — the activation file must never silently satisfy it")
}
