package run

// N11-P05-T03 wiring tests at the admin entry point seam: the offline
// paid-module entitlement resolves (nil, nil) when unconfigured, fails
// closed when half-configured or invalid, and — the I24 core — still
// resolves AFTER the maintenance term has ended, with only the renewal
// status flipped. All documents are signed with a fixed-seed test key
// swapped into license.VendorPublicKey (deterministic; restored via defer).

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/license"
)

// entitlementWiringSeed is a fixed 32-byte test-only signing seed
// (deterministic; never a production key).
var entitlementWiringSeed = []byte("yabanin-n11-p05-t03-wiring-seed0")

func entitlementWiringKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(entitlementWiringSeed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	require.True(t, ok)
	return pub, priv
}

// pinEntitlementEnvClean empties the entitlement variables so a developer's
// host environment cannot flip the branch under test.
func pinEntitlementEnvClean(t *testing.T) {
	t.Helper()
	t.Setenv(licenseModuleEntitlementFileEnv, "")
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "")
}

// swapVendorKey swaps the embedded vendor key for the deterministic test key
// and restores it when the test finishes.
func swapVendorKey(t *testing.T, pub ed25519.PublicKey) {
	t.Helper()
	old := license.VendorPublicKey
	license.VendorPublicKey = pub
	t.Cleanup(func() { license.VendorPublicKey = old })
}

// writeEntitlementToken issues a paid-module entitlement for the wiring tests
// and writes its token to a temp file.
func writeEntitlementToken(t *testing.T, priv ed25519.PrivateKey, modules []string, issued, maintenanceEnd time.Time) string {
	t.Helper()
	token, err := fixtureSignedModuleEntitlement(priv, license.PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        modules,
		IssuedAt:       issued,
		MaintenanceEnd: maintenanceEnd,
		Nonce:          "wiring-0001",
	}, issued)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "module-entitlement.token")
	require.NoError(t, os.WriteFile(path, []byte(token+"\n"), 0o600))
	return path
}

// writeEntitlementTokenWithTrial is writeEntitlementToken plus the optional
// signed evaluation term (TrialEnd), for the explicit-trial-state tests.
func writeEntitlementTokenWithTrial(t *testing.T, priv ed25519.PrivateKey, modules []string, issued, maintenanceEnd, trialEnd time.Time) string {
	t.Helper()
	token, err := fixtureSignedModuleEntitlement(priv, license.PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        modules,
		IssuedAt:       issued,
		MaintenanceEnd: maintenanceEnd,
		TrialEnd:       trialEnd,
		Nonce:          "wiring-trial-0001",
	}, issued)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "module-entitlement-trial.token")
	require.NoError(t, os.WriteFile(path, []byte(token+"\n"), 0o600))
	return path
}

func TestModuleEntitlementWiring_Unconfigured_NotEnforced(t *testing.T) {
	pinEntitlementEnvClean(t)

	ent, err := resolveModuleEntitlement()

	require.NoError(t, err, "an unconfigured contour is enterprise-free: absence is never a failure")
	assert.Nil(t, ent, "no entitlement object may appear without configuration")
}

func TestModuleEntitlementWiring_HalfConfigured_FailClosed(t *testing.T) {
	t.Run("file_without_deployment", func(t *testing.T) {
		pinEntitlementEnvClean(t)
		t.Setenv(licenseModuleEntitlementFileEnv, filepath.Join(t.TempDir(), "ent.token"))

		ent, err := resolveModuleEntitlement()

		require.Error(t, err)
		assert.Nil(t, ent)
		assert.Contains(t, err.Error(), licenseModuleEntitlementDeploymentEnv)
		assert.Contains(t, err.Error(), "env incomplete")
	})

	t.Run("deployment_without_file", func(t *testing.T) {
		pinEntitlementEnvClean(t)
		t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")

		ent, err := resolveModuleEntitlement()

		require.Error(t, err)
		assert.Nil(t, ent)
		assert.Contains(t, err.Error(), licenseModuleEntitlementFileEnv)
		assert.Contains(t, err.Error(), "env incomplete")
	})
}

func TestModuleEntitlementWiring_InvalidDocument_FailClosed(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, _ := entitlementWiringKeys(t)
	swapVendorKey(t, pub)
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
	// Absent file → read failure; a present-but-garbage file → verify failure.
	missing := filepath.Join(t.TempDir(), "absent.token")
	t.Setenv(licenseModuleEntitlementFileEnv, missing)

	ent, err := resolveModuleEntitlement()
	require.Error(t, err)
	assert.Nil(t, ent)
	assert.Contains(t, err.Error(), "read module entitlement file")

	garbage := filepath.Join(t.TempDir(), "garbage.token")
	require.NoError(t, os.WriteFile(garbage, []byte("not-a-token"), 0o600))
	t.Setenv(licenseModuleEntitlementFileEnv, garbage)

	ent, err = resolveModuleEntitlement()
	require.Error(t, err)
	assert.Nil(t, ent)
	assert.Contains(t, err.Error(), "verify module entitlement")
}

// TestModuleEntitlementWiring_ValidDocumentOffline is the acceptance path at
// the entry point: a correctly signed document for the running contour
// resolves to the paid module list with no external server (pure file read +
// embedded-key signature check).
func TestModuleEntitlementWiring_ValidDocumentOffline(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
	t.Setenv(licenseModuleEntitlementFileEnv, writeEntitlementToken(t, priv,
		[]string{"internal-loop", "media-persistence"}, now.Add(-24*time.Hour), now.Add(365*24*time.Hour)))

	ent, err := resolveModuleEntitlement()
	require.NoError(t, err)
	require.NotNil(t, ent)
	assert.True(t, ent.HasModule("internal-loop"))
	assert.True(t, ent.HasModule("media-persistence"))
	assert.False(t, ent.HasModule("protection-pack-nextgen"), "unsigned pack must stay ungranted")
	assert.True(t, ent.UpdatesEntitledAt(now), "inside the paid term updates/support are included (I24)")
}

// TestModuleEntitlementWiring_PaidVersionKeepsRunningAfterMaintenanceEnd is
// the I24 acceptance core at the entry point: the SAME document whose
// maintenance term ended still resolves at startup — the paid version keeps
// running — and only the renewal status flips (updates no longer included).
// A maintenance date must never turn into a startup failure for the paid
// deployment.
func TestModuleEntitlementWiring_PaidVersionKeepsRunningAfterMaintenanceEnd(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
	t.Setenv(licenseModuleEntitlementFileEnv, writeEntitlementToken(t, priv,
		[]string{"protection-pack-av", "internal-loop", "media-persistence", "conditional-original-text-retention"},
		now.Add(-400*24*time.Hour), now.Add(-30*24*time.Hour)))

	ent, err := resolveModuleEntitlement()
	require.NoError(t, err, "a paid deployment must start after its maintenance term ended (I24)")
	require.NotNil(t, ent)
	for _, m := range []string{"protection-pack-av", "internal-loop", "media-persistence", "conditional-original-text-retention"} {
		assert.True(t, ent.HasModule(m), "paid module %s must keep running after maintenance end", m)
	}
	assert.True(t, ent.MaintenanceEndedAt(now))
	assert.False(t, ent.UpdatesEntitledAt(now), "new versions/pack updates/support require renewal (I24)")
}

// TestModuleEntitlementWiring_RestartAndOfflineRestoreAfterMaintenanceEnd
// pins the I24 acceptance core across lifecycle events: after the
// maintenance term has ended, the SAME deployment restarts (re-entry
// through AdminServer's resolve path) and its disaster-recovery restore
// (same signed token file, fresh copy, fresh process semantics) both keep
// every paid module running — offline, no renewal, no external server.
// Only the renewal status stays flipped; a restart or restore never turns a
// maintenance date into a startup failure or a lost module.
func TestModuleEntitlementWiring_RestartAndOfflineRestoreAfterMaintenanceEnd(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	modules := []string{"protection-pack-av", "internal-loop", "media-persistence", "conditional-original-text-retention"}
	originalPath := writeEntitlementToken(t, priv, modules,
		now.Add(-400*24*time.Hour), now.Add(-30*24*time.Hour)) // maintenance ended 30d ago
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")

	assertResolved := func(t *testing.T, ent *license.PaidModuleEntitlement) {
		t.Helper()
		require.NotNil(t, ent)
		for _, m := range modules {
			assert.True(t, ent.HasModule(m), "paid module %s must keep running across restart/restore (I24)", m)
		}
		assert.True(t, ent.MaintenanceEndedAt(now))
		assert.False(t, ent.UpdatesEntitledAt(now), "renewal status stays renewal-gated across restart/restore (I24)")
	}

	// Startup (first boot past maintenance end).
	t.Setenv(licenseModuleEntitlementFileEnv, originalPath)
	first, err := resolveModuleEntitlement()
	require.NoError(t, err, "startup after maintenance end must keep the paid version running (I24)")
	assertResolved(t, first)

	// Restart: re-entry through the same resolve path must be deterministic
	// and equally offline — same document, same grants, same renewal status.
	second, err := resolveModuleEntitlement()
	require.NoError(t, err, "restart after maintenance end must keep the paid version running (I24)")
	assertResolved(t, second)

	// Offline restore: the token file is restored from backup to a fresh
	// path (pure local file copy — the DR contour still never contacts any
	// external server) and the restored deployment resolves it identically.
	restoredPath := filepath.Join(t.TempDir(), "restored", "module-entitlement.token")
	require.NoError(t, os.MkdirAll(filepath.Dir(restoredPath), 0o700))
	data, err := os.ReadFile(originalPath) //nolint:gosec // G304: test-only read of the t.TempDir token file written by writeEntitlementToken (operator-path simulation)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(restoredPath, data, 0o600)) //nolint:gosec // G703: path is t.TempDir() literals only, no external input — DR-restore simulation
	t.Setenv(licenseModuleEntitlementFileEnv, restoredPath)

	restored, err := resolveModuleEntitlement()
	require.NoError(t, err, "offline restore after maintenance end must keep the paid version running (I24)")
	assertResolved(t, restored)
}

// TestModuleEntitlementWiring_TrialStateReportedExplicitly pins the optional
// trial layer at the entry point: a document with a signed evaluation term
// resolves normally with the run right untouched by the trial state, and the
// startup report exposes the explicit trial state (active before the signed
// end, ended after it) rather than an indefinite condition.
func TestModuleEntitlementWiring_TrialStateReportedExplicitly(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")
	// Evaluation issued 8 days ago with a 7-day term: the trial is already
	// explicitly over, while the paid maintenance term runs for a year.
	t.Setenv(licenseModuleEntitlementFileEnv, writeEntitlementTokenWithTrial(t, priv,
		[]string{"internal-loop"},
		now.Add(-8*24*time.Hour), now.Add(365*24*time.Hour), now.Add(-1*24*time.Hour)))

	ent, err := resolveModuleEntitlement()
	require.NoError(t, err, "an expired trial must never fail startup — it is an explicit state, not an enforcement gate")
	require.NotNil(t, ent)
	assert.True(t, ent.HasModule("internal-loop"), "paid module unaffected by trial end (I24)")
	assert.False(t, ent.TrialActiveAt(now), "trial end is the explicit signed state, not a silent continuation")
	assert.True(t, ent.UpdatesEntitledAt(now), "trial state must not gate the paid update term")
}

// TestModuleEntitlementWiring_WrongContourRejected pins I23 at the entry
// point: an independently licensed contour cannot resolve another contour's
// document.
func TestModuleEntitlementWiring_WrongContourRejected(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-us-2")
	t.Setenv(licenseModuleEntitlementFileEnv, writeEntitlementToken(t, priv,
		[]string{"internal-loop"}, now.Add(-time.Hour), now.Add(365*24*time.Hour)))

	ent, err := resolveModuleEntitlement()
	require.Error(t, err)
	assert.Nil(t, ent)
	assert.Contains(t, err.Error(), "prod-eu-1")
	assert.Contains(t, err.Error(), "prod-us-2")
}
