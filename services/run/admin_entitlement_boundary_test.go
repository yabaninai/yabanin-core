package run

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration proof for the entitlement boundary (pkg/license
// .EntitlementSource) at the real consumer entry point named by the contract:
// services/run/admin.go. The Apache core ships without any enterprise
// component, so AdminServer runs with a nil EntitlementSource — the
// documented "not in enforcement mode" state (no feature grant, no failure).
// These tests drive the actual startup path (config → session secret →
// license gate → datastore), not a direct helper call, and pin the license
// activation env vars so a developer's host environment cannot flip the
// branch under test.

// pinLicenseEnvClean empties every license-activation variable so the
// startup takes the unactivated (enterprise-free) path regardless of the
// host environment.
func pinLicenseEnvClean(t *testing.T) {
	t.Helper()
	t.Setenv("YABANIN_CONFIG", "")
	t.Setenv("YABANIN_LICENSE_FILE", "")
	t.Setenv("YABANIN_LICENSE_ROOT_PUBKEY", "")
	t.Setenv("YABANIN_LICENSE_CRL_FILE", "")
	t.Setenv("YABANIN_LICENSE_INTERMEDIATE_CERT", "")
}

// synthetic closed-port datastore URI (nothing can listen on port 1
// unprivileged): the startup fails fast exactly at the datastore stage with
// no external service. Kept inline like the existing tests in run_test.go.

// TestAdminServer_NoLicenseRunsEnterpriseFree pins the pack criterion through
// the real entry point: with no license activation (nil EntitlementSource =
// not enforced) the admin startup must pass the license gate and proceed
// into the datastore stage. A core without any enterprise component starts —
// the absence of a source is never treated as a failure and no feature is
// granted from defaults.
func TestAdminServer_NoLicenseRunsEnterpriseFree(t *testing.T) {
	pinLicenseEnvClean(t)
	t.Setenv("YABANIN_PG_URI", "postgres://user:pass@127.0.0.1:1/yabanin")
	t.Setenv("YABANIN_SESSION_KEY", "")
	t.Setenv("YABANIN_ENV", "dev") // keep startup cheap: ephemeral secret, no DB expected

	err := AdminServer(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect",
		"startup must proceed past the license/entitlement gate into the datastore stage")
	assert.NotContains(t, err.Error(), "license",
		"an unactivated, enterprise-free core must not fail on the license boundary")
}

// TestAdminServer_LicenseEnvIncomplete_FailClosed pins the half-activated
// negative axis at the real entry point: exactly one of the two required
// license variables must refuse startup before any datastore work —
// enforcement never half-starts.
func TestAdminServer_LicenseEnvIncomplete_FailClosed(t *testing.T) {
	t.Run("file_without_pubkey", func(t *testing.T) {
		pinLicenseEnvClean(t)
		t.Setenv("YABANIN_LICENSE_FILE", filepath.Join(t.TempDir(), "license.json"))
		t.Setenv("YABANIN_PG_URI", "postgres://user:pass@127.0.0.1:1/yabanin")
		t.Setenv("YABANIN_SESSION_KEY", "")
		t.Setenv("YABANIN_ENV", "dev")

		err := AdminServer(context.Background())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "license env incomplete (missing root pubkey)")
	})

	t.Run("pubkey_without_file", func(t *testing.T) {
		pinLicenseEnvClean(t)
		t.Setenv("YABANIN_LICENSE_ROOT_PUBKEY", "ab00")
		t.Setenv("YABANIN_PG_URI", "postgres://user:pass@127.0.0.1:1/yabanin")
		t.Setenv("YABANIN_SESSION_KEY", "")
		t.Setenv("YABANIN_ENV", "dev")

		err := AdminServer(context.Background())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "license env incomplete (missing license file)")
	})
}

// TestAdminServer_InvalidLicense_FailClosed pins the activated-but-broken
// axis: a license file + root key pair whose chain verification fails must
// refuse startup (fail-closed licensing at the consumer entry point).
func TestAdminServer_InvalidLicense_FailClosed(t *testing.T) {
	pinLicenseEnvClean(t)
	t.Setenv("YABANIN_LICENSE_FILE", filepath.Join(t.TempDir(), "absent-license.json"))
	t.Setenv("YABANIN_LICENSE_ROOT_PUBKEY", "ab00")
	t.Setenv("YABANIN_PG_URI", "postgres://user:pass@127.0.0.1:1/yabanin")
	t.Setenv("YABANIN_SESSION_KEY", "")
	t.Setenv("YABANIN_ENV", "dev")

	err := AdminServer(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "license invalid")
}
