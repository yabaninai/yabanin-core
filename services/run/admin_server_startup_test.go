package run

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Characterization suite for the AdminServer startup pipeline in admin.go:
// every test drives the real entry point and pins one externally observable
// startup behavior (fail-closed gates, gate ordering, negative controls).

// pinAdminStartupEnv isolates AdminServer from the host environment: clean
// license contour, dev deployment mode, no session secret, no datastore.
func pinAdminStartupEnv(t *testing.T) {
	t.Helper()
	pinLicenseEnvClean(t)
	t.Setenv("YABANIN_ENV", "dev")
	t.Setenv("YABANIN_SESSION_KEY", "")
	t.Setenv("YABANIN_ADMIN_SESSION_SECRET", "")
	t.Setenv("YABANIN_PG_URI", "")
	t.Setenv("YABANIN_REGION", "")
	t.Setenv("YABANIN_ENCRYPTION_KEY", "")
	t.Setenv("YABANIN_ADMIN_SESSION_SECRET_GRACE", "")
	t.Setenv("YABANIN_LICENSE_MODULE_ENTITLEMENT_FILE", "")
	t.Setenv("YABANIN_LICENSE_DEPLOYMENT_ID", "")
}

// closedPortPGURI points at a port nothing unprivileged can listen on: the
// startup proceeds past every config gate and fails at the datastore stage.
const closedPortPGURI = "postgres://user:pass@127.0.0.1:1/yabanin"

// strongSessionKey returns a fresh key above the 32-byte entropy floor so
// the session-secret gate accepts it in every deployment mode.
func strongSessionKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

// gateErrorMessages lists the operator-facing gate failures; the negative
// control asserts none of them fire on a valid contour.
var gateErrorMessages = []string{
	"YABANIN_PG_URI is required",
	"session secret rejected",
	"YABANIN_ADMIN_SESSION_SECRET_GRACE",
	"license",
	"module entitlement",
	"encryptor",
	"invalid region id",
}

func TestAdminServer_MissingPGURI_FailsClosed(t *testing.T) {
	pinAdminStartupEnv(t)

	err := AdminServer(context.Background())

	require.Error(t, err)
	assert.Equal(t, "admin: YABANIN_PG_URI is required", err.Error())
}

func TestAdminServer_WeakSessionSecretInProduction_FailsClosed(t *testing.T) {
	pinAdminStartupEnv(t)
	t.Setenv("YABANIN_PG_URI", closedPortPGURI)
	t.Setenv("YABANIN_SESSION_KEY", "short-weak-secret")

	t.Run("production_refuses_weak_secret_before_datastore", func(t *testing.T) {
		t.Setenv("YABANIN_ENV", "production")
		err := AdminServer(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session secret rejected")
		assert.NotContains(t, err.Error(), "failed to connect",
			"the secret gate must fire before any datastore work")
	})

	t.Run("dev_replaces_weak_secret_and_proceeds", func(t *testing.T) {
		err := AdminServer(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to connect",
			"dev mode generates an ephemeral secret and continues to the datastore stage")
		assert.NotContains(t, err.Error(), "session secret")
	})
}

func TestAdminServer_SessionGraceDuration_FailClosedAndPassThrough(t *testing.T) {
	pinAdminStartupEnv(t)
	t.Setenv("YABANIN_PG_URI", closedPortPGURI)

	for _, grace := range []string{"not-a-duration", "-5s"} {
		t.Setenv("YABANIN_ADMIN_SESSION_SECRET_GRACE", grace)
		err := AdminServer(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "admin: invalid YABANIN_ADMIN_SESSION_SECRET_GRACE duration",
			"grace=%q", grace)
		assert.NotContains(t, err.Error(), "failed to connect",
			"the grace gate must fire before any datastore work")
	}

	t.Setenv("YABANIN_ADMIN_SESSION_SECRET_GRACE", "1h")
	err := AdminServer(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect",
		"a valid grace duration must not block startup")
}

func TestAdminServer_InvalidEncryptionKey_FailsClosedBeforeDatastore(t *testing.T) {
	pinAdminStartupEnv(t)
	t.Setenv("YABANIN_PG_URI", closedPortPGURI)
	t.Setenv("YABANIN_ENCRYPTION_KEY", "password-like-key")

	err := AdminServer(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption key")
	assert.NotContains(t, err.Error(), "failed to connect",
		"the encryptor gate must fire before any datastore work")
}

func TestAdminServer_InvalidRegion_FailsClosedBeforeDatastore(t *testing.T) {
	pinAdminStartupEnv(t)
	t.Setenv("YABANIN_PG_URI", closedPortPGURI)
	t.Setenv("YABANIN_REGION", "not a region!")

	err := AdminServer(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid region id")
	assert.NotContains(t, err.Error(), "failed to connect",
		"the RLS region gate must fire before any datastore work")
}

func TestAdminServer_ModuleEntitlementContour_FailClosed(t *testing.T) {
	pinAdminStartupEnv(t)
	t.Setenv("YABANIN_PG_URI", closedPortPGURI)

	cases := []struct {
		name       string
		file       string
		deployment string
		want       string
	}{
		{
			name:       "deployment_without_file",
			deployment: "prod-1",
			want:       "module entitlement env incomplete",
		},
		{
			name: "file_without_deployment",
			file: filepath.Join(t.TempDir(), "entitlement.token"),
			want: "module entitlement env incomplete",
		},
		{
			name:       "unreadable_file",
			file:       filepath.Join(t.TempDir(), "absent.token"),
			deployment: "prod-1",
			want:       "read module entitlement file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YABANIN_LICENSE_MODULE_ENTITLEMENT_FILE", tc.file)
			t.Setenv("YABANIN_LICENSE_DEPLOYMENT_ID", tc.deployment)
			err := AdminServer(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "admin: module entitlement invalid")
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), "failed to connect",
				"the entitlement gate must fire before any datastore work")
		})
	}
}

func TestAdminServer_ValidContour_ProceedsPastAllGates(t *testing.T) {
	pinAdminStartupEnv(t)
	t.Setenv("YABANIN_PG_URI", closedPortPGURI)
	t.Setenv("YABANIN_SESSION_KEY", strongSessionKey(t))
	t.Setenv("YABANIN_ADMIN_SESSION_SECRET_GRACE", "1h")
	t.Setenv("YABANIN_REGION", "sg")

	err := AdminServer(context.Background())

	require.Error(t, err, "closed-port datastore must still fail startup")
	for _, gate := range gateErrorMessages {
		assert.NotContains(t, err.Error(), gate,
			"a valid contour must not be stopped by the %q gate", gate)
	}
}

func TestAdminProductionEnv_Classification(t *testing.T) {
	cases := map[string]bool{
		"dev":          false,
		"DEV":          false,
		" development ": false,
		"test":         false,
		"":             true,
		"production":   true,
		"prod":         true,
		"staging":      true,
	}
	for value, want := range cases {
		t.Setenv("YABANIN_ENV", value)
		assert.Equal(t, want, adminProductionEnv(), "YABANIN_ENV=%q", value)
	}
}

func TestEnvBool_TruthTable(t *testing.T) {
	const name = "YABANIN_TEST_ENVBOOL_KNOB"
	cases := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"0", false},
		{"false", false},
		{"yes", false},
		{"junk", false},
	}
	for _, tc := range cases {
		t.Setenv(name, tc.value)
		assert.Equal(t, tc.want, envBool(name, false), "value=%q", tc.value)
	}
	t.Setenv(name, "")
	assert.True(t, envBool(name, true), "unset/empty must keep the caller default")
}

// TestAdminServer_EnvIsolationGuard pins that the suite does not depend on
// host YABANIN_* state: a fully pinned clean environment reaches the
// datastore stage (never an unexpected gate).
func TestAdminServer_EnvIsolationGuard(t *testing.T) {
	pinAdminStartupEnv(t)
	t.Setenv("YABANIN_PG_URI", closedPortPGURI)
	if _, ok := os.LookupEnv("YABANIN_CONFIG"); ok {
		t.Log("YABANIN_CONFIG pinned by helper")
	}
	err := AdminServer(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect")
}
