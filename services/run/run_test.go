package run

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoggerd_MissingConfigFile pins the fail-closed path: an unreadable config
// file must return an error before any consumer/server setup.
func TestLoggerd_MissingConfigFile(t *testing.T) {
	t.Setenv("YABANIN_CONFIG", filepath.Join(t.TempDir(), "does-not-exist.yaml"))

	err := Loggerd(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "read config file")
}

// TestLoggerd_MissingPGURI pins the fail-closed path: Postgres is required for
// request logging, so an empty PG_URI must not start a degraded consumer.
func TestLoggerd_MissingPGURI(t *testing.T) {
	t.Setenv("YABANIN_PG_URI", "")
	cfgPath := filepath.Join(t.TempDir(), "cfg.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("{}\n"), 0600))
	t.Setenv("YABANIN_CONFIG", cfgPath)

	err := Loggerd(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "pg_uri is required")
}

// TestLoggerd_InvalidPGURI pins the early parse-failure path: a syntactically
// invalid PG_URI must be reported without attempting any database connection.
func TestLoggerd_InvalidPGURI(t *testing.T) {
	t.Setenv("YABANIN_PG_URI", "::://not-a-valid-uri")
	cfgPath := filepath.Join(t.TempDir(), "cfg.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("{}\n"), 0600))
	t.Setenv("YABANIN_CONFIG", cfgPath)

	err := Loggerd(context.Background())

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "pg_uri is required",
		"expected the parse failure, not the empty-URI validation error")
}

// TestAdminServer_MissingPGURI pins the fail-closed path: the admin plane must
// not start without a datastore URI.
func TestAdminServer_MissingPGURI(t *testing.T) {
	t.Setenv("YABANIN_PG_URI", "")

	err := AdminServer(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "YABANIN_PG_URI is required")
}

// configured key the server generates an ephemeral secret (warn only — the
// admin is still startable, sessions just do not survive restarts), while a
// weak configured key in a production environment must be rejected.
func TestAdminServer_MissingSessionKey(t *testing.T) {
	t.Setenv("YABANIN_PG_URI", "postgres://user:pass@localhost:5432/yabanin")
	t.Setenv("YABANIN_SESSION_KEY", "")
	t.Setenv("YABANIN_ENV", "dev") // keep startup cheap: no DB connection expected past config

	err := AdminServer(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "session secret rejected",
		"an empty key must generate an ephemeral secret, not fail closed")
	assert.Contains(t, err.Error(), "failed to connect",
		"the server proceeds past the secret policy into the PG connection attempt")
}

// TestAdminServer_WeakSessionKeyInProduction pins the fail-closed branch:
// a dev-placeholder key with no YABANIN_ENV override is production, and the
// startup must refuse it.
func TestAdminServer_WeakSessionKeyInProduction(t *testing.T) {
	t.Setenv("YABANIN_PG_URI", "postgres://user:pass@localhost:5432/yabanin")
	t.Setenv("YABANIN_SESSION_KEY", "changeme")
	t.Setenv("YABANIN_ENV", "")

	err := AdminServer(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session secret rejected")
}
