package run

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
	cli "github.com/reireirei/yabanin/pkg/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGateway_MissingConfigFile pins the fail-closed path: an unreadable config
// file must return an error before any pool or server setup.
func TestGateway_MissingConfigFile(t *testing.T) {
	t.Setenv("YABANIN_CONFIG", filepath.Join(t.TempDir(), "does-not-exist.yaml"))

	err := Gateway(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "read config file")
}

func TestPolicyWiringFromEnv_RejectsUnknownModeBeforeStartup(t *testing.T) {
	const raw = "private-mode-sentinel"
	t.Setenv("YABANIN_POLICY_MODE", raw)
	t.Setenv("YABANIN_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))

	err := Gateway(context.Background())
	require.Error(t, err)
	require.EqualError(t, err, "invalid YABANIN_POLICY_MODE")
	assert.NotContains(t, err.Error(), raw)

	for _, tc := range []struct {
		name     string
		value    string
		unset    bool
		wantMode cli.PolicyMode
	}{
		{name: "unset defaults off", unset: true, wantMode: cli.PolicyModeOff},
		{name: "empty defaults off", value: "", wantMode: cli.PolicyModeOff},
		{name: "explicit off remains off", value: "off", wantMode: cli.PolicyModeOff},
		{name: "shadow remains valid", value: "shadow", wantMode: cli.PolicyModeShadow},
		{name: "enforce remains valid", value: "enforce", wantMode: cli.PolicyModeEnforce},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unset {
				// Set a value first so this case proves true absence rather than an
				// empty string inherited from the parent process.
				t.Setenv("YABANIN_POLICY_MODE", "stale-value")
				require.NoError(t, os.Unsetenv("YABANIN_POLICY_MODE"))
			} else {
				t.Setenv("YABANIN_POLICY_MODE", tc.value)
			}
			wiring, err := policyWiringFromEnv(slog.New(slog.DiscardHandler))
			require.NoError(t, err)
			assert.Equal(t, tc.wantMode, wiring.Mode)
		})
	}
}

// TestGateway_InvalidConfig pins the validation order: a config that loads but
// fails gateway validation must be rejected before any listener is created.
func TestGateway_InvalidConfig(t *testing.T) {
	t.Setenv("YABANIN_PG_URI", "")
	cfgPath := filepath.Join(t.TempDir(), "cfg.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("gateway:\n  listen_address: \"\"\n"), 0600))
	t.Setenv("YABANIN_CONFIG", cfgPath)

	err := Gateway(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen_address is required")
}

// TestOpenGatewayPool_EmptyPGURI confirms that when no PGURI is configured the
// helper returns the errNoDatabaseConfigured sentinel (not a hard failure) and a
// nil pool, so the gateway runs in resolver-fallback-only mode. This is the
// path that the pool-shadowing bug silently broke: the caller must receive
// exactly what the helper returns. Moved here from cmd/yabanin with the
func TestOpenGatewayPool_EmptyPGURI(t *testing.T) {
	cfg := config.All{} // Gateway.PGURI == ""
	pool, err := openGatewayPool(context.Background(), cfg, slog.Default())
	if !errors.Is(err, errNoDatabaseConfigured) {
		t.Fatalf("expected errNoDatabaseConfigured for empty PGURI, got %v", err)
	}
	if pool != nil {
		t.Fatalf("expected nil pool for empty PGURI, got non-nil %T", pool)
	}
}

// TestOpenGatewayPool_InvalidURI confirms a malformed PGURI surfaces as an error
// to the caller rather than being swallowed into a shadowed scope.
func TestOpenGatewayPool_InvalidURI(t *testing.T) {
	cfg := config.All{}
	cfg.Gateway.PGURI = "postgres://[::1" // unterminated bracket -> url.Parse error

	pool, err := openGatewayPool(context.Background(), cfg, slog.Default())
	if err == nil {
		t.Fatal("expected error for invalid PGURI, got nil")
	}
	if pool != nil {
		t.Fatalf("expected nil pool on parse error, got non-nil %T", pool)
	}
}
