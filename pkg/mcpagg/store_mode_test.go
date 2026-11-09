package mcpagg

// N05-P02-T02 (I54) store-level tests for the credential mode: the API-layer
// vocabulary validation (a 400, not a DB-constraint 500), the auto default
// on create, the whole-configuration version bump on update, and the scan
// round-trip of the new columns.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCredentialMode(t *testing.T) {
	for _, m := range []string{"", CredModeAuto, CredModeService, CredModeDelegated} {
		require.NoError(t, ValidateCredentialMode(m), "mode %q must be accepted", m)
	}
	for _, m := range []string{"user", "AUTO", "service ", "oauth", "headers"} {
		assert.Error(t, ValidateCredentialMode(m), "mode %q must be rejected", m)
	}
}

// capturingRow records the QueryRow SQL/args and returns a Server row for
// the RETURNING scan.
type capturingRow struct {
	sql  string
	args []any
	srv  *Server
}

func (r *capturingRow) store(sql string, args []any) {
	r.sql, r.args = sql, args
}

func (r *capturingRow) Scan(dest ...any) error {
	if r.srv == nil {
		return pgx.ErrNoRows
	}
	return bindServer(r.srv, dest...)
}

func TestCreate_CredentialModeDefaultAndPassthrough(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{in: "", want: CredModeAuto},
		{in: CredModeDelegated, want: CredModeDelegated},
		{in: CredModeService, want: CredModeService},
	} {
		cap := &capturingRow{srv: &Server{
			ID: "srv-1", OrgID: "org-1", Name: "knowledge", URL: "https://mcp.example.com/mcp",
			Transport: TransportHTTP, CredentialMode: tc.want, ConfigVersion: 1, AllowedTools: []string{},
		}}
		db := &mcpMockDB{
			queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
				cap.store(sql, args)
				return cap
			},
		}
		st := NewStore(db)
		srv, err := st.Create(context.Background(), CreateParams{
			OrgID: "org-1", Name: "knowledge", URL: "https://mcp.example.com/mcp",
			CredentialMode: tc.in,
		})
		require.NoError(t, err, "mode %q", tc.in)
		assert.Equal(t, tc.want, srv.CredentialMode, "stored/returned mode")
		assert.Equal(t, int64(1), srv.ConfigVersion, "a fresh row starts at config_version 1")
		require.Len(t, cap.args, 8, "INSERT carries the mode column")
		assert.Equal(t, tc.want, cap.args[7], "INSERT arg 8 is credential_mode")
	}
}

func TestCreate_CredentialModeInvalidRejectedBeforeDB(t *testing.T) {
	db := &mcpMockDB{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			t.Fatal("a rejected mode must not reach the database")
			return nil
		},
	}
	_, err := NewStore(db).Create(context.Background(), CreateParams{
		OrgID: "org-1", Name: "knowledge", URL: "https://mcp.example.com/mcp",
		CredentialMode: "user",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential_mode")
}

func TestUpdate_CredentialModeBumpsConfigVersion(t *testing.T) {
	cap := &capturingRow{srv: &Server{
		ID: "srv-1", OrgID: "org-1", Name: "knowledge", URL: "https://mcp.example.com/mcp",
		Transport: TransportHTTP, CredentialMode: CredModeService, ConfigVersion: 2, AllowedTools: []string{},
	}}
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			cap.store(sql, args)
			return cap
		},
	}
	mode := CredModeService
	enabled := false
	srv, err := NewStore(db).Update(context.Background(), "org-1", "knowledge", UpdateParams{
		CredentialMode: &mode,
		Enabled:        &enabled,
	})
	require.NoError(t, err)
	assert.Equal(t, CredModeService, srv.CredentialMode)
	assert.Equal(t, int64(2), srv.ConfigVersion, "the mock returns the bumped revision")
	assert.Contains(t, cap.sql, "credential_mode = $", "the mode is part of the update")
	assert.Contains(t, cap.sql, "config_version = config_version + 1",
		"every applied update versions the connection configuration")
	// The mode placeholder follows the dynamic-set order (display, url,
	// transport, tools, enabled, mode): here enabled=$3, mode=$4.
	assert.Contains(t, cap.sql, "credential_mode = $4")
	assert.Equal(t, CredModeService, cap.args[3])
}

func TestUpdate_InvalidModeRejectedBeforeDB(t *testing.T) {
	db := &mcpMockDB{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			t.Fatal("a rejected mode must not reach the database")
			return nil
		},
	}
	bogus := "root"
	_, err := NewStore(db).Update(context.Background(), "org-1", "knowledge", UpdateParams{CredentialMode: &bogus})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sql", "the rejection is API-layer, not a DB error")
}

func TestUpdate_NilModeLeavesModeUntouchedButStillBumps(t *testing.T) {
	cap := &capturingRow{srv: &Server{
		ID: "srv-1", OrgID: "org-1", Name: "knowledge", URL: "https://mcp.example.com/mcp",
		Transport: TransportHTTP, CredentialMode: CredModeDelegated, ConfigVersion: 3, AllowedTools: []string{},
	}}
	db := &mcpMockDB{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			cap.store(sql, args)
			return cap
		},
	}
	name := "Docs Portal"
	srv, err := NewStore(db).Update(context.Background(), "org-1", "knowledge", UpdateParams{DisplayName: &name})
	require.NoError(t, err)
	assert.Equal(t, CredModeDelegated, srv.CredentialMode, "a nil-mode update keeps the configured mode")
	assert.NotContains(t, cap.sql, "credential_mode =")
	assert.Contains(t, cap.sql, "config_version = config_version + 1",
		"any applied configuration change re-versions the row")
}
