package handlers

// negative
// config.Load("") → SetMCPStore → CreateMCPServer → real mcpagg store —
// same chain as mcp_allowlist_deploy_int_test.go).
//
// allow-list env"):
//   - partially invalid env: bad entries are skipped with a warning, the
//     valid remainder governs registration (not silently everything);
//   - all-invalid env: Load("") yields a nil list → every registration is
//     400 fail-closed with no row (the unconnected-knob boundary);
//   - a misconfigured list reaching SetMCPStore directly is a 503 with a
//     diagnosable cause (fail closed, never permissive);
//   - an allow-list match alone is NOT success: a DNS answer pointing into
//     a reserved range is a 400 rebind rejection; recovery on a public
//     answer is a clean 201 (retry after failure leaves exactly one row);
//   - invalid input matrix (malformed JSON, bad name, cleartext scheme,
//     embedded credentials) → 400 with a diagnosable message and no rows;
//   - interrupt: a cancelled request context maps to a 500 with no partial
//     row — cancellation never counts as success;
//   - duplicate retry: re-registering an existing name is a typed conflict,
//     never a second row.

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPDeployPath_ErrorBoundaries(t *testing.T) {
	pool := testdb.Postgres(t)
	orgStore := adminstore.New(pool, slog.New(slog.DiscardHandler), nil)
	mcpStore := mcpagg.NewStore(pool)

	ctx := context.Background()
	suffix := time.Now().UnixNano()
	org, err := orgStore.CreateOrganization(ctx,
		fmt.Sprintf("mcp-errors-%d", suffix), fmt.Sprintf("mcp-errors-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() { _ = orgStore.DeleteOrganization(context.Background(), org.ID) })

	seam := func(h *AdminHandlers, ip string) {
		h.mcp.dnsResolver = func(_ context.Context, _ string) ([]net.IP, error) {
			return []net.IP{net.ParseIP(ip)}, nil
		}
	}
	register := func(t *testing.T, h *AdminHandlers, name, url string) *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"org_id":%q,"name":%q,"url":%q,"enabled":true}`, org.ID, name, url)
		req := rootRequest("POST", "/api/organizations/"+org.ID+"/mcp/servers", body)
		w := httptest.NewRecorder()
		h.CreateMCPServer()(w, req)
		return w
	}
	countServers := func(t *testing.T) int {
		t.Helper()
		servers, err := mcpStore.List(ctx, org.ID)
		require.NoError(t, err)
		return len(servers)
	}

	// 1. Partially invalid env: invalid entries are skipped with a warning
	// (parseMCPAllowedUpstreams posture) and only the valid remainder
	// governs the registry.
	t.Setenv("YABANIN_MCP_ALLOWED_UPSTREAMS", "mcp.example.com, bad_*entry")
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, []string{"mcp.example.com"}, cfg.Gateway.MCPAllowedUpstreams,
		"invalid env entries must be skipped, valid ones must survive Load(\"\")")

	h := New(nil, "", "", []string{})
	h.SetMCPStore(mcpStore, cfg.Gateway.MCPAllowedUpstreams)
	seam(h, "140.82.121.3") // public, non-reserved

	nameOK := fmt.Sprintf("ok%d", suffix)
	w := register(t, h, nameOK, "https://mcp.example.com/mcp")
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	_, err = mcpStore.Get(ctx, org.ID, nameOK)
	require.NoError(t, err, "the allow-listed host must persist")
	require.NoError(t, mcpStore.Delete(ctx, org.ID, nameOK))

	nameBlocked := fmt.Sprintf("unlisted%d", suffix)
	w = register(t, h, nameBlocked, "https://evil.example.com/mcp")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "not in the allowed")
	_, err = mcpStore.Get(ctx, org.ID, nameBlocked)
	require.ErrorIs(t, err, mcpagg.ErrNotFound, "a rejected registration must leave no row")

	// 2. All-invalid env: Load("") yields nil → fail-closed 400 for every
	// host (the "unconnected allow-list env" boundary beyond the empty
	// knob case already pinned by mcp_allowlist_deploy_int_test.go).
	t.Setenv("YABANIN_MCP_ALLOWED_UPSTREAMS", "bad_*entry, no*such*domain")
	cfgInvalid, err := config.Load("")
	require.NoError(t, err)
	require.Nil(t, cfgInvalid.Gateway.MCPAllowedUpstreams,
		"an all-invalid env must parse to a nil (fail-closed) list")

	hClosed := New(nil, "", "", []string{})
	hClosed.SetMCPStore(mcpStore, cfgInvalid.Gateway.MCPAllowedUpstreams)
	seam(hClosed, "140.82.121.3")
	nameClosed := fmt.Sprintf("closed%d", suffix)
	w = register(t, hClosed, nameClosed, "https://mcp.example.com/mcp")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "not in the allowed")
	_, err = mcpStore.Get(ctx, org.ID, nameClosed)
	require.ErrorIs(t, err, mcpagg.ErrNotFound)

	// 3. A misconfigured list that reaches SetMCPStore directly (bypassing
	// the env parser) fails the request closed with a diagnosable 503 —
	// never a permissive default.
	hBad := New(nil, "", "", []string{})
	hBad.SetMCPStore(mcpStore, []string{"no*such*domain"})
	seam(hBad, "140.82.121.3")
	w = register(t, hBad, fmt.Sprintf("misconfig%d", suffix), "https://mcp.example.com/mcp")
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "bad gateway allowed_upstreams")

	// 4. Allow-list membership is not success: a domain that resolves into a
	// reserved range is a 400 rebind rejection with no row; on a public DNS
	// answer the same registration recovers with exactly one row.
	hRebind := New(nil, "", "", []string{})
	hRebind.SetMCPStore(mcpStore, []string{"rebind.example"})
	seam(hRebind, "127.0.0.1") // loopback answer → reserved
	nameRebind := fmt.Sprintf("rebind%d", suffix)
	w = register(t, hRebind, nameRebind, "https://rebind.example/mcp")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "reserved IP")
	_, err = mcpStore.Get(ctx, org.ID, nameRebind)
	require.ErrorIs(t, err, mcpagg.ErrNotFound, "the rebind rejection must leave no row")

	seam(hRebind, "140.82.121.3") // recovery: public answer for the same name
	nameOK2 := fmt.Sprintf("recovered%d", suffix)
	w = register(t, hRebind, nameOK2, "https://rebind.example/mcp")
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String(),
		"after a rejection the registration must still succeed on a clean answer")
	require.Equal(t, 1, countServers(t), "failures must not leave partial rows behind")

	// 5. Invalid input matrix: every refusal is 400 with a diagnosable
	// message and leaves no row (the recovered row is still the only one).
	name := fmt.Sprintf("bad%d", suffix)
	cases := []struct {
		label string
		body  string
		want  string
	}{
		{"malformed-json", `{invalid`, "malformed JSON body"},
		{"bad-name", fmt.Sprintf(`{"org_id":%q,"name":"Bad Name!","url":"https://mcp.example.com/mcp"}`, org.ID), "name must match"},
		{"cleartext-scheme", fmt.Sprintf(`{"org_id":%q,"name":%q,"url":"http://mcp.example.com/mcp"}`, org.ID, name), "url must be https"},
		{"embedded-credentials", fmt.Sprintf(`{"org_id":%q,"name":%q,"url":"https://user:pass@mcp.example.com/mcp"}`, org.ID, name), "must not contain credentials"},
	}
	for _, tc := range cases {
		req := rootRequest("POST", "/api/organizations/"+org.ID+"/mcp/servers", tc.body)
		rec := httptest.NewRecorder()
		hRebind.CreateMCPServer()(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, "%s: %s", tc.label, rec.Body.String())
		assert.Contains(t, rec.Body.String(), tc.want, tc.label)
		_, err := mcpStore.Get(ctx, org.ID, name)
		require.ErrorIs(t, err, mcpagg.ErrNotFound, "%s must leave no row", tc.label)
	}
	require.Equal(t, 1, countServers(t))

	// 6. Interrupt: a cancelled request context is a 500 with the diagnosable
	// cause and no partial row — cancellation never counts as success.
	cancelledName := fmt.Sprintf("cancelled%d", suffix)
	req := rootRequest("POST", "/api/organizations/"+org.ID+"/mcp/servers",
		fmt.Sprintf(`{"org_id":%q,"name":%q,"url":"https://rebind.example/mcp","enabled":true}`, org.ID, cancelledName))
	cancelCtx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(cancelCtx)
	rec := httptest.NewRecorder()
	hRebind.CreateMCPServer()(rec, req)
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "context canceled")
	_, err = mcpStore.Get(ctx, org.ID, cancelledName)
	require.ErrorIs(t, err, mcpagg.ErrNotFound, "an interrupted registration must leave no row")
	require.Equal(t, 1, countServers(t))

	// 7. Duplicate retry: re-registering the same name is a typed conflict
	// ("already exists"), never a second row.
	w = register(t, hRebind, nameOK2, "https://rebind.example/mcp")
	require.NotEqual(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "already exists")
	require.Equal(t, 1, countServers(t), "a conflicting retry must not duplicate the row")
	require.NoError(t, mcpStore.Delete(ctx, org.ID, nameOK2))
}
