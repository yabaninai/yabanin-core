package handlers

// (config.Load("") in services/run/admin.go) and hands
// cfg.Gateway.MCPAllowedUpstreams to SetMCPStore. Before the F-5 fix no
// deployment surface passed YABANIN_MCP_ALLOWED_UPSTREAMS through, so the
// list was always nil and EVERY MCP server registration failed closed with
// 400 ("ssrf: host not in the allowed domains list").
//
// This test drives the real chain end to end on the disposable stand:
// env knob → config.Load("") → SetMCPStore → CreateMCPServer handler → real
// mcpagg store (persisted row). The DNS seam (QG2-D3) answers deterministically
// so the registration-time SSRF guard never leaves the process.

import (
	"context"
	"encoding/json"
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

// survives the admin boot path and the resulting list — nothing else — decides
// which upstream hosts the registry accepts. Allowed (exact and *.suffix)
// hosts register and persist; an unlisted host is rejected 400 with no row;
// an empty knob is fail-closed for every host (the historical F-5 state).
func TestMCPDeployPath_EnvAllowListGovernsRegistration(t *testing.T) {
	pool := testdb.Postgres(t)
	orgStore := adminstore.New(pool, slog.New(slog.DiscardHandler), nil)
	mcpStore := mcpagg.NewStore(pool)

	ctx := context.Background()
	suffix := time.Now().UnixNano()
	org, err := orgStore.CreateOrganization(ctx,
		fmt.Sprintf("mcp-deploy-%d", suffix), fmt.Sprintf("mcp-deploy-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() { _ = orgStore.DeleteOrganization(context.Background(), org.ID) })

	// 1. The deploy knob is set exactly as an operator would in
	// deploy/.env.example → compose/helm passthrough → container env.
	t.Setenv("YABANIN_MCP_ALLOWED_UPSTREAMS", "mcp.example.com, *.corp.example")

	// 2. The admin boot path parses it (services/run/admin.go: config.Load("")
	//    → cfg.Gateway.MCPAllowedUpstreams → h.SetMCPStore).
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, []string{"mcp.example.com", "*.corp.example"}, cfg.Gateway.MCPAllowedUpstreams,
		`YABANIN_MCP_ALLOWED_UPSTREAMS must survive the Load("") admin boot path`)

	h := New(nil, "", "", []string{}) // audit-free wiring; the MCP registry store is real
	h.SetMCPStore(mcpStore, cfg.Gateway.MCPAllowedUpstreams)
	h.mcp.dnsResolver = func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("140.82.121.3")}, nil // public, non-reserved
	}

	register := func(t *testing.T, h *AdminHandlers, name, url string) *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"org_id":%q,"name":%q,"url":%q,"enabled":true}`, org.ID, name, url)
		req := rootRequest("POST", "/api/organizations/"+org.ID+"/mcp/servers", body)
		w := httptest.NewRecorder()
		h.CreateMCPServer()(w, req)
		return w
	}
	cleanupServer := func(name string) {
		_ = mcpStore.Delete(context.Background(), org.ID, name)
	}

	// 3a. Exact allow-listed host registers and the row persists.
	name := fmt.Sprintf("exact%d", suffix)
	w := register(t, h, name, "https://mcp.example.com/mcp")
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var srv mcpagg.Server
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &srv))
	assert.Equal(t, org.ID, srv.OrgID)
	assert.Equal(t, "https://mcp.example.com/mcp", srv.URL)
	got, err := mcpStore.Get(ctx, org.ID, name)
	require.NoError(t, err, "registration must persist through the real store")
	assert.Equal(t, srv.ID, got.ID)
	cleanupServer(name)

	// 3b. A *.suffix entry admits subdomains.
	wild := fmt.Sprintf("wild%d", suffix)
	w = register(t, h, wild, "https://api.corp.example/v1")
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	cleanupServer(wild)

	// 3c. Unlisted host: 400 fail-closed, nothing persisted (the SSRF guard
	// runs before the store).
	blocked := fmt.Sprintf("blocked%d", suffix)
	w = register(t, h, blocked, "https://evil.example.com/mcp")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "not in the allowed")
	_, err = mcpStore.Get(ctx, org.ID, blocked)
	require.ErrorIs(t, err, mcpagg.ErrNotFound, "a rejected registration must not leave a row")

	// 4. The historical F-5 deployment state: knob absent/empty → nil list →
	// every registration fails closed with 400.
	t.Setenv("YABANIN_MCP_ALLOWED_UPSTREAMS", "")
	cfgEmpty, err := config.Load("")
	require.NoError(t, err)
	require.Nil(t, cfgEmpty.Gateway.MCPAllowedUpstreams)

	hClosed := New(nil, "", "", []string{})
	hClosed.SetMCPStore(mcpStore, cfgEmpty.Gateway.MCPAllowedUpstreams)
	w = register(t, hClosed, fmt.Sprintf("closed%d", suffix), "https://mcp.example.com/mcp")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "not in the allowed")
}
