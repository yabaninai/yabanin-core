package cli

// MC-2 contract test: the gateway renders the lazy-authorization error as
// {"error":{"code":"mcp_auth_required","kind":...,"url":...}} with a 401 —
// the shape agents (and the MC-3 flows) branch on. The error FLOW (proxy →
// AuthRequiredError) is pinned in pkg/mcpagg; here the wire rendering and
// the source-over-real-store integration are the subject.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestWriteMCPAuthRequired_Shape(t *testing.T) {
	w := httptest.NewRecorder()
	writeMCPAuthRequired(w, &mcpagg.AuthRequiredError{
		Kind:    mcpagg.CredKindHeaders,
		URL:     "/api/mcp/credentials/knowledge",
		Message: "the mcp server requires authorization",
	})

	require.Equal(t, 401, w.Code, "lazy authorization is a 401")
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Kind    string `json:"kind"`
			URL     string `json:"url"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "mcp_auth_required", body.Error.Code)
	assert.Equal(t, "headers", body.Error.Kind)
	assert.Equal(t, "/api/mcp/credentials/knowledge", body.Error.URL)
	assert.NotEmpty(t, body.Error.Message)
	assert.NotContains(t, w.Body.String(), "secret", "no secret material on the wire")
}

// TestMCPCredsSource_OverRealStore_Integration wires the MC-2 source over
// the real adminstore on the disposable Postgres: resolution order (user →
// server), the grant ceiling on the refresh path, and needs_reauth flipping
// through the real SQL/RLS stack.
func TestMCPCredsSource_OverRealStore_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), enc)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	org, err := store.CreateOrganization(ctx, fmt.Sprintf("mcpsrc-%d", suffix), fmt.Sprintf("mcpsrc-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", org.ID)
	})

	serverName := fmt.Sprintf("src-srv-%d", suffix)
	seedMCPServerRow(t, pool, org.ID, serverName)
	agentID := seedMCPAgentWithGrant(t, pool, org.ID, serverName)

	src := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second})

	// No credential anywhere: miss.
	h, kind, err := src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.Nil(t, h)
	assert.Equal(t, mcpagg.CredKindNone, kind)

	// Server-level credential resolves (decrypted per request).
	_, err = store.UpsertMCPServerCredential(ctx, org.ID, serverName, adminstore.MCPCredKindHeaders,
		`{"Authorization":"Bearer srv-real-1"}`)
	require.NoError(t, err)
	src = newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second}) // fresh cache
	h, kind, err = src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer srv-real-1"}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindHeaders, kind)

	// Per-user credential wins.
	_, err = store.UpsertMCPUserCredential(ctx, org.ID, serverName, agentID, adminstore.MCPCredKindHeaders,
		`{"Authorization":"Bearer user-real-1"}`, nil)
	require.NoError(t, err)
	src = newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second})
	h, _, err = src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer user-real-1"}, h["Authorization"])

	// A headers credential rejected by the upstream → needs_reauth (sticky:
	// the resolution misses right after).
	h, retry, err := src.OnUpstreamUnauthorized(ctx, org.ID, serverName, agentID, mcpagg.CredKindHeaders)
	require.NoError(t, err)
	assert.False(t, retry)
	assert.Nil(t, h)
	got, err := store.GetMCPUserCredential(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.Equal(t, adminstore.MCPUserCredStatusNeedsReauth, got.Status)

	src = newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second})
	h, _, err = src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer srv-real-1"}, h["Authorization"], "runtime falls back to the server-level credential")
}

func seedMCPServerRow(t *testing.T, pool *pgxpool.Pool, orgID, name string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO mcp_servers (org_id, name, url, enabled) VALUES ($1::uuid, $2, 'https://mcp.example.test', true)
		 ON CONFLICT (org_id, name) DO NOTHING`, orgID, name)
	require.NoError(t, err)
}

func seedMCPAgentWithGrant(t *testing.T, pool *pgxpool.Pool, orgID, serverName string) string {
	t.Helper()
	var agentID string
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		orgID, serverName+"-agent", "hash-"+orgID+"-"+serverName).Scan(&agentID))
	_, err := pool.Exec(context.Background(),
		`INSERT INTO mcp_server_grants (org_id, agent_id, server_name, enabled) VALUES ($1::uuid, $2::uuid, $3, true)`,
		orgID, agentID, serverName)
	require.NoError(t, err)
	return agentID
}
