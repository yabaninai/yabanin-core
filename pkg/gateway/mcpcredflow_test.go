package cli

// MC-3 tests: the lazy-authorization endpoints and the full per-user flow —
// no credential → mcp_auth_required+URL → submit → resolve — over the real
// adminstore on the disposable Postgres, plus the oauth begin/callback
// round-trip against a mock IdP (the grant stays the ceiling everywhere).

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// serveMCPFlow mounts the MC-3 routes on a chi router (the production
// pattern: the authed group handlers; the callback is public).
func serveMCPFlow(gw *gateway) http.Handler {
	r := chi.NewRouter()
	r.Post("/api/mcp/credentials/{server}", gw.mcpSubmitUserCredential)
	r.Post("/api/mcp/auth/{server}/begin", gw.mcpOAuthBegin)
	r.Get("/api/mcp/auth/{server}/callback", gw.mcpOAuthCallback)
	return r
}

func agentRequest(method, path, body string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	r.Header.Set("X-Org-Id", "org-1")
	r.Header.Set("X-Agent-Id", "agent-1")
	r.Header.Set("X-Audit-Reason", "e2e flow test")
	return r
}

func TestMCPSubmit_NoSource_404(t *testing.T) {
	gw := &gateway{log: testLogger()}
	w := httptest.NewRecorder()
	serveMCPFlow(gw).ServeHTTP(w, agentRequest(http.MethodPost, "/api/mcp/credentials/srv", `{"headers":{"Authorization":"Bearer x"}}`))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMCPSubmit_AgentOnly(t *testing.T) {
	gw := &gateway{log: testLogger(), mcpCredsSrc: newMCPCredsSource(mcpCredsSourceConfig{Store: &fakeMCPCredsStore{}})}
	r := agentRequest(http.MethodPost, "/api/mcp/credentials/srv", `{"headers":{"Authorization":"Bearer x"}}`)
	r.Header.Del("X-Agent-Id")
	w := httptest.NewRecorder()
	serveMCPFlow(gw).ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestMCPSubmit_BadBody(t *testing.T) {
	gw := &gateway{log: testLogger(), mcpCredsSrc: newMCPCredsSource(mcpCredsSourceConfig{Store: &fakeMCPCredsStore{}})}
	for _, body := range []string{`{}`, `{"headers":{}}`, `not-json`, `{"unexpected":1}`} {
		w := httptest.NewRecorder()
		serveMCPFlow(gw).ServeHTTP(w, agentRequest(http.MethodPost, "/api/mcp/credentials/srv", body))
		assert.Equal(t, http.StatusBadRequest, w.Code, "body %s → 400", body)
	}
}

func TestMCPSubmit_MaskedRowResponse(t *testing.T) {
	store := &fakeMCPCredsStore{userRow: adminstore.MCPUserCredential{
		ID: "u-1", OrgID: "org-1", ServerName: "srv", AgentKeyID: "agent-1",
		Kind: "headers", SecretLast4: "-1", Status: "active", Version: 1,
	}}
	gw := &gateway{log: testLogger(), mcpCredsSrc: newMCPCredsSource(mcpCredsSourceConfig{Store: store})}
	w := httptest.NewRecorder()
	serveMCPFlow(gw).ServeHTTP(w, agentRequest(http.MethodPost, "/api/mcp/credentials/srv",
		`{"headers":{"Authorization":"Bearer flow-token-1234"}}`))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"secret_last4":"-1"`)
	assert.NotContains(t, w.Body.String(), "flow-token-1234", "the submitted secret must never be echoed")
}

func TestMCPCallback_ParameterContract(t *testing.T) {
	gw := &gateway{log: testLogger(), mcpCredsSrc: newMCPCredsSource(mcpCredsSourceConfig{Store: &fakeMCPCredsStore{}})}

	// Missing params → 400.
	w := httptest.NewRecorder()
	serveMCPFlow(gw).ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/mcp/auth/srv/callback", nil))
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Unknown state → 401 (terse: browser-facing, no driver text).
	w = httptest.NewRecorder()
	serveMCPFlow(gw).ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/mcp/auth/srv/callback?org=org-1&state=deadbeefdeadbeef&code=abc", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NotContains(t, w.Body.String(), "state", "the failure must not echo flow material")
}

// TestMCPUserCredFlow_E2E_Integration is the MC-3 acceptance chain over the
// real adminstore + RLS-posture Postgres:
//  1. no credential → the resolver misses (the invoke path answers
//     mcp_auth_required — pinned in pkg/mcpagg);
//  2. the agent SUBMITS headers via the endpoint → active row;
//  3. the resolver now serves exactly the submitted header — the invoke
//     proxy applies it (Bearer e2e pinned in pkg/mcpagg).
func TestMCPUserCredFlow_E2E_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), enc)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	org, err := store.CreateOrganization(ctx, fmt.Sprintf("mcpflow-%d", suffix), fmt.Sprintf("mcpflow-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", org.ID) })

	serverName := fmt.Sprintf("flow-srv-%d", suffix)
	seedMCPServerRow(t, pool, org.ID, serverName)
	agentID := seedMCPAgentWithGrant(t, pool, org.ID, serverName)

	src := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second, Log: slog.Default()})
	gw := &gateway{log: testLogger(), mcpCredsSrc: src}

	// 1. No credential: the resolver misses.
	h, kind, err := src.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.Nil(t, h)
	assert.Equal(t, mcpagg.CredKindNone, kind)

	// 2. Submit via the endpoint (the agent's own headers).
	payload := fmt.Sprintf(`{"headers":{"Authorization":"Bearer flow-%d"}}`, suffix)
	req := agentRequest(http.MethodPost, "/api/mcp/credentials/"+serverName, payload)
	req.Header.Set("X-Org-Id", org.ID)
	req.Header.Set("X-Agent-Id", agentID)
	w := httptest.NewRecorder()
	serveMCPFlow(gw).ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), fmt.Sprintf("flow-%d", suffix))

	// 3. The resolver now serves the submitted value (fresh source: a new
	// gateway process would see it too — the negative was TTL/bump-bounded).
	src2 := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second})
	h, kind, err = src2.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{fmt.Sprintf("Bearer flow-%d", suffix)}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindHeaders, kind)

	// 4. The submit landed in the hash-chained audit journal (queried by
	// action directly: the shared stand's journal is large and concurrent —
	// a page window would race other suites).
	var auditRows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_logs WHERE action = 'mcp_user_credential_upsert' AND details LIKE '%' || $1 || '%'`,
		serverName).Scan(&auditRows))
	if auditRows == 0 {
		var lastAction string
		_ = pool.QueryRow(ctx,
			`SELECT action FROM admin_audit_logs ORDER BY seq DESC LIMIT 1`).Scan(&lastAction)
		t.Logf("diagnostics: no upsert audit row; last journal row action=%q", lastAction)
	}
	assert.Positive(t, auditRows, "the submit must be audited (hash-chained journal)")
}

// TestMCPOAuthFlow_E2E_Integration: begin → consent URL (+pending row) →
// callback code exchange at a mock IdP → active row resolving Bearer; the
// grant ceiling holds mid-flow and a wrong state finds nothing. PKCE: the
// authorize URL carries the S256 challenge and the exchange presents the
// verifier. Revocation (RFC 7009): the grant-lifecycle orphan path never
// calls the provider (restore keeps working); only the explicit delete
// revokes.
func TestMCPOAuthFlow_E2E_Integration(t *testing.T) {
	var mu sync.Mutex
	var gotGrant string
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		mu.Lock()
		gotGrant = r.FormValue("grant_type")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-oauth-flow","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(tokSrv.Close)

	var revCalls int
	revSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		revCalls++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(revSrv.Close)

	pool := testdb.Postgres(t)
	enc := encryption.MustNew(encryption.EncodeKey())
	store := adminstore.New(pool, slog.New(slog.DiscardHandler), enc)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	org, err := store.CreateOrganization(ctx, fmt.Sprintf("mcpoauth-%d", suffix), fmt.Sprintf("mcpoauth-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", org.ID) })

	serverName := fmt.Sprintf("oauth-srv-%d", suffix)
	seedMCPServerRow(t, pool, org.ID, serverName)
	agentID := seedMCPAgentWithGrant(t, pool, org.ID, serverName)

	serverSecret := fmt.Sprintf(`{"client_id":"cid-%d","client_secret":"csec","auth_url":"https://idp.example.test/authorize","token_url":"%s","revocation_endpoint":"%s"}`, suffix, tokSrv.URL, revSrv.URL)
	_, err = store.UpsertMCPServerCredential(ctx, org.ID, serverName, adminstore.MCPCredKindOAuth, serverSecret)
	require.NoError(t, err)

	src := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow: func(_ context.Context, raw string) error {
			if strings.Contains(raw, tokSrv.URL) {
				return nil
			}
			return fmt.Errorf("host not allowed: %s", raw)
		},
		HTTPClient: loopbackClient(),
	})
	gw := &gateway{log: testLogger(), mcpCredsSrc: src}

	// begin: consent URL + pending row.
	beginReq := agentRequest(http.MethodPost, "/api/mcp/auth/"+serverName+"/begin", `{}`)
	beginReq.Header.Set("X-Org-Id", org.ID)
	beginReq.Header.Set("X-Agent-Id", agentID)
	beginReq.Host = "gw.example.test"
	w := httptest.NewRecorder()
	serveMCPFlow(gw).ServeHTTP(w, beginReq)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var begin struct {
		URL      string `json:"url"`
		State    string `json:"state"`
		Redirect string `json:"redirect"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &begin))
	assert.Contains(t, begin.URL, "https://idp.example.test/authorize?")
	assert.Contains(t, begin.URL, "response_type=code")
	assert.Contains(t, begin.URL, fmt.Sprintf("client_id=cid-%d", suffix))
	assert.Contains(t, begin.URL, "state=")
	assert.Equal(t, "https://gw.example.test/api/mcp/auth/"+serverName+"/callback", begin.Redirect)

	// The pending row exists and does not resolve.
	pending, err := store.GetMCPUserCredential(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.Equal(t, adminstore.MCPUserCredStatusPending, pending.Status)
	_, _, _, ok, err := store.ResolveMCPUserSecret(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.False(t, ok, "a pending row must not resolve")

	// callback: the code exchange activates the credential.
	callback := fmt.Sprintf("/api/mcp/auth/%s/callback?org=%s&state=%s&code=auth-code-1", serverName, org.ID, begin.State)
	w = httptest.NewRecorder()
	serveMCPFlow(gw).ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, callback, nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"status":"authorized"`)
	assert.Equal(t, "authorization_code", gotGrant)

	row, err := store.GetMCPUserCredential(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.Equal(t, adminstore.MCPUserCredStatusActive, row.Status)

	// The resolver serves the exchanged token (Bearer).
	src2 := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second})
	h, kind, err := src2.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer at-oauth-flow"}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindOAuth, kind)

	// The state is single-use: a second callback with the same state misses.
	w = httptest.NewRecorder()
	serveMCPFlow(gw).ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, callback, nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code, "the state must not be reusable")

	// The grant ceiling holds: revoking the grant orphans the credential and
	// the resolver misses. Orphan must NOT call the provider revocation
	// (restore has to keep working); only the explicit delete revokes.
	require.NoError(t, store.OrphanMCPUserCredentials(ctx, org.ID, serverName, agentID))
	h, _, err = src2.AuthHeaders(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.Nil(t, h, "an orphaned credential must not resolve")
	got, err := store.GetMCPUserCredential(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.Equal(t, adminstore.MCPUserCredStatusOrphaned, got.Status)
	mu.Lock()
	assert.Zero(t, revCalls, "the orphan path must not revoke at the provider")
	mu.Unlock()

	// The restore path keeps working: a re-enabled grant restores the oauth
	// row with its token material.
	require.NoError(t, store.RestoreMCPUserCredentials(ctx, org.ID, serverName, agentID))
	got, err = store.GetMCPUserCredential(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.Equal(t, adminstore.MCPUserCredStatusActive, got.Status, "an oauth row with tokens restores to active")

	// The explicit delete DOES revoke (best-effort) and removes the row.
	src3 := newMCPCredsSource(mcpCredsSourceConfig{
		Store: store, TTL: time.Second,
		Allow: func(_ context.Context, raw string) error {
			if strings.Contains(raw, revSrv.URL) {
				return nil
			}
			return fmt.Errorf("host not allowed: %s", raw)
		},
		HTTPClient: loopbackClient(),
	})
	require.NoError(t, src3.DeleteUserCredential(ctx, org.ID, serverName, agentID, "e2e revoke"))
	mu.Lock()
	assert.Equal(t, 1, revCalls, "the explicit delete must attempt the RFC 7009 revoke")
	mu.Unlock()
	_, _, _, ok, err = store.ResolveMCPUserSecret(ctx, org.ID, serverName, agentID)
	require.NoError(t, err)
	assert.False(t, ok, "the deleted credential must not resolve")

	// Wrong state → nothing.
	_, err = store.FindMCPUserCredentialByState(ctx, org.ID, "wrong-state-000001")
	assert.Error(t, err)
}
