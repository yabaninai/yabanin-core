package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rootRequest returns a request with the root flag set (so requireOrgScope
// treats it as an operator, any org in scope).
func rootRequest(method, target, body string) *http.Request {
	// Always attach a (possibly empty) body reader so a handler that decodes a
	// JSON body does not fail on a nil Body (root callers send an empty body for
	// GET/DELETE/PUT-without-payload).
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	ctx := context.WithValue(r.Context(), adminauth.ContextKeyIsRoot{}, true)
	return r.WithContext(ctx)
}

func TestCreateAgentKey(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys", `{"name":"agent-a","org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateAgentKey()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	key, _ := resp["key"].(string)
	assert.True(t, strings.HasPrefix(key, "yag_"), "plaintext key must start with yag_, got %q", key)
	assert.NotEmpty(t, resp["key_id"])
}

func TestCreateAgentKey_MissingName(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys", `{"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateAgentKey()(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAgentKey_MissingOrg_Root(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys", `{"name":"agent-a"}`)
	w := httptest.NewRecorder()
	h.CreateAgentKey()(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAgentKeys(t *testing.T) {
	store := newMockStore()
	store.agentKeys["agent-key-1"] = &adminstore.AgentKey{ID: "agent-key-1", Name: "agent-a", OrgID: "org-1"}
	h := newTestAdminH(store)
	req := rootRequest("GET", "/api/agent-keys?org_id=org-1", "")
	w := httptest.NewRecorder()
	h.ListAgentKeys()(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAgentKeyByID(t *testing.T) {
	store := newMockStore()
	store.agentKeys["agent-key-1"] = &adminstore.AgentKey{ID: "agent-key-1", Name: "agent-a", OrgID: "org-1"}
	h := newTestAdminH(store)
	req := rootRequest("GET", "/api/agent-keys/agent-key-1", "")
	w := httptest.NewRecorder()
	wrapWithParams(h.GetAgentKey(), "/api/agent-keys/{id}")(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRevokeAgentKey(t *testing.T) {
	store := newMockStore()
	store.agentKeys["agent-key-1"] = &adminstore.AgentKey{ID: "agent-key-1", Name: "agent-a", OrgID: "org-1", Active: true}
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/agent-key-1/revoke", "")
	w := httptest.NewRecorder()
	wrapWithParams(h.RevokeAgentKey(), "/api/agent-keys/{id}/revoke")(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, store.agentKeys["agent-key-1"].Active)
}

func TestRevokeAgentKey_NotFound(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/missing/revoke", "")
	w := httptest.NewRecorder()
	wrapWithParams(h.RevokeAgentKey(), "/api/agent-keys/{id}/revoke")(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Agent key delegation (ADL-03) ---

// seedRootParent adds an active ROOT agent key (parent_id NULL) to the mock
// store and returns it. Delegation requires the parent to be a root.
func seedRootParent(store *mockStore, id, orgID string) *adminstore.AgentKey {
	k := &adminstore.AgentKey{ID: id, Name: "parent", OrgID: orgID, Active: true, ParentID: nil}
	store.agentKeys[id] = k
	return k
}

func TestCreateDelegatedAgentKey_HappyPath_NilMCP(t *testing.T) {
	store := newMockStore()
	seedRootParent(store, "parent-1", "org-1")
	h := newTestAdminH(store)
	// mcpStore is nil → effective grants are empty, but the child key is issued.
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child-a","ttl":3600,"org_id":"org-1","mcp_grants":["server-a"]}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	key, _ := resp["key"].(string)
	assert.True(t, strings.HasPrefix(key, "yag_"), "plaintext child key must start with yag_")
	assert.Equal(t, "parent-1", resp["parent_agent"])
	assert.Equal(t, "org-1", resp["org_id"])
	assert.Equal(t, "agent-key-child", resp["key_id"])
	// No MCP store → no grants can be intersected.
	assert.Equal(t, []any{}, resp["mcp_grants"])
	// The child row carries the delegation fields.
	child := store.agentKeys["agent-key-child"]
	require.NotNil(t, child)
	require.NotNil(t, child.ParentID)
	assert.Equal(t, "parent-1", *child.ParentID)
	require.NotNil(t, child.ExpiresAt)
	// TTL was 3600s; expires_at must be in the future (a past expiry would mean
	// the resolver rejects it immediately).
	assert.True(t, child.ExpiresAt.After(time.Now()),
		"child expires_at must be in the future, got %v", child.ExpiresAt)
}

func TestCreateDelegatedAgentKey_BudgetMirrored(t *testing.T) {
	store := newMockStore()
	// AUDIT-P1-03: a capped delegation requires the parent to have a budget
	// row and the cap to fit under it; the store writes the child's
	// enforcement row in the same transaction.
	seedParentWithBudget(store, "parent-1", 2500)
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child-b","ttl":3600,"budget_caps":2500,"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.InDelta(t, float64(2500), resp["daily_limit_cents"], 1e-9)
	child := store.agentKeys["agent-key-child"]
	require.NotNil(t, child)
	require.NotNil(t, child.DailyLimitCents)
	assert.Equal(t, int64(2500), *child.DailyLimitCents)
	if b := store.agentBudgets["agent-key-child"]; assert.NotNil(t, b) {
		assert.Equal(t, int64(2500), b.DailyLimitCents)
	}
}

func TestCreateDelegatedAgentKey_GrantIntersection(t *testing.T) {
	store := newMockStore()
	seedRootParent(store, "parent-1", "org-1")
	h := newTestAdminH(store)
	// Wire the shared MCP test store. The parent holds enabled grants on
	// server-a and server-b. The child requests server-a, server-b, server-c:
	// the intersection is {server-a, server-b} (server-c is dropped — the
	// parent lacks it, so escalation is impossible).
	mcpDB := newMCPTestStore()
	mcpDB.grants[grantKey("org-1", "server-a", "parent-1")] = &mcpagg.Grant{
		ID: "gr-a", OrgID: "org-1", AgentID: "parent-1", ServerName: "server-a", Enabled: true,
	}
	mcpDB.grants[grantKey("org-1", "server-b", "parent-1")] = &mcpagg.Grant{
		ID: "gr-b", OrgID: "org-1", AgentID: "parent-1", ServerName: "server-b", Enabled: true,
	}
	h.SetMCPStore(mcpagg.NewStore(mcpDB), nil)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child-c","ttl":3600,"org_id":"org-1","mcp_grants":["server-a","server-b","server-c"]}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	grants, _ := resp["mcp_grants"].([]any)
	require.Len(t, grants, 2, "child must get exactly the parent∩requested intersection")
	assert.Equal(t, "server-a", grants[0])
	assert.Equal(t, "server-b", grants[1])
}

func TestCreateDelegatedAgentKey_ChildGrantInheritsParentToolScope(t *testing.T) {
	store := newMockStore()
	seedRootParent(store, "parent-1", "org-1")
	h := newTestAdminH(store)
	// The parent's grant on server-a is TOOL-RESTRICTED (search_a only).
	mcpDB := newMCPTestStore()
	mcpDB.grants[grantKey("org-1", "server-a", "parent-1")] = &mcpagg.Grant{
		ID: "gr-a", OrgID: "org-1", AgentID: "parent-1", ServerName: "server-a",
		AllowedTools: []string{"search_a"}, Enabled: true,
	}
	h.SetMCPStore(mcpagg.NewStore(mcpDB), nil)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child-scoped","ttl":3600,"org_id":"org-1","mcp_grants":["server-a"]}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	// AUTH-02: the child's stored grant must carry the PARENT's tool scope —
	// not the unrestricted [] (= every tool the server allows). An unrestricted
	// child grant under a restricted parent lets the child invoke tools the
	// parent may never call.
	child := mcpDB.grants[grantKey("org-1", "server-a", "agent-key-child")]
	require.NotNil(t, child)
	assert.Equal(t, []string{"search_a"}, child.AllowedTools,
		"child grant must inherit the parent's tool restriction (AUTH-02)")
}

func TestCreateDelegatedAgentKey_UnrestrictedParentStaysUnrestricted(t *testing.T) {
	store := newMockStore()
	seedRootParent(store, "parent-1", "org-1")
	h := newTestAdminH(store)
	// The parent holds an unrestricted grant ([] = every server tool); the
	// child inherits the same unrestricted scope — no accidental narrowing.
	mcpDB := newMCPTestStore()
	mcpDB.grants[grantKey("org-1", "server-a", "parent-1")] = &mcpagg.Grant{
		ID: "gr-a", OrgID: "org-1", AgentID: "parent-1", ServerName: "server-a",
		AllowedTools: []string{}, Enabled: true,
	}
	h.SetMCPStore(mcpagg.NewStore(mcpDB), nil)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child-open","ttl":3600,"org_id":"org-1","mcp_grants":["server-a"]}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	child := mcpDB.grants[grantKey("org-1", "server-a", "agent-key-child")]
	require.NotNil(t, child)
	assert.Empty(t, child.AllowedTools,
		"unrestricted parent must stay unrestricted for the child")
}

func TestCreateDelegatedAgentKey_ParentNotFound(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"nope","name":"child","ttl":3600,"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCreateDelegatedAgentKey_ParentRevoked(t *testing.T) {
	store := newMockStore()
	// Parent exists but is revoked (active=false).
	k := &adminstore.AgentKey{ID: "parent-1", Name: "parent", OrgID: "org-1", Active: false}
	store.agentKeys["parent-1"] = k
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child","ttl":3600,"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestCreateDelegatedAgentKey_ChildOfChild(t *testing.T) {
	store := newMockStore()
	// Parent is itself a child (parent_id set) → cannot delegate further.
	parentID := "grandparent-1"
	k := &adminstore.AgentKey{ID: "parent-1", Name: "mid", OrgID: "org-1", Active: true, ParentID: &parentID}
	store.agentKeys["parent-1"] = k
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child","ttl":3600,"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestCreateDelegatedAgentKey_ParentOtherOrg(t *testing.T) {
	store := newMockStore()
	seedRootParent(store, "parent-1", "org-2") // parent lives in a DIFFERENT org
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child","ttl":3600,"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCreateDelegatedAgentKey_MissingName(t *testing.T) {
	store := newMockStore()
	seedRootParent(store, "parent-1", "org-1")
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","ttl":3600,"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateDelegatedAgentKey_MissingParent(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"name":"child","ttl":3600,"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateDelegatedAgentKey_TTLTooLarge(t *testing.T) {
	store := newMockStore()
	seedRootParent(store, "parent-1", "org-1")
	h := newTestAdminH(store)
	// 91 days exceeds the 90d ceiling.
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child","ttl":7862400,"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateDelegatedAgentKey_NonPositiveTTL(t *testing.T) {
	store := newMockStore()
	seedRootParent(store, "parent-1", "org-1")
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child","ttl":0,"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateDelegatedAgentKey_NonPositiveBudget(t *testing.T) {
	store := newMockStore()
	seedRootParent(store, "parent-1", "org-1")
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child","ttl":3600,"budget_caps":0,"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
