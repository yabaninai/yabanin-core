package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Agent role profiles (ADL-06) ---

// seedOrgServers registers the named MCP servers for an org (the grant ceiling).
func seedOrgServers(db *mcpTestStore, orgID string, names ...string) {
	for _, n := range names {
		db.servers[key(orgID, n)] = &mcpagg.Server{ID: "srv-" + n, OrgID: orgID, Name: n, Enabled: true}
	}
}

func TestCreateAgentProfile_HappyPath(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	// No MCP store → ceiling unknown → grants accepted best-effort.
	req := rootRequest("POST", "/api/agent-profiles",
		`{"org_id":"org-1","name":"builder","tier_hint":"premium","mcp_grants":["search"],"budget_cap_cents":5000,"guard_mode":"strict"}`)
	w := httptest.NewRecorder()
	h.CreateAgentProfile()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var prof adminstore.AgentProfile
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &prof))
	assert.Equal(t, "builder", prof.Name)
	assert.Equal(t, "premium", prof.TierHint)
	assert.Equal(t, []string{"search"}, prof.MCPGrants)
	require.NotNil(t, prof.BudgetCapCents)
	assert.Equal(t, int64(5000), *prof.BudgetCapCents)
}

func TestCreateAgentProfile_EnforcesGrantCeiling(t *testing.T) {
	store := newMockStore()
	mcpDB := newMCPTestStore()
	// org-1 has only "search" registered — "web" is NOT available to the org.
	seedOrgServers(mcpDB, "org-1", "search")
	h := newTestAdminH(store)
	h.SetMCPStore(mcpagg.NewStore(mcpDB), nil)

	req := rootRequest("POST", "/api/agent-profiles",
		`{"org_id":"org-1","name":"builder","mcp_grants":["search","web"]}`)
	w := httptest.NewRecorder()
	h.CreateAgentProfile()(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code,
		"grant outside the org's server registry must be rejected")

	// In-bounds grant succeeds.
	req2 := rootRequest("POST", "/api/agent-profiles",
		`{"org_id":"org-1","name":"builder","mcp_grants":["search"]}`)
	w2 := httptest.NewRecorder()
	h.CreateAgentProfile()(w2, req2)
	assert.Equal(t, http.StatusCreated, w2.Code)
}

func TestCreateAgentProfile_MissingName(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-profiles", `{"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateAgentProfile()(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAgentProfiles(t *testing.T) {
	store := newMockStore()
	store.agentProfiles["profile-1"] = &adminstore.AgentProfile{ID: "profile-1", OrgID: "org-1", Name: "builder"}
	h := newTestAdminH(store)
	req := rootRequest("GET", "/api/agent-profiles?org_id=org-1", "")
	w := httptest.NewRecorder()
	h.ListAgentProfiles()(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAgentProfile(t *testing.T) {
	store := newMockStore()
	store.agentProfiles["profile-1"] = &adminstore.AgentProfile{ID: "profile-1", OrgID: "org-1", Name: "builder"}
	h := newTestAdminH(store)
	w := httptest.NewRecorder()
	wrapWithParams(h.GetAgentProfile(), "/api/agent-profiles/{id}")(w, rootRequest("GET", "/api/agent-profiles/profile-1", ""))
	assert.Equal(t, http.StatusOK, w.Code)

	w2 := httptest.NewRecorder()
	wrapWithParams(h.GetAgentProfile(), "/api/agent-profiles/{id}")(w2, rootRequest("GET", "/api/agent-profiles/missing", ""))
	assert.Equal(t, http.StatusNotFound, w2.Code)
}

func TestUpdateAgentProfile(t *testing.T) {
	store := newMockStore()
	store.agentProfiles["profile-1"] = &adminstore.AgentProfile{ID: "profile-1", OrgID: "org-1", Name: "builder"}
	h := newTestAdminH(store)
	req := rootRequest("PUT", "/api/agent-profiles/profile-1", `{"tier_hint":"cheap"}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateAgentProfile(), "/api/agent-profiles/{id}")(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "cheap", store.agentProfiles["profile-1"].TierHint)
}

func TestDeleteAgentProfile(t *testing.T) {
	store := newMockStore()
	store.agentProfiles["profile-1"] = &adminstore.AgentProfile{ID: "profile-1", OrgID: "org-1", Name: "builder"}
	h := newTestAdminH(store)
	w := httptest.NewRecorder()
	wrapWithParams(h.DeleteAgentProfile(), "/api/agent-profiles/{id}")(w, rootRequest("DELETE", "/api/agent-profiles/profile-1", ""))
	assert.Equal(t, http.StatusNoContent, w.Code)
	_, ok := store.agentProfiles["profile-1"]
	assert.False(t, ok, "profile must be removed")
}

// --- Key issuance inheritance (ADL-06) ---

func TestCreateAgentKey_OnProfile_Inherits(t *testing.T) {
	store := newMockStore()
	mcpDB := newMCPTestStore()
	// org-1 has "search" and "web" registered.
	seedOrgServers(mcpDB, "org-1", "search", "web")
	cap := int64(7777)
	store.agentProfiles["profile-1"] = &adminstore.AgentProfile{
		ID: "profile-1", OrgID: "org-1", Name: "builder", TierHint: "premium",
		MCPGrants: []string{"search", "web"}, BudgetCapCents: &cap, GuardMode: "strict",
	}
	h := newTestAdminH(store)
	h.SetMCPStore(mcpagg.NewStore(mcpDB), nil)

	req := rootRequest("POST", "/api/agent-keys",
		`{"name":"agent-on-profile","org_id":"org-1","profile_id":"profile-1"}`)
	w := httptest.NewRecorder()
	h.CreateAgentKey()(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "profile-1", resp["profile_id"])
	assert.Equal(t, "premium", resp["tier_hint"])
	// Both in-bounds grants inherited (∩ org servers = both).
	grants, _ := resp["inherited_mcp_grants"].([]any)
	require.Len(t, grants, 2, "key must inherit the profile's in-bounds grants")
	// The key row carries the inherited daily cap.
	keyID, _ := resp["key_id"].(string)
	require.NotNil(t, store.agentKeys[keyID])
	require.NotNil(t, store.agentKeys[keyID].DailyLimitCents)
	assert.Equal(t, int64(7777), *store.agentKeys[keyID].DailyLimitCents)
	_, hasSearch := mcpDB.grants[grantKey("org-1", "search", keyID)]
	_, hasWeb := mcpDB.grants[grantKey("org-1", "web", keyID)]
	assert.True(t, hasSearch, "search grant inherited")
	assert.True(t, hasWeb, "web grant inherited")
}

func TestCreateAgentKey_OnProfile_NotFound(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys",
		`{"name":"agent-x","org_id":"org-1","profile_id":"missing"}`)
	w := httptest.NewRecorder()
	h.CreateAgentKey()(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCreateAgentKey_OnProfile_WrongOrg(t *testing.T) {
	store := newMockStore()
	cap := int64(1)
	// Profile belongs to org-2; the key is issued for org-1.
	store.agentProfiles["profile-2"] = &adminstore.AgentProfile{
		ID: "profile-2", OrgID: "org-2", Name: "other", MCPGrants: []string{}, BudgetCapCents: &cap,
	}
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys",
		`{"name":"agent-x","org_id":"org-1","profile_id":"profile-2"}`)
	w := httptest.NewRecorder()
	h.CreateAgentKey()(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code,
		"a profile from a different org must not be usable")
}

func TestCreateAgentKey_NoProfile_Unchanged(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys", `{"name":"plain","org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateAgentKey()(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	// No profile → no profile fields in the response.
	_, hasProfile := resp["profile_id"]
	assert.False(t, hasProfile)
}
