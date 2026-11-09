package handlers

// AUDIT-P1-03 handler-level contract: capped delegations and child budget
// updates route through the DelegationBudgetStore capability, and the
// sentinel errors map to their HTTP semantics (409 for invariant refusals,
// 404 for unknown keys, 409-with-current for CAS conflicts, 501 when the
// store lacks the capability, 500 for outages). The enforcement math itself
// is proven against real Postgres in pkg/adminstore; here we prove the WIRE
// behavior: status codes, no child key on refusal, legacy paths untouched.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedParentWithBudget adds an active root parent with a budget row.
func seedParentWithBudget(store *mockStore, id string, limitCents int64) *adminstore.AgentKey {
	parent := seedRootParent(store, id, "org-1")
	store.agentBudgets[id] = &adminstore.AgentBudget{AgentID: id, DailyLimitCents: limitCents, UpdatedAt: time.Now()}
	return parent
}

// newTestAdminHStore is newTestAdminH for arbitrary StoreInterface
// implementations (capability-missing wrappers).
func newTestAdminHStore(store StoreInterface) *testAdminHandlers {
	return &testAdminHandlers{AdminHandlers: New(store, "", "", []string{})}
}

func TestCreateDelegatedAgentKey_CappedOverHeadroom_409(t *testing.T) {
	store := newMockStore()
	seedParentWithBudget(store, "parent-1", 500)
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child-a","ttl":3600,"org_id":"org-1","budget_caps":700}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "headroom")
	assert.Empty(t, store.agentKeys["agent-key-child"], "refusal happens before any insert")
}

func TestCreateDelegatedAgentKey_CappedWithinHeadroom_201(t *testing.T) {
	store := newMockStore()
	seedParentWithBudget(store, "parent-1", 1000)
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child-a","ttl":3600,"org_id":"org-1","budget_caps":600}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "agent-key-child", resp["key_id"])
	child := store.agentKeys["agent-key-child"]
	require.NotNil(t, child)
	b := store.agentBudgets["agent-key-child"]
	require.NotNil(t, b, "capped delegation writes the enforcement row")
	assert.Equal(t, int64(600), b.DailyLimitCents)
}

func TestCreateDelegatedAgentKey_CaplessLegacyPath_201(t *testing.T) {
	store := newMockStore()
	seedParentWithBudget(store, "parent-1", 1000)
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child-a","ttl":3600,"org_id":"org-1"}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	assert.Nil(t, store.agentBudgets["agent-key-child"],
		"cap-less delegation keeps the legacy path: no budget row (fail-closed at spend)")
}

func TestCreateDelegatedAgentKey_ParentBudgetMissing_409(t *testing.T) {
	store := newMockStore()
	seedRootParent(store, "parent-1", "org-1") // root, but NO budget row
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child-a","ttl":3600,"org_id":"org-1","budget_caps":100}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "budget")
}

func TestCreateDelegatedAgentKey_CheckedStoreOutage_500(t *testing.T) {
	store := newMockStore()
	seedParentWithBudget(store, "parent-1", 1000)
	store.delegationErr = errors.New("connection refused")
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child-a","ttl":3600,"org_id":"org-1","budget_caps":100}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, store.agentKeys["agent-key-child"])
}

// noDelegationBudgetStore satisfies StoreInterface but deliberately lacks
// the DelegationBudgetStore capability methods (embedded interface keeps
// them out of the method set), so the type assertion in delegationBudget()
// fails — the fail-closed 501 path.
type noDelegationBudgetStore struct {
	StoreInterface
	base *mockStore
}

func (s *noDelegationBudgetStore) GetAgentKeyByID(ctx context.Context, id string) (*adminstore.AgentKey, error) {
	return s.base.GetAgentKeyByID(ctx, id)
}

func TestDelegatedAgentKey_NoCapability_501(t *testing.T) {
	base := newMockStore()
	seedParentWithBudget(base, "parent-1", 1000)
	h := newTestAdminHStore(&noDelegationBudgetStore{StoreInterface: base, base: base})
	req := rootRequest("POST", "/api/agent-keys/delegate",
		`{"parent_agent":"parent-1","name":"child-a","ttl":3600,"org_id":"org-1","budget_caps":100}`)
	w := httptest.NewRecorder()
	h.CreateDelegatedAgentKey()(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Empty(t, base.agentKeys["agent-key-child"], "refusal happens before any insert")
}

func TestUpsertAgentBudget_ChildOverHeadroom_409(t *testing.T) {
	store := newMockStore()
	parent := seedParentWithBudget(store, "parent-1", 500)
	store.agentKeys["child-1"] = &adminstore.AgentKey{
		ID: "child-1", Name: "child", OrgID: "org-1", Active: true, ParentID: &parent.ID}
	h := newTestAdminH(store)
	req := rootRequest("PUT", "/api/agent-keys/child-1/budget", `{"daily_limit_cents":700}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpsertAgentBudget(), "/api/agent-keys/{id}/budget")(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "headroom")
	_, wrote := store.agentBudgets["child-1"]
	assert.False(t, wrote, "refused update must not write the budget row")
}

func TestUpsertAgentBudget_ChildWithinHeadroom_200(t *testing.T) {
	store := newMockStore()
	parent := seedParentWithBudget(store, "parent-1", 500)
	store.agentKeys["child-1"] = &adminstore.AgentKey{
		ID: "child-1", Name: "child", OrgID: "org-1", Active: true, ParentID: &parent.ID}
	h := newTestAdminH(store)
	req := rootRequest("PUT", "/api/agent-keys/child-1/budget", `{"daily_limit_cents":400}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpsertAgentBudget(), "/api/agent-keys/{id}/budget")(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	b := store.agentBudgets["child-1"]
	require.NotNil(t, b)
	assert.Equal(t, int64(400), b.DailyLimitCents)
}

func TestUpsertAgentBudget_RootUnconstrained_200(t *testing.T) {
	store := newMockStore()
	seedParentWithBudget(store, "root-1", 500) // root key, small budget
	h := newTestAdminH(store)
	req := rootRequest("PUT", "/api/agent-keys/root-1/budget", `{"daily_limit_cents":999999}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpsertAgentBudget(), "/api/agent-keys/{id}/budget")(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	b := store.agentBudgets["root-1"]
	require.NotNil(t, b)
	assert.Equal(t, int64(999999), b.DailyLimitCents,
		"root budgets keep the legacy unconstrained path")
}

func TestUpsertAgentBudget_ChildCASConflict_409WithCurrent(t *testing.T) {
	store := newMockStore()
	parent := seedParentWithBudget(store, "parent-1", 1000)
	store.agentKeys["child-1"] = &adminstore.AgentKey{
		ID: "child-1", Name: "child", OrgID: "org-1", Active: true, ParentID: &parent.ID}
	store.agentBudgets["child-1"] = &adminstore.AgentBudget{AgentID: "child-1", DailyLimitCents: 500}
	h := newTestAdminH(store)

	// CAS success.
	req := rootRequest("PUT", "/api/agent-keys/child-1/budget",
		`{"daily_limit_cents":600,"expected":{"daily_limit_cents":500}}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpsertAgentBudget(), "/api/agent-keys/{id}/budget")(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Stale expectation → 409 carrying the current row.
	req = rootRequest("PUT", "/api/agent-keys/child-1/budget",
		`{"daily_limit_cents":600,"expected":{"daily_limit_cents":500}}`)
	w = httptest.NewRecorder()
	wrapWithParams(h.UpsertAgentBudget(), "/api/agent-keys/{id}/budget")(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "600", "conflict payload must carry the current limit")
}

func TestUpsertAgentBudget_ChildCASOverHeadroom_409(t *testing.T) {
	store := newMockStore()
	parent := seedParentWithBudget(store, "parent-1", 500)
	store.agentKeys["child-1"] = &adminstore.AgentKey{
		ID: "child-1", Name: "child", OrgID: "org-1", Active: true, ParentID: &parent.ID}
	store.agentBudgets["child-1"] = &adminstore.AgentBudget{AgentID: "child-1", DailyLimitCents: 100}
	h := newTestAdminH(store)
	// Matching expectation, but the widen blows the parent headroom.
	req := rootRequest("PUT", "/api/agent-keys/child-1/budget",
		`{"daily_limit_cents":60000,"expected":{"daily_limit_cents":100}}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpsertAgentBudget(), "/api/agent-keys/{id}/budget")(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "headroom")
	assert.Equal(t, int64(100), store.agentBudgets["child-1"].DailyLimitCents,
		"refused CAS must leave the stored cap untouched")
}

func TestUpsertAgentBudget_ChildCASAbsentWithinHeadroom_200(t *testing.T) {
	store := newMockStore()
	parent := seedParentWithBudget(store, "parent-1", 500)
	store.agentKeys["child-1"] = &adminstore.AgentKey{
		ID: "child-1", Name: "child", OrgID: "org-1", Active: true, ParentID: &parent.ID}
	h := newTestAdminH(store)
	req := rootRequest("PUT", "/api/agent-keys/child-1/budget",
		`{"daily_limit_cents":400,"expected":{"absent":true}}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpsertAgentBudget(), "/api/agent-keys/{id}/budget")(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	b := store.agentBudgets["child-1"]
	require.NotNil(t, b)
	assert.Equal(t, int64(400), b.DailyLimitCents)
}

func TestUpsertAgentBudget_NoCapability_501(t *testing.T) {
	base := newMockStore()
	parent := seedParentWithBudget(base, "parent-1", 500)
	base.agentKeys["child-1"] = &adminstore.AgentKey{
		ID: "child-1", Name: "child", OrgID: "org-1", Active: true, ParentID: &parent.ID}
	h := newTestAdminHStore(&noDelegationBudgetStore{StoreInterface: base, base: base})
	req := rootRequest("PUT", "/api/agent-keys/child-1/budget", `{"daily_limit_cents":400}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpsertAgentBudget(), "/api/agent-keys/{id}/budget")(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
	_, wrote := base.agentBudgets["child-1"]
	assert.False(t, wrote, "refusal happens before any write")
}

func TestUpsertAgentBudget_ChildNotFound_404(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("PUT", "/api/agent-keys/missing/budget", `{"daily_limit_cents":400}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpsertAgentBudget(), "/api/agent-keys/{id}/budget")(w, req)

	// agentKeyVisible 404s before the budget path is reached.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpsertAgentBudget_ChildBudgetParentMissing_409(t *testing.T) {
	store := newMockStore()
	seedRootParent(store, "root-1", "org-1") // root WITHOUT budget row
	store.agentKeys["child-1"] = &adminstore.AgentKey{
		ID: "child-1", Name: "child", OrgID: "org-1", Active: true, ParentID: strPtr("root-1")}
	h := newTestAdminH(store)
	req := rootRequest("PUT", "/api/agent-keys/child-1/budget", `{"daily_limit_cents":400}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpsertAgentBudget(), "/api/agent-keys/{id}/budget")(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "budget")
}
