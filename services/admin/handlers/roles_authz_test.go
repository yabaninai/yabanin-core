package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENT-02: RBAC — role checks on org-scoped routes + membership management.

// nonRootRequest builds a request with a NON-root admin session context (the
// shape adminauth.ChiAuthMiddleware produces) + an org scope, so the handler's
// requireOrgScope role check is exercised.
func nonRootRequest(method, target, orgScope string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	ctx := r.Context()
	ctx = context.WithValue(ctx, adminauth.ContextKeyUserID{}, "u-nonroot")
	ctx = context.WithValue(ctx, adminauth.ContextKeyEmail{}, "non@x.test")
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, false)
	ctx = context.WithValue(ctx, ctxKeyOrgScope{}, orgScope)
	return r.WithContext(ctx)
}

func TestCreateOrgMember_Root(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/organizations/org-1/members", `{"user_id":"u1","role":"operator"}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.CreateOrgMember(), "/api/organizations/{id}/members")(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
	require.NotNil(t, store.orgMembers["u1/org-1"])
	assert.Equal(t, adminstore.RoleOperator, store.orgMembers["u1/org-1"].Role)
}

func TestCreateOrgMember_InvalidRole(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/organizations/org-1/members", `{"user_id":"u1","role":"superuser"}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.CreateOrgMember(), "/api/organizations/{id}/members")(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateOrgMember_Duplicate(t *testing.T) {
	store := newMockStore()
	store.orgMembers["u1/org-1"] = &adminstore.OrgMembership{ID: "m", UserID: "u1", OrgID: "org-1", Role: adminstore.RoleReader}
	h := newTestAdminH(store)
	req := rootRequest("POST", "/api/organizations/org-1/members", `{"user_id":"u1","role":"operator"}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.CreateOrgMember(), "/api/organizations/{id}/members")(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestUpdateOrgMember(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := rootRequest("PUT", "/api/organizations/org-1/members/u1", `{"role":"org-admin"}`)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateOrgMember(), "/api/organizations/{id}/members/{userID}")(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, store.orgMembers["u1/org-1"])
	assert.Equal(t, adminstore.RoleOrgAdmin, store.orgMembers["u1/org-1"].Role)
}

func TestDeleteOrgMember(t *testing.T) {
	store := newMockStore()
	store.orgMembers["u1/org-1"] = &adminstore.OrgMembership{ID: "m", UserID: "u1", OrgID: "org-1", Role: adminstore.RoleReader}
	h := newTestAdminH(store)
	req := rootRequest("DELETE", "/api/organizations/org-1/members/u1", "")
	w := httptest.NewRecorder()
	wrapWithParams(h.DeleteOrgMember(), "/api/organizations/{id}/members/{userID}")(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
	_, ok := store.orgMembers["u1/org-1"]
	assert.False(t, ok)
}

func TestListOrgMembers(t *testing.T) {
	store := newMockStore()
	store.orgMembers["u1/org-1"] = &adminstore.OrgMembership{ID: "m", UserID: "u1", OrgID: "org-1", Role: adminstore.RoleReader}
	h := newTestAdminH(store)
	req := rootRequest("GET", "/api/organizations/org-1/members", "")
	w := httptest.NewRecorder()
	wrapWithParams(h.ListOrgMembers(), "/api/organizations/{id}/members")(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- RBAC gate: non-root role check in requireOrgScope ---

func TestRequireOrgRole_NonRootNoRole(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	// A non-root caller with NO role on org-1 must be 403'd on an org-scoped
	// mutation (the RBAC gate in requireOrgScope).
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.requireOrgScope(w, r, "org-1") == "" {
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	w := httptest.NewRecorder()
	probe.ServeHTTP(w, nonRootRequest("PUT", "/api/organizations/org-1", "org-1"))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireOrgRole_NonRootWithRole(t *testing.T) {
	store := newMockStore()
	store.orgMembers["u-nonroot/org-1"] = &adminstore.OrgMembership{UserID: "u-nonroot", OrgID: "org-1", Role: adminstore.RoleOrgAdmin}
	h := newTestAdminH(store)
	// A non-root caller WITH an org-admin role on org-1 passes the gate.
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.requireOrgScope(w, r, "org-1") == "" {
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	w := httptest.NewRecorder()
	probe.ServeHTTP(w, nonRootRequest("PUT", "/api/organizations/org-1", "org-1"))
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- RequireOrgRole middleware ---

func TestRequireOrgRole_Middleware(t *testing.T) {
	store := newMockStore()
	store.orgMembers["u-nonroot/org-1"] = &adminstore.OrgMembership{UserID: "u-nonroot", OrgID: "org-1", Role: adminstore.RoleReader}
	h := newTestAdminH(store)

	// A reader can satisfy a reader-min route, but not an org-admin-min route.
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// No chi route match → PathValue is empty → targetOrgID falls back to the
	// OrgHeader (set here).
	req := nonRootRequest("GET", "/api/organizations/org-1/members", "org-1")
	req.Header.Set(OrgHeader, "org-1")

	w := httptest.NewRecorder()
	h.RequireOrgRole(adminstore.RoleReader)(next).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "reader may read with a reader-min role")

	w2 := httptest.NewRecorder()
	h.RequireOrgRole(adminstore.RoleOrgAdmin)(next).ServeHTTP(w2, nonRootRequest("GET", "/api/organizations/org-1/members", "org-1"))
	assert.Equal(t, http.StatusForbidden, w2.Code, "reader is 403 on an org-admin-min route")
}
