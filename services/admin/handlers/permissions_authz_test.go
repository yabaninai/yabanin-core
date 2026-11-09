package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
)

func TestRequireOrgPermission(t *testing.T) {
	store := newMockStore()
	store.orgMembers["u-reader/org-1"] = &adminstore.OrgMembership{UserID: "u-reader", OrgID: "org-1", Role: adminstore.RoleReader}
	store.orgMembers["u-unknown/org-1"] = &adminstore.OrgMembership{UserID: "u-unknown", OrgID: "org-1", Role: adminstore.OrgRole("nope")}
	h := newTestAdminH(store)
	next := h.RequireOrgPermission(adminstore.PermAnalyticsRead)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	root := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics?org_id=org-1", nil)
	root = root.WithContext(context.WithValue(root.Context(), adminauth.ContextKeyIsRoot{}, true))
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, root)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	reader := sessionRequest("u-reader", false, "/api/analytics?org_id=org-1")
	rec = httptest.NewRecorder()
	next.ServeHTTP(rec, reader)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	denied := h.RequireOrgPermission(adminstore.PermKeysManage)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rec = httptest.NewRecorder()
	denied.ServeHTTP(rec, reader)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	stranger := sessionRequest("u-none", false, "/api/analytics?org_id=org-1")
	rec = httptest.NewRecorder()
	next.ServeHTTP(rec, stranger)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	unknown := sessionRequest("u-unknown", false, "/api/analytics?org_id=org-1")
	rec = httptest.NewRecorder()
	next.ServeHTTP(rec, unknown)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func sessionRequest(userID string, root bool, target string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	ctx := r.Context()
	ctx = context.WithValue(ctx, adminauth.ContextKeyUserID{}, userID)
	ctx = context.WithValue(ctx, adminauth.ContextKeyEmail{}, userID+"@x.test")
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, root)
	return r.WithContext(ctx)
}
