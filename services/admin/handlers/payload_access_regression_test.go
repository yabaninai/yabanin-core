package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/require"
)

func TestRequestPayloadAccessWithoutGrant(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{name: "root", ctx: rootRequest("GET", "/", "").Context()},
		{name: "org-admin", ctx: WithOrgRole(context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "admin-a"), "org-1", adminstore.RoleOrgAdmin)},
		{name: "reader", ctx: WithOrgRole(context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "reader-a"), "org-1", adminstore.RoleReader)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMockStore()
			h := newTestAdminH(store)
			paths := []struct {
				name string
				h    http.HandlerFunc
				path string
			}{
				{"detail", h.apiOrgRequestDetail(), "/api/organizations/org-1/requests/req-1"},
				{"list-search", h.apiOrgRequests(), "/api/organizations/org-1/requests?q=git"},
				{"search-count", h.apiOrgRequestStats(), "/api/organizations/org-1/requests/stats?q=git"},
			}
			for _, p := range paths {
				t.Run(p.name, func(t *testing.T) {
					req := httptest.NewRequestWithContext(tc.ctx, http.MethodGet, p.path, nil)
					rec := httptest.NewRecorder()
					if p.name == "detail" {
						wrapWithParams(p.h, "/api/organizations/{id}/requests/{request_id}")(rec, req)
					} else {
						p.h.ServeHTTP(rec, req)
					}
					require.Equal(t, http.StatusOK, rec.Code)
					require.NotContains(t, rec.Body.String(), `"response"`)
					require.NotContains(t, rec.Body.String(), `"arguments"`)
					require.NotContains(t, rec.Body.String(), "git status")
					require.NotContains(t, rec.Body.String(), `"upstream_request"`)
					require.NotContains(t, rec.Body.String(), `"upstream_response"`)
					if p.name != "detail" {
						require.False(t, store.lastRequestFilters.PayloadGrant)
						require.True(t, store.lastRequestFilters.PayloadAuthorizationSet)
						if tc.name == "root" {
							require.False(t, store.lastRequestFilters.PayloadSearchAllowed)
						}
					}
				})
			}
		})
	}
}

func TestOrgAdminDoesNotInheritRequestPayloadAccess(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	ctx := WithOrgRole(context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "payload-admin"), "org-1", adminstore.RoleOrgAdmin)
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/organizations/org-1/requests/req-1", nil)
	rec := httptest.NewRecorder()
	wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), `"response"`)
	require.NotContains(t, rec.Body.String(), `"arguments"`)
	require.NotContains(t, rec.Body.String(), "git status")
}
