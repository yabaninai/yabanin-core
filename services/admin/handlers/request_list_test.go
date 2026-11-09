package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApiOrgRequests_YQLQuery(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/organizations/org-1/requests?query=status+%3E%3D+400+and+tool+%3D+bash+order+by+cost+desc", nil)
	w := httptest.NewRecorder()
	h.apiOrgRequests()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var env struct {
		Data []adminstore.RequestListRow `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	require.Len(t, env.Data, 1)
}

func TestApiOrgRequests_ContentSearchWithoutPayloadScopeHasNoMatches(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	ctx := WithOrgRole(context.Background(), "org-1", adminstore.RoleOrgAdmin)
	req := httptest.NewRequestWithContext(ctx, http.MethodGet,
		"/api/organizations/org-1/requests?q=secret-fragment", nil)
	w := httptest.NewRecorder()
	h.apiOrgRequests()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, store.lastRequestFilters.PayloadUserID)
	assert.False(t, store.lastRequestFilters.PayloadGrant)
	assert.True(t, store.lastRequestFilters.PayloadAuthorizationSet)
	assert.False(t, store.lastRequestFilters.PayloadSearchAllowed)
	assert.Contains(t, w.Body.String(), `"total":0`)
}

func TestApiOrgRequests_ContentSearchUsesOwnSubjectScope(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "subject-a")
	ctx = WithOrgRole(ctx, "org-1", adminstore.RoleOrgAdmin)
	req := httptest.NewRequestWithContext(ctx, http.MethodGet,
		"/api/organizations/org-1/requests?q=secret-fragment", nil)
	w := httptest.NewRecorder()
	h.apiOrgRequests()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "subject-a", store.lastRequestFilters.PayloadUserID)
	assert.False(t, store.lastRequestFilters.PayloadGrant)
	assert.True(t, store.lastRequestFilters.PayloadSearchAllowed)
}

func TestApiOrgRequests_InvalidYQLIs400(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/organizations/org-1/requests?query=bogus+%3D+1", nil)
	w := httptest.NewRecorder()
	h.apiOrgRequests()(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unknown field")
}

func TestApiOrgRequestStats_YQLQuery(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/organizations/org-1/requests/stats?query=status+in+(500%2C+502)", nil)
	w := httptest.NewRecorder()
	h.apiOrgRequestStats()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var stats adminstore.RequestListStats
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &stats))
	assert.Equal(t, int64(1), stats.TotalRequests)
}

func TestApiOrgRequestStats_InvalidYQLIs400(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/organizations/org-1/requests/stats?query=status+%3E+abc", nil)
	w := httptest.NewRecorder()
	h.apiOrgRequestStats()(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "expects a number")
}

func TestRootRequestMetadataRequiresRequestsRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		role adminstore.OrgRole
		want bool
	}{
		{name: "root without org grant"},
		{name: "root with requests.read", role: adminstore.RoleOrgAdmin, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMockStore()
			h := newTestAdminH(store)
			ctx := context.WithValue(context.Background(), adminauth.ContextKeyIsRoot{}, true)
			if tc.role != "" {
				ctx = WithOrgRole(ctx, "org-1", tc.role)
			}
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/organizations/org-1/requests", nil)
			rec := httptest.NewRecorder()
			wrapWithParams(h.apiOrgRequests(), "/api/organizations/{id}/requests")(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
			}
			if got := store.lastRequestFilters.OrgWideMetadata; got != tc.want {
				t.Errorf("list OrgWideMetadata=%v, want %v", got, tc.want)
			}
			req = httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/organizations/org-1/requests/stats", nil)
			rec = httptest.NewRecorder()
			wrapWithParams(h.apiOrgRequestStats(), "/api/organizations/{id}/requests/stats")(rec, req)
			if got := store.lastRequestFilters.OrgWideMetadata; got != tc.want {
				t.Errorf("stats OrgWideMetadata=%v, want %v", got, tc.want)
			}
		})
	}
}
