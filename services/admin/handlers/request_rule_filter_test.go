package handlers

// CORE-TRACE-04: rule_id query param on the org request list/stats — strict
// uuid validation (400 on garbage, never silently ignored) and passthrough
// into the store filters for both endpoints that share parseRequestListFilters.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ruleFilterParamID = "9b1deb4d-3b7d-4bec-8a21-7c9d0e1b2a33"

func TestApiOrgRequests_RuleIDFilterParam(t *testing.T) {
	t.Run("valid uuid reaches the store filters", func(t *testing.T) {
		for _, path := range []string{
			"/api/organizations/org-1/requests?rule_id=" + ruleFilterParamID,
			"/api/organizations/org-1/requests/stats?rule_id=" + ruleFilterParamID,
		} {
			store := newMockStore()
			h := newTestAdminH(store)
			w := httptest.NewRecorder()
			if path[len(path)-6:] == "/stats" {
				h.apiOrgRequestStats()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
			} else {
				h.apiOrgRequests()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
			}
			require.Equal(t, http.StatusOK, w.Code, "%s: %s", path, w.Body.String())
			assert.Equal(t, ruleFilterParamID, store.lastRequestFilters.RuleID, path)
		}
	})

	t.Run("garbage uuid is an explicit 400 on both endpoints", func(t *testing.T) {
		for _, path := range []string{
			"/api/organizations/org-1/requests?rule_id=not-a-uuid",
			"/api/organizations/org-1/requests/stats?rule_id=not-a-uuid",
		} {
			store := newMockStore()
			h := newTestAdminH(store)
			w := httptest.NewRecorder()
			if path[len(path)-6:] == "/stats" {
				h.apiOrgRequestStats()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
			} else {
				h.apiOrgRequests()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
			}
			assert.Equal(t, http.StatusBadRequest, w.Code, path)
			assert.Contains(t, w.Body.String(), "rule_id", path)
		}
	})

	t.Run("absent param leaves the filter empty", func(t *testing.T) {
		store := newMockStore()
		h := newTestAdminH(store)
		w := httptest.NewRecorder()
		h.apiOrgRequests()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"/api/organizations/org-1/requests", nil))
		require.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, store.lastRequestFilters.RuleID)
	})
}
