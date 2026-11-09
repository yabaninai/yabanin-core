package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

func TestApiAnalyticsQuery_ValidationAndCSV(t *testing.T) {
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1", Timezone: "UTC"}
	h := newTestAdminH(store)
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	to := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

	t.Run("org required", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/analytics/query?from="+from+"&to="+to, nil)
		w := httptest.NewRecorder()
		h.apiAnalyticsQuery()(w, req)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "org_required")
	})

	t.Run("bad metric", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
			"/api/analytics/query?org_id=org-1&from="+from+"&to="+to+"&metrics=nope", nil)
		w := httptest.NewRecorder()
		h.apiAnalyticsQuery()(w, req)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "invalid_metric")
	})

	t.Run("timeout", func(t *testing.T) {
		store.err = adminstore.ErrAnalyticsTimeout
		t.Cleanup(func() { store.err = nil })
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
			"/api/analytics/query?org_id=org-1&from="+from+"&to="+to+"&metrics=requests", nil)
		w := httptest.NewRecorder()
		h.apiAnalyticsQuery()(w, req)
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.Contains(t, w.Body.String(), "analytics_timeout")
	})

	t.Run("csv", func(t *testing.T) {
		store.analytics = &adminstore.AnalyticsResult{
			Columns: []adminstore.AnalyticsColumn{{Name: "team", Type: "string"}, {Name: "cost_usd", Type: "number", Unit: "usd"}},
			Rows:    [][]any{{"=cmd", 1.0}},
			DisplayNames: map[string]map[string]string{
				"team": {},
			},
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
			"/api/analytics/query?org_id=org-1&from="+from+"&to="+to+"&metrics=cost_usd&group_by=team&format=csv", nil)
		w := httptest.NewRecorder()
		h.apiAnalyticsQuery()(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Header().Get("Content-Type"), "text/csv")
		require.Contains(t, w.Header().Get("Content-Disposition"), "yabanin-analytics-org-1-20260901-20260902.csv")
		require.Contains(t, w.Body.String(), "team,team_name,cost_usd")
		require.Contains(t, w.Body.String(), "'=cmd")
	})
}

func TestApiAnalyticsQuery_ReaderOtherOrgIs403(t *testing.T) {
	store := newMockStore()
	store.orgMembers["admin-1/org-mine"] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: "org-mine", Role: adminstore.RoleReader}
	const secret = "test-secret-32-bytes-long-here!!" //nolint:gosec // test-only HMAC key, not a stored credential
	h := New(store, secret, "", nil)
	router := h.SetupRouter()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/query?org_id=org-other", nil)
	req.AddCookie(makeSessionCookie(false, secret))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
}
