package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApiTaskAnalytics(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/analytics/tasks?org_id=org-1&group_by=task&from=2026-09-01T00:00:00Z&to=2026-09-02T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.apiTaskAnalytics()(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var rep adminstore.TaskAnalyticsReport
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rep))
	assert.Equal(t, "org-1", rep.OrgID)
	assert.Equal(t, "task", rep.GroupBy)
	require.NotEmpty(t, rep.Groups)
	assert.Equal(t, "task-1", rep.Groups[0].Group)
}

func TestApiTaskAnalytics_DefaultGroupByTask(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/tasks?org_id=org-1", nil)
	w := httptest.NewRecorder()
	h.apiTaskAnalytics()(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var rep adminstore.TaskAnalyticsReport
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rep))
	assert.Equal(t, "task", rep.GroupBy)
}

func TestApiTaskAnalytics_MissingOrg(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/tasks?group_by=task", nil)
	w := httptest.NewRecorder()
	h.apiTaskAnalytics()(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestApiTaskAnalytics_InvalidTime(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/tasks?org_id=org-1&from=not-a-time", nil)
	w := httptest.NewRecorder()
	h.apiTaskAnalytics()(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestApiTaskAnalytics_StoreError500(t *testing.T) {
	store := newMockStore()
	store.err = errors.New("db down")
	h := newTestAdminH(store)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/analytics/tasks?org_id=org-1", nil)
	w := httptest.NewRecorder()
	h.apiTaskAnalytics()(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
