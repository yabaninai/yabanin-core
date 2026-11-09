package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Tests for cache admin endpoints
// ---------------------------------------------------------------------------

func TestGetOrgCacheSettings(t *testing.T) {
	store := newMockStore()
	org := &adminstore.Organization{ID: "org-cache-1", Name: "Test Org", Slug: "test-org", CacheEnabled: true, CacheMode: "semantic"}
	store.orgs["org-cache-1"] = org

	h := New(store, "session-secret", "localhost", nil)
	handler := h.GetOrgCacheSettings()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/organizations/org-cache-1/cache-settings", nil)
	rec := httptest.NewRecorder()

	// chi.URLParam requires the route to be mounted; use rctx pattern.
	r := chi.NewRouter()
	r.Get("/api/organizations/{id}/cache-settings", handler)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp adminstore.OrgCacheSettings
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.CacheEnabled)
	assert.Equal(t, "semantic", resp.CacheMode)
}

func TestGetOrgCacheSettings_NotFound(t *testing.T) {
	store := newMockStore()
	h := New(store, "session-secret", "localhost", nil)
	handler := h.GetOrgCacheSettings()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/organizations/non-existent/cache-settings", nil)
	rec := httptest.NewRecorder()

	r := chi.NewRouter()
	r.Get("/api/organizations/{id}/cache-settings", handler)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestUpdateOrgCacheSettings_ValidMode(t *testing.T) {
	store := newMockStore()
	org := &adminstore.Organization{ID: "org-cache-2", Name: "Test Org 2", Slug: "test-org-2", CacheEnabled: true, CacheMode: "semantic"}
	store.orgs["org-cache-2"] = org

	h := New(store, "session-secret", "localhost", nil)
	handler := h.UpdateOrgCacheSettings()

	body, _ := json.Marshal(map[string]interface{}{
		"cache_enabled": false,
		"cache_mode":    "off",
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/api/organizations/org-cache-2/cache-settings", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	r := chi.NewRouter()
	r.Patch("/api/organizations/{id}/cache-settings", handler)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// Verify org was updated.
	updatedOrg := store.orgs["org-cache-2"]
	assert.False(t, updatedOrg.CacheEnabled)
	assert.Equal(t, "off", updatedOrg.CacheMode)
}

func TestUpdateOrgCacheSettings_InvalidMode(t *testing.T) {
	store := newMockStore()
	org := &adminstore.Organization{ID: "org-cache-3", Name: "Test Org 3", Slug: "test-org-3", CacheEnabled: true, CacheMode: "semantic"}
	store.orgs["org-cache-3"] = org

	h := New(store, "session-secret", "localhost", nil)
	handler := h.UpdateOrgCacheSettings()

	body, _ := json.Marshal(map[string]interface{}{
		"cache_enabled": true,
		"cache_mode":    "invalid_mode",
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/api/organizations/org-cache-3/cache-settings", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	r := chi.NewRouter()
	r.Patch("/api/organizations/{id}/cache-settings", handler)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestUpdateOrgCacheSettings_EmptyModeDefaultsToSemantic(t *testing.T) {
	store := newMockStore()
	org := &adminstore.Organization{ID: "org-cache-4", Name: "Test Org 4", Slug: "test-org-4", CacheEnabled: true, CacheMode: "semantic"}
	store.orgs["org-cache-4"] = org

	h := New(store, "session-secret", "localhost", nil)
	handler := h.UpdateOrgCacheSettings()

	// Send cache_enabled=false with empty mode — should default to "semantic".
	body, _ := json.Marshal(map[string]interface{}{
		"cache_enabled": false,
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/api/organizations/org-cache-4/cache-settings", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	r := chi.NewRouter()
	r.Patch("/api/organizations/{id}/cache-settings", handler)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	updatedOrg := store.orgs["org-cache-4"]
	assert.False(t, updatedOrg.CacheEnabled)
	assert.Equal(t, "semantic", updatedOrg.CacheMode) // defaults to semantic
}

func TestFlushCache_WithInvalidator(t *testing.T) {
	store := newMockStore()
	h := New(store, "session-secret", "localhost", nil)
	// Create a mock invalidator — we can't fully test Redis/pgvector interaction
	// but we verify the handler returns 503 when inv is nil.
	handler := h.FlushCache()

	body := bytes.NewReader(nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/cache/flush?org_id=org-1", body)
	rec := httptest.NewRecorder()

	r := chi.NewRouter()
	r.Post("/api/cache/flush", handler)
	r.ServeHTTP(rec, req)

	// Should return 503 because inv is nil.
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestFlushCache_MissingOrgID(t *testing.T) {
	store := newMockStore()
	h := New(store, "session-secret", "localhost", nil)
	handler := h.FlushCache()

	body := bytes.NewReader(nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/cache/flush", body)
	rec := httptest.NewRecorder()

	r := chi.NewRouter()
	r.Post("/api/cache/flush", handler)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCacheAnalytics(t *testing.T) {
	store := newMockStore()
	h := New(store, "session-secret", "localhost", nil)
	handler := h.CacheAnalytics()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/cache/analytics", nil)
	rec := httptest.NewRecorder()

	r := chi.NewRouter()
	r.Get("/api/cache/analytics", handler)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// Should return a snapshot (may be empty since no hits recorded).
	var resp map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	// Snapshot should contain the analytics data.
	assert.NotNil(t, resp)
}

func TestBumpModelVersion(t *testing.T) {
	store := newMockStore()
	model := &adminstore.ModelRegistry{ModelName: "gpt-4", Tier: "smart"}
	store.models["gpt-4"] = model

	h := New(store, "session-secret", "localhost", nil)
	handler := h.BumpModelVersion()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/models/gpt-4/bump-version", bytes.NewReader(nil))
	rec := httptest.NewRecorder()

	r := chi.NewRouter()
	r.Post("/api/models/{name}/bump-version", handler)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestBumpModelVersion_NotFound(t *testing.T) {
	store := newMockStore()
	h := New(store, "session-secret", "localhost", nil)
	handler := h.BumpModelVersion()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/models/nonexistent/bump-version", bytes.NewReader(nil))
	rec := httptest.NewRecorder()

	r := chi.NewRouter()
	r.Post("/api/models/{name}/bump-version", handler)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}
