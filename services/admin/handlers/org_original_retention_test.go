package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/require"
)

type originalRetentionTestStore struct {
	*mockStore
	setting *adminstore.OrgOriginalRetention
}

func (s *originalRetentionTestStore) GetOrgOriginalRetention(_ context.Context, orgID string) (*adminstore.OrgOriginalRetention, error) {
	if s.setting == nil {
		return &adminstore.OrgOriginalRetention{OrgID: orgID, Effective: adminstore.OriginalRetentionPlatformDefault, Inherited: true}, nil
	}
	copy := *s.setting
	copy.OrgID = orgID
	return &copy, nil
}

func (s *originalRetentionTestStore) UpdateOrgOriginalRetention(_ context.Context, orgID string, enabled *bool) error {
	if enabled == nil {
		s.setting = &adminstore.OrgOriginalRetention{OrgID: orgID, Effective: adminstore.OriginalRetentionPlatformDefault, Inherited: true}
		return nil
	}
	value := *enabled
	s.setting = &adminstore.OrgOriginalRetention{OrgID: orgID, Enabled: &value, Effective: value}
	return nil
}

func TestOrgOriginalRetentionHandlersDefaultOptInAndInheritance(t *testing.T) {
	store := &originalRetentionTestStore{mockStore: newMockStore()}
	h := New(store, "session-secret", "localhost", nil)
	router := chi.NewRouter()
	router.Get("/api/organizations/{id}/original-retention", h.GetOrgOriginalRetention())
	router.Patch("/api/organizations/{id}/original-retention", h.UpdateOrgOriginalRetention())

	get := func() adminstore.OrgOriginalRetention {
		t.Helper()
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/organizations/org-1/original-retention", nil))
		require.Equal(t, http.StatusOK, rec.Code)
		var got adminstore.OrgOriginalRetention
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		return got
	}
	initial := get()
	require.True(t, initial.Inherited)
	require.False(t, initial.Effective, "inherited platform default is processed-only")

	set := func(body string) {
		t.Helper()
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, rootRequest(http.MethodPatch, "/api/organizations/org-1/original-retention", body))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	}
	set(`{"enabled":true}`)
	optedIn := get()
	require.False(t, optedIn.Inherited)
	require.True(t, optedIn.Effective)
	require.NotNil(t, optedIn.Enabled)
	require.True(t, *optedIn.Enabled)

	set(`{"enabled":null}`)
	inherited := get()
	require.True(t, inherited.Inherited)
	require.False(t, inherited.Effective)
}

func TestOrgOriginalRetentionHandlerRejectsMalformedBody(t *testing.T) {
	store := &originalRetentionTestStore{mockStore: newMockStore()}
	h := New(store, "session-secret", "localhost", nil)
	router := chi.NewRouter()
	router.Patch("/api/organizations/{id}/original-retention", h.UpdateOrgOriginalRetention())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, rootRequest(http.MethodPatch, "/api/organizations/org-1/original-retention", "not-json"))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOrgOriginalRetentionHandlerRequiresExplicitChoice(t *testing.T) {
	store := &originalRetentionTestStore{mockStore: newMockStore()}
	h := New(store, "session-secret", "localhost", nil)
	router := chi.NewRouter()
	router.Patch("/api/organizations/{id}/original-retention", h.UpdateOrgOriginalRetention())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, rootRequest(http.MethodPatch, "/api/organizations/org-1/original-retention", `{}`))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Nil(t, store.setting, "missing enabled must not silently reset inheritance")
}
