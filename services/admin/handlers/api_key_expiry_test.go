package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// every UpdateAPIKeyExpiry call.
type expiryCapStore struct {
	*mockStore
	mu     sync.Mutex
	expiry map[string]*time.Time
	calls  int
}

func newExpiryCapStore() *expiryCapStore {
	return &expiryCapStore{
		mockStore: newMockStore(),
		expiry:    map[string]*time.Time{},
	}
}

func (m *expiryCapStore) UpdateAPIKeyExpiry(_ context.Context, id string, expiresAt *time.Time) error {
	if _, ok := m.apiKeys[id]; !ok {
		return adminstore.ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expiry[id] = expiresAt
	m.calls++
	return nil
}

func TestCreateAPIKey_WithExpiresAt(t *testing.T) {
	store := newExpiryCapStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1"}
	h := New(store, "", "", []string{})

	body := strings.NewReader(`{"name":"prod-key","org_id":"org-1","expires_at":"2030-01-01T00:00:00Z"}`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/api-keys", body)
	w := httptest.NewRecorder()
	h.CreateAPIKey()(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	require.Equal(t, 1, store.calls, "expiry must be applied on create")
	require.Contains(t, store.expiry, "key-1")
	want := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	assert.True(t, store.expiry["key-1"].Equal(want))

	var doc struct {
		ExpiresAt *time.Time `json:"expires_at"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	require.NotNil(t, doc.ExpiresAt)
	assert.True(t, doc.ExpiresAt.Equal(want), "the response must echo the stored expiry")
}

// An empty expires_at explicitly pins "never expires" (NULL).
func TestCreateAPIKey_EmptyExpiresAt_ClearsToNull(t *testing.T) {
	store := newExpiryCapStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1"}
	h := New(store, "", "", []string{})

	body := strings.NewReader(`{"name":"prod-key","org_id":"org-1","expires_at":""}`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/api-keys", body)
	w := httptest.NewRecorder()
	h.CreateAPIKey()(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	require.Equal(t, 1, store.calls)
	require.Contains(t, store.expiry, "key-1")
	assert.Nil(t, store.expiry["key-1"], "an empty string must clear the column to NULL")
}

func TestCreateAPIKey_InvalidExpiresAt_RejectedBeforeInsert(t *testing.T) {
	store := newExpiryCapStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1"}
	h := New(store, "", "", []string{})

	body := strings.NewReader(`{"name":"prod-key","org_id":"org-1","expires_at":"not-a-time"}`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/api-keys", body)
	w := httptest.NewRecorder()
	h.CreateAPIKey()(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, store.apiKeys, "a malformed expiry must not leave a half-created key")
	assert.Zero(t, store.calls)
}

func TestCreateAPIKey_ExpiryUnsupportedStore_501(t *testing.T) {
	store := newMockStore() // implements StoreInterface, not the expiry capability
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1"}
	h := newTestAdminH(store)

	body := strings.NewReader(`{"name":"prod-key","org_id":"org-1","expires_at":"2030-01-01T00:00:00Z"}`)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/api-keys", body)
	w := httptest.NewRecorder()
	h.CreateAPIKey()(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Empty(t, store.apiKeys, "refusal happens before the insert")
}

func TestUpdateAPIKey_WithExpiresAt(t *testing.T) {
	store := newExpiryCapStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", Name: "prod-key", Active: true}
	h := New(store, "", "", []string{})

	body := strings.NewReader(`{"active":true,"expires_at":"2030-06-01T12:00:00Z"}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/api-keys/key-1", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateAPIKeyActive(), "/api/api-keys/{id}")(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 1, store.calls)
	want := time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC)
	assert.True(t, store.expiry["key-1"].Equal(want))
	assert.True(t, store.apiKeys["key-1"].Active, "the toggle still applies")
}

func TestUpdateAPIKey_ExpiryOnly_KeepsActive(t *testing.T) {
	store := newExpiryCapStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", Name: "prod-key", Active: true}
	h := New(store, "", "", []string{})

	body := strings.NewReader(`{"expires_at":"2030-06-01T12:00:00Z"}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/api-keys/key-1", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateAPIKeyActive(), "/api/api-keys/{id}")(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, store.calls)
	assert.True(t, store.apiKeys["key-1"].Active, "an expiry-only PUT must not touch active")
}

// An empty expires_at clears the column (back to never-expires).
func TestUpdateAPIKey_ClearExpiresAt(t *testing.T) {
	store := newExpiryCapStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", Name: "prod-key", Active: true}
	h := New(store, "", "", []string{})

	body := strings.NewReader(`{"active":true,"expires_at":""}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/api-keys/key-1", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateAPIKeyActive(), "/api/api-keys/{id}")(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 1, store.calls)
	assert.Nil(t, store.expiry["key-1"], "an empty string must clear the column to NULL")
}

func TestUpdateAPIKey_InvalidExpiresAt_400(t *testing.T) {
	store := newExpiryCapStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", Name: "prod-key", Active: true}
	h := New(store, "", "", []string{})

	body := strings.NewReader(`{"active":true,"expires_at":"tomorrow"}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/api-keys/key-1", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateAPIKeyActive(), "/api/api-keys/{id}")(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Zero(t, store.calls)
}

func TestUpdateAPIKey_ExpiryUnsupportedStore_501(t *testing.T) {
	store := newMockStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", Name: "prod-key", Active: true}
	h := newTestAdminH(store)

	body := strings.NewReader(`{"active":true,"expires_at":"2030-06-01T12:00:00Z"}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/api-keys/key-1", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateAPIKeyActive(), "/api/api-keys/{id}")(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestUpdateAPIKey_EmptyBody_400(t *testing.T) {
	store := newExpiryCapStore()
	store.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", Name: "prod-key", Active: true}
	h := New(store, "", "", []string{})

	body := strings.NewReader(`{}`)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", "/api/api-keys/key-1", body)
	w := httptest.NewRecorder()
	wrapWithParams(h.UpdateAPIKeyActive(), "/api/api-keys/{id}")(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Zero(t, store.calls)
}
