package handlers_test

// W-SECADM: the admin API never returns key_hash material for API keys or
// test.go): every response that echoes a key row carries has_hash instead,
// the planted probe hash never leaves the process, and rotate answers a
// bare {"status":"ok"}.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	adminstore "github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const (
	keyHashSecret = "keyhash-test-session-secret" // #nosec G101 -- test-only HMAC key
	keyHashCSRF   = "keyhash-csrf-token"          // #nosec G101 -- test-only value
	// keyHashProbe is the planted sha256 material that must never serialize.
	keyHashProbe = "sha256-probe-0123456789abcdef0123456789abcdef"
)

// keyHashStore serves one API key and one agent key carrying the probe hash.
type keyHashStore struct {
	stubStore
	key      *adminstore.APIKey
	agentKey *adminstore.AgentKey
	rotated  string
}

func newKeyHashStore() *keyHashStore {
	created := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	org := "org-1"
	team := "team-1"
	return &keyHashStore{
		key: &adminstore.APIKey{
			ID: "key-1", KeyHash: keyHashProbe, HasHash: true, OrgID: &org, TeamID: &team,
			Name: "probe-key", Active: true, CreatedAt: created, Labels: map[string]string{},
		},
		agentKey: &adminstore.AgentKey{
			ID: "agent-key-1", KeyHash: keyHashProbe, HasHash: true, OrgID: "org-1",
			Name: "probe-agent", Active: true, CreatedAt: created,
		},
	}
}

func (s *keyHashStore) ListAPIKeys(_ context.Context, orgID *string, _ adminstore.PageFilter) ([]*adminstore.APIKey, int64, error) {
	if orgID != nil && *orgID != *s.key.OrgID {
		return nil, 0, nil
	}
	return []*adminstore.APIKey{s.key}, 1, nil
}

func (s *keyHashStore) GetAPIKeyByID(_ context.Context, id string) (*adminstore.APIKey, error) {
	if id == s.key.ID {
		return s.key, nil
	}
	return nil, adminstore.ErrNotFound
}

func (s *keyHashStore) RotateAPIKey(_ context.Context, _ string, newHash string) error {
	s.rotated = newHash
	return nil
}

func (s *keyHashStore) RevokeSessionKeysByParent(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (s *keyHashStore) ListAgentKeys(_ context.Context, orgID string) ([]*adminstore.AgentKey, error) {
	if orgID != s.agentKey.OrgID {
		return nil, nil
	}
	return []*adminstore.AgentKey{s.agentKey}, nil
}

func (s *keyHashStore) GetAgentKeyByID(_ context.Context, id string) (*adminstore.AgentKey, error) {
	if id == s.agentKey.ID {
		return s.agentKey, nil
	}
	return nil, adminstore.ErrNotFound
}

func keyHashRouter(t *testing.T, store *keyHashStore) http.Handler {
	t.Helper()
	return handlers.New(store, keyHashSecret, "localhost", nil).SetupRouter()
}

func keyHashRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, rdr)
	req.AddCookie(testCookie("yabanin_admin_session", makeSessionCookie(t, "root@x.test", true, keyHashSecret)))
	req.AddCookie(testCookie("yabanin_csrf_token", keyHashCSRF))
	req.Header.Set("X-CSRF-Token", keyHashCSRF)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(handlers.OrgHeader, "org-1")
	return req
}

// keyHashAssertClean pins the no-key_hash contract on a single-object body.
func keyHashAssertClean(t *testing.T, route string, body string, wantHasHash bool) {
	t.Helper()
	assert.NotContains(t, body, keyHashProbe, "%s leaked the probe hash", route)
	assert.NotContains(t, body, "key_hash", "%s carried a key_hash field", route)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &decoded), "%s: non-JSON body", route)
	has, ok := decoded["has_hash"]
	assert.True(t, ok, "%s must report has_hash", route)
	if ok {
		assert.Equal(t, wantHasHash, has, "%s has_hash mismatch", route)
	}
}

// keyHashAssertList pins the no-key_hash contract on a paginated/list body.
func keyHashAssertList(t *testing.T, route string, body string, wantItems int) {
	t.Helper()
	assert.NotContains(t, body, keyHashProbe, "%s leaked the probe hash", route)
	assert.NotContains(t, body, "key_hash", "%s carried a key_hash field", route)

	var decoded struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &decoded), "%s: non-JSON body", route)
	require.Len(t, decoded.Data, wantItems, "%s: item count", route)
	for i, item := range decoded.Data {
		has, ok := item["has_hash"]
		assert.True(t, ok, "%s: item %d must report has_hash", route, i)
		if ok {
			assert.Equal(t, true, has, "%s: item %d has_hash mismatch", route, i)
		}
		assert.NotContains(t, item, "key_hash", "%s: item %d carried key_hash", route, i)
	}
}

func TestKeyHashContract_APIKeysListGetRotate(t *testing.T) {
	store := newKeyHashStore()
	router := keyHashRouter(t, store)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, keyHashRequest(t, http.MethodGet, "/api/api-keys?org_id=org-1", ""))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	keyHashAssertList(t, "GET /api/api-keys", w.Body.String(), 1)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, keyHashRequest(t, http.MethodGet, "/api/api-keys/key-1", ""))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	keyHashAssertClean(t, "GET /api/api-keys/key-1", w.Body.String(), true)

	// Rotate: the request body carries the NEW hash; the response must not
	// echo it (it never contained a key row to begin with).
	w = httptest.NewRecorder()
	router.ServeHTTP(w, keyHashRequest(t, http.MethodPost, "/api/api-keys/key-1/rotate", `{"key_hash":"`+keyHashProbe+`-rotated"}`))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), keyHashProbe, "rotate response echoed hash material")
	assert.NotContains(t, w.Body.String(), "key_hash", "rotate response carried a key_hash field")
	assert.Equal(t, keyHashProbe+"-rotated", store.rotated, "the new hash must still reach the store")
}

func TestKeyHashContract_AgentKeysListGet(t *testing.T) {
	store := newKeyHashStore()
	router := keyHashRouter(t, store)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, keyHashRequest(t, http.MethodGet, "/api/agent-keys?org_id=org-1", ""))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	keyHashAssertList(t, "GET /api/agent-keys", w.Body.String(), 1)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, keyHashRequest(t, http.MethodGet, "/api/agent-keys/agent-key-1", ""))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	keyHashAssertClean(t, "GET /api/agent-keys/agent-key-1", w.Body.String(), true)
}
