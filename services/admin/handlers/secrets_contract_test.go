package handlers_test

//
// Three layers are pinned here:
//
//  1. A grep-format contract walk over EVERY GET route of the admin router
//     (session+CSRF authenticated as root, exactly like the dashboard): no
//     response body may contain a planted probe key, an `upstream_api_key`
//     field with a value, or any sk-shaped secret. New routes are covered
//     automatically as they register.
//  2. Write paths accept the key but never echo it: POST /api/models answers
//     with has_key, PUT /api/models/{name} answers {"status":"ok"}, and the
//     key is cleared through the explicit clear_upstream_key field.
//  3. has_key is correct for models with a key (plaintext or stored under
//     encryption — the store hands the handler a readable value either way)
//     and for models without one.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	adminstore "github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	imp90SessionSecret = "imp90-test-session-secret" // #nosec G101 -- test-only HMAC key
	imp90CSRF          = "imp90-csrf-token"          // #nosec G101 -- test-only CSRF value
	// imp90ProbeKey is the planted upstream secret the contract must never leak.
	imp90ProbeKey = "sk-imp90-probe-0123456789abcdef0123456789abcdef" // #nosec G101 -- test probe value
	// imp90StoredBlob mimics an encrypted-at-rest value as the store would
	// surface it when the handler reads a key-configured model.
	imp90StoredBlob = "aGVsbG8tc2VjcmV0LWJsb2ItMTIzNDU2Nzg5MEFCQ0RFRg=="
)

// imp90Model builds a ModelRegistry carrying the probe upstream key.
func imp90Model(name, key string) *adminstore.ModelRegistry {
	m := &adminstore.ModelRegistry{
		ID:          "model-imp90",
		ModelName:   name,
		DisplayName: "IMP-90 probe model",
		Tier:        "smart",
		Provider:    "openai-compat",
		Enabled:     true,
		CreatedAt:   time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC),
	}
	if key != "" {
		m.UpstreamAPIKey = &key
	}
	return m
}

// probeStore serves a key-carrying model through the read/write surfaces and
// records what the write handlers passed down. Everything else keeps the
// errStub surface (a 500 with a generic body is a valid walk hit — it must
// not leak either).
type probeStore struct {
	stubStore
	org        *adminstore.Organization
	model      *adminstore.ModelRegistry
	lastUpdate adminstore.UpdateModelParams
	lastCreate adminstore.CreateModelParams
}

func newProbeStore(key string) *probeStore {
	return &probeStore{
		org:   &adminstore.Organization{ID: "org-1", Name: "Org One", Slug: "org-one", Currency: "USD", Timezone: "UTC"},
		model: imp90Model("probe-model", key),
	}
}

func (s *probeStore) ListOrganizations(_ context.Context, _ adminstore.PageFilter) ([]*adminstore.Organization, int64, error) {
	return []*adminstore.Organization{s.org}, 1, nil
}

func (s *probeStore) GetOrganizationByID(_ context.Context, id string) (*adminstore.Organization, error) {
	if id == s.org.ID {
		return s.org, nil
	}
	return nil, errStub
}

func (s *probeStore) ListModels(_ context.Context, _ adminstore.PageFilter) ([]*adminstore.ModelRegistry, int64, error) {
	return []*adminstore.ModelRegistry{s.model}, 1, nil
}

func (s *probeStore) GetModelByName(_ context.Context, name string) (*adminstore.ModelRegistry, error) {
	if name == s.model.ModelName {
		return s.model, nil
	}
	return nil, errStub
}

func (s *probeStore) CreateModelWithParams(_ context.Context, p adminstore.CreateModelParams) (*adminstore.ModelRegistry, error) {
	s.lastCreate = p
	m := imp90Model(p.ModelName, "")
	if p.UpstreamAPIKey != nil {
		// The real store echoes the (internal) value in its row struct; the
		// handler contract under test is that it never reaches the response.
		m.UpstreamAPIKey = p.UpstreamAPIKey
	}
	return m, nil
}

func (s *probeStore) UpdateModelWithParams(_ context.Context, p adminstore.UpdateModelParams) error {
	s.lastUpdate = p
	if p.ClearUpstreamKey {
		s.model.UpstreamAPIKey = nil
	} else if p.UpstreamAPIKey != nil {
		s.model.UpstreamAPIKey = p.UpstreamAPIKey
	}
	return nil
}

// imp90Router builds the full admin router for the probe store.
func imp90Router(t *testing.T, store *probeStore) http.Handler {
	t.Helper()
	return handlers.New(store, imp90SessionSecret, "localhost", nil).SetupRouter()
}

// imp90RootGet performs an authenticated root GET against the router.
func imp90RootGet(t *testing.T, router http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	req.AddCookie(testCookie("yabanin_admin_session", makeSessionCookie(t, "root@x.test", true, imp90SessionSecret)))
	req.AddCookie(testCookie("yabanin_csrf_token", imp90CSRF))
	req.Header.Set("X-CSRF-Token", imp90CSRF)
	req.Header.Set(handlers.OrgHeader, "org-1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// imp90Subst replaces chi URL params with seeded identifiers.
func imp90Subst(param string) string {
	switch param {
	case "name", "model_name":
		return "probe-model"
	case "request_id":
		return "req-1"
	case "target_id":
		return "key-1"
	case "exp_id":
		return "exp-1"
	case "agent_id":
		return "agent-1"
	case "userID":
		return "user-1"
	case "alias":
		return "alias-1"
	case "packID":
		return "pack-1"
	case "region":
		return "us-east"
	case "preset":
		return "baseline"
	case "templateID":
		return "tpl-1"
	case "vertical":
		return "eu"
	default: // id, org_id, orgID, anything else
		return "org-1"
	}
}

var imp90ParamRe = regexp.MustCompile(`\{[^}]+\}`)
var imp90SecretLikeRe = regexp.MustCompile(`sk-[A-Za-z0-9_-]{8,}`)

// imp90ScanJSON walks decoded JSON and reports every offending value:
// a non-empty upstream_api_key field or any sk-shaped secret.
func imp90ScanJSON(t *testing.T, prefix string, v any, problems *[]string) {
	t.Helper()
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			if k == "upstream_api_key" {
				if s, ok := child.(string); ok && s != "" {
					*problems = append(*problems, prefix+"/upstream_api_key carries a value")
				}
			}
			imp90ScanJSON(t, prefix+"/"+k, child, problems)
		}
	case []any:
		for i, child := range val {
			imp90ScanJSON(t, prefix, child, problems)
			_ = i
		}
	case string:
		if imp90SecretLikeRe.MatchString(val) {
			*problems = append(*problems, prefix+" carries an sk-shaped secret")
		}
	}
}

// TestIMP90_AdminGETRoutesNeverReturnUpstreamKey walks every registered GET
// route under /api and fails if any response carries upstream key material.
func TestIMP90_AdminGETRoutesNeverReturnUpstreamKey(t *testing.T) {
	store := newProbeStore(imp90ProbeKey)
	router := imp90Router(t, store)

	mux, ok := router.(chi.Router)
	require.True(t, ok, "SetupRouter must return a chi router")

	var problems []string
	var walked int
	err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method != http.MethodGet || !strings.HasPrefix(route, "/api/") {
			return nil
		}
		path := imp90ParamRe.ReplaceAllStringFunc(route, imp90Subst)
		w := imp90RootGet(t, router, path+"?org_id=org-1")
		walked++

		body := w.Body.String()
		if strings.Contains(body, imp90ProbeKey) {
			problems = append(problems, route+" leaks the probe upstream key")
		}
		if strings.Contains(body, imp90StoredBlob) {
			problems = append(problems, route+" leaks a stored key blob")
		}
		var decoded any
		if json.Unmarshal(w.Body.Bytes(), &decoded) == nil {
			imp90ScanJSON(t, route, decoded, &problems)
		}
		return nil
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, walked, 40, "the walk must cover the admin GET surface")
	assert.Empty(t, problems, "admin GET responses must never carry upstream key material: %v", problems)
}

// imp90RootDo performs an authenticated root write against the router.
func imp90RootDo(t *testing.T, router http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.AddCookie(testCookie("yabanin_admin_session", makeSessionCookie(t, "root@x.test", true, imp90SessionSecret)))
	req.AddCookie(testCookie("yabanin_csrf_token", imp90CSRF))
	req.Header.Set("X-CSRF-Token", imp90CSRF)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(handlers.OrgHeader, "org-1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestIMP90_CreateModelAcceptsKeyWithoutEcho: the write path stores the key
// (the store receives it) but the 201 response only states has_key.
func TestIMP90_CreateModelAcceptsKeyWithoutEcho(t *testing.T) {
	store := newProbeStore("")
	router := imp90Router(t, store)

	w := imp90RootDo(t, router, http.MethodPost, "/api/models",
		`{"model_name":"created-model","display_name":"Created","tier":"smart","upstream_api_key":"`+imp90ProbeKey+`"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	assert.NotContains(t, w.Body.String(), imp90ProbeKey, "create response must not echo the upstream key")
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["has_key"], "created model with a key must report has_key=true")
	assert.NotContains(t, resp, "upstream_api_key")

	require.NotNil(t, store.lastCreate.UpstreamAPIKey, "the key must still reach the store")
	assert.Equal(t, imp90ProbeKey, *store.lastCreate.UpstreamAPIKey)
}

// TestIMP90_UpdateModelNoEchoClearAndConflict pins the update contract: the
// key updates silently (status ok, no echo), clear_upstream_key is the
// explicit removal path, and mixing both is a 400.
func TestIMP90_UpdateModelNoEchoClearAndConflict(t *testing.T) {
	t.Run("key update without echo", func(t *testing.T) {
		store := newProbeStore(imp90ProbeKey)
		router := imp90Router(t, store)

		w := imp90RootDo(t, router, http.MethodPut, "/api/models/probe-model",
			`{"upstream_api_key":"`+imp90ProbeKey+`-rotated"}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.NotContains(t, w.Body.String(), imp90ProbeKey)
		require.NotNil(t, store.lastUpdate.UpstreamAPIKey)
		assert.Equal(t, imp90ProbeKey+"-rotated", *store.lastUpdate.UpstreamAPIKey)
	})

	t.Run("clear_upstream_key removes the key", func(t *testing.T) {
		store := newProbeStore(imp90ProbeKey)
		router := imp90Router(t, store)

		w := imp90RootDo(t, router, http.MethodPut, "/api/models/probe-model", `{"clear_upstream_key":true}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.True(t, store.lastUpdate.ClearUpstreamKey, "clear_upstream_key must reach the store")

		// The cleared model now reports has_key=false.
		got := imp90RootGet(t, router, "/api/models/probe-model")
		require.Equal(t, http.StatusOK, got.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(got.Body.Bytes(), &resp))
		assert.Equal(t, false, resp["has_key"])
	})

	t.Run("key and clear together are rejected", func(t *testing.T) {
		store := newProbeStore(imp90ProbeKey)
		router := imp90Router(t, store)

		w := imp90RootDo(t, router, http.MethodPut, "/api/models/probe-model",
			`{"upstream_api_key":"`+imp90ProbeKey+`","clear_upstream_key":true}`)
		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	})
}

// TestIMP90_HasKeyCorrectWithAndWithoutKey: has_key must hold for a model
// whose key arrives as plaintext and for one stored as an opaque blob
// (encrypted at rest — the store hands the handler a readable value either
// way), and stay false without a key.
func TestIMP90_HasKeyCorrectWithAndWithoutKey(t *testing.T) {
	t.Run("plaintext key reports has_key", func(t *testing.T) {
		store := newProbeStore(imp90ProbeKey)
		router := imp90Router(t, store)

		w := imp90RootGet(t, router, "/api/models/probe-model")
		require.Equal(t, http.StatusOK, w.Code)
		assert.NotContains(t, w.Body.String(), imp90ProbeKey)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, true, resp["has_key"])
	})

	t.Run("stored blob reports has_key without leaking the blob", func(t *testing.T) {
		store := newProbeStore(imp90StoredBlob)
		router := imp90Router(t, store)

		w := imp90RootGet(t, router, "/api/models/probe-model")
		require.Equal(t, http.StatusOK, w.Code)
		assert.NotContains(t, w.Body.String(), imp90StoredBlob)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, true, resp["has_key"])
	})

	t.Run("list reports has_key per model", func(t *testing.T) {
		store := newProbeStore(imp90ProbeKey)
		router := imp90Router(t, store)

		w := imp90RootGet(t, router, "/api/models")
		require.Equal(t, http.StatusOK, w.Code)
		assert.NotContains(t, w.Body.String(), imp90ProbeKey)
		var resp struct {
			Data []map[string]any `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.Len(t, resp.Data, 1)
		assert.Equal(t, true, resp.Data[0]["has_key"])
		assert.NotContains(t, resp.Data[0], "upstream_api_key")
	})

	t.Run("model without key reports has_key=false", func(t *testing.T) {
		store := newProbeStore("")
		router := imp90Router(t, store)

		w := imp90RootGet(t, router, "/api/models/probe-model")
		require.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, false, resp["has_key"])
	})
}
