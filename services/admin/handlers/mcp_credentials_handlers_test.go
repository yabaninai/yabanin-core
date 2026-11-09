package handlers

// MC-1 handler tests for the server-level MCP credential surface: masked
// wire shape (no secret material, ever), 503 when unwired, 400 on malformed
// payloads, 404 on missing rows, and the version-bumper hook.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// chiServeReq serves a pre-built request (root context, headers) against a
// handler bound to pattern — the chiServe variant for requests that carry
// headers (X-Audit-Reason).
func chiServeReq(pattern string, handler http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	rw := httptest.NewRecorder()
	chiCtx := &chi.Context{}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx))
	patternParts := strings.Split(pattern, "/")
	pathParts := strings.Split(req.URL.Path, "/")
	for i, p := range patternParts {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") && i < len(pathParts) {
			chiCtx.URLParams.Add(p[1:len(p)-1], pathParts[i])
		}
	}
	router := chi.NewRouter()
	router.Get(pattern, handler)
	router.Post(pattern, handler)
	router.Put(pattern, handler)
	router.Patch(pattern, handler)
	router.Delete(pattern, handler)
	router.ServeHTTP(rw, req)
	return rw
}

// fakeMCPCredStore is the in-memory MCPCredentialStore double.
type fakeMCPCredStore struct {
	mu   sync.Mutex
	rows map[string]adminstore.MCPServerCredential // key: org+"/"+server
}

func newFakeMCPCredStore() *fakeMCPCredStore {
	return &fakeMCPCredStore{rows: map[string]adminstore.MCPServerCredential{}}
}

func (f *fakeMCPCredStore) UpsertMCPServerCredential(_ context.Context, orgID, serverName, kind, _ string) (adminstore.MCPServerCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := orgID + "/" + serverName
	prev, existed := f.rows[k]
	row := adminstore.MCPServerCredential{
		ID: "cred-1", OrgID: orgID, ServerID: "srv-1", ServerName: serverName,
		Kind: kind, SecretLast4: "7777", HasSecret: true, Enabled: true, Version: 1,
		CreatedAt: prev.CreatedAt, UpdatedAt: prev.UpdatedAt,
	}
	if existed {
		row.Version = prev.Version + 1
	}
	f.rows[k] = row
	return row, nil
}

func (f *fakeMCPCredStore) GetMCPServerCredential(_ context.Context, orgID, serverName string) (adminstore.MCPServerCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.rows[orgID+"/"+serverName]
	if !ok {
		return adminstore.MCPServerCredential{}, adminstore.ErrNotFound
	}
	return row, nil
}

func (f *fakeMCPCredStore) DeleteMCPServerCredential(_ context.Context, orgID, serverName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := orgID + "/" + serverName
	if _, ok := f.rows[k]; !ok {
		return adminstore.ErrNotFound
	}
	delete(f.rows, k)
	return nil
}

func (f *fakeMCPCredStore) SetMCPServerCredentialEnabled(_ context.Context, orgID, serverName string, enabled bool) (adminstore.MCPServerCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.rows[orgID+"/"+serverName]
	if !ok {
		return adminstore.MCPServerCredential{}, adminstore.ErrNotFound
	}
	row.Enabled = enabled
	f.rows[orgID+"/"+serverName] = row
	return row, nil
}

// fakeMCPCredBumper records the version bumps.
type fakeMCPCredBumper struct {
	mu   sync.Mutex
	orgs []string
	err  error
}

func (b *fakeMCPCredBumper) SetMCPCredsVersion(_ context.Context, orgID string, _ int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	b.orgs = append(b.orgs, orgID)
	return nil
}

func newMCPCredTestH(store MCPCredentialStore, bumper MCPCredsVersionBumper) *AdminHandlers {
	h := New(nil, "", "", []string{})
	h.SetMCPCredentialStore(store, bumper)
	return h
}

func TestPutMCPServerCredential_NoStore(t *testing.T) {
	h := New(nil, "", "", []string{})
	w := chiServeReq("/api/organizations/{id}/mcp/servers/{name}/credential", h.PutMCPServerCredential(),
		rootRequest("PUT", "/api/organizations/org-1/mcp/servers/knowledge/credential",
			`{"kind":"headers","secret":{"Authorization":"Bearer x"}}`))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestPutMCPServerCredential_SuccessMasked(t *testing.T) {
	store := newFakeMCPCredStore()
	bumper := &fakeMCPCredBumper{}
	h := newMCPCredTestH(store, bumper)

	req := rootRequest("PUT", "/api/organizations/org-1/mcp/servers/knowledge/credential",
		`{"kind":"headers","secret":{"Authorization":"Bearer super-secret-value-7777"}}`)
	req.Header.Set("X-Audit-Reason", "onboard upstream")
	w := chiServeReq("/api/organizations/{id}/mcp/servers/{name}/credential", h.PutMCPServerCredential(), req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := w.Body.String()
	assert.Contains(t, body, `"secret_last4":"7777"`)
	assert.Contains(t, body, `"has_secret":true`)
	assert.NotContains(t, body, "super-secret-value-7777", "the plaintext secret must never reach the response")
	assert.Len(t, bumper.orgs, 1, "a successful upsert must bump the org version")
	assert.Equal(t, "org-1", bumper.orgs[0])

	// Rotation bumps the store version.
	w = chiServeReq("/api/organizations/{id}/mcp/servers/{name}/credential", h.PutMCPServerCredential(),
		rootRequest("PUT", "/api/organizations/org-1/mcp/servers/knowledge/credential",
			`{"kind":"headers","secret":{"Authorization":"Bearer rotated-value-9999"}}`))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"version":2`)
}

func TestPutMCPServerCredential_Validation(t *testing.T) {
	h := newMCPCredTestH(newFakeMCPCredStore(), nil)
	cases := []struct {
		name string
		body string
	}{
		{"missing secret", `{"kind":"headers"}`},
		{"empty secret string", `{"kind":"headers","secret":""}`},
		{"array secret", `{"kind":"headers","secret":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := chiServeReq("/api/organizations/{id}/mcp/servers/{name}/credential", h.PutMCPServerCredential(),
				rootRequest("PUT", "/api/organizations/org-1/mcp/servers/knowledge/credential", tc.body))
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		})
	}
}

func TestGetMCPServerCredential_MaskedAndNotFound(t *testing.T) {
	store := newFakeMCPCredStore()
	h := newMCPCredTestH(store, nil)

	w := chiServe("/api/organizations/{id}/mcp/servers/{name}/credential", h.GetMCPServerCredential(),
		"GET", "/api/organizations/org-1/mcp/servers/missing/credential", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)

	_, err := store.UpsertMCPServerCredential(context.Background(), "org-1", "knowledge", "headers", "x")
	require.NoError(t, err)
	w = chiServe("/api/organizations/{id}/mcp/servers/{name}/credential", h.GetMCPServerCredential(),
		"GET", "/api/organizations/org-1/mcp/servers/knowledge/credential", nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"secret_last4":"7777"`)
}

func TestDeleteMCPServerCredential_NotFoundAndBump(t *testing.T) {
	store := newFakeMCPCredStore()
	bumper := &fakeMCPCredBumper{}
	h := newMCPCredTestH(store, bumper)

	w := chiServe("/api/organizations/{id}/mcp/servers/{name}/credential", h.DeleteMCPServerCredential(),
		"DELETE", "/api/organizations/org-1/mcp/servers/missing/credential", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Empty(t, bumper.orgs, "a failed delete must not bump")

	_, err := store.UpsertMCPServerCredential(context.Background(), "org-1", "knowledge", "headers", "x")
	require.NoError(t, err)
	w = chiServe("/api/organizations/{id}/mcp/servers/{name}/credential", h.DeleteMCPServerCredential(),
		"DELETE", "/api/organizations/org-1/mcp/servers/knowledge/credential", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []string{"org-1"}, bumper.orgs)
}

func TestPutMCPServerCredential_BumperFailureNeverFailsResponse(t *testing.T) {
	store := newFakeMCPCredStore()
	bumper := &fakeMCPCredBumper{err: errors.New("redis down")}
	h := newMCPCredTestH(store, bumper)

	w := chiServeReq("/api/organizations/{id}/mcp/servers/{name}/credential", h.PutMCPServerCredential(),
		rootRequest("PUT", "/api/organizations/org-1/mcp/servers/knowledge/credential",
			`{"kind":"headers","secret":{"Authorization":"Bearer whatever-0000"}}`))
	assert.Equal(t, http.StatusOK, w.Code, "a failed bump is a warning, never a failed response")
}
