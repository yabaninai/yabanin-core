package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mockPayloadGrantMu sync.Mutex
var mockPayloadGrants = map[*mockStore]map[string]adminstore.RequestPayloadGrant{}

func (m *mockStore) CreateRequestPayloadGrant(orgID, requestID, rootID string, ttl time.Duration, now time.Time) (adminstore.RequestPayloadGrant, error) {
	return m.CreateRequestPayloadGrantScope(orgID, requestID, rootID, adminstore.RequestPayloadScopeRead, ttl, now)
}

func (m *mockStore) CreateRequestPayloadGrantScope(orgID, requestID, rootID, scope string, ttl time.Duration, now time.Time) (adminstore.RequestPayloadGrant, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return adminstore.RequestPayloadGrant{}, err
	}
	grant := adminstore.RequestPayloadGrant{ID: "grant-a", Token: hex.EncodeToString(token[:]), OrgID: orgID, RequestID: requestID, RootID: rootID, ExpiresAt: now.Add(ttl), Scope: scope}
	mockPayloadGrantMu.Lock()
	defer mockPayloadGrantMu.Unlock()
	if mockPayloadGrants[m] == nil {
		mockPayloadGrants[m] = make(map[string]adminstore.RequestPayloadGrant)
	}
	mockPayloadGrants[m][grant.Token] = grant
	if err := m.InsertAuditLogEntry(context.Background(), adminstore.AuditLogEntryRecord{
		ID: "grant-a-issued", Action: "request_payload.grant_issued", Resource: "request:" + requestID,
		Details: `{"org_id":"` + orgID + `","request_id":"` + requestID + `"}`,
		AdminID: rootID, CreatedAt: now,
	}); err != nil {
		delete(mockPayloadGrants[m], grant.Token)
		return adminstore.RequestPayloadGrant{}, err
	}
	return grant, nil
}

func (m *mockStore) ConsumeRequestPayloadGrant(token, orgID, requestID, rootID string, now time.Time) bool {
	return m.ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, adminstore.RequestPayloadScopeRead, now) == nil
}

func (m *mockStore) ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope string, now time.Time) error {
	mockPayloadGrantMu.Lock()
	defer mockPayloadGrantMu.Unlock()
	grant, ok := mockPayloadGrants[m][token]
	if !ok || !now.Before(grant.ExpiresAt) || grant.OrgID != orgID || grant.RequestID != requestID || grant.RootID != rootID || grant.Scope != scope {
		return adminstore.ErrInvalidRequestPayloadGrant
	}
	delete(mockPayloadGrants[m], token)
	return nil
}

func (m *mockStore) RevokeRequestPayloadGrant(token, rootID string) error {
	mockPayloadGrantMu.Lock()
	defer mockPayloadGrantMu.Unlock()
	grant, exists := mockPayloadGrants[m][token]
	if !exists || grant.RootID != rootID {
		return adminstore.ErrInvalidRequestPayloadGrant
	}
	delete(mockPayloadGrants[m], token)
	return nil
}

func (m *mockStore) ListRequestPayloadGrants(_ context.Context, rootID string) ([]adminstore.RequestPayloadGrant, error) {
	mockPayloadGrantMu.Lock()
	defer mockPayloadGrantMu.Unlock()
	grants := []adminstore.RequestPayloadGrant{}
	for _, grant := range mockPayloadGrants[m] {
		if grant.RootID == rootID {
			grant.Token = ""
			grants = append(grants, grant)
		}
	}
	return grants, nil
}

func rootPayloadRequest(method, target, body string) *http.Request {
	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "admin-root")
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, true)
	return httptest.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
}

func TestRootPayloadSelfGrantIsExplicitAuditedAndSingleUse(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	url := "/api/root/payload-grants"
	w := httptest.NewRecorder()
	h.apiRootRequestPayloadGrant()(w, rootPayloadRequest(http.MethodPost, url, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var issued struct {
		Token string `json:"payload_grant"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &issued))
	require.NotEmpty(t, issued.Token)
	require.Len(t, store.auditRecords, 1)
	assert.Equal(t, "request_payload.grant_issued", store.auditRecords[0].Action)
	assert.Contains(t, store.auditRecords[0].Details, `"org_id":"org-1"`)
	assert.Contains(t, store.auditRecords[0].Details, `"request_id":"req-1"`)
	assert.NotContains(t, store.auditRecords[0].Details, issued.Token, "bearer token must not be written to audit")

	get := func(token string) *httptest.ResponseRecorder {
		out := httptest.NewRecorder()
		target := "/api/organizations/org-1/requests/req-1"
		if token != "" {
			target += "?payload_grant=" + token
		}
		wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(
			out, rootPayloadRequest(http.MethodGet, target, ""))
		return out
	}
	denied := get("")
	assert.Equal(t, http.StatusOK, denied.Code)
	assert.NotContains(t, denied.Body.String(), "choices", "root without a self-grant must not see foreign payload")
	allowed := get(issued.Token)
	assert.Equal(t, http.StatusOK, allowed.Code)
	assert.Contains(t, allowed.Body.String(), "choices", "an explicit scoped grant allows its request payload")
	again := get(issued.Token)
	assert.NotContains(t, again.Body.String(), "choices", "a grant can be redeemed only once")
}

func TestRootPayloadSelfGrantRequiresDurableAudit(t *testing.T) {
	store := newMockStore()
	store.insertAuditErr = fmt.Errorf("journal unavailable")
	h := newTestAdminH(store)
	url := "/api/root/payload-grants"
	w := httptest.NewRecorder()
	h.apiRootRequestPayloadGrant()(w, rootPayloadRequest(http.MethodPost, url, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	mockPayloadGrantMu.Lock()
	var token string
	for id := range mockPayloadGrants[store] {
		token = id
	}
	mockPayloadGrantMu.Unlock()
	assert.Empty(t, token, "failed durable audit must revoke the pending grant")
}

func TestRootPayloadGrantListAndRevoke(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	url := "/api/root/payload-grants"
	issue := httptest.NewRecorder()
	h.apiRootRequestPayloadGrant()(issue, rootPayloadRequest(http.MethodPost, url, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`))
	require.Equal(t, http.StatusCreated, issue.Code)
	var issued struct {
		Token string `json:"payload_grant"`
	}
	require.NoError(t, json.Unmarshal(issue.Body.Bytes(), &issued))

	listed := httptest.NewRecorder()
	h.apiRootRequestPayloadGrant()(listed, rootPayloadRequest(http.MethodPost, url, `{"action":"list"}`))
	require.Equal(t, http.StatusOK, listed.Code)
	assert.Contains(t, listed.Body.String(), "grant-a")
	assert.NotContains(t, listed.Body.String(), issued.Token)

	revoked := httptest.NewRecorder()
	h.apiRootRequestPayloadGrant()(revoked, rootPayloadRequest(http.MethodPost, url, `{"action":"revoke","payload_grant":"`+issued.Token+`"}`))
	assert.Equal(t, http.StatusNoContent, revoked.Code)
	assert.False(t, store.ConsumeRequestPayloadGrant(issued.Token, "org-1", "req-1", "admin-root", time.Now().UTC()))
}

func TestAgentKeyDoesNotInheritHumanHistory(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "human-owner")
	ctx = adminstore.WithRequestPayloadSubject(ctx, adminstore.RequestPayloadSubject{
		Type: adminstore.RequestPayloadAgent, AgentID: "agent-1", APIKeyID: "key-1",
	})
	req := httptest.NewRequestWithContext(ctx, http.MethodGet,
		"/api/organizations/org-1/requests?q=owner-secret", nil)
	w := httptest.NewRecorder()
	h.apiOrgRequests()(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, store.lastRequestFilters.PayloadUserID, "agent/CI principal must not be treated as its human key issuer")
	assert.True(t, store.lastRequestFilters.PayloadDenied)
	assert.False(t, store.lastRequestFilters.PayloadSearchAllowed)
}

func TestDenyOwnHistoryOverridesGrantAtDetailBoundary(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "subject-a")
	ctx = adminstore.WithRequestPayloadDenyOwnHistory(ctx, true)
	ctx = adminstore.WithRequestPayloadSubject(ctx, adminstore.RequestPayloadSubject{Type: adminstore.RequestPayloadHuman})
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/organizations/org-1/requests/req-1", nil)
	w := httptest.NewRecorder()
	wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	assert.NotContains(t, w.Body.String(), "choices", "explicit deny hides the human's own resource")
}
