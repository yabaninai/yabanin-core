package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/require"
)

type exportRetentionStore struct {
	*mockStore
	enabled bool
	access  adminstore.RequestPayloadAccess
	// retentionErr simulates a database failure in the retention lookup.
	retentionErr error
	// consumeErr simulates a database failure in the grant consume path.
	consumeErr error
}

func (m *mockStore) StreamRequestExport(ctx context.Context, filters adminstore.RequestListFilters, access adminstore.RequestPayloadAccess, maxRows int, emit func(*adminstore.RequestDetail) error) (int, error) {
	filters.Page, filters.PageSize = 1, maxRows
	rows, total, err := m.ListRequests(ctx, filters)
	if err != nil || total > maxRows {
		return total, err
	}
	for _, row := range rows {
		detailCtx := adminstore.WithRequestPayloadAccess(ctx, access)
		detail, err := m.GetRequestDetail(detailCtx, filters.OrgID, row.RequestID)
		if err != nil {
			if adminstore.IsNotFound(err) {
				continue
			}
			return total, err
		}
		if err := emit(detail); err != nil {
			return total, err
		}
	}
	return total, nil
}

func (m *mockStore) SearchRequestArchive(ctx context.Context, filters adminstore.RequestListFilters) ([]adminstore.RequestListRow, int, error) {
	return m.ListRequests(ctx, filters)
}

var _ requestPayloadGrantStore = (*exportRetentionStore)(nil)

func (s *exportRetentionStore) GetOrgOriginalRetention(_ context.Context, orgID string) (*adminstore.OrgOriginalRetention, error) {
	if s.retentionErr != nil {
		return nil, s.retentionErr
	}
	return &adminstore.OrgOriginalRetention{OrgID: orgID, Effective: s.enabled}, nil
}

func (s *exportRetentionStore) UpdateOrgOriginalRetention(context.Context, string, *bool) error {
	return nil
}

func (s *exportRetentionStore) GetRequestDetail(ctx context.Context, orgID, requestID string) (*adminstore.RequestDetail, error) {
	s.access, _ = adminstore.RequestPayloadAccessFromContext(ctx)
	return s.mockStore.GetRequestDetail(ctx, orgID, requestID)
}

func (s *exportRetentionStore) ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope string, now time.Time) error {
	if s.consumeErr != nil {
		return s.consumeErr
	}
	return s.mockStore.ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope, now)
}

func TestRequestExportAppliesPayloadMatrix(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ctx      context.Context
		wantArgs bool
	}{
		{name: "metadata only", ctx: WithOrgRole(rootRequest("GET", "/", "").Context(), "org-1", adminstore.RoleReader)},
		{name: "own payload", ctx: context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "subject-a"), wantArgs: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMockStore()
			h := newTestAdminH(store)
			req := httptest.NewRequestWithContext(tc.ctx, http.MethodGet, "/api/organizations/org-1/requests/export", nil)
			rec := httptest.NewRecorder()
			wrapWithParams(h.apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Equal(t, "application/x-ndjson", rec.Header().Get("Content-Type"))
			require.Equal(t, 1, strings.Count(strings.TrimSpace(rec.Body.String()), "\n")+1)
			if tc.wantArgs {
				require.Contains(t, rec.Body.String(), `"arguments":"{\"cmd\":\"git status\"}"`)
				require.NotContains(t, rec.Body.String(), `"upstream_request"`, "own-history access is not an originals grant")
			} else {
				require.NotContains(t, rec.Body.String(), `"arguments"`)
				require.NotContains(t, rec.Body.String(), `"response"`)
			}
		})
	}
}

func TestArchiveSearchUsesSharedScopeAndLabelsHotSource(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	ctx := WithOrgRole(rootRequest("GET", "/", "").Context(), "org-1", adminstore.RoleReader)
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/organizations/org-1/requests/archive-search?q=secret", nil)
	rec := httptest.NewRecorder()
	wrapWithParams(h.apiOrgArchiveSearch(), "/api/organizations/{id}/requests/archive-search")(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"source":"hot"`)
	require.NotContains(t, rec.Body.String(), "git status")
	require.False(t, store.lastRequestFilters.PayloadSearchAllowed)
	require.True(t, store.lastRequestFilters.PayloadAuthorizationSet)
}

func TestRequestExportGrantIncludesPayloadAndIsOneUse(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store)
	issued := httptest.NewRecorder()
	h.apiRootRequestPayloadGrant()(issued, rootPayloadRequest(http.MethodPost, "/api/root/payload-grants", `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read"}`))
	require.Equal(t, http.StatusCreated, issued.Code, issued.Body.String())
	var grant struct {
		Token string `json:"payload_grant"`
	}
	require.NoError(t, json.Unmarshal(issued.Body.Bytes(), &grant))

	get := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		url := "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant=" + grant.Token
		wrapWithParams(h.apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(rec, rootPayloadRequest(http.MethodGet, url, ""))
		return rec
	}
	first := get()
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.Contains(t, first.Body.String(), `"arguments"`)
	second := get()
	require.Equal(t, http.StatusForbidden, second.Code, second.Body.String())
}

func TestOriginalPayloadGrantRequiresRetention(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			store := &exportRetentionStore{mockStore: newMockStore(), enabled: enabled}
			h := New(store, "", "", nil)
			t.Cleanup(h.Stop)
			_, supportsGrant := h.store.(requestPayloadGrantStore)
			require.True(t, supportsGrant)
			issued := httptest.NewRecorder()
			h.apiRootRequestPayloadGrant()(issued, rootPayloadRequest(http.MethodPost, "/api/root/payload-grants", `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read_originals"}`))
			require.Equal(t, http.StatusCreated, issued.Code, issued.Body.String())
			var grant struct {
				Token string `json:"payload_grant"`
			}
			require.NoError(t, json.Unmarshal(issued.Body.Bytes(), &grant))
			mockPayloadGrantMu.Lock()
			storedGrant := mockPayloadGrants[store.mockStore][grant.Token]
			mockPayloadGrantMu.Unlock()
			require.Equal(t, adminstore.RequestPayloadScopeOriginals, storedGrant.Scope)
			require.Equal(t, "admin-root", storedGrant.RootID)
			probe := rootPayloadRequest(http.MethodGet, "/api/organizations/org-1/requests/req-1", "")
			require.True(t, h.authorizeRequestContent(probe, "org-1", "req-1", true, false).Allowed)
			url := "/api/organizations/org-1/requests/req-1?payload_grant=" + grant.Token + "&scope=payload.read_originals"
			rec := httptest.NewRecorder()
			req := rootPayloadRequest(http.MethodGet, url, "")
			require.True(t, isRoot(req))
			require.Equal(t, grant.Token, requestPayloadGrantToken(req))
			wrapWithParams(h.apiOrgRequestDetail(), "/api/organizations/{id}/requests/{request_id}")(rec, req)
			if !enabled {
				// FIX-08 detail symmetry: retention gating for the originals
				// scope happens BEFORE the consume and fails loudly — the
				// same contract as the export endpoint.
				require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
				require.Contains(t, rec.Body.String(), "original payload retention is disabled")
				require.NotContains(t, rec.Body.String(), "choices")
				require.True(t, grantAlive(store.mockStore, grant.Token),
					"a retention denial must not consume the grant")
				return
			}
			require.Equal(t, http.StatusOK, rec.Code)
			require.True(t, store.access.Grant, "original scope with effective retention must carry the verified grant into the store: access=%+v", store.access)
			require.True(t, store.access.Originals)
			require.Contains(t, rec.Body.String(), "choices")
			require.Contains(t, rec.Body.String(), `"upstream_request":{"messages":[{"content":"source"}]}`)
		})
	}
}

func TestRequestPayloadGrantScopeRejectsUnknownScope(t *testing.T) {
	_, err := (&adminstore.Store{}).CreateRequestPayloadGrantScope("org", "req", "root", "payload.everything", time.Minute, time.Now())
	require.ErrorIs(t, err, adminstore.ErrInvalidRequestPayloadGrant)
}

// issueExportGrant issues a root payload grant through the audited API and
// returns its bearer token.
func issueExportGrant(t *testing.T, h *AdminHandlers, body string) string {
	t.Helper()
	issued := httptest.NewRecorder()
	h.apiRootRequestPayloadGrant()(issued, rootPayloadRequest(http.MethodPost, "/api/root/payload-grants", body))
	require.Equal(t, http.StatusCreated, issued.Code, issued.Body.String())
	var grant struct {
		Token string `json:"payload_grant"`
	}
	require.NoError(t, json.Unmarshal(issued.Body.Bytes(), &grant))
	require.NotEmpty(t, grant.Token)
	return grant.Token
}

// runRootExport invokes the export handler as root with a concrete query.
func runRootExport(h *AdminHandlers, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	wrapWithParams(h.apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(
		rec, rootPayloadRequest(http.MethodGet, target, ""))
	return rec
}

func grantAlive(store *mockStore, token string) bool {
	mockPayloadGrantMu.Lock()
	defer mockPayloadGrantMu.Unlock()
	_, ok := mockPayloadGrants[store][token]
	return ok
}

// NEGATIVE: an agent/CI subject can never export, and a denied redemption must
// not burn the root's one-time token (N04-P05: history is closed to agents/CI
// by default; a bearer grant is a root self-grant, never a delegation).
func TestRequestExportDeniedForAgentSubjectAndGrantNotConsumed(t *testing.T) {
	store := newMockStore()
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	ctx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "human-owner")
	ctx = adminstore.WithRequestPayloadSubject(ctx, adminstore.RequestPayloadSubject{
		Type: adminstore.RequestPayloadAgent, AgentID: "agent-1", APIKeyID: "key-1",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet,
		"/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token, nil)
	wrapWithParams(h.apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "arguments")
	require.True(t, grantAlive(store, token), "a denied export must not consume the grant")
}

// NEGATIVE: expired, revoked, and foreign (cross-request / cross-org) grants
// are unusable, and none of the failed redemptions destroys the token —
// cross-tenant isolation without a consume side channel.
func TestRequestExportRejectsExpiredRevokedAndForeignGrants(t *testing.T) {
	store := newMockStore()
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	t.Run("expired", func(t *testing.T) {
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)
		mockPayloadGrantMu.Lock()
		g := mockPayloadGrants[store][token]
		g.ExpiresAt = time.Now().UTC().Add(-time.Second)
		mockPayloadGrants[store][token] = g
		mockPayloadGrantMu.Unlock()
		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), "arguments")
	})

	t.Run("revoked", func(t *testing.T) {
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)
		require.NoError(t, store.RevokeRequestPayloadGrant(token, "admin-root"))
		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), "arguments")
	})

	t.Run("cross-request", func(t *testing.T) {
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)
		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-2&payload_grant="+token)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.True(t, grantAlive(store, token), "cross-request redemption must not consume the grant")
	})

	t.Run("cross-org", func(t *testing.T) {
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)
		rec := runRootExport(h, "/api/organizations/org-2/requests/export?request_id=req-1&payload_grant="+token)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.True(t, grantAlive(store, token), "cross-org redemption must not consume the grant")
		require.NotContains(t, rec.Body.String(), "arguments", "a foreign org must never see payload content")
	})
}

// NEGATIVE: payload.read never unlocks retained originals even when original
// retention is effective — originals are a distinct capability.
func TestRequestExportReadScopeDoesNotUnlockOriginals(t *testing.T) {
	store := &exportRetentionStore{mockStore: newMockStore(), enabled: true}
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	read := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read"}`)
	rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+read)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"arguments"`, "payload.read unlocks processed payload")
	require.NotContains(t, rec.Body.String(), "upstream_request", "payload.read must not unlock originals")
	require.NotContains(t, rec.Body.String(), `"content":"source"`)

	originals := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read_originals"}`)
	rec = runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+originals+"&scope=payload.read_originals")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"upstream_request":{"messages":[{"content":"source"}]}`)
}

// NEGATIVE: every database failure fails closed — grant-store unavailability
// and list errors never open payload content, and a retention lookup error
// denies originals while leaving the grant redeemable.
func TestRequestExportFailsClosedOnStoreErrors(t *testing.T) {
	t.Run("grant store unavailable", func(t *testing.T) {
		store := &exportRetentionStore{mockStore: newMockStore(), consumeErr: adminstore.ErrRequestPayloadGrantUnavailable}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)
		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), "arguments")
	})

	t.Run("list store error", func(t *testing.T) {
		store := newMockStore()
		store.err = fmt.Errorf("database unavailable")
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		rec := runRootExport(h, "/api/organizations/org-1/requests/export")
		require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), "application/x-ndjson", "no stream may start on a store error")
	})

	t.Run("retention lookup error", func(t *testing.T) {
		store := &exportRetentionStore{mockStore: newMockStore(), enabled: true, retentionErr: fmt.Errorf("retention read failed")}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1","scope":"payload.read_originals"}`)
		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token+"&scope=payload.read_originals")
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		require.True(t, grantAlive(store.mockStore, token), "fail-closed retention must not consume the grant")
	})

	t.Run("archive search store error", func(t *testing.T) {
		store := newMockStore()
		store.err = fmt.Errorf("database unavailable")
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		rec := httptest.NewRecorder()
		wrapWithParams(h.apiOrgArchiveSearch(), "/api/organizations/{id}/requests/archive-search")(
			rec, rootPayloadRequest(http.MethodGet, "/api/organizations/org-1/requests/archive-search?q=secret", ""))
		require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), "git status", "a store error must never return rows")
	})
}

// Every export decision is journalled through the durable audit seam; details
// carry identifiers and flags only — never payload content or the token.
func TestRequestExportDecisionsAreAudited(t *testing.T) {
	store := newMockStore()
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)
	token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

	rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	agentCtx := context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "human-owner")
	agentCtx = adminstore.WithRequestPayloadSubject(agentCtx, adminstore.RequestPayloadSubject{
		Type: adminstore.RequestPayloadAgent, AgentID: "agent-1", APIKeyID: "key-1",
	})
	denied := httptest.NewRecorder()
	deniedReq := httptest.NewRequestWithContext(agentCtx, http.MethodGet,
		"/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token, nil)
	wrapWithParams(h.apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(denied, deniedReq)
	require.Equal(t, http.StatusForbidden, denied.Code)

	mockPayloadGrantMu.Lock()
	defer mockPayloadGrantMu.Unlock()
	var allowedRec, deniedRec *adminstore.AuditLogEntryRecord
	for i := range store.auditRecords {
		r := store.auditRecords[i]
		switch r.Action {
		case "request_export":
			allowedRec = &store.auditRecords[i]
		case "request_export.denied":
			deniedRec = &store.auditRecords[i]
		}
	}
	require.NotNil(t, allowedRec, "an allowed export must be journalled")
	require.Contains(t, allowedRec.Details, `"payload":true`)
	require.Contains(t, allowedRec.Details, `"outcome":"completed"`)
	require.NotNil(t, deniedRec, "a denied export must be journalled")
	require.Contains(t, deniedRec.Details, `"outcome":"authorization_denied"`)
	for _, r := range []*adminstore.AuditLogEntryRecord{allowedRec, deniedRec} {
		require.NotContains(t, r.Details, token, "bearer grant token must never reach the journal")
		require.NotContains(t, r.Details, "git status", "payload content must never reach the journal")
	}
}

// REGRESSION (n04rights2 review): request_id is query-controlled, and the old
// fmt.Sprintf("%q", …) journal escaped control characters as \x1b-style
// sequences (and mangled invalid UTF-8), which strict JSON parsers reject —
// one hostile request_id corrupted the whole journal payload. The stored
// detail must be valid JSON for any raw request_id bytes.
func TestRequestExportAuditDetailIsValidJSONForHostileRequestID(t *testing.T) {
	store := newMockStore()
	h := New(store, "", "", nil)
	t.Cleanup(h.Stop)

	// Control characters (\x01, \x1b) and an invalid UTF-8 byte (\xFF) in the
	// query-controlled request_id.
	rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req%01%1b%FF")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	mockPayloadGrantMu.Lock()
	defer mockPayloadGrantMu.Unlock()
	require.NotEmpty(t, store.auditRecords, "the export decision must be journalled")
	journalled := false
	for _, r := range store.auditRecords {
		if r.Action != "request_export" {
			continue
		}
		journalled = true
		require.True(t, json.Valid([]byte(r.Details)),
			"journal details must be valid JSON for a hostile request_id, got %q", r.Details)
		require.Contains(t, r.Details, `"request_id":"req`)
	}
	require.True(t, journalled, "the allowed export decision must be journalled")
}
