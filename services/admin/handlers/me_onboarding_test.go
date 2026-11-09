package handlers_test

// W-WELCOME: per-org onboarding progress — GET/POST /api/me/onboarding.
//
// Locked contract:
//   - the org gate is RequireOrgRole(reader+): a member acts on their own
//     org, a foreign org 403s (no information leak), root bypasses;
//   - GET answers {org_id, completed, skipped}; a MISSING row is the zero
//     state (a fresh org has not onboarded — never a 404);
//   - POST advances exactly one flag (completed | skipped); both/neither is
//     a 400 and must not reach the store;
//   - a store without the capability answers 501 (the dashboard degrades to
//     an unpersisted flow) and GET 400s without org_id;
//   - every successful mark is audit-logged.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const onbSecret = "onboarding-test-session-secret" // #nosec G101 -- test-only HMAC key

type onbMark struct {
	OrgID     string
	Completed bool
	Skipped   bool
}

// onbStore serves the /api/me surfaces (identity + membership) plus the
// W-WELCOME capability. states maps org → flag row; a missing entry is the
// zero state. Audit assertions go through GET /api/audit-logs (the legacy
// in-buffer journal path this store exercises), not a store spy: recordAudit
// never calls store.InsertAuditLog directly (AF-10 journal/buffer path).
type onbStore struct {
	*meStore
	states map[string]adminstore.OrgOnboarding
	marks  []onbMark
}

func newOnbStore() *onbStore {
	return &onbStore{
		meStore: newMeStore(),
		states:  map[string]adminstore.OrgOnboarding{},
	}
}

func (s *onbStore) GetOrgOnboarding(_ context.Context, orgID string) (*adminstore.OrgOnboarding, error) {
	if state, ok := s.states[orgID]; ok {
		return &state, nil
	}
	return &adminstore.OrgOnboarding{OrgID: orgID}, nil
}

func (s *onbStore) UpsertOrgOnboarding(_ context.Context, orgID string, completed, skipped bool) error {
	if orgID == "org-gone" {
		return adminstore.ErrNotFound // simulated unknown-org FK violation
	}
	s.marks = append(s.marks, onbMark{OrgID: orgID, Completed: completed, Skipped: skipped})
	prev := s.states[orgID]
	s.states[orgID] = adminstore.OrgOnboarding{
		OrgID:     orgID,
		Completed: prev.Completed || completed,
		Skipped:   prev.Skipped || skipped,
	}
	return nil
}

// onbAuditEntries reads the legacy in-buffer journal the way the audit-log
// screen does (GET /api/audit-logs, root-only).
func onbAuditEntries(t *testing.T, router http.Handler, cookie string) []auditEntryJSON {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/audit-logs?page=1&page_size=50", nil)
	req.AddCookie(testCookie("yabanin_admin_session", cookie))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var payload struct {
		AuditLogs []auditEntryJSON `json:"audit_logs"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &payload))
	return payload.AuditLogs
}

type auditEntryJSON struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Details  string `json:"details"`
}

// onbRouter builds the full router with a root admin ("root@x.test") and a
// plain member holding reader on org-a only.
func onbRouter(t *testing.T, store *onbStore) http.Handler {
	t.Helper()
	store.admins["test-root"] = &adminstore.AdminUser{ID: "test-root", Email: "root@x.test", DisplayName: "Root", IsRoot: true, Active: true}
	store.admins["test-admin"] = &adminstore.AdminUser{ID: "test-admin", Email: "member@x.test", DisplayName: "Member", Active: true}
	store.userRoles["test-admin"] = map[string]adminstore.OrgRole{"org-a": adminstore.RoleReader}
	return handlers.New(store, onbSecret, "localhost", nil).SetupRouter()
}

func onbGet(t *testing.T, router http.Handler, cookie, org string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/me/onboarding?org_id="+org, nil)
	if cookie != "" {
		req.AddCookie(testCookie("yabanin_admin_session", cookie))
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func onbPost(t *testing.T, router http.Handler, cookie, org, body string) (int, string) {
	t.Helper()
	// The org target rides the query string: the route middleware resolves it
	// (targetOrgID) before the handler ever decodes the body.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/me/onboarding?org_id="+org, strings.NewReader(body))
	if cookie != "" {
		req.AddCookie(testCookie("yabanin_admin_session", cookie))
		req.AddCookie(testCookie("yabanin_csrf_token", keyHashCSRF))
		req.Header.Set("X-CSRF-Token", keyHashCSRF)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

type onbStateJSON struct {
	OrgID     string `json:"org_id"`
	Completed bool   `json:"completed"`
	Skipped   bool   `json:"skipped"`
}

func rootCookie(t *testing.T) string {
	t.Helper()
	return makeSessionCookie(t, "root@x.test", true, onbSecret)
}

func memberCookie(t *testing.T) string {
	t.Helper()
	return makeSessionCookie(t, "member@x.test", false, onbSecret)
}

func TestMyOnboarding_GetZeroStateForFreshOrg(t *testing.T) {
	router := onbRouter(t, newOnbStore())

	code, body := onbGet(t, router, rootCookie(t), "org-a")
	require.Equal(t, http.StatusOK, code, body)
	var state onbStateJSON
	require.NoError(t, json.Unmarshal([]byte(body), &state))
	assert.Equal(t, "org-a", state.OrgID)
	assert.False(t, state.Completed, "a missing row must read as the zero state, not an error")
	assert.False(t, state.Skipped)
}

func TestMyOnboarding_GetPersistsState(t *testing.T) {
	store := newOnbStore()
	store.states["org-a"] = adminstore.OrgOnboarding{OrgID: "org-a", Skipped: true}
	router := onbRouter(t, store)

	code, body := onbGet(t, router, rootCookie(t), "org-a")
	require.Equal(t, http.StatusOK, code, body)
	var state onbStateJSON
	require.NoError(t, json.Unmarshal([]byte(body), &state))
	assert.True(t, state.Skipped)
	assert.False(t, state.Completed)
}

func TestMyOnboarding_MemberReadsOwnOrg_RootBypasses(t *testing.T) {
	store := newOnbStore()
	router := onbRouter(t, store)

	code, _ := onbGet(t, router, memberCookie(t), "org-a")
	assert.Equal(t, http.StatusOK, code, "a reader must read their org's flow state")

	code, _ = onbGet(t, router, rootCookie(t), "org-a")
	assert.Equal(t, http.StatusOK, code, "root bypasses the membership gate")
}

func TestMyOnboarding_ForeignOrgForbidden(t *testing.T) {
	store := newOnbStore()
	// The store could answer org-b, but the member holds no membership on it.
	store.states["org-b"] = adminstore.OrgOnboarding{OrgID: "org-b", Completed: true}
	router := onbRouter(t, store)

	code, body := onbGet(t, router, memberCookie(t), "org-b")
	assert.Equal(t, http.StatusForbidden, code, body)

	code, body = onbPost(t, router, memberCookie(t), "org-b", `{"completed":true}`)
	assert.Equal(t, http.StatusForbidden, code, body)
	assert.Empty(t, store.marks, "a 403 must never reach the store")
}

func TestMyOnboarding_Unauthenticated(t *testing.T) {
	router := onbRouter(t, newOnbStore())

	code, _ := onbGet(t, router, "", "org-a")
	assert.Equal(t, http.StatusUnauthorized, code)

	code, _ = onbPost(t, router, "", "org-a", `{"completed":true}`)
	assert.Equal(t, http.StatusUnauthorized, code)
}

func TestMyOnboarding_GetRequiresOrgID(t *testing.T) {
	router := onbRouter(t, newOnbStore())

	code, _ := onbGet(t, router, rootCookie(t), "")
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestMyOnboarding_MarkCompletedAndSkipped(t *testing.T) {
	store := newOnbStore()
	router := onbRouter(t, store)
	cookie := rootCookie(t)

	code, body := onbPost(t, router, cookie, "org-a", `{"completed":true}`)
	require.Equal(t, http.StatusOK, code, body)

	code, body = onbGet(t, router, cookie, "org-a")
	require.Equal(t, http.StatusOK, code, body)
	var state onbStateJSON
	require.NoError(t, json.Unmarshal([]byte(body), &state))
	assert.True(t, state.Completed)

	// A skip mark is the operator's dismissal: persisted and audit-logged
	// (read back through the audit-log screen's own endpoint).
	code, body = onbPost(t, router, cookie, "org-a", `{"skipped":true}`)
	require.Equal(t, http.StatusOK, code, body)
	require.Len(t, store.marks, 2)
	assert.True(t, store.marks[1].Skipped)
	assert.False(t, store.marks[1].Completed)

	entries := onbAuditEntries(t, router, cookie)
	var onb []auditEntryJSON
	for _, e := range entries {
		if e.Resource == "org_onboarding" {
			onb = append(onb, e)
		}
	}
	require.Len(t, onb, 2, "every mark must be audit-logged: %+v", entries)
	assert.Equal(t, "update", onb[0].Action)
	assert.Contains(t, onb[0].Details, "org=org-a")
	assert.Contains(t, onb[0].Details, "state=completed")
	assert.Contains(t, onb[1].Details, "state=skipped")
}

func TestMyOnboarding_MarkValidation(t *testing.T) {
	store := newOnbStore()
	router := onbRouter(t, store)
	cookie := rootCookie(t)

	for name, body := range map[string]string{
		"both flags":   `{"completed":true,"skipped":true}`,
		"neither flag": `{}`,
		"false flags":  `{"completed":false,"skipped":false}`,
		"broken json":  `{`,
	} {
		code, _ := onbPost(t, router, cookie, "org-a", body)
		assert.Equal(t, http.StatusBadRequest, code, name)
	}
	{
		code, _ := onbPost(t, router, cookie, "", `{"completed":true}`)
		assert.Equal(t, http.StatusBadRequest, code, "missing org target")
	}
	assert.Empty(t, store.marks, "invalid marks must never reach the store")
	entries := onbAuditEntries(t, router, cookie)
	for _, e := range entries {
		assert.NotEqual(t, "org_onboarding", e.Resource, "a rejected mark must not be audit-logged")
	}
}

func TestMyOnboarding_MarkUnknownOrgNotFound(t *testing.T) {
	store := newOnbStore()
	router := onbRouter(t, store)

	code, body := onbPost(t, router, rootCookie(t), "org-gone", `{"completed":true}`)
	assert.Equal(t, http.StatusNotFound, code, body)
}

func TestMyOnboarding_StoreWithoutCapability(t *testing.T) {
	// A store that does NOT implement the W-WELCOME capability (plain meStore)
	// keeps the endpoints at 501 — the dashboard degrades to an unpersisted
	// flow instead of failing.
	store := newMeStore()
	store.admins["test-root"] = &adminstore.AdminUser{ID: "test-root", Email: "root@x.test", DisplayName: "Root", IsRoot: true, Active: true}
	router := handlers.New(store, onbSecret, "localhost", nil).SetupRouter()
	cookie := rootCookie(t)

	code, body := onbGet(t, router, cookie, "org-a")
	assert.Equal(t, http.StatusNotImplemented, code, body)

	code, body = onbPost(t, router, cookie, "org-a", `{"completed":true}`)
	assert.Equal(t, http.StatusNotImplemented, code, body)
}
