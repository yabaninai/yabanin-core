package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memViews struct {
	mu    sync.Mutex
	views []adminstore.AnalyticsView
	next  int
	fail  string
}

func (m *memViews) failed(op string) error {
	if m.fail == op {
		return errors.New(op + " failed")
	}
	return nil
}

func (m *memViews) ListAnalyticsViews(_ context.Context, orgID, ownerID string) ([]adminstore.AnalyticsView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failed("list"); err != nil {
		return nil, err
	}
	var out []adminstore.AnalyticsView
	for _, view := range m.views {
		if view.OrgID == orgID && (view.OwnerID == ownerID || view.Shared) {
			out = append(out, view)
		}
	}
	if out == nil {
		out = []adminstore.AnalyticsView{}
	}
	return out, nil
}

func (m *memViews) CountAnalyticsViews(_ context.Context, orgID, ownerID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failed("count"); err != nil {
		return 0, err
	}
	n := 0
	for _, view := range m.views {
		if view.OrgID == orgID && view.OwnerID == ownerID {
			n++
		}
	}
	return n, nil
}

func (m *memViews) CreateAnalyticsView(_ context.Context, view adminstore.AnalyticsView) (adminstore.AnalyticsView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failed("create"); err != nil {
		return adminstore.AnalyticsView{}, err
	}
	m.next++
	view.ID = "view-" + strings.TrimSpace(strings.ReplaceAll(time.Now().Format("150405"), "", "")+string(rune('a'+m.next%26)))
	if view.ID == "" {
		view.ID = "view"
	}
	view.ID = "view-" + itoa(m.next)
	view.CreatedAt = time.Now().UTC()
	view.UpdatedAt = view.CreatedAt
	m.views = append(m.views, view)
	return view, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func (m *memViews) GetAnalyticsView(_ context.Context, id string) (adminstore.AnalyticsView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, view := range m.views {
		if view.ID == id {
			return view, nil
		}
	}
	return adminstore.AnalyticsView{}, adminstore.ErrNotFound
}

func (m *memViews) UpdateAnalyticsView(_ context.Context, view adminstore.AnalyticsView) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failed("update"); err != nil {
		return err
	}
	for i := range m.views {
		if m.views[i].ID == view.ID {
			m.views[i].Name = view.Name
			m.views[i].Query = view.Query
			m.views[i].Shared = view.Shared
			return nil
		}
	}
	return adminstore.ErrNotFound
}

func (m *memViews) DeleteAnalyticsView(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failed("delete"); err != nil {
		return err
	}
	for i := range m.views {
		if m.views[i].ID == id {
			m.views = append(m.views[:i], m.views[i+1:]...)
			return nil
		}
	}
	return adminstore.ErrNotFound
}

func TestAnalyticsViews_PermissionsCSRFNormalizeLimit(t *testing.T) {
	const secret = "test-secret-32-bytes-long-here!!" // #nosec G101 -- test-only HMAC key
	ms := newMockStore()
	ms.orgMembers["admin-1/org-1"] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: "org-1", Role: adminstore.RoleReader}
	views := &memViews{}
	h := New(ms, secret, "", nil)
	h.SetAnalyticsViewStore(views)
	router := h.SetupRouter()
	query := `{"name":"cost","query":{"org_id":"org-1","from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"requests","group_by":"label:Issue"},"shared":true}`

	req := httptestNoCSRF(t, http.MethodPost, "/api/analytics/views?org_id=org-1", query, secret)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	code, body := labelCall(t, router, secret, false, http.MethodPost, "/api/analytics/views?org_id=org-1", query)
	require.Equal(t, http.StatusCreated, code, body)
	assert.Contains(t, body, `"group_by":"label:issue"`)
	require.Equal(t, 1, auditJournalDepth(h))
	assert.Equal(t, "analytics_view.create", lastAuditEntry(t, h).Action)

	code, body = labelCall(t, router, secret, false, http.MethodPost, "/api/analytics/views?org_id=org-1",
		`{"name":"bad","query":{"org_id":"org-1","from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"nope"}}`)
	assert.Equal(t, http.StatusBadRequest, code, body)
	assert.Contains(t, body, "invalid_metric")

	views.views = append(views.views, adminstore.AnalyticsView{
		ID: "foreign", OrgID: "org-1", OwnerID: "other", Name: "secret", Shared: false,
		Query: map[string]string{"org_id": "org-1"},
	})
	code, body = labelCall(t, router, secret, false, http.MethodDelete, "/api/analytics/views/foreign?org_id=org-1", "")
	assert.Equal(t, http.StatusNotFound, code, body)

	views.views = append(views.views, adminstore.AnalyticsView{
		ID: "shared-other", OrgID: "org-1", OwnerID: "other", Name: "team", Shared: true,
		Query: map[string]string{"org_id": "org-1", "from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z", "metrics": "requests"},
	})
	code, body = labelCall(t, router, secret, false, http.MethodPut, "/api/analytics/views/shared-other?org_id=org-1",
		`{"name":"taken","query":{"org_id":"org-1","from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"requests"},"shared":true}`)
	assert.Equal(t, http.StatusForbidden, code, body)

	ms.orgMembers["admin-1/org-1"].Role = adminstore.RoleOrgAdmin
	code, body = labelCall(t, router, secret, false, http.MethodDelete, "/api/analytics/views/shared-other?org_id=org-1", "")
	assert.Equal(t, http.StatusNoContent, code, body)

	views.views = nil
	for i := 0; i < analyticsViewLimit; i++ {
		views.views = append(views.views, adminstore.AnalyticsView{ID: itoa(i), OrgID: "org-1", OwnerID: "admin-1", Name: "n"})
	}
	code, body = labelCall(t, router, secret, false, http.MethodPost, "/api/analytics/views?org_id=org-1", query)
	assert.Equal(t, http.StatusConflict, code, body)
	assert.Contains(t, body, "view_limit")
}

func TestAnalyticsViews_ListOwnerAndRejects(t *testing.T) {
	const secret = "test-secret-32-bytes-long-here!!" // #nosec G101 -- test-only HMAC key
	ms := newMockStore()
	ms.orgMembers["admin-1/org-1"] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: "org-1", Role: adminstore.RoleReader}
	h := New(ms, secret, "", nil)
	router := h.SetupRouter()
	code, body := labelCall(t, router, secret, false, http.MethodGet, "/api/analytics/views?org_id=org-1", "")
	assert.Equal(t, http.StatusServiceUnavailable, code, body)

	views := &memViews{}
	h.SetAnalyticsViewStore(views)
	query := `{"name":"mine","query":{"org_id":"org-1","from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"requests"},"shared":false}`
	code, body = labelCall(t, router, secret, false, http.MethodPost, "/api/analytics/views?org_id=org-1", query)
	require.Equal(t, http.StatusCreated, code, body)
	assert.Empty(t, auditJournalDepth(h))

	code, body = labelCall(t, router, secret, false, http.MethodGet, "/api/analytics/views?org_id=org-1", "")
	require.Equal(t, http.StatusOK, code, body)
	assert.Contains(t, body, `"name":"mine"`)

	rec := httptest.NewRecorder()
	h.ListAnalyticsViews()(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/analytics/views", nil))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	code, body = labelCall(t, router, secret, false, http.MethodPost, "/api/analytics/views?org_id=org-1", `{"name":""}`)
	assert.Equal(t, http.StatusBadRequest, code, body)

	code, body = labelCall(t, router, secret, false, http.MethodPost, "/api/analytics/views?org_id=org-1", `{`)
	assert.Equal(t, http.StatusBadRequest, code, body)

	ms.orgMembers["admin-1/org-2"] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: "org-2", Role: adminstore.RoleReader}
	code, body = labelCall(t, router, secret, false, http.MethodPost, "/api/analytics/views?org_id=org-2",
		`{"name":"x","query":{"org_id":"org-1","from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"requests"}}`)
	assert.Equal(t, http.StatusBadRequest, code, body)

	code, body = labelCall(t, router, secret, false, http.MethodPut, "/api/analytics/views/view-1?org_id=org-1",
		`{"name":"renamed","query":{"from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"cost_usd"},"shared":false}`)
	require.Equal(t, http.StatusOK, code, body)
	assert.Contains(t, body, "renamed")

	code, body = labelCall(t, router, secret, false, http.MethodPut, "/api/analytics/views/view-1?org_id=org-1",
		`{"name":"other-org","query":{"org_id":"org-2","from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"requests"}}`)
	assert.Equal(t, http.StatusBadRequest, code, body)

	code, body = labelCall(t, router, secret, false, http.MethodPut, "/api/analytics/views/missing?org_id=org-1",
		`{"name":"nope","query":{"org_id":"org-1","from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"requests"}}`)
	assert.Equal(t, http.StatusNotFound, code, body)

	views.fail = "list"
	code, body = labelCall(t, router, secret, false, http.MethodGet, "/api/analytics/views?org_id=org-1", "")
	assert.Equal(t, http.StatusInternalServerError, code, body)
	views.fail = "count"
	code, _ = labelCall(t, router, secret, false, http.MethodPost, "/api/analytics/views?org_id=org-1", query)
	assert.Equal(t, http.StatusInternalServerError, code)
	views.fail = "create"
	code, _ = labelCall(t, router, secret, false, http.MethodPost, "/api/analytics/views?org_id=org-1", query)
	assert.Equal(t, http.StatusInternalServerError, code)
	views.fail = "update"
	code, _ = labelCall(t, router, secret, false, http.MethodPut, "/api/analytics/views/view-1?org_id=org-1", query)
	assert.Equal(t, http.StatusInternalServerError, code)
	views.fail = "delete"
	code, _ = labelCall(t, router, secret, false, http.MethodDelete, "/api/analytics/views/view-1?org_id=org-1", "")
	assert.Equal(t, http.StatusInternalServerError, code)
}

func httptestNoCSRF(t *testing.T, method, path, body, secret string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.AddCookie(makeSessionCookie(false, secret))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// orgIDs lists the org of every stored view (insertion order, locked).
func (m *memViews) orgIDs(t *testing.T) []string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.views))
	for _, view := range m.views {
		out = append(out, view.OrgID)
	}
	return out
}

// viewsRouterCall drives the full router as admin-1 with session+CSRF and an
// optional X-Yabanin-Org-Id header (labelCall cannot set headers).
func viewsRouterCall(t *testing.T, router http.Handler, secret, method, path, orgHeader, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.AddCookie(makeSessionCookie(false, secret))
	req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: "csrf-admin", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	req.Header.Set("X-CSRF-Token", "csrf-admin")
	req.Header.Set("Content-Type", "application/json")
	if orgHeader != "" {
		req.Header.Set(OrgHeader, orgHeader)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// viewsDirectReq invokes a handler without the router: the session context is
// injected by hand and the {id} route param is pre-populated.
func viewsDirectReq(t *testing.T, method, target, userID, body, viewID string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), adminauth.ContextKeyUserID{}, userID)
	if viewID != "" {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", viewID)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	}
	return req.WithContext(ctx)
}

// AT-22: the created view's org is bound to the request identity (the
// membership-checked ?org_id query or the org header) — the body never
// chooses it.
func TestAnalyticsViews_CreateOrgBoundToRequestIdentity(t *testing.T) {
	const secret = "test-secret-32-bytes-long-here!!" // #nosec G101 -- test-only HMAC key
	ms := newMockStore()
	ms.orgMembers["admin-1/org-1"] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: "org-1", Role: adminstore.RoleOrgAdmin}
	views := &memViews{}
	h := New(ms, secret, "", nil)
	h.SetAnalyticsViewStore(views)
	router := h.SetupRouter()

	valid := func(org string) string {
		return `{"name":"v","query":{"org_id":"` + org + `","from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"requests"},"shared":true}`
	}
	plain := `{"name":"hdr","query":{"from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"requests"},"shared":true}`

	// The bypass: empty ?org_id, identity header org-1, body org_id=org-2 —
	// rejected instead of creating a shared view in org-2 (no role there).
	code, body := viewsRouterCall(t, router, secret, http.MethodPost, "/api/analytics/views", "org-1", valid("org-2"))
	assert.Equal(t, http.StatusBadRequest, code, body)
	assert.Empty(t, views.orgIDs(t))

	// Explicit query org vs body org mismatch stays rejected.
	code, body = viewsRouterCall(t, router, secret, http.MethodPost, "/api/analytics/views?org_id=org-1", "org-1", valid("org-2"))
	assert.Equal(t, http.StatusBadRequest, code, body)
	assert.Empty(t, views.orgIDs(t))

	// Empty ?org_id + header org-1 → the view lands in the identity org.
	code, body = viewsRouterCall(t, router, secret, http.MethodPost, "/api/analytics/views", "org-1", plain)
	require.Equal(t, http.StatusCreated, code, body)
	assert.Equal(t, []string{"org-1"}, views.orgIDs(t))

	// A body org_id matching the identity org is accepted.
	code, body = viewsRouterCall(t, router, secret, http.MethodPost, "/api/analytics/views", "org-1", valid("org-1"))
	require.Equal(t, http.StatusCreated, code, body)
	assert.Equal(t, []string{"org-1", "org-1"}, views.orgIDs(t))

	// No identity target at all (no query, no header) → 400, no create.
	code, body = viewsRouterCall(t, router, secret, http.MethodPost, "/api/analytics/views", "", plain)
	assert.Equal(t, http.StatusBadRequest, code, body)
	assert.Len(t, views.orgIDs(t), 2)
}

// AT-22: edits stay inside the request identity org; a foreign shared view is
// 404 (not 403) for a non-member; root keeps the operator path.
func TestAnalyticsViews_EditOrgBindingNonMember404Root(t *testing.T) {
	const secret = "test-secret-32-bytes-long-here!!" // #nosec G101 -- test-only HMAC key
	ms := newMockStore()
	views := &memViews{}
	h := New(ms, secret, "", nil)
	h.SetAnalyticsViewStore(views)
	router := h.SetupRouter()

	put := `{"name":"renamed","query":{"org_id":"org-2","from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"requests"},"shared":true}`
	views.views = append(views.views, adminstore.AnalyticsView{
		ID: "shared-org2", OrgID: "org-2", OwnerID: "owner-2", Name: "team", Shared: true,
		Query: map[string]string{"org_id": "org-2", "from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z", "metrics": "requests"},
	})

	// Root edits a foreign-org shared view without naming an org (operator).
	code, body := labelCall(t, router, secret, true, http.MethodPut, "/api/analytics/views/shared-org2", put)
	require.Equal(t, http.StatusOK, code, body)

	// Root create still names the target org via query.
	code, body = labelCall(t, router, secret, true, http.MethodPost, "/api/analytics/views?org_id=org-2",
		`{"name":"rootv","query":{"org_id":"org-2","from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"requests"}}`)
	require.Equal(t, http.StatusCreated, code, body)
	assert.Contains(t, body, `"org_id":"org-2"`)

	// A non-member of org-2 gets 404 on the foreign shared view — not 403 —
	// so its existence stays hidden. Direct handler call: through the router
	// RequireOrgPermission 403s the same caller earlier at the org-target
	// check; this pins the handler-side branch.
	req := viewsDirectReq(t, http.MethodPut, "/api/analytics/views/shared-org2?org_id=org-2", "admin-2", put, "shared-org2")
	rec := httptest.NewRecorder()
	h.UpdateAnalyticsView()(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	req = viewsDirectReq(t, http.MethodDelete, "/api/analytics/views/shared-org2?org_id=org-2", "admin-2", "", "shared-org2")
	rec = httptest.NewRecorder()
	h.DeleteAnalyticsView()(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	// Ownership does not cross the org boundary either: admin-1 (org-admin of
	// org-1 only) owns a view that lives in org-2 — editing it under an org-1
	// scope is 404.
	ms.orgMembers["admin-1/org-1"] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: "org-1", Role: adminstore.RoleOrgAdmin}
	views.views = append(views.views, adminstore.AnalyticsView{
		ID: "mine-elsewhere", OrgID: "org-2", OwnerID: "admin-1", Name: "m", Shared: false,
		Query: map[string]string{"org_id": "org-2"},
	})
	code, body = labelCall(t, router, secret, false, http.MethodPut, "/api/analytics/views/mine-elsewhere?org_id=org-1",
		`{"name":"nope","query":{"from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z","metrics":"requests"}}`)
	assert.Equal(t, http.StatusNotFound, code, body)
}
