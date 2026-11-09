package handlers_test

// NEXT-15: trust-boundary matrix rows for the ADMIN service that complete
// the S01 role×route matrix (authz_test.go) with the org A/B dimension and
// the routes that take a client-supplied org id.
//
// Findings surfaced here are registered as separate cards (per the card
// contract: found defects are NOT fixed in this card):
//
//   - FINDING NEXT-15-F1: the analytics group is session-only (any
//     authenticated admin, non-root included) and takes org_id as a plain
//     query parameter with no org-membership check (RequireOrgRole exists
//     since ENT-02 but is not wired to any route). A non-root admin can
//     read ANY org's analytics today. Characterized below — the assertion
//     documents the CURRENT behavior; the fix card flips it to 403.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// memberStubStore lets a non-root admin hold roles for the positive RBAC rows
// (everything else stays the errStub surface).
type memberStubStore struct {
	stubStore
	roles map[string]adminstore.OrgRole
}

func (s *memberStubStore) GetUserOrgRoles(context.Context, string) (map[string]adminstore.OrgRole, error) {
	return s.roles, nil
}

func TestNEXT15_AdminOrgTrustBoundary(t *testing.T) {
	const secret = "test-session-secret" // #nosec G101 -- test-only HMAC key
	const csrfToken = "csrf-token-value" // #nosec G101 -- test-only value
	h := handlers.New(&stubStore{}, secret, "localhost", nil)
	router := h.SetupRouter()

	do := func(t *testing.T, method, path, cookie string) int {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		if cookie != "" {
			req.AddCookie(testCookie("yabanin_admin_session", cookie))
			req.AddCookie(testCookie("yabanin_csrf_token", csrfToken))
			req.Header.Set("X-CSRF-Token", csrfToken)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	anon := ""
	adminCookie := makeSessionCookie(t, "admin@x.test", false, secret)
	rootCookie := makeSessionCookie(t, "root@x.test", true, secret)

	t.Run("anon cannot read analytics", func(t *testing.T) {
		if code := do(t, http.MethodGet, "/api/analytics/stats?org_id=org-a", anon); code != http.StatusUnauthorized {
			t.Errorf("analytics as anon = %d, want 401", code)
		}
	})

	t.Run("NEXT-15-F1 fixed: non-root admin gets 403 on an org with no role", func(t *testing.T) {
		// The stub store's GetUserOrgRoles errors → no membership → 403.
		code := do(t, http.MethodGet, "/api/analytics/stats?org_id=org-not-mine", adminCookie)
		if code != http.StatusForbidden {
			t.Errorf("analytics cross-org read as role-less non-root = %d, want 403", code)
		}
	})

	t.Run("NEXT-15-F1 fixed: non-root with a reader role reaches their org's analytics", func(t *testing.T) {
		member := &memberStubStore{roles: map[string]adminstore.OrgRole{"org-mine": adminstore.RoleReader}}
		mh := handlers.New(member, secret, "localhost", nil)
		mrouter := mh.SetupRouter()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
			"/api/analytics/stats?org_id=org-mine", nil)
		req.AddCookie(testCookie("yabanin_admin_session", adminCookie))
		req.AddCookie(testCookie("yabanin_csrf_token", csrfToken))
		req.Header.Set("X-CSRF-Token", csrfToken)
		w := httptest.NewRecorder()
		mrouter.ServeHTTP(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("analytics own-org read with reader role = %d, want 500 (stub handler ran)", w.Code)
		}
	})

	t.Run("NEXT-15-F1 fixed: non-root with reader role still 403 on another org", func(t *testing.T) {
		member := &memberStubStore{roles: map[string]adminstore.OrgRole{"org-mine": adminstore.RoleReader}}
		mh := handlers.New(member, secret, "localhost", nil)
		mrouter := mh.SetupRouter()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
			"/api/analytics/stats?org_id=org-other", nil)
		req.AddCookie(testCookie("yabanin_admin_session", adminCookie))
		req.AddCookie(testCookie("yabanin_csrf_token", csrfToken))
		req.Header.Set("X-CSRF-Token", csrfToken)
		w := httptest.NewRecorder()
		mrouter.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("analytics other-org read with reader role = %d, want 403", w.Code)
		}
	})

	t.Run("NEXT-15-F1 fixed: non-root without org target gets 400, not cross-org data", func(t *testing.T) {
		if code := do(t, http.MethodGet, "/api/analytics/stats", adminCookie); code != http.StatusBadRequest {
			t.Errorf("analytics without org_id as non-root = %d, want 400 (fail-closed)", code)
		}
	})

	t.Run("NEXT-15-F1 fixed: top-orgs aggregate is root-only", func(t *testing.T) {
		if code := do(t, http.MethodGet, "/api/analytics/top-orgs", adminCookie); code != http.StatusForbidden {
			t.Errorf("top-orgs as non-root = %d, want 403 (cross-org aggregate)", code)
		}
	})

	t.Run("root still reads any analytics (operator)", func(t *testing.T) {
		code := do(t, http.MethodGet, "/api/analytics/stats?org_id=org-a", rootCookie)
		if code != http.StatusInternalServerError {
			t.Errorf("analytics as root = %d, want 500 (stub handler ran)", code)
		}
	})

	t.Run("api-key creation is 403 for a non-root with no org role", func(t *testing.T) {
		// POST /api/api-keys is keys.manage, not MustBeRoot. This caller has
		// no membership, so RequireOrgPermission still rejects them.
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/api-keys",
			httptest.NewRecorder().Body)
		req.Body = http.NoBody
		req.AddCookie(testCookie("yabanin_admin_session", adminCookie))
		req.AddCookie(testCookie("yabanin_csrf_token", csrfToken))
		req.Header.Set("X-CSRF-Token", csrfToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Yabanin-Org-Id", "org-a")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST /api/api-keys as role-less non-root = %d, want 403", w.Code)
		}
	})

	t.Run("root reaches org CRUD regardless of scope header (operator)", func(t *testing.T) {
		// Root is the operator: body/query org ids are trusted by design.
		// Pinned so a future tightening does not silently change semantics.
		if code := do(t, http.MethodGet, "/api/organizations", rootCookie); code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Errorf("GET orgs as root = %d — must not be authz-rejected", code)
		}
	})
}

// multiOrgStatsStore returns distinct per-org sums so a test can prove which
// scope answered. The unscoped (nil-org) totals are the cross-org aggregate
// the dashboard must not hand to a non-root admin (TP-01).
type multiOrgStatsStore struct {
	stubStore
}

func (s *multiOrgStatsStore) GetRequestLogStats(_ context.Context, orgID *string, _ time.Time) (*adminstore.RequestLogStats, error) {
	switch {
	case orgID == nil:
		return &adminstore.RequestLogStats{TotalRequests: 300}, nil
	case *orgID == "org-a":
		return &adminstore.RequestLogStats{TotalRequests: 100}, nil
	case *orgID == "org-b":
		return &adminstore.RequestLogStats{TotalRequests: 200}, nil
	}
	return nil, errStub
}

func (s *multiOrgStatsStore) TopModels(_ context.Context, orgID *string, _ int) ([]adminstore.TopModelCount, error) {
	if orgID == nil {
		return []adminstore.TopModelCount{{ModelName: "aggregate-model", Count: 300}}, nil
	}
	return []adminstore.TopModelCount{{ModelName: "scoped-model-" + *orgID, Count: 1}}, nil
}

func (s *multiOrgStatsStore) TopOrgs(_ context.Context, _ int) ([]adminstore.TopOrgCount, error) {
	return []adminstore.TopOrgCount{{OrgID: "org-a", Count: 100}, {OrgID: "org-b", Count: 200}}, nil
}

// TP-01: the global dashboard aggregate at GET / is a cross-org view and must
// stay root-only; org-scoped analytics keep serving the member's own org.
func TestTP01_DashboardAggregateIsRootOnly(t *testing.T) {
	const secret = "test-session-secret" // #nosec G101 -- test-only HMAC key
	const csrfToken = "csrf-token-value" // #nosec G101 -- test-only value
	h := handlers.New(&multiOrgStatsStore{}, secret, "localhost", nil)
	router := h.SetupRouter()

	do := func(t *testing.T, method, path, cookie string) (*httptest.ResponseRecorder, int) {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		if cookie != "" {
			req.AddCookie(testCookie("yabanin_admin_session", cookie))
			req.AddCookie(testCookie("yabanin_csrf_token", csrfToken))
			req.Header.Set("X-CSRF-Token", csrfToken)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w, w.Code
	}

	adminCookie := makeSessionCookie(t, "admin@x.test", false, secret)
	rootCookie := makeSessionCookie(t, "root@x.test", true, secret)

	t.Run("non-root admin gets no cross-org aggregate at GET /", func(t *testing.T) {
		w, code := do(t, http.MethodGet, "/", adminCookie)
		if code != http.StatusForbidden {
			t.Errorf("GET / as non-root admin = %d, want 403", code)
		}
		if strings.Contains(w.Body.String(), `"total_requests":300`) || strings.Contains(w.Body.String(), "aggregate-model") {
			t.Errorf("GET / as non-root admin leaked the cross-org aggregate: %s", w.Body.String())
		}
	})

	t.Run("root keeps the aggregate", func(t *testing.T) {
		w, code := do(t, http.MethodGet, "/", rootCookie)
		if code != http.StatusOK {
			t.Fatalf("GET / as root = %d, want 200", code)
		}
		var dash struct {
			TotalRequests int64 `json:"total_requests"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &dash); err != nil {
			t.Fatalf("decode dashboard: %v", err)
		}
		if dash.TotalRequests != 300 {
			t.Errorf("root dashboard total = %d, want 300 (org-a 100 + org-b 200)", dash.TotalRequests)
		}
	})

	t.Run("anon gets 401 at GET /", func(t *testing.T) {
		if _, code := do(t, http.MethodGet, "/", ""); code != http.StatusUnauthorized {
			t.Errorf("GET / as anon = %d, want 401", code)
		}
	})

	t.Run("org-scoped analytics still serve the member's own org", func(t *testing.T) {
		member := &memberStubStore{roles: map[string]adminstore.OrgRole{"org-a": adminstore.RoleReader}}
		// The dashboard itself reads the store: give the member handler the
		// multi-org store with membership overridden for the analytics route.
		mh := handlers.New(&rolesOnStatsStore{multiOrgStatsStore{}, member.roles}, secret, "localhost", nil)
		mrouter := mh.SetupRouter()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
			"/api/analytics/stats?org_id=org-a", nil)
		req.AddCookie(testCookie("yabanin_admin_session", adminCookie))
		req.AddCookie(testCookie("yabanin_csrf_token", csrfToken))
		req.Header.Set("X-CSRF-Token", csrfToken)
		w := httptest.NewRecorder()
		mrouter.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("own-org analytics = %d, want 200", w.Code)
		}
		var stats struct {
			TotalRequests int64 `json:"total_requests"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
			t.Fatalf("decode stats: %v", err)
		}
		if stats.TotalRequests != 100 {
			t.Errorf("own-org stats total = %d, want 100 (org-a only, never the 300 aggregate)", stats.TotalRequests)
		}
	})
}

// rolesOnStatsStore combines the per-org stats with membership lookup so the
// analytics RBAC path passes for the allowed org.
type rolesOnStatsStore struct {
	multiOrgStatsStore
	roles map[string]adminstore.OrgRole
}

func (s *rolesOnStatsStore) GetUserOrgRoles(context.Context, string) (map[string]adminstore.OrgRole, error) {
	return s.roles, nil
}

// adminUsersStore answers session revalidation (TP-02) with a configurable
// admin row; everything else stays the errStub surface.
type adminUsersStore struct {
	stubStore
	user *adminstore.AdminUser // nil = lookup error (deleted user / DB down)
}

func (s *adminUsersStore) GetAdminUserByID(context.Context, string) (*adminstore.AdminUser, error) {
	if s.user == nil {
		return nil, errStub
	}
	return s.user, nil
}

// TP-02: the session cookie must not outlive the DB's answer about the user —
// deletion, deactivation and demotion take effect on the next request, and a
// lookup failure closes the boundary instead of trusting the cookie.
func TestTP02_AdminSessionRevalidatedAgainstStore(t *testing.T) {
	const secret = "test-session-secret" // #nosec G101 -- test-only HMAC key
	const csrfToken = "csrf-token-value" // #nosec G101 -- test-only value

	setup := func(user *adminstore.AdminUser) http.Handler {
		h := handlers.New(&adminUsersStore{user: user}, secret, "localhost", nil)
		return h.SetupRouter()
	}
	do := func(t *testing.T, router http.Handler, method, path, cookie string) int {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		if cookie != "" {
			req.AddCookie(testCookie("yabanin_admin_session", cookie))
			req.AddCookie(testCookie("yabanin_csrf_token", csrfToken))
			req.Header.Set("X-CSRF-Token", csrfToken)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	activeRoot := &adminstore.AdminUser{ID: "u-1", Email: "root@x.test", IsRoot: true, Active: true}
	demotedUser := &adminstore.AdminUser{ID: "u-1", Email: "root@x.test", IsRoot: false, Active: true}

	t.Run("cookie of a deleted user is rejected", func(t *testing.T) {
		rootCookie := makeSessionCookie(t, "root@x.test", true, secret)
		if code := do(t, setup(nil), http.MethodGet, "/api/audit-logs", rootCookie); code != http.StatusUnauthorized {
			t.Errorf("deleted user cookie on audit-logs = %d, want 401", code)
		}
	})

	t.Run("demoted root does not pass the root guard", func(t *testing.T) {
		rootCookie := makeSessionCookie(t, "root@x.test", true, secret)
		if code := do(t, setup(demotedUser), http.MethodGet, "/api/audit-logs", rootCookie); code != http.StatusForbidden {
			t.Errorf("demoted root on audit-logs = %d, want 403", code)
		}
	})

	t.Run("active root keeps working", func(t *testing.T) {
		rootCookie := makeSessionCookie(t, "root@x.test", true, secret)
		if code := do(t, setup(activeRoot), http.MethodGet, "/api/audit-logs", rootCookie); code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Errorf("active root on audit-logs = %d — must not be authz-rejected", code)
		}
	})

	t.Run("store lookup failure closes access (fail-closed)", func(t *testing.T) {
		// adminUsersStore with nil user already errors; a demoted cookie must
		// not turn that error into anonymous access either.
		anonReq := func() int {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/audit-logs", nil)
			w := httptest.NewRecorder()
			setup(nil).ServeHTTP(w, req)
			return w.Code
		}
		if code := anonReq(); code != http.StatusUnauthorized {
			t.Errorf("anon on audit-logs with failing store = %d, want 401", code)
		}
	})

	t.Run("csrf endpoint revalidates too", func(t *testing.T) {
		rootCookie := makeSessionCookie(t, "root@x.test", true, secret)
		if code := do(t, setup(nil), http.MethodGet, "/auth/csrf", rootCookie); code != http.StatusUnauthorized {
			t.Errorf("deleted user cookie on /auth/csrf = %d, want 401", code)
		}
		if code := do(t, setup(activeRoot), http.MethodGet, "/auth/csrf", rootCookie); code != http.StatusOK {
			t.Errorf("active root on /auth/csrf = %d, want 200", code)
		}
	})
}
