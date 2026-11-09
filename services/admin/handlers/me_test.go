package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// AUX-13: console GET /api/me. The payload must mirror the RequireOrgPermission
// model (adminstore roles), never name a foreign organization, and degrade
// honestly (empty org list for a membershipless admin, 500 without error
// detail on store failure).

type meOrgJSON struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

type meJSON struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Email         string      `json:"email"`
	IsRoot        bool        `json:"is_root"`
	Organizations []meOrgJSON `json:"organizations"`
}

// meStore extends the shared stubStore with the two surfaces /api/me reads:
// the admin record (display name) and the caller's org roles. roleLookups
// records every GetUserOrgRoles call so tests can prove root bypasses it.
type meStore struct {
	*stubStore
	admins      map[string]*adminstore.AdminUser
	userRoles   map[string]map[string]adminstore.OrgRole
	orgs        map[string]*adminstore.Organization
	rolesErr    error
	roleLookups []string
}

func newMeStore() *meStore {
	return &meStore{
		stubStore: &stubStore{},
		admins:    map[string]*adminstore.AdminUser{},
		userRoles: map[string]map[string]adminstore.OrgRole{},
		orgs:      map[string]*adminstore.Organization{},
	}
}

func (s *meStore) GetAdminUserByID(_ context.Context, id string) (*adminstore.AdminUser, error) {
	if u, ok := s.admins[id]; ok {
		return u, nil
	}
	return nil, adminstore.ErrNotFound
}

func (s *meStore) GetUserOrgRoles(_ context.Context, userID string) (map[string]adminstore.OrgRole, error) {
	s.roleLookups = append(s.roleLookups, userID)
	if s.rolesErr != nil {
		return nil, s.rolesErr
	}
	return s.userRoles[userID], nil
}

func (s *meStore) GetOrganizationByID(_ context.Context, id string) (*adminstore.Organization, error) {
	if org, ok := s.orgs[id]; ok {
		return org, nil
	}
	return nil, adminstore.ErrNotFound
}

// getMe performs an authenticated GET /api/me through the full router
// (session cookie + revalidation, like the S01 matrix tests).
func getMe(t *testing.T, router http.Handler, cookie string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/me", nil)
	if cookie != "" {
		req.AddCookie(testCookie("yabanin_admin_session", cookie))
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func decodeMe(t *testing.T, body string) meJSON {
	t.Helper()
	var me meJSON
	if err := json.Unmarshal([]byte(body), &me); err != nil {
		t.Fatalf("decode /api/me body: %v\nbody: %s", err, body)
	}
	return me
}

const meSecret = "test-session-secret" // #nosec G101 -- test-only HMAC key

func TestMe_RootBypassesMembership(t *testing.T) {
	store := newMeStore()
	store.admins["test-root"] = &adminstore.AdminUser{ID: "test-root", Email: "root@x.test", DisplayName: "Root Operator", IsRoot: true, Active: true}
	// Canary: if the handler consulted memberships anyway, rolesErr would 500.
	store.rolesErr = errStub
	h := handlers.New(store, meSecret, "localhost", nil)
	router := h.SetupRouter()

	code, body := getMe(t, router, makeSessionCookie(t, "root@x.test", true, meSecret))
	if code != http.StatusOK {
		t.Fatalf("GET /api/me as root = %d, want 200; body: %s", code, body)
	}
	me := decodeMe(t, body)
	if !me.IsRoot {
		t.Errorf("is_root = false, want true")
	}
	if me.ID != "test-root" || me.Name != "Root Operator" || me.Email != "root@x.test" {
		t.Errorf("identity mismatch: %+v", me)
	}
	if len(me.Organizations) != 0 {
		t.Errorf("root organizations = %+v, want empty list", me.Organizations)
	}
	if len(store.roleLookups) != 0 {
		t.Errorf("GetUserOrgRoles consulted for root: %v", store.roleLookups)
	}
}

func TestMe_MemberWithPartialRights(t *testing.T) {
	store := newMeStore()
	store.admins["test-admin"] = &adminstore.AdminUser{ID: "test-admin", Email: "admin@x.test", DisplayName: "Alice Admin", Active: true}
	store.userRoles["test-admin"] = map[string]adminstore.OrgRole{
		"org-a": adminstore.RoleReader,
		"org-c": adminstore.RoleOperator,
	}
	// org-b is visible to the STORE but the admin holds no membership on it:
	// it must never appear in the response.
	store.orgs["org-a"] = &adminstore.Organization{ID: "org-a", Name: "Org A"}
	store.orgs["org-b"] = &adminstore.Organization{ID: "org-b", Name: "Org B"}
	store.orgs["org-c"] = &adminstore.Organization{ID: "org-c", Name: "Org C"}
	h := handlers.New(store, meSecret, "localhost", nil)
	router := h.SetupRouter()

	code, body := getMe(t, router, makeSessionCookie(t, "admin@x.test", false, meSecret))
	if code != http.StatusOK {
		t.Fatalf("GET /api/me as member = %d, want 200; body: %s", code, body)
	}
	me := decodeMe(t, body)
	if me.IsRoot {
		t.Errorf("is_root = true, want false")
	}
	if len(me.Organizations) != 2 {
		t.Fatalf("organizations = %+v, want 2 entries (org-a, org-c)", me.Organizations)
	}
	if strings.Contains(body, "org-b") || strings.Contains(body, "Org B") {
		t.Errorf("response leaked foreign org: %s", body)
	}
	// Sorted by org id: org-a first (reader), org-c second (operator).
	a, c := me.Organizations[0], me.Organizations[1]
	if a.ID != "org-a" || a.Name != "Org A" || a.Role != "reader" {
		t.Errorf("org-a entry = %+v", a)
	}
	wantReader := []string{"analytics.read", "requests.read", "lineage.read"}
	if strings.Join(a.Permissions, ",") != strings.Join(wantReader, ",") {
		t.Errorf("reader permissions = %v, want %v", a.Permissions, wantReader)
	}
	if c.ID != "org-c" || c.Role != "operator" {
		t.Errorf("org-c entry = %+v", c)
	}
	wantOperator := []string{
		"analytics.read", "requests.read", "lineage.read", "lineage.verify",
		"keys.manage", "agent_keys.manage", "budgets.manage", "routing.manage",
	}
	if strings.Join(c.Permissions, ",") != strings.Join(wantOperator, ",") {
		t.Errorf("operator permissions = %v, want %v", c.Permissions, wantOperator)
	}
}

func TestMe_MemberWithoutOrganization(t *testing.T) {
	store := newMeStore()
	store.admins["test-admin"] = &adminstore.AdminUser{ID: "test-admin", Email: "admin@x.test", DisplayName: "No Org", Active: true}
	store.orgs["org-a"] = &adminstore.Organization{ID: "org-a", Name: "Org A"}
	h := handlers.New(store, meSecret, "localhost", nil)
	router := h.SetupRouter()

	code, body := getMe(t, router, makeSessionCookie(t, "admin@x.test", false, meSecret))
	if code != http.StatusOK {
		t.Fatalf("GET /api/me without memberships = %d, want 200; body: %s", code, body)
	}
	me := decodeMe(t, body)
	if me.Organizations == nil {
		t.Errorf("organizations = null, want []")
	}
	if len(me.Organizations) != 0 {
		t.Errorf("organizations = %+v, want empty", me.Organizations)
	}
	// The membershipless admin must not learn which orgs exist at all.
	if strings.Contains(body, "org-a") {
		t.Errorf("response names an org the caller has no membership on: %s", body)
	}
}

func TestMe_OrphanedMembershipSkipped(t *testing.T) {
	store := newMeStore()
	store.admins["test-admin"] = &adminstore.AdminUser{ID: "test-admin", Email: "admin@x.test", DisplayName: "Orphan", Active: true}
	store.userRoles["test-admin"] = map[string]adminstore.OrgRole{
		"org-gone": adminstore.RoleReader,
	}
	h := handlers.New(store, meSecret, "localhost", nil)
	router := h.SetupRouter()

	code, body := getMe(t, router, makeSessionCookie(t, "admin@x.test", false, meSecret))
	if code != http.StatusOK {
		t.Fatalf("GET /api/me with orphaned membership = %d, want 200; body: %s", code, body)
	}
	me := decodeMe(t, body)
	if len(me.Organizations) != 0 {
		t.Errorf("organizations = %+v, want the deleted org skipped", me.Organizations)
	}
}

func TestMe_StoreErrorIsGeneric500(t *testing.T) {
	store := newMeStore()
	store.admins["test-admin"] = &adminstore.AdminUser{ID: "test-admin", Email: "admin@x.test", DisplayName: "Broken", Active: true}
	store.rolesErr = errStub
	h := handlers.New(store, meSecret, "localhost", nil)
	router := h.SetupRouter()

	code, body := getMe(t, router, makeSessionCookie(t, "admin@x.test", false, meSecret))
	if code != http.StatusInternalServerError {
		t.Fatalf("GET /api/me with store error = %d, want 500", code)
	}
	if strings.Contains(body, "stub") {
		t.Errorf("raw store error leaked: %s", body)
	}
}

func TestMe_Unauthenticated(t *testing.T) {
	h := handlers.New(newMeStore(), meSecret, "localhost", nil)
	router := h.SetupRouter()

	if code, _ := getMe(t, router, ""); code != http.StatusUnauthorized {
		t.Errorf("GET /api/me without a session = %d, want 401", code)
	}
}
