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
	// Additive presentation fields (tenant UI/API parity).
	Slug     string `json:"slug"`
	Currency string `json:"currency"`
	Timezone string `json:"timezone"`
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

// ListOrganizations serves the root-only directory from the same fixture
// orgs (only used by the no-widening control below).
func (s *meStore) ListOrganizations(_ context.Context, _ adminstore.PageFilter) ([]*adminstore.Organization, int64, error) {
	out := make([]*adminstore.Organization, 0, len(s.orgs))
	for _, org := range s.orgs {
		out = append(out, org)
	}
	return out, int64(len(out)), nil
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

// assertMePresentation checks one /api/me org entry against the expected
// authoritative presentation values ("" = field omitted).
func assertMePresentation(t *testing.T, org meOrgJSON, slug, currency, timezone, why string) {
	t.Helper()
	if org.Slug != slug || org.Currency != currency || org.Timezone != timezone {
		t.Errorf("%s presentation = slug %q currency %q timezone %q, want %q/%q/%q (%s)",
			org.ID, org.Slug, org.Currency, org.Timezone, slug, currency, timezone, why)
	}
}

// assertBodyOmits fails when any marker string appears in the body: a
// foreign org's identity or presentation values must never leak.
func assertBodyOmits(t *testing.T, body string, markers ...string) {
	t.Helper()
	for _, leak := range markers {
		if strings.Contains(body, leak) {
			t.Errorf("payload leaked foreign-org data (%q): %s", leak, body)
		}
	}
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

// Tenant UI/API parity: the member's own organizations carry their
// authoritative presentation settings (slug/currency/timezone) so readers
// resolve display settings — and OrgSelect lists their orgs — from /api/me
// alone. Values come from the same org record the name does; unset values
// are omitted (the client applies USD/UTC defaults); a foreign org's
// presentation must never leak.
func TestMe_MemberPresentationScopedToOwnOrgs(t *testing.T) {
	store := newMeStore()
	store.admins["test-admin"] = &adminstore.AdminUser{ID: "test-admin", Email: "admin@x.test", DisplayName: "Alice Admin", Active: true}
	store.userRoles["test-admin"] = map[string]adminstore.OrgRole{
		"org-a": adminstore.RoleReader,
		"org-c": adminstore.RoleOperator,
	}
	store.orgs["org-a"] = &adminstore.Organization{ID: "org-a", Name: "Org A", Slug: "acme", Currency: "EUR", Timezone: "Europe/Berlin"}
	// org-c has no presentation set: fields must be absent (empty), never
	// fabricated defaults — the client owns the default fallback.
	store.orgs["org-c"] = &adminstore.Organization{ID: "org-c", Name: "Org C"}
	// Foreign org the caller holds no membership on: its values must not
	// appear anywhere in the payload.
	store.orgs["org-b"] = &adminstore.Organization{ID: "org-b", Name: "Org B", Slug: "foreign", Currency: "JPY", Timezone: "Asia/Tokyo"}
	h := handlers.New(store, meSecret, "localhost", nil)
	router := h.SetupRouter()

	code, body := getMe(t, router, makeSessionCookie(t, "admin@x.test", false, meSecret))
	if code != http.StatusOK {
		t.Fatalf("GET /api/me as member = %d, want 200; body: %s", code, body)
	}
	me := decodeMe(t, body)
	if len(me.Organizations) != 2 {
		t.Fatalf("organizations = %+v, want 2 entries", me.Organizations)
	}
	a, c := me.Organizations[0], me.Organizations[1]
	if a.ID != "org-a" {
		t.Fatalf("first entry = %+v, want org-a", a)
	}
	assertMePresentation(t, a, "acme", "EUR", "Europe/Berlin", "authoritative store values")
	assertMePresentation(t, c, "", "", "", "client applies defaults")
	assertBodyOmits(t, body, "org-b", "Org B", "foreign", "JPY", "Asia/Tokyo")
}

// No-widening control: the org directory stays root-only. A member session
// — even one whose /api/me now carries presentation — must keep receiving
// 403 from GET /api/organizations; root still lists.
func TestMe_DirectoryStaysRootOnly(t *testing.T) {
	store := newMeStore()
	store.admins["test-root"] = &adminstore.AdminUser{ID: "test-root", Email: "root@x.test", DisplayName: "Root", IsRoot: true, Active: true}
	store.admins["test-admin"] = &adminstore.AdminUser{ID: "test-admin", Email: "admin@x.test", DisplayName: "Alice", Active: true}
	store.userRoles["test-admin"] = map[string]adminstore.OrgRole{"org-a": adminstore.RoleReader}
	store.orgs["org-a"] = &adminstore.Organization{ID: "org-a", Name: "Org A", Slug: "acme", Currency: "EUR", Timezone: "Europe/Berlin"}
	h := handlers.New(store, meSecret, "localhost", nil)
	router := h.SetupRouter()

	get := func(cookie string) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/organizations", nil)
		req.AddCookie(testCookie("yabanin_admin_session", cookie))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}
	if code := get(makeSessionCookie(t, "admin@x.test", false, meSecret)); code != http.StatusForbidden {
		t.Errorf("GET /api/organizations as member = %d, want 403 (directory not widened)", code)
	}
	if code := get(makeSessionCookie(t, "root@x.test", true, meSecret)); code != http.StatusOK {
		t.Errorf("GET /api/organizations as root = %d, want 200", code)
	}
}
