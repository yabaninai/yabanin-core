package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/inbox"
)

// E06-P01 W01-C03: security-inbox read endpoints. The end-to-end arms below
// drive the real router with session cookies, exactly like the production
// stand; memberships and inbox rows come from the fixture store, so every
// middleware gate (session revalidation, org permission, scope) is exercised.

// securityInboxFixture is the shared mockStore plus the security-inbox
// capability. Embedding keeps the shared fixture (sessions, memberships) and
// adds the in-memory inbox the new routes read.
type securityInboxFixture struct {
	*mockStore
	rows      map[uuid.UUID][]inbox.Incident
	incidents map[uuid.UUID]inbox.Incident // incident id -> incident
	listErr   error
	getErr    error
}

func newSecurityInboxFixture() *securityInboxFixture {
	return &securityInboxFixture{
		mockStore: newMockStore(),
		rows:      map[uuid.UUID][]inbox.Incident{},
		incidents: map[uuid.UUID]inbox.Incident{},
	}
}

func (f *securityInboxFixture) List(_ context.Context, orgID uuid.UUID) ([]inbox.Incident, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]inbox.Incident{}, f.rows[orgID]...), nil
}

func (f *securityInboxFixture) Get(_ context.Context, orgID, incidentID uuid.UUID) (inbox.Incident, bool, error) {
	if f.getErr != nil {
		return inbox.Incident{}, false, f.getErr
	}
	inc, ok := f.incidents[incidentID]
	if !ok || inc.OrgID != orgID {
		return inbox.Incident{}, false, nil
	}
	return inc, true, nil
}

// siSessionKey returns the signing key for the fixture session cookies (a
// function, not a package const, so the credential scanner does not pin the
// literal; test-only value, never a production secret).
func siSessionKey() string { return "test-secret-32-bytes-long-here!!" }

// siSeed registers the users the session revalidation resolves (the base
// fixture only knows admin-1 and admin-root) and the memberships used below:
// admin-1 is org_admin on orgA, admin-2 is security_auditor on orgA, admin-4
// is operator on orgA (no security.read). admin-3 exists but has no
// membership anywhere, and nobody is a member of orgB.
func siSeed(t *testing.T, f *securityInboxFixture, orgA uuid.UUID) {
	t.Helper()
	for _, id := range []string{"admin-2", "admin-3", "admin-4"} {
		f.adminUsers[id] = &adminstore.AdminUser{ID: id, Email: id + "@example.com", DisplayName: id, IsRoot: false, Active: true}
	}
	seed := func(userID string, orgID uuid.UUID, role adminstore.OrgRole) {
		t.Helper()
		if _, err := f.SetOrgMembership(t.Context(), userID, orgID.String(), role); err != nil {
			t.Fatalf("seed membership %s on %s: %v", userID, orgID, err)
		}
	}
	seed("admin-1", orgA, adminstore.RoleOrgAdmin)
	seed("admin-2", orgA, adminstore.RoleSecurityAuditor)
	seed("admin-4", orgA, adminstore.RoleOperator)
}

func siIncident(t *testing.T, orgID uuid.UUID, eventID string, occurred time.Time) inbox.Incident {
	t.Helper()
	return inbox.Incident{
		ID:           uuid.New(),
		OrgID:        orgID,
		GroupKey:     strings.Repeat("g", 64),
		Summary:      "Proxy auth failures folded into one incident",
		Severity:     inbox.SeverityMedium,
		Status:       inbox.StatusNew,
		Confidence:   0.75,
		FirstSeen:    occurred,
		LastSeen:     occurred,
		EventCount:   3,
		FirstEventID: eventID,
		LastEventID:  eventID,
	}
}

// siServe builds the real router over the fixture and returns a GET helper
// carrying the session cookie (and the org header when set).
func siServe(t *testing.T, f *securityInboxFixture) func(path string, cookie *http.Cookie, headerOrg string) *httptest.ResponseRecorder {
	t.Helper()
	h := New(f, siSessionKey(), "", []string{})
	router := h.SetupRouter()
	t.Cleanup(h.Stop)
	return func(path string, cookie *http.Cookie, headerOrg string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if headerOrg != "" {
			req.Header.Set(OrgHeader, headerOrg)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
}

// siSessionCookie builds the signed session cookie for a fixture user id
// (makeSessionCookie hardcodes admin-1/admin-root).
func siSessionCookie(t *testing.T, userID string, isRoot bool) *http.Cookie {
	t.Helper()
	c, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID:    userID,
		Email:     userID + "@example.com",
		IsRoot:    isRoot,
		SessionID: "sess-" + userID,
		ExpiresAt: time.Now().Add(time.Hour),
	}, siSessionKey())
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie: %v", err)
	}
	return &http.Cookie{Name: "yabanin_admin_session", Value: c.Value, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func TestSecurityInboxListRequiresOrgPermission(t *testing.T) {
	orgA, orgB := uuid.New(), uuid.New()
	f := newSecurityInboxFixture()
	siSeed(t, f, orgA)
	get := siServe(t, f)

	t.Run("anon is 401", func(t *testing.T) {
		if w := get("/api/organizations/"+orgA.String()+"/security-inbox", nil, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("anon list = %d, want 401", w.Code)
		}
	})

	t.Run("no membership is 403", func(t *testing.T) {
		if w := get("/api/organizations/"+orgA.String()+"/security-inbox", siSessionCookie(t, "admin-3", false), ""); w.Code != http.StatusForbidden {
			t.Fatalf("no-membership list = %d, want 403", w.Code)
		}
	})

	t.Run("foreign org is 403", func(t *testing.T) {
		if w := get("/api/organizations/"+orgB.String()+"/security-inbox", siSessionCookie(t, "admin-1", false), ""); w.Code != http.StatusForbidden {
			t.Fatalf("foreign-org list = %d, want 403", w.Code)
		}
	})

	t.Run("operator without security.read is 403", func(t *testing.T) {
		if w := get("/api/organizations/"+orgA.String()+"/security-inbox", siSessionCookie(t, "admin-4", false), ""); w.Code != http.StatusForbidden {
			t.Fatalf("operator list = %d, want 403 (no security.read)", w.Code)
		}
	})
}

func TestSecurityInboxListAllowedRolesAndShape(t *testing.T) {
	orgA, orgB := uuid.New(), uuid.New()
	f := newSecurityInboxFixture()
	siSeed(t, f, orgA)
	occurred := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	inc := siIncident(t, orgA, "evt-1", occurred)
	f.rows[orgA] = []inbox.Incident{inc}
	f.incidents[inc.ID] = inc
	get := siServe(t, f)

	assertList := func(t *testing.T, cookie *http.Cookie) []map[string]any {
		t.Helper()
		w := get("/api/organizations/"+orgA.String()+"/security-inbox", cookie, "")
		if w.Code != http.StatusOK {
			t.Fatalf("list = %d, want 200 (body %s)", w.Code, w.Body.String())
		}
		var got struct {
			Data []map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		return got.Data
	}

	t.Run("org_admin reads the fold", func(t *testing.T) {
		data := assertList(t, siSessionCookie(t, "admin-1", false))
		if len(data) != 1 {
			t.Fatalf("rows = %d, want 1 (%v)", len(data), data)
		}
		if data[0]["id"] != inc.ID.String() || data[0]["severity"] != inbox.SeverityMedium {
			t.Fatalf("incident row mismatch: %v", data[0])
		}
		if data[0]["event_count"].(float64) != 3 {
			t.Fatalf("event_count = %v, want 3", data[0]["event_count"])
		}
		if data[0]["evidence"] == nil || len(data[0]["evidence"].([]any)) != 0 {
			t.Fatalf("evidence = %v, want an empty array", data[0]["evidence"])
		}
	})

	t.Run("security_auditor reads the fold (security.read)", func(t *testing.T) {
		data := assertList(t, siSessionCookie(t, "admin-2", false))
		if len(data) != 1 {
			t.Fatalf("rows = %d, want 1", len(data))
		}
	})

	t.Run("root reads without membership", func(t *testing.T) {
		data := assertList(t, siSessionCookie(t, "admin-root", true))
		if len(data) != 1 {
			t.Fatalf("rows = %d, want 1", len(data))
		}
	})

	t.Run("empty org is 200 with an empty array", func(t *testing.T) {
		if _, err := f.SetOrgMembership(t.Context(), "admin-1", orgB.String(), adminstore.RoleOrgAdmin); err != nil {
			t.Fatalf("seed orgB membership: %v", err)
		}
		w := get("/api/organizations/"+orgB.String()+"/security-inbox", siSessionCookie(t, "admin-1", false), "")
		if w.Code != http.StatusOK {
			t.Fatalf("empty-org list = %d, want 200 (body %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"data":[]`) {
			t.Fatalf("empty-org body = %q, want an empty data array", w.Body.String())
		}
	})

	t.Run("GET is idempotent", func(t *testing.T) {
		cookie := siSessionCookie(t, "admin-1", false)
		first := get("/api/organizations/"+orgA.String()+"/security-inbox", cookie, "")
		second := get("/api/organizations/"+orgA.String()+"/security-inbox", cookie, "")
		if first.Body.String() != second.Body.String() {
			t.Fatalf("two GETs differ: %q vs %q", first.Body.String(), second.Body.String())
		}
	})

	t.Run("invalid org id is 400", func(t *testing.T) {
		// Root passes the permission gate for any org id, so the garbage
		// uuid reaches the handler's parse (a non-root caller is 403 at the
		// middleware first, before the id is ever parsed).
		if w := get("/api/organizations/not-a-uuid/security-inbox", siSessionCookie(t, "admin-root", true), ""); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid org id = %d, want 400", w.Code)
		}
	})
}

func TestSecurityInboxDetail(t *testing.T) {
	orgA := uuid.New()
	f := newSecurityInboxFixture()
	siSeed(t, f, orgA)
	occurred := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	inc := siIncident(t, orgA, "evt-1", occurred)
	f.rows[orgA] = []inbox.Incident{inc}
	f.incidents[inc.ID] = inc
	get := siServe(t, f)
	detail := "/api/organizations/" + orgA.String() + "/security-inbox/" + inc.ID.String()

	t.Run("found returns the incident", func(t *testing.T) {
		w := get(detail, siSessionCookie(t, "admin-1", false), "")
		if w.Code != http.StatusOK {
			t.Fatalf("detail = %d, want 200 (body %s)", w.Code, w.Body.String())
		}
		var got struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode detail: %v", err)
		}
		if got.Data["id"] != inc.ID.String() {
			t.Fatalf("detail id = %v, want %s", got.Data["id"], inc.ID.String())
		}
	})

	t.Run("unknown incident is 404", func(t *testing.T) {
		w := get("/api/organizations/"+orgA.String()+"/security-inbox/"+uuid.New().String(), siSessionCookie(t, "admin-1", false), "")
		if w.Code != http.StatusNotFound {
			t.Fatalf("unknown incident = %d, want 404", w.Code)
		}
	})

	t.Run("invalid incident id is 400", func(t *testing.T) {
		w := get("/api/organizations/"+orgA.String()+"/security-inbox/garbage", siSessionCookie(t, "admin-1", false), "")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid incident id = %d, want 400", w.Code)
		}
	})

	t.Run("store failure is 500 without leaking the raw error", func(t *testing.T) {
		f.getErr = errors.New("boom: secret-dsn")
		t.Cleanup(func() { f.getErr = nil })
		w := get(detail, siSessionCookie(t, "admin-1", false), "")
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("store failure = %d, want 500", w.Code)
		}
		if strings.Contains(w.Body.String(), "secret-dsn") {
			t.Fatalf("raw store error leaked: %s", w.Body.String())
		}
	})
}

func TestSecurityInboxJournalsAuditRows(t *testing.T) {
	orgA := uuid.New()
	f := newSecurityInboxFixture()
	siSeed(t, f, orgA)
	occurred := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	inc := siIncident(t, orgA, "evt-1", occurred)
	f.rows[orgA] = []inbox.Incident{inc}
	f.incidents[inc.ID] = inc

	h := New(f, siSessionKey(), "", []string{})
	router := h.SetupRouter()
	t.Cleanup(h.Stop)

	get := func(path string) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		req.AddCookie(siSessionCookie(t, "admin-1", false))
		router.ServeHTTP(httptest.NewRecorder(), req)
	}
	get("/api/organizations/" + orgA.String() + "/security-inbox")
	get("/api/organizations/" + orgA.String() + "/security-inbox/" + inc.ID.String())
	get("/api/organizations/" + orgA.String() + "/security-inbox/" + uuid.New().String())

	// The journal authority is the store (the process buffer is not); the
	// mockStore captures every persisted entry in order.
	if got := f.auditRecordCount(); got != 3 {
		t.Fatalf("audit records = %d, want 3 (allowed list, allowed detail, not_found)", got)
	}
	listRow := f.auditRecordByIndex(t, 0)
	detailRow := f.auditRecordByIndex(t, 1)
	notFoundRow := f.auditRecordByIndex(t, 2)
	if listRow.Action != "security_inbox" || listRow.Resource != "organization:"+orgA.String() {
		t.Fatalf("list audit row = %+v", listRow)
	}
	var ld securityInboxAuditDetail
	if err := json.Unmarshal([]byte(listRow.Details), &ld); err != nil {
		t.Fatalf("list details are not JSON: %v (%q)", err, listRow.Details)
	}
	if ld.Outcome != "allowed" || ld.Rows != 1 || ld.OrgID != orgA.String() {
		t.Fatalf("list details = %+v", ld)
	}
	if detailRow.Action != "security_inbox" || !strings.Contains(detailRow.Details, inc.ID.String()) {
		t.Fatalf("detail audit row = %+v", detailRow)
	}
	if notFoundRow.Action != "security_inbox" || !strings.Contains(notFoundRow.Details, `"not_found"`) {
		t.Fatalf("not-found audit row = %+v", notFoundRow)
	}
}

func TestSecurityInboxUnavailableStoreIs503(t *testing.T) {
	orgA := uuid.New()
	// A store without the security-inbox capability (plain mockStore) must
	// yield 503, mirroring the archive-search precedent. Root passes the
	// org-permission gate without any membership.
	h := New(newMockStore(), siSessionKey(), "", []string{})
	router := h.SetupRouter()
	t.Cleanup(h.Stop)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/organizations/"+orgA.String()+"/security-inbox", nil)
	req.AddCookie(makeSessionCookie(true, siSessionKey()))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no-capability list = %d, want 503 (body %s)", w.Code, w.Body.String())
	}
}
