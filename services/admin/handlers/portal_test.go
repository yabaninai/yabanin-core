package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

func TestPortalOIDC_InviteDomainAndUnverified(t *testing.T) {
	const secret = "portal-session-hmac-key" // #nosec G101 -- test-only HMAC key
	p := newFakeOIDCProvider(t)
	p.email = "dev@example.com"

	store := newMemPortal()
	store.users["u-1"] = &adminstore.DeveloperUser{
		ID: "u-1", Email: "dev@example.com", DisplayName: "Dev", OrgID: "org-1", TeamID: "team-1", Active: true,
	}
	store.byEmail["dev@example.com"] = "u-1"

	h := New(newMockStore(), secret, "admin.test", nil)
	client := portalOIDCClient(t, p)
	h.SetPortal(PortalOptions{Enabled: true, Provisioning: "invite", MaxKeys: 5, KeyTTLDays: 90, Client: client, Store: store})
	router := h.SetupRouter()

	t.Run("unknown invite is refused", func(t *testing.T) {
		p.email = "stranger@example.com"
		p.emailVerified = true
		w := portalCallback(t, router, p)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status %d body %s", w.Code, w.Body.String())
		}
	})

	t.Run("unverified email is refused", func(t *testing.T) {
		p.email = "dev@example.com"
		p.emailVerified = false
		w := portalCallback(t, router, p)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status %d", w.Code)
		}
	})

	t.Run("invite signs in", func(t *testing.T) {
		p.email = "dev@example.com"
		p.emailVerified = true
		w := portalCallback(t, router, p)
		if w.Code != http.StatusFound {
			t.Fatalf("status %d body %s", w.Code, w.Body.String())
		}
		if portalSession(w) == "" {
			t.Fatal("no portal session")
		}
		if store.users["u-1"].OIDCSubject == "" {
			t.Fatal("subject was not recorded")
		}
	})

	t.Run("domain provisions a user", func(t *testing.T) {
		p.email = "new@example.com"
		p.emailVerified = true
		dh := New(newMockStore(), secret, "admin.test", nil)
		dh.SetPortal(PortalOptions{
			Enabled: true, Provisioning: "domain", AllowedDomains: []string{"example.com"},
			DefaultOrg: "org-1", DefaultTeam: "team-1", MaxKeys: 5, KeyTTLDays: 0,
			Client: client, Store: store,
		})
		w := portalCallback(t, dh.SetupRouter(), p)
		if w.Code != http.StatusFound {
			t.Fatalf("status %d body %s", w.Code, w.Body.String())
		}
		if _, ok := store.byEmail["new@example.com"]; !ok {
			t.Fatal("domain user was not created")
		}
	})

	t.Run("domain outside the allowlist is refused", func(t *testing.T) {
		p.email = "new@elsewhere.test"
		p.emailVerified = true
		dh := New(newMockStore(), secret, "admin.test", nil)
		dh.SetPortal(PortalOptions{
			Enabled: true, Provisioning: "domain", AllowedDomains: []string{"example.com"},
			DefaultOrg: "org-1", DefaultTeam: "team-1", MaxKeys: 5,
			Client: client, Store: store,
		})
		w := portalCallback(t, dh.SetupRouter(), p)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status %d", w.Code)
		}
	})
}

func TestPortalKeys_LimitForeignAndPurge(t *testing.T) {
	const secret = "portal-session-hmac-key" // #nosec G101 -- test-only HMAC key
	store := newMemPortal()
	store.users["u-1"] = &adminstore.DeveloperUser{ID: "u-1", Email: "a@example.com", OrgID: "org-1", TeamID: "team-1", Active: true}
	store.users["u-2"] = &adminstore.DeveloperUser{ID: "u-2", Email: "b@example.com", OrgID: "org-1", TeamID: "team-1", Active: true}
	store.keys["k-b"] = &memKey{DeveloperKey: adminstore.DeveloperKey{ID: "k-b", Name: "theirs", Active: true}, userID: "u-2", hash: "hash-b"}
	cache := &memResolverCache{}
	h := New(newMockStore(), secret, "", nil)
	h.SetResolverCache(cache)
	h.SetPortal(PortalOptions{Enabled: true, MaxKeys: 2, KeyTTLDays: 90, Store: store})
	router := h.SetupRouter()

	code, body := portalCall(t, router, secret, "u-1", http.MethodPost, "/api/me/keys", `{"name":"one"}`)
	if code != http.StatusCreated || !strings.Contains(body, `"key":"yb_`) || strings.Contains(body, "ybs_") {
		t.Fatalf("create: %d %s", code, body)
	}
	if !strings.Contains(body, "expires_at") {
		t.Fatalf("ttl missing: %s", body)
	}
	code, body = portalCall(t, router, secret, "u-1", http.MethodPost, "/api/me/keys", `{"name":"two"}`)
	if code != http.StatusCreated {
		t.Fatalf("second: %d %s", code, body)
	}
	code, body = portalCall(t, router, secret, "u-1", http.MethodPost, "/api/me/keys", `{"name":"three"}`)
	if code != http.StatusConflict {
		t.Fatalf("limit: %d %s", code, body)
	}
	code, body = portalCall(t, router, secret, "u-1", http.MethodGet, "/api/me/keys", "")
	if code != http.StatusOK || strings.Contains(body, "hash") || strings.Contains(body, "key_hash") {
		t.Fatalf("list leaked hash: %d %s", code, body)
	}
	code, _ = portalCall(t, router, secret, "u-1", http.MethodDelete, "/api/me/keys/k-b", "")
	if code != http.StatusNotFound {
		t.Fatalf("foreign delete: %d", code)
	}
	if !store.keys["k-b"].Active {
		t.Fatal("foreign key was deactivated")
	}
	var ownID string
	for id, k := range store.keys {
		if k.userID == "u-1" && k.Active {
			ownID = id
			break
		}
	}
	code, _ = portalCall(t, router, secret, "u-1", http.MethodDelete, "/api/me/keys/"+ownID, "")
	if code != http.StatusNoContent {
		t.Fatalf("delete own: %d", code)
	}
	if store.keys[ownID].Active {
		t.Fatal("own key still active")
	}
	if len(cache.keys) != 1 || !strings.Contains(cache.keys[0], "org:resolve:") {
		t.Fatalf("purge: %v", cache.keys)
	}

	code, body = portalCall(t, router, secret, "u-1", http.MethodGet, "/api/me", "")
	if code != http.StatusOK || !strings.Contains(body, "a@example.com") {
		t.Fatalf("me: %d %s", code, body)
	}
}

func TestPortalAdminDevelopers(t *testing.T) {
	const secret = "test-secret-32-bytes-long-here!!" // #nosec G101 -- test-only HMAC key
	store := newMemPortal()
	store.users["u-b"] = &adminstore.DeveloperUser{ID: "u-b", Email: "b@example.com", OrgID: "org-2", TeamID: "team-2", Active: true}
	store.keys["k-b"] = &memKey{DeveloperKey: adminstore.DeveloperKey{ID: "k-b", Name: "b", Active: true}, userID: "u-b", hash: "hash-b"}
	h := New(newMockStore(), secret, "", nil)
	h.SetPortal(PortalOptions{Enabled: true, MaxKeys: 5, Store: store})
	router := h.SetupRouter()
	ms := h.store.(*mockStore)
	ms.orgMembers["admin-1/org-1"] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: "org-1", Role: adminstore.RoleOrgAdmin}

	code, body := adminCall(t, router, secret, false, http.MethodPost, "/api/organizations/org-1/developers", `{"email":"new@example.com","display_name":"New"}`)
	if code != http.StatusCreated || !strings.Contains(body, "new@example.com") {
		t.Fatalf("invite: %d %s", code, body)
	}
	ms.orgMembers["admin-1/org-1"].Role = adminstore.RoleReader
	code, _ = adminCall(t, router, secret, false, http.MethodPost, "/api/organizations/org-1/developers", `{"email":"x@example.com"}`)
	if code != http.StatusForbidden {
		t.Fatalf("reader: %d", code)
	}
	ms.orgMembers["admin-1/org-1"].Role = adminstore.RoleOrgAdmin
	code, _ = adminCall(t, router, secret, false, http.MethodDelete, "/api/organizations/org-1/developers/u-b", "")
	if code != http.StatusNotFound {
		t.Fatalf("idor: %d", code)
	}
	if !store.keys["k-b"].Active || !store.users["u-b"].Active {
		t.Fatal("other org developer was changed")
	}
	code, body = adminCall(t, router, secret, false, http.MethodGet, "/api/organizations/org-1/developers", "")
	if code != http.StatusOK || !strings.Contains(body, "new@example.com") {
		t.Fatalf("list: %d %s", code, body)
	}
	var createdID string
	for id, u := range store.users {
		if u.Email == "new@example.com" {
			createdID = id
		}
	}
	code, body = adminCall(t, router, secret, false, http.MethodPut, "/api/organizations/org-1/developers/"+createdID, `{"active":false}`)
	if code != http.StatusOK || store.users[createdID].Active {
		t.Fatalf("deactivate: %d %s", code, body)
	}
	code, _ = adminCall(t, router, secret, true, http.MethodDelete, "/api/organizations/org-2/developers/u-b", "")
	if code != http.StatusNoContent {
		t.Fatalf("root delete: %d", code)
	}
	if store.users["u-b"].Active || store.keys["k-b"].Active {
		t.Fatal("root deactivate did not revoke")
	}
}

func portalOIDCClient(t *testing.T, p *fakeOIDCProvider) *adminauth.OIDCClient {
	t.Helper()
	c, err := adminauth.NewOIDCClient(context.Background(), p.server.URL, p.clientID, "idp-test-secret", "https://admin.test/portal/callback")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func portalCallback(t *testing.T, router http.Handler, p *fakeOIDCProvider) *httptest.ResponseRecorder {
	t.Helper()
	login := httptest.NewRecorder()
	router.ServeHTTP(login, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/portal/login", nil))
	if login.Code != http.StatusFound {
		t.Fatalf("login %d", login.Code)
	}
	var raw string
	for _, c := range login.Result().Cookies() {
		if c.Name == adminauth.PortalOIDCFlowCookieName {
			raw = c.Value
		}
	}
	flow, err := adminauth.ParseOIDCFlowCookie(raw)
	if err != nil {
		t.Fatal(err)
	}
	p.nonceToEmbed = flow.Nonce
	loc, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	q.Set("code", "ok")
	q.Set("state", loc.Query().Get("state"))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/portal/callback?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: adminauth.PortalOIDCFlowCookieName, Value: raw, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func portalSession(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == adminauth.PortalSessionCookieName {
			return c.Value
		}
	}
	return ""
}

func portalCall(t *testing.T, router http.Handler, secret, userID, method, path, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, rdr)
	cookie, err := adminauth.CreatePortalSessionCookie(adminauth.PortalSession{
		UserID: userID, Email: userID + "@example.com", SessionID: "s", ExpiresAt: time.Now().Add(time.Hour),
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: "yabanin_portal_csrf", Value: "csrf-portal", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	req.Header.Set("X-CSRF-Token", "csrf-portal")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func adminCall(t *testing.T, router http.Handler, secret string, root bool, method, path, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, rdr)
	req.AddCookie(makeSessionCookie(root, secret))
	req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: "csrf-admin", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	req.Header.Set("X-CSRF-Token", "csrf-admin")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

type memResolverCache struct{ keys []string }

func (m *memResolverCache) Del(_ context.Context, keys ...string) error {
	m.keys = append(m.keys, keys...)
	return nil
}

type memKey struct {
	adminstore.DeveloperKey
	userID string
	hash   string
}

type memPortal struct {
	users   map[string]*adminstore.DeveloperUser
	byEmail map[string]string
	keys    map[string]*memKey
	n       int
}

func newMemPortal() *memPortal {
	return &memPortal{
		users:   map[string]*adminstore.DeveloperUser{},
		byEmail: map[string]string{},
		keys:    map[string]*memKey{},
	}
}

func (m *memPortal) GetDeveloperByEmail(ctx context.Context, email string) (*adminstore.DeveloperUser, error) {
	id, ok := m.byEmail[strings.ToLower(email)]
	if !ok {
		return nil, adminstore.ErrNotFound
	}
	return m.GetDeveloperByID(ctx, id)
}

func (m *memPortal) GetDeveloperByID(_ context.Context, id string) (*adminstore.DeveloperUser, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, adminstore.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (m *memPortal) CreateDeveloper(_ context.Context, u adminstore.DeveloperUser) (*adminstore.DeveloperUser, error) {
	if _, ok := m.byEmail[u.Email]; ok {
		return nil, errExists("developer already exists")
	}
	m.n++
	u.ID = "gen-" + strings.Repeat("x", 0) + jsonID(m.n)
	m.users[u.ID] = &u
	m.byEmail[u.Email] = u.ID
	cp := u
	return &cp, nil
}

func jsonID(n int) string {
	b, _ := json.Marshal(n)
	return strings.Trim(string(b), "\"")
}

func (m *memPortal) BindDeveloperSubject(_ context.Context, id, subject string) error {
	u, ok := m.users[id]
	if !ok {
		return adminstore.ErrNotFound
	}
	if u.OIDCSubject != "" && u.OIDCSubject != subject {
		return errExists("developer subject mismatch")
	}
	u.OIDCSubject = subject
	return nil
}

func (m *memPortal) ListDevelopers(_ context.Context, orgID string) ([]adminstore.DeveloperUser, error) {
	var out []adminstore.DeveloperUser
	for _, u := range m.users {
		if u.OrgID == orgID {
			out = append(out, *u)
		}
	}
	return out, nil
}

func (m *memPortal) SetDeveloperActive(_ context.Context, id string, active bool) error {
	u, ok := m.users[id]
	if !ok {
		return adminstore.ErrNotFound
	}
	u.Active = active
	return nil
}

func (m *memPortal) CountActiveDeveloperKeys(_ context.Context, userID string) (int, error) {
	n := 0
	for _, k := range m.keys {
		if k.userID == userID && k.Active {
			n++
		}
	}
	return n, nil
}

func (m *memPortal) ListDeveloperKeys(_ context.Context, userID string) ([]adminstore.DeveloperKey, error) {
	var out []adminstore.DeveloperKey
	for _, k := range m.keys {
		if k.userID == userID {
			out = append(out, k.DeveloperKey)
		}
	}
	return out, nil
}

func (m *memPortal) CreateDeveloperKey(_ context.Context, userID, orgID, teamID, name, keyHash string, expiresAt *time.Time) (*adminstore.DeveloperKey, error) {
	m.n++
	k := &memKey{
		DeveloperKey: adminstore.DeveloperKey{ID: "k-" + jsonID(m.n), Name: name, Active: true, CreatedAt: time.Now(), ExpiresAt: expiresAt},
		userID:       userID,
		hash:         keyHash,
	}
	_ = orgID
	_ = teamID
	m.keys[k.ID] = k
	cp := k.DeveloperKey
	return &cp, nil
}

func (m *memPortal) DeactivateDeveloperKey(_ context.Context, userID, keyID string) (string, error) {
	k, ok := m.keys[keyID]
	if !ok || k.userID != userID || !k.Active {
		return "", adminstore.ErrNotFound
	}
	k.Active = false
	return k.hash, nil
}

func (m *memPortal) DeactivateDeveloperKeys(_ context.Context, userID string) ([]string, error) {
	var hashes []string
	for _, k := range m.keys {
		if k.userID == userID && k.Active {
			k.Active = false
			hashes = append(hashes, k.hash)
		}
	}
	return hashes, nil
}

type errExists string

func (e errExists) Error() string { return string(e) }
