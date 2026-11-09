package handlers

import (
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

func TestPortalHome_NoSessionRedirects(t *testing.T) {
	h := newPortalPageHandlers(t, newMemPortal(), "")
	rec := httptest.NewRecorder()
	h.SetupRouter().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/portal", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/portal/login" {
		t.Fatalf("location %q", loc)
	}
}

func TestPortalHome_KeyShownOnceAndNameEscaped(t *testing.T) {
	const secret = "portal-page-hmac" // #nosec G101 -- test-only HMAC key
	store := newMemPortal()
	store.users["u-1"] = &adminstore.DeveloperUser{
		ID: "u-1", Email: "dev@example.com", OrgID: "org-1", TeamID: "team-1", Active: true,
	}
	store.keys["k-xss"] = &memKey{
		DeveloperKey: adminstore.DeveloperKey{
			ID: "k-xss", Name: `<script>alert(1)</script>`, Active: true, CreatedAt: time.Now(),
		},
		userID: "u-1",
		hash:   "hash-xss",
	}
	h := New(newMockStore(), secret, "", nil)
	h.SetPortal(PortalOptions{
		Enabled: true, MaxKeys: 5, KeyTTLDays: 0,
		GatewayURL: "https://gateway.example.test", Store: store,
	})
	router := h.SetupRouter()

	rec := portalForm(t, router, secret, "u-1", http.MethodGet, "/portal", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("home %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("key name was not escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("escaped name missing: %s", body)
	}
	if !strings.Contains(body, "https://gateway.example.test") {
		t.Fatal("gateway url missing from snippets")
	}
	if strings.Contains(body, "yb_") && strings.Contains(body, "This key is shown once") {
		t.Fatal("home page revealed a key")
	}

	rec = portalForm(t, router, secret, "u-1", http.MethodPost, "/portal/keys", url.Values{"name": {"laptop"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	created := rec.Body.String()
	if !strings.Contains(created, "This key is shown once") || !strings.Contains(created, "yb_") {
		t.Fatalf("key not shown once: %s", created)
	}
	start := strings.Index(created, `id="new-key">`)
	if start < 0 {
		t.Fatal("new-key element missing")
	}
	start += len(`id="new-key">`)
	end := strings.Index(created[start:], "</code>")
	revealed := created[start : start+end]

	again := portalForm(t, router, secret, "u-1", http.MethodGet, "/portal", nil)
	if strings.Contains(again.Body.String(), revealed) {
		t.Fatal("key was shown again on the next page")
	}

	bad := portalForm(t, router, secret, "u-1", http.MethodPost, "/portal/keys", url.Values{"name": {"  "}})
	if bad.Code != http.StatusOK || !strings.Contains(bad.Body.String(), "name is required") {
		t.Fatalf("blank name: %d %s", bad.Code, bad.Body.String())
	}
	forged := portalForm(t, router, secret, "u-1", http.MethodPost, "/portal/keys/k-xss/revoke", url.Values{"_csrf": {"nope"}})
	if forged.Code != http.StatusForbidden {
		t.Fatalf("csrf: %d", forged.Code)
	}
	rev := portalForm(t, router, secret, "u-1", http.MethodPost, "/portal/keys/k-xss/revoke", url.Values{})
	if rev.Code != http.StatusSeeOther || rev.Header().Get("Location") != "/portal" {
		t.Fatalf("revoke: %d %s", rev.Code, rev.Header().Get("Location"))
	}
	if store.keys["k-xss"].Active {
		t.Fatal("key still active")
	}
	missing := portalForm(t, router, secret, "u-1", http.MethodPost, "/portal/keys/missing/revoke", url.Values{})
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing revoke: %d", missing.Code)
	}
}

func TestPortalHome_ExpiredSessionAndUnsetGateway(t *testing.T) {
	const secret = "portal-page-hmac" // #nosec G101 -- test-only HMAC key
	store := newMemPortal()
	exp := time.Now().UTC().Add(48 * time.Hour)
	store.users["u-1"] = &adminstore.DeveloperUser{ID: "u-1", Email: "dev@example.com", OrgID: "org-1", TeamID: "team-1", Active: true}
	store.keys["k-1"] = &memKey{DeveloperKey: adminstore.DeveloperKey{ID: "k-1", Name: "old", Active: true, CreatedAt: time.Now(), ExpiresAt: &exp}, userID: "u-1", hash: "h"}
	h := New(newMockStore(), secret, "", nil)
	h.SetPortal(PortalOptions{Enabled: true, MaxKeys: 1, Store: store})
	router := h.SetupRouter()

	page := portalForm(t, router, secret, "u-1", http.MethodGet, "/portal", nil)
	if !strings.Contains(page.Body.String(), "YABANIN_PORTAL_GATEWAY_URL") || !strings.Contains(page.Body.String(), exp.Format(time.RFC3339)) {
		t.Fatalf("page: %s", page.Body.String())
	}
	limited := portalForm(t, router, secret, "u-1", http.MethodPost, "/portal/keys", url.Values{"name": {"another"}})
	if !strings.Contains(limited.Body.String(), "active key limit reached") {
		t.Fatalf("limit: %s", limited.Body.String())
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/portal", nil)
	cookie, err := adminauth.CreatePortalSessionCookie(adminauth.PortalSession{
		UserID: "u-1", Email: "dev@example.com", SessionID: "s", ExpiresAt: time.Now().Add(-time.Minute),
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expired %d", rec.Code)
	}
	store.users["u-1"].Active = false
	inactive := portalForm(t, router, secret, "u-1", http.MethodGet, "/portal", nil)
	if inactive.Code != http.StatusFound {
		t.Fatalf("inactive %d", inactive.Code)
	}
}

func newPortalPageHandlers(t *testing.T, store *memPortal, gateway string) *AdminHandlers {
	t.Helper()
	const secret = "portal-page-hmac" // #nosec G101 -- test-only HMAC key
	h := New(newMockStore(), secret, "", nil)
	h.SetPortal(PortalOptions{Enabled: true, MaxKeys: 5, GatewayURL: gateway, Store: store})
	return h
}

func portalForm(t *testing.T, router http.Handler, secret, userID, method, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		if form.Get("_csrf") == "" {
			form.Set("_csrf", "csrf-portal")
		}
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	cookie, err := adminauth.CreatePortalSessionCookie(adminauth.PortalSession{
		UserID: userID, Email: "dev@example.com", SessionID: "s", ExpiresAt: time.Now().Add(time.Hour),
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: "yabanin_portal_csrf", Value: "csrf-portal", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}
