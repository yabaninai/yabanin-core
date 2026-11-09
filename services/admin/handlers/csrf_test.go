package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// csrfHashStore serves a real bcrypt hash so the login handler can verify a password.
type csrfHashStore struct {
	*mockStore
	hash string
}

func (s *csrfHashStore) GetAdminUserByEmailWithHash(ctx context.Context, email string) (*adminstore.AdminUserWithHash, error) {
	u, err := s.mockStore.GetAdminUserByEmailWithHash(ctx, email)
	if err != nil {
		return nil, err
	}
	u.PasswordHash = s.hash
	return u, nil
}

func sessionKey() string {
	return "test-secret-" + "32-bytes-long-here!!"
}

func TestCSRFEndpoint_RequiresSession(t *testing.T) {
	h := New(newMockStore(), sessionKey(), "", nil)
	router := h.SetupRouter()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/csrf", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", w.Code)
	}
}

func TestCSRFEndpoint_ReturnsCookieValue(t *testing.T) {
	h := New(newMockStore(), sessionKey(), "", nil)
	router := h.SetupRouter()
	session := makeSessionCookie(true, sessionKey())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/csrf", nil)
	req.AddCookie(session)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control %q", w.Header().Get("Cache-Control"))
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.CSRFToken == "" {
		t.Fatal("empty csrf token")
	}
	var issued *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_csrf_token" {
			issued = c
		}
	}
	if issued == nil || !issued.HttpOnly {
		t.Fatalf("cookie %#v", issued)
	}
	if issued.Value != body.CSRFToken {
		t.Fatalf("body %q cookie %q", body.CSRFToken, issued.Value)
	}

	again := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/csrf", nil)
	again.AddCookie(session)
	again.AddCookie(issued)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, again)
	var body2 struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &body2); err != nil {
		t.Fatal(err)
	}
	if body2.CSRFToken != issued.Value {
		t.Fatalf("rotated token %q", body2.CSRFToken)
	}
}

func TestProtectedPOST_WithTokenFromEndpoint_Passes(t *testing.T) {
	h := New(newMockStore(), sessionKey(), "", nil)
	router := h.SetupRouter()
	session := makeSessionCookie(true, sessionKey())

	csrfReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/csrf", nil)
	csrfReq.AddCookie(session)
	csrfRec := httptest.NewRecorder()
	router.ServeHTTP(csrfRec, csrfReq)
	if csrfRec.Code != http.StatusOK {
		t.Fatalf("csrf status %d", csrfRec.Code)
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(csrfRec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var csrfCookie *http.Cookie
	for _, c := range csrfRec.Result().Cookies() {
		if c.Name == "yabanin_csrf_token" {
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatal("missing csrf cookie")
	}

	post := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/teams", strings.NewReader(`{"name":"t","org_id":"org-1"}`))
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("X-CSRF-Token", body.CSRFToken)
	post.AddCookie(session)
	post.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, post)
	if rec.Code == http.StatusForbidden && strings.TrimSpace(rec.Body.String()) == "forbidden" {
		t.Fatalf("CSRF rejected the token from GET /auth/csrf")
	}

	// The same cookie without the header is still rejected.
	bare := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/teams", strings.NewReader(`{"name":"t","org_id":"org-1"}`))
	bare.Header.Set("Content-Type", "application/json")
	bare.AddCookie(session)
	bare.AddCookie(csrfCookie)
	bareRec := httptest.NewRecorder()
	router.ServeHTTP(bareRec, bare)
	if bareRec.Code != http.StatusForbidden {
		t.Fatalf("missing header status %d", bareRec.Code)
	}
}

func TestLoginThenCSRFThenProtectedPOST(t *testing.T) {
	hash, err := adminauth.HashPassword("correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	store := newMockStore()
	if _, err := store.CreateAdminUser(t.Context(), "root@example.com", "Root", hash, true); err != nil {
		t.Fatal(err)
	}
	h := New(&csrfHashStore{mockStore: store, hash: hash}, sessionKey(), "", nil)
	router := h.SetupRouter()

	loginPage := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/login", nil)
	loginRec := httptest.NewRecorder()
	router.ServeHTTP(loginRec, loginPage)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login page %d", loginRec.Code)
	}
	var loginCSRF *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "yabanin_csrf_token" {
			loginCSRF = c
		}
	}
	if loginCSRF == nil || !loginCSRF.HttpOnly || loginCSRF.Value == "" {
		t.Fatalf("login csrf cookie %#v", loginCSRF)
	}
	match := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindStringSubmatch(loginRec.Body.String())
	if len(match) != 2 || match[1] != loginCSRF.Value {
		t.Fatalf("form token %v cookie %s", match, loginCSRF.Value)
	}

	form := url.Values{}
	form.Set("email", "root@example.com")
	form.Set("password", "correct-horse")
	form.Set("_csrf", loginCSRF.Value)
	loginPost := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	loginPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginPost.AddCookie(loginCSRF)
	loginPostRec := httptest.NewRecorder()
	router.ServeHTTP(loginPostRec, loginPost)
	if loginPostRec.Code != http.StatusFound {
		t.Fatalf("login %d body %s", loginPostRec.Code, loginPostRec.Body.String())
	}
	var session *http.Cookie
	for _, c := range loginPostRec.Result().Cookies() {
		if c.Name == "yabanin_admin_session" {
			session = c
		}
	}
	if session == nil || session.Value == "" {
		t.Fatal("missing session cookie")
	}

	csrfReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/csrf", nil)
	csrfReq.AddCookie(session)
	csrfReq.AddCookie(loginCSRF)
	csrfRec := httptest.NewRecorder()
	router.ServeHTTP(csrfRec, csrfReq)
	if csrfRec.Code != http.StatusOK {
		t.Fatalf("csrf %d %s", csrfRec.Code, csrfRec.Body.String())
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(csrfRec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.CSRFToken != loginCSRF.Value {
		t.Fatalf("token %q want %q", body.CSRFToken, loginCSRF.Value)
	}

	post := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/teams", strings.NewReader(`{"name":"platform","slug":"platform","org_id":"org-1"}`))
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("X-CSRF-Token", body.CSRFToken)
	post.AddCookie(session)
	post.AddCookie(loginCSRF)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, post)
	if rec.Code != http.StatusCreated {
		t.Fatalf("protected post %d body %s", rec.Code, rec.Body.String())
	}
}
