package handlers

// open-redirect-hardened `next`, generic HTML 401 errors (reason only in the
// server log), rate-limit interaction with the HTML error path, and CSRF on
// POST /auth/logout (the POST route itself is a HOT-PATCH to router.go — the
// test mirrors the exact mount the patch applies).

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminauth"
)

// quietLogger drops handler log lines (failed logins are logged by design).
func quietLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// --- helpers ----------------------------------------------------------------

// newLoginTestHandlers wires a store with a real bcrypt hash + a quiet logger
// so failed logins do not spam test output. The login user gets its own email
// (the mock store seeds others) so the by-email lookup is deterministic.
func newLoginTestHandlers(t *testing.T) (*AdminHandlers, string) {
	t.Helper()
	hash, err := adminauth.HashPassword("correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	store := &csrfHashStore{mockStore: newMockStore(), hash: hash}
	if _, err := store.CreateAdminUser(t.Context(), "login-admin@example.com", "Login Admin", hash, true); err != nil {
		t.Fatal(err)
	}
	h := New(store, sessionKey(), "", nil)
	h.logger = quietLogger()
	return h, "login-admin@example.com"
}

// loginPageGET drives GET /auth/login and returns the CSRF cookie + form
// token extracted from the page.
func loginPageGET(t *testing.T, h *AdminHandlers, rawQuery, acceptLanguage string) (*http.Cookie, string, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/login"+rawQuery, nil)
	if acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}
	w := httptest.NewRecorder()
	h.LoginPage()(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login page: got %d, want 200", w.Code)
	}
	var csrf *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_csrf_token" {
			csrf = c
		}
	}
	if csrf == nil || csrf.Value == "" {
		t.Fatal("login page: no csrf cookie")
	}
	m := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(m) != 2 {
		t.Fatal("login page: no form csrf token")
	}
	return csrf, m[1], w
}

// loginPOST drives POST /auth/login with the given form against the handler.
func loginPOST(t *testing.T, h *AdminHandlers, form url.Values, csrf *http.Cookie, acceptLanguage string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}
	if csrf != nil {
		req.AddCookie(csrf)
	}
	w := httptest.NewRecorder()
	h.HandleLogin()(w, req)
	return w
}

// --- next: open redirect matrix ----------------------------------------------

func TestSafeRedirectTarget(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/dashboard", "/dashboard"},
		{"/#keys?org=acme", "/#keys?org=acme"},
		{"/teams/1#settings", "/teams/1#settings"},
		// Open-redirect vectors: protocol-relative, backslash, absolute
		// URLs, schemes, encoded doubles (after one query-decode) and
		// control characters all collapse to "/".
		{"//evil.com", "/"},
		{"/\\evil.com", "/"},
		{"https://evil.com", "/"},
		{"http://evil.com/x", "/"},
		{"javascript:alert(1)", "/"},
		{" //evil.com", "/"},
		{"/foo\r\nSet-Cookie: x", "/"},
		{"/foo\\bar", "/"},
		{"/key:secret", "/"},
		{"relative/path", "/"},
	}
	for _, tc := range cases {
		if got := safeRedirectTarget(tc.in); got != tc.want {
			t.Errorf("safeRedirectTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLogin_Next_ValidHashRouteRedirects(t *testing.T) {
	h, email := newLoginTestHandlers(t)
	csrf, token, page := loginPageGET(t, h, "?next=%2F%23keys%3Forg%3Dacme", "")
	// The page carries the validated next through the form.
	if next := regexp.MustCompile(`name="next" value="([^"]*)"`).FindStringSubmatch(page.Body.String()); len(next) != 2 || next[1] != "/#keys?org=acme" {
		t.Fatalf("hidden next = %v, want /#keys?org=acme", next)
	}
	form := url.Values{"email": {email}, "password": {"correct-horse"}, "_csrf": {token}, "next": {"/#keys?org=acme"}}
	w := loginPOST(t, h, form, csrf, "")
	if w.Code != http.StatusFound {
		t.Fatalf("login: got %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/#keys?org=acme" {
		t.Fatalf("Location = %q, want /#keys?org=acme", loc)
	}
}

func TestLogin_Next_OpenRedirectVectorsRejected(t *testing.T) {
	h, email := newLoginTestHandlers(t)
	vectors := []struct {
		name string
		// formNext is placed in the POST body; rawNext goes into the query
		// string instead (encoded form: next=%2F%2Fevil.com decodes to
		// //evil.com server-side).
		formNext, rawNext string
	}{
		{"protocol-relative", "//evil.com", ""},
		{"backslash", `/\\evil.com`, ""},
		{"absolute-url", "https://evil.com", ""},
		{"javascript-scheme", "javascript:alert(1)", ""},
		{"encoded-double-in-query", "", "?next=%2F%2Fevil.com"},
	}
	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			csrf, token, _ := loginPageGET(t, h, "", "")
			form := url.Values{"email": {email}, "password": {"correct-horse"}, "_csrf": {token}}
			if tc.formNext != "" {
				form.Set("next", tc.formNext)
			}
			w := httptest.NewRecorder()
			target := "/auth/login"
			if tc.rawNext != "" {
				target += tc.rawNext
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(csrf)
			h.HandleLogin()(w, req)
			if w.Code != http.StatusFound {
				t.Fatalf("login: got %d, want 302", w.Code)
			}
			if loc := w.Header().Get("Location"); loc != "/" {
				t.Fatalf("Location = %q, want / (open redirect)", loc)
			}
		})
	}
}

func TestLoginPage_InvalidNextNormalizedInForm(t *testing.T) {
	h, _ := newLoginTestHandlers(t)
	_, _, w := loginPageGET(t, h, "?next=//evil.com", "")
	if next := regexp.MustCompile(`name="next" value="([^"]*)"`).FindStringSubmatch(w.Body.String()); len(next) != 2 || next[1] != "/" {
		t.Fatalf("hidden next = %v, want /", next)
	}
}

// --- HTML error page (no JSON, no reason disclosure) --------------------------

func TestLogin_BadPassword_HTMLErrorWithoutJSON(t *testing.T) {
	h, email := newLoginTestHandlers(t)
	csrf, token, _ := loginPageGET(t, h, "", "")
	form := url.Values{"email": {email}, "password": {"definitely-wrong"}, "_csrf": {token}}
	w := loginPOST(t, h, form, csrf, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad password: got %d, want 401", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Invalid email or password.") {
		t.Fatalf("generic error message missing: %s", body)
	}
	if strings.Contains(body, `"error":`) || strings.HasPrefix(strings.TrimSpace(body), "{") {
		t.Fatalf("HTML error must not be JSON: %s", body)
	}
	// Email preserved, password never.
	if !strings.Contains(body, `value="`+email+`"`) {
		t.Fatalf("email not preserved: %s", body)
	}
	if strings.Contains(body, "definitely-wrong") {
		t.Fatal("password must not be echoed back")
	}
	if strings.Contains(body, "password</p>") || strings.Contains(body, "credentials") {
		t.Fatalf("reason leaked to the client: %s", body)
	}
}

func TestLogin_DisabledAccount_SameGenericHTML401(t *testing.T) {
	h, email := newLoginTestHandlers(t)
	store := h.store.(*csrfHashStore)
	store.adminUsers["admin-1"].Active = false

	csrf, token, _ := loginPageGET(t, h, "", "")
	w := loginPOST(t, h, url.Values{"email": {email}, "password": {"correct-horse"}, "_csrf": {token}}, csrf, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("disabled account: got %d, want 401", w.Code)
	}
	body := w.Body.String()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(body, "Invalid email or password.") {
		t.Fatalf("generic error message missing: %s", body)
	}
	if strings.Contains(strings.ToLower(body), "disabled") || strings.Contains(strings.ToLower(body), "deactiv") {
		t.Fatalf("account state leaked: %s", body)
	}
}

func TestLogin_UnknownUser_SameGenericHTML401(t *testing.T) {
	h, _ := newLoginTestHandlers(t)
	csrf, token, _ := loginPageGET(t, h, "", "")
	w := loginPOST(t, h, url.Values{"email": {"nobody@example.com"}, "password": {"x"}, "_csrf": {token}}, csrf, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown user: got %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid email or password.") {
		t.Fatalf("generic error message missing: %s", w.Body.String())
	}
}

// --- localization -------------------------------------------------------------

func TestNegotiateLoginLocale(t *testing.T) {
	cases := []struct {
		header, want string
	}{
		{"", "en"},
		{"garbage", "en"},
		{"*", "en"},
		{"de-DE,de;q=0.9", "en"},
		{"ja", "ja"},
		{"ja-JP,ja;q=0.9", "ja"},
		{"pt-BR,pt;q=0.9,en;q=0.8", "pt-BR"},
		{"pt", "pt-BR"},
		{"PT-br", "pt-BR"},
		{"ar", "ar"},
		{"ar-EG,ar;q=0.9,en;q=0.8", "ar"},
		{"en;q=0.1, ja", "ja"},
		{"ko;q=0.5, id;q=0.9", "id"},
		{"es-419,es;q=0.9", "es"},
		{"ja; q=0.2, ko; q=0.8", "ko"},
		{"ja; q=broken, ko", "ko"},
		{"ja; q=0", "en"},
	}
	for _, tc := range cases {
		if got := negotiateLoginLocale(tc.header); got != tc.want {
			t.Errorf("negotiateLoginLocale(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestLoginPage_LocalizedByAcceptLanguage(t *testing.T) {
	h, _ := newLoginTestHandlers(t)
	cases := []struct {
		accept, marker string
	}{
		{"ja", "メールアドレス"},
		{"ko", "이메일"},
		{"pt-BR,pt;q=0.9", "E-mail"},
		{"ar", `dir="rtl"`},
		{"hi", "पासवर्ड"},
		{"id", "Kata sandi"},
		{"es", "Contraseña"},
		{"", "Sign in"},
	}
	for _, tc := range cases {
		_, _, w := loginPageGET(t, h, "", tc.accept)
		if !strings.Contains(w.Body.String(), tc.marker) {
			t.Errorf("Accept-Language %q: page missing %q", tc.accept, tc.marker)
		}
	}
	_, _, w := loginPageGET(t, h, "", "ar")
	if !strings.Contains(w.Body.String(), `lang="ar"`) {
		t.Error("arabic page must set lang=ar")
	}
}

// --- rate limiting applies to the HTML error path ------------------------------

func TestLogin_HTMLErrorResponse_CountsTowardLoginRateLimit(t *testing.T) {
	h, email := newLoginTestHandlers(t)
	handler := h.loginRateLimitMiddleware(h.HandleLogin())

	sawHTML401 := false
	for i := 0; i < 7; i++ {
		csrf, token, _ := loginPageGET(t, h, "", "")
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/login",
			strings.NewReader(url.Values{"email": {email}, "password": {"wrong"}, "_csrf": {token}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrf)
		req.RemoteAddr = "203.0.113.77:1444" // unique IP: no cross-test interference
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		switch {
		case i < 5:
			if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("attempt %d: got %d %q, want 401 text/html", i, w.Code, w.Header().Get("Content-Type"))
			}
			sawHTML401 = true
		default:
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("attempt %d: got %d, want 429 (HTML path must not bypass the limit)", i, w.Code)
			}
		}
	}
	if !sawHTML401 {
		t.Fatal("expected at least one HTML 401 before the limit")
	}
}

// --- logout -------------------------------------------------------------------

func mountLogoutHotPatch(h *AdminHandlers) http.Handler {
	r := chi.NewRouter()
	r.Get("/auth/logout", h.HandleLogout())
	r.With(adminauth.CSRFValidation()).Post("/auth/logout", h.HandleLogout())
	return r
}

func TestLogoutPost_RequiresCSRF(t *testing.T) {
	h, _ := newLoginTestHandlers(t)
	router := mountLogoutHotPatch(h)

	// Without a CSRF token the POST must be refused.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/logout", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST logout without csrf: got %d, want 403", w.Code)
	}

	// With cookie + form token it logs out: 302 to the login page and both
	// cookies cleared.
	token := adminauth.GenerateCSRFToken(httptest.NewRecorder())
	w = httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/logout",
		strings.NewReader(url.Values{"_csrf": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	router.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("POST logout with csrf: got %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/auth/login" {
		t.Fatalf("logout Location = %q, want /auth/login", loc)
	}
	cleared := map[string]bool{}
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" || c.Name == "yabanin_csrf_token" {
			cleared[c.Name] = c.MaxAge < 0
		}
	}
	if !cleared["yabanin_admin_session"] || !cleared["yabanin_csrf_token"] {
		t.Fatalf("cookies not cleared: %v", cleared)
	}
}

// Documents the backward-compatible GET /auth/logout behavior kept by OD-08
// (RM-40 finding F1): 302 to the login page with both cookies cleared — the
// least sensitive state change, nuisance-level logout-CSRF at worst (the
// handler is unconditional and sends no data). The CSRF-validated POST twin
// is the intended route (TestLogoutPost_RequiresCSRF); GET stays for old
// links/bookmarks.
func TestLogoutGET_BackwardCompatible(t *testing.T) {
	h, _ := newLoginTestHandlers(t)
	router := mountLogoutHotPatch(h)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/logout", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("GET logout: got %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/auth/login" {
		t.Fatalf("GET logout Location = %q, want /auth/login", loc)
	}
	cleared := map[string]bool{}
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" || c.Name == "yabanin_csrf_token" {
			cleared[c.Name] = c.MaxAge < 0
		}
	}
	if !cleared["yabanin_admin_session"] || !cleared["yabanin_csrf_token"] {
		t.Fatalf("GET logout did not clear both cookies: %v", cleared)
	}
}

// --- login page base rendering --------------------------------------------------

func TestLoginPage_PaperOliveTokensEmbedded(t *testing.T) {
	h, _ := newLoginTestHandlers(t)
	_, _, w := loginPageGET(t, h, "", "")
	body := w.Body.String()
	for _, token := range []string{"#f2efe6", "#faf8f1", "#292d24", "#59633f", "#4c6236", "--height-control:44px", "border-radius:var(--radius-control)"} {
		if !strings.Contains(body, token) {
			t.Errorf("login page missing Paper & Olive token %q", token)
		}
	}
	if !strings.Contains(body, `name="next"`) {
		t.Error("login page must carry the next parameter through the form")
	}
}

func TestLogin_SuccessIssuesSessionAndDefaultsToRoot(t *testing.T) {
	h, email := newLoginTestHandlers(t)
	csrf, token, _ := loginPageGET(t, h, "", "")
	w := loginPOST(t, h, url.Values{"email": {email}, "password": {"correct-horse"}, "_csrf": {token}}, csrf, "")
	if w.Code != http.StatusFound {
		t.Fatalf("login: got %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Fatalf("Location = %q, want /", loc)
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session cookie issued")
	}
	sess, err := adminauth.ParseAdminSessionCookie(session.Value, sessionKey())
	if err != nil {
		t.Fatalf("session cookie does not verify: %v", err)
	}
	if sess.Email != email || !sess.IsRoot {
		t.Fatalf("session identity: %+v", sess)
	}
}

// W-SECADM: the password issuer must honor adminauth.SessionDuration (24h),
// not the legacy hardcoded week.
func TestLogin_SessionUsesConfiguredDuration(t *testing.T) {
	h, email := newLoginTestHandlers(t)
	csrf, token, _ := loginPageGET(t, h, "", "")
	w := loginPOST(t, h, url.Values{"email": {email}, "password": {"correct-horse"}, "_csrf": {token}}, csrf, "")
	if w.Code != http.StatusFound {
		t.Fatalf("login: got %d, want 302", w.Code)
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session cookie issued")
	}
	sess, err := adminauth.ParseAdminSessionCookie(session.Value, sessionKey())
	if err != nil {
		t.Fatalf("session cookie does not verify: %v", err)
	}
	lifetime := time.Until(sess.ExpiresAt)
	if lifetime < adminauth.SessionDuration-time.Minute || lifetime > adminauth.SessionDuration+time.Minute {
		t.Fatalf("session lifetime %s, want ~%s (adminauth.SessionDuration)", lifetime, adminauth.SessionDuration)
	}
}
