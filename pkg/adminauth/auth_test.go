package adminauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCreateAndParseSessionCookie(t *testing.T) {
	secret := "test-secret"
	session := AdminSession{
		UserID:    "user-1",
		Email:     "admin@example.com",
		IsRoot:    true,
		SessionID: "sess-abc",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	cookie, err := CreateAdminSessionCookie(session, secret)
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie error: %v", err)
	}

	if cookie.Name != sessionCookieName {
		t.Errorf("expected cookie name %q, got %q", sessionCookieName, cookie.Name)
	}
	if !cookie.HttpOnly {
		t.Error("expected HttpOnly to be true")
	}
	if !cookie.Secure {
		t.Error("expected Secure to be true")
	}

	parsed, err := ParseAdminSessionCookie(cookie.Value, secret)
	if err != nil {
		t.Fatalf("ParseAdminSessionCookie error: %v", err)
	}
	if parsed.UserID != session.UserID {
		t.Errorf("expected UserID %q, got %q", session.UserID, parsed.UserID)
	}
	if parsed.Email != session.Email {
		t.Errorf("expected Email %q, got %q", session.Email, parsed.Email)
	}
	if parsed.IsRoot != session.IsRoot {
		t.Errorf("expected IsRoot %v, got %v", session.IsRoot, parsed.IsRoot)
	}
	if parsed.SessionID != session.SessionID {
		t.Errorf("expected SessionID %q, got %q", session.SessionID, parsed.SessionID)
	}
}

func TestSessionCookieRotationGraceAndCurrentSigning(t *testing.T) {
	oldKey, currentKey := strings.Repeat("o", 32), strings.Repeat("n", 32)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	session := AdminSession{UserID: "admin-rotation", SessionID: "rotation-session", ExpiresAt: start.Add(48 * time.Hour)}
	oldCookie, err := CreateAdminSessionCookie(session, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, usedPrevious, err := ParseAdminSessionCookieRotating(oldCookie.Value, currentKey, oldKey, start, 24*time.Hour, start.Add(time.Hour))
	if err != nil || !usedPrevious || parsed.UserID != session.UserID {
		t.Fatalf("grace validation: session=%+v previous=%v err=%v", parsed, usedPrevious, err)
	}
	if _, _, err := ParseAdminSessionCookieRotating(oldCookie.Value, currentKey, oldKey, start, 24*time.Hour, start.Add(24*time.Hour)); err == nil {
		t.Fatal("previous key accepted at grace deadline")
	}
	newCookie, err := CreateAdminSessionCookie(session, currentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAdminSessionCookie(newCookie.Value, currentKey); err != nil {
		t.Fatalf("new cookie not signed by current key: %v", err)
	}
	if _, err := ParseAdminSessionCookie(newCookie.Value, oldKey); err == nil {
		t.Fatal("new cookie was signed by previous key")
	}
}

func TestSessionCookieRotationConcurrent(t *testing.T) {
	oldKey, currentKey := strings.Repeat("o", 32), strings.Repeat("n", 32)
	start := time.Now()
	cookie, err := CreateAdminSessionCookie(AdminSession{UserID: "admin", SessionID: "concurrent", ExpiresAt: start.Add(time.Hour)}, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, usedPrevious, err := ParseAdminSessionCookieRotating(cookie.Value, currentKey, oldKey, start, time.Hour, start.Add(time.Minute)); err != nil || !usedPrevious {
				t.Errorf("concurrent parse: previous=%v err=%v", usedPrevious, err)
			}
		}()
	}
	wg.Wait()
}

func TestParseSessionCookie_IsRootFalse(t *testing.T) {
	secret := "test-secret"
	session := AdminSession{
		UserID:    "user-2",
		Email:     "editor@example.com",
		IsRoot:    false,
		SessionID: "sess-def",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	cookie, err := CreateAdminSessionCookie(session, secret)
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie error: %v", err)
	}

	parsed, err := ParseAdminSessionCookie(cookie.Value, secret)
	if err != nil {
		t.Fatalf("ParseAdminSessionCookie error: %v", err)
	}
	if parsed.IsRoot {
		t.Error("expected IsRoot to be false")
	}
}

func TestParseSessionCookie_TamperedSignature(t *testing.T) {
	secret := "test-secret"
	session := AdminSession{
		UserID:    "user-1",
		Email:     "admin@example.com",
		IsRoot:    true,
		SessionID: "sess-abc",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	cookie, err := CreateAdminSessionCookie(session, secret)
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie error: %v", err)
	}

	// Tamper with the cookie value so the decoded signature bytes are
	// guaranteed to change: the second-to-last base64 character carries six
	// full data bits, so replacing it always changes the MAC content. (The
	// historical "append XX" tamper occasionally produced a non-canonical
	// base64 spelling of the *same* MAC bytes — tokens with suffix "XU",
	// about 1/1024, decode identically to "XX" under a lenient decoder —
	// which made this test fail roughly once per 1024 distinct tokens. The
	// parser now rejects non-canonical spellings outright; see
	// TestParseSessionCookie_RejectsNonCanonicalMac.)
	suffix := cookie.Value[len(cookie.Value)-2:]
	replacement := []byte{'A', 'A'}
	if suffix[0] == 'A' {
		replacement[0] = 'B'
	}
	tampered := cookie.Value[:len(cookie.Value)-2] + string(replacement)
	if tampered == cookie.Value {
		t.Fatal("test bug: tampered value equals the original")
	}
	_, err = ParseAdminSessionCookie(tampered, secret)
	if err == nil {
		t.Fatal("expected error for tampered cookie, got nil")
	}
}

// TestParseSessionCookie_RejectsNonCanonicalMac pins the parser against the
// AUTHFLAKESEC1 finding: Go's lenient base64 decoding ignores the two
// discarded bits of the final base64 character, so a token whose MAC ends in
// "XU" (about 1/1024 of tokens) re-spelled with suffix "XX" decodes to the
// exact same MAC bytes and used to be accepted as a second, malleable
// spelling of the same cookie. The signature must verify only in its exact
// issued, canonical form.
func TestParseSessionCookie_RejectsNonCanonicalMac(t *testing.T) {
	const secret = "test-secret"
	var token string
	for i := 0; i < 200000; i++ {
		cookie, err := CreateAdminSessionCookie(AdminSession{
			UserID:    "user-1",
			Email:     "admin@example.com",
			IsRoot:    true,
			SessionID: fmt.Sprintf("sess-%d", i),
			ExpiresAt: time.Unix(4102444800, 0),
		}, secret)
		if err != nil {
			t.Fatalf("CreateAdminSessionCookie error: %v", err)
		}
		if cookie.Value[len(cookie.Value)-2:] == "XU" {
			token = cookie.Value
			break
		}
	}
	if token == "" {
		t.Fatal("no XU-suffix token found in 200000 tries (expected ~1/1024)")
	}

	if _, err := ParseAdminSessionCookie(token, secret); err != nil {
		t.Fatalf("canonical token rejected: %v", err)
	}

	// The exact historical flake transformation: last two characters -> "XX".
	tampered := token[:len(token)-2] + "XX"
	if tampered == token {
		t.Fatal("test bug: tampered value equals the original")
	}
	if _, err := ParseAdminSessionCookie(tampered, secret); err == nil {
		t.Fatal("non-canonical MAC spelling of a valid token was accepted")
	}
}

func TestParseSessionCookie_WrongSecret(t *testing.T) {
	secret := "correct-secret"
	wrongSecret := "wrong-secret"
	session := AdminSession{
		UserID:    "user-1",
		Email:     "admin@example.com",
		IsRoot:    true,
		SessionID: "sess-abc",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	cookie, err := CreateAdminSessionCookie(session, secret)
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie error: %v", err)
	}

	_, err = ParseAdminSessionCookie(cookie.Value, wrongSecret)
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
}

func TestParseSessionCookie_MalformedNoPipe(t *testing.T) {
	_, err := ParseAdminSessionCookie("no-pipes-here", "secret")
	if err == nil {
		t.Fatal("expected error for malformed cookie without pipe, got nil")
	}
}

func TestParseSessionCookie_InvalidBase64Mac(t *testing.T) {
	_, err := ParseAdminSessionCookie("payload|!!!invalid-base64!!!", "secret")
	if err == nil {
		t.Fatal("expected error for invalid base64 MAC, got nil")
	}
}

func TestParseSessionCookie_ExpiredSession(t *testing.T) {
	secret := "test-secret"
	session := AdminSession{
		UserID:    "user-1",
		Email:     "admin@example.com",
		IsRoot:    true,
		SessionID: "sess-abc",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // expired 1 hour ago
	}

	cookie, err := CreateAdminSessionCookie(session, secret)
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie error: %v", err)
	}

	// Cookie value itself parses fine (MAC is valid), but middleware should reject it
	parsed, err := ParseAdminSessionCookie(cookie.Value, secret)
	if err != nil {
		t.Fatalf("ParseAdminSessionCookie should not error on expired cookie: %v", err)
	}
	if !parsed.ExpiresAt.Before(time.Now()) {
		t.Error("expected session to be expired")
	}
}

func TestClearSessionCookie(t *testing.T) {
	cookie := ClearSessionCookie()
	if cookie.Name != sessionCookieName {
		t.Errorf("expected name %q, got %q", sessionCookieName, cookie.Name)
	}
	if cookie.Value != "" {
		t.Errorf("expected empty value, got %q", cookie.Value)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("expected MaxAge -1, got %d", cookie.MaxAge)
	}
}

func TestChiAuthMiddleware_ValidSession(t *testing.T) {
	secret := "test-secret"
	session := AdminSession{
		UserID:    "user-1",
		Email:     "admin@example.com",
		IsRoot:    true,
		SessionID: "sess-abc",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	cookie, err := CreateAdminSessionCookie(session, secret)
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie error: %v", err)
	}

	middleware := ChiAuthMiddleware(secret)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminUser, ok := AdminUserFromContext(r)
		if !ok {
			t.Fatal("expected admin user from context")
		}
		if adminUser.ID != session.UserID {
			t.Errorf("expected userID %q, got %q", session.UserID, adminUser.ID)
		}
		if adminUser.Email != session.Email {
			t.Errorf("expected email %q, got %q", session.Email, adminUser.Email)
		}
		if !adminUser.IsRoot {
			t.Error("expected IsRoot to be true")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestChiAuthMiddleware_NoCookie(t *testing.T) {
	middleware := ChiAuthMiddleware("secret")
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

// K3: unauthenticated API requests get a JSON 401 body for machine clients,
// while non-API paths keep the legacy plain-text 401 (SPA behavior unchanged).
func TestChiAuthMiddleware_UnauthorizedBodyFormat(t *testing.T) {
	middleware := ChiAuthMiddleware("secret")
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// API path -> JSON
	apiReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/analytics/stats", nil)
	apiRec := httptest.NewRecorder()
	handler.ServeHTTP(apiRec, apiReq)
	if apiRec.Code != http.StatusUnauthorized {
		t.Fatalf("api path: expected 401, got %d", apiRec.Code)
	}
	if ct := apiRec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("api path: expected JSON content type, got %q", ct)
	}
	if body := apiRec.Body.String(); body != `{"error":"unauthorized"}` {
		t.Errorf("api path: expected JSON body, got %q", body)
	}

	// Non-API path -> legacy plain text
	webReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/dashboard", nil)
	webRec := httptest.NewRecorder()
	handler.ServeHTTP(webRec, webReq)
	if webRec.Code != http.StatusUnauthorized {
		t.Fatalf("web path: expected 401, got %d", webRec.Code)
	}
	if body := webRec.Body.String(); body != "unauthorized\n" {
		t.Errorf("web path: expected plain-text body, got %q", body)
	}
}

func TestChiAuthMiddleware_InvalidSignature(t *testing.T) {
	middleware := ChiAuthMiddleware("secret")
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "tampered|signature", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestChiAuthMiddleware_ExpiredSession(t *testing.T) {
	secret := "test-secret"
	session := AdminSession{
		UserID:    "user-1",
		Email:     "admin@example.com",
		IsRoot:    true,
		SessionID: "sess-abc",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	cookie, err := CreateAdminSessionCookie(session, secret)
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie error: %v", err)
	}

	middleware := ChiAuthMiddleware(secret)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for expired session, got %d", rec.Code)
	}

	// Verify the cookie was cleared in the response
	respCookies := rec.Result().Cookies()
	var foundCleared bool
	for _, c := range respCookies {
		if c.Name == sessionCookieName && c.MaxAge == -1 {
			foundCleared = true
			break
		}
	}
	if !foundCleared {
		t.Error("expected cleared cookie with MaxAge -1 in response")
	}
}

func TestMustBeRoot_AllowsRoot(t *testing.T) {
	middleware := MustBeRoot()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), ContextKeyIsRoot{}, true)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 for root user, got %d", rec.Code)
	}
}

func TestMustBeRoot_RejectsNonRoot(t *testing.T) {
	middleware := MustBeRoot()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), ContextKeyIsRoot{}, false)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for non-root user, got %d", rec.Code)
	}
}

func TestMustBeRoot_RejectsMissingRoot(t *testing.T) {
	middleware := MustBeRoot()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for missing root flag, got %d", rec.Code)
	}
}

func TestAdminUserFromContext_MissingFields(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	_, ok := AdminUserFromContext(req)
	if ok {
		t.Error("expected false for missing admin user in context")
	}
}

func TestExtractAdminEmail(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	email := ExtractAdminEmail(req)
	if email != "" {
		t.Errorf("expected empty email, got %q", email)
	}

	ctx := context.WithValue(req.Context(), ContextKeyEmail{}, "test@example.com")
	req = req.WithContext(ctx)
	email = ExtractAdminEmail(req)
	if email != "test@example.com" {
		t.Errorf("expected test@example.com, got %q", email)
	}
}

func TestSanitizeForURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"admin@example.com", "admin_at_example.com"},
		{"user.name@domain.org", "user_name_at_domain.org"},
		{"simple", "simple"},
	}

	for _, tt := range tests {
		result := SanitizeForURL(tt.input)
		if result != tt.expected {
			t.Errorf("SanitizeForURL(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestAuthFromHeader_ValidKey(t *testing.T) {
	middleware := AuthFromHeader("secret-key")
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("X-Admin-Key", "secret-key")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestAuthFromHeader_WrongKey(t *testing.T) {
	middleware := AuthFromHeader("secret-key")
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("X-Admin-Key", "wrong-key")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestAuthFromHeader_MissingKey(t *testing.T) {
	middleware := AuthFromHeader("secret-key")
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestAuthFromHeader_EmptyKey_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when key is empty, got none")
		}
	}()
	AuthFromHeader("")
}

func TestDBProvider_Authenticate_Success(t *testing.T) {
	dbProvider := &DBProvider{
		GetPasswordHash: func(ctx context.Context, email string) (string, error) {
			hashed, _ := HashPassword("correct-password")
			return hashed, nil
		},
		GetUserByIDFn: func(ctx context.Context, id string) (*AdminUser, error) {
			return &AdminUser{ID: "user-1", Email: id, DisplayName: "Admin User", IsRoot: true, Active: true}, nil
		},
	}

	user, err := dbProvider.Authenticate(context.Background(), "admin@example.com", "correct-password")
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if user.ID != "user-1" {
		t.Errorf("expected userID %q, got %q", "user-1", user.ID)
	}
}

func TestDBProvider_Authenticate_WrongPassword(t *testing.T) {
	dbProvider := &DBProvider{
		GetPasswordHash: func(ctx context.Context, email string) (string, error) {
			hashed, _ := HashPassword("correct-password")
			return hashed, nil
		},
		GetUserByIDFn: func(ctx context.Context, id string) (*AdminUser, error) {
			return nil, nil //nolint:nilnil // test stub: user lookup is not reached in this scenario
		},
	}

	_, err := dbProvider.Authenticate(context.Background(), "admin@example.com", "wrong-password")
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestDBProvider_Authenticate_HashLookupError(t *testing.T) {
	dbProvider := &DBProvider{
		GetPasswordHash: func(ctx context.Context, email string) (string, error) {
			return "", fmt.Errorf("database error")
		},
		GetUserByIDFn: func(ctx context.Context, id string) (*AdminUser, error) {
			return nil, nil //nolint:nilnil // test stub: user lookup is not reached in this scenario
		},
	}

	_, err := dbProvider.Authenticate(context.Background(), "admin@example.com", "any-password")
	if err == nil {
		t.Fatal("expected error for hash lookup failure, got nil")
	}
}

func TestDBProvider_GetUserByID(t *testing.T) {
	expectedUser := &AdminUser{ID: "user-1", Email: "admin@example.com"}
	dbProvider := &DBProvider{
		GetUserByIDFn: func(ctx context.Context, id string) (*AdminUser, error) {
			return expectedUser, nil
		},
	}

	user, err := dbProvider.GetUserByID(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("GetUserByID error: %v", err)
	}
	if user.ID != expectedUser.ID {
		t.Errorf("expected ID %q, got %q", expectedUser.ID, user.ID)
	}
}

func TestSessionDuration_Default(t *testing.T) {
	expected := 24 * time.Hour
	if SessionDuration != expected {
		t.Errorf("expected default SessionDuration %v, got %v", expected, SessionDuration)
	}
}

// --- CSRF Tests ---

func TestGenerateCSRFToken_ReturnsTokenAndSetsCookie(t *testing.T) {
	w := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := GenerateCSRFToken(w)
		_, _ = w.Write([]byte(token))
	})
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))

	resp := w.Result()
	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body error: %v", err)
	}
	token := string(tokenBytes)
	if len(token) == 0 {
		t.Fatal("expected non-empty CSRF token")
	}

	cookies := resp.Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == csrfCookieName {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("expected CSRF cookie in response")
	}
	if csrfCookie.Value != token {
		t.Errorf("expected cookie value %q, got %q", token, csrfCookie.Value)
	}
	if !csrfCookie.HttpOnly {
		t.Error("expected CSRF cookie to be HttpOnly")
	}
	if !csrfCookie.Secure {
		t.Error("expected CSRF cookie to be Secure")
	}
	if csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite %v, got %v", http.SameSiteStrictMode, csrfCookie.SameSite)
	}
}

func TestGenerateCSRFToken_Uniqueness(t *testing.T) {
	w1 := httptest.NewRecorder()
	token1 := GenerateCSRFToken(w1)
	w2 := httptest.NewRecorder()
	token2 := GenerateCSRFToken(w2)
	if token1 == token2 {
		t.Fatal("expected two CSRF tokens to be different")
	}
}

func TestCSRFValidation_GETExempted(t *testing.T) {
	middleware := CSRFValidation()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET request should be exempted from CSRF validation, got status %d", rec.Code)
	}
}

func TestCSRFValidation_HEADExempted(t *testing.T) {
	middleware := CSRFValidation()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodHead, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("HEAD request should be exempted from CSRF validation, got status %d", rec.Code)
	}
}

func TestCSRFValidation_OPTIONSExempted(t *testing.T) {
	middleware := CSRFValidation()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("OPTIONS request should be exempted from CSRF validation, got status %d", rec.Code)
	}
}

func TestCSRFValidation_ValidToken(t *testing.T) {
	middleware := CSRFValidation()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
	req.Header.Set(csrfHeaderName, "valid-token")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "valid-token", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 for valid CSRF token, got %d", rec.Code)
	}
}

func TestCSRFValidation_MissingToken(t *testing.T) {
	middleware := CSRFValidation()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for missing CSRF cookie, got %d", rec.Code)
	}
}

func TestCSRFValidation_MissingCookie(t *testing.T) {
	middleware := CSRFValidation()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
	req.Header.Set(csrfHeaderName, "some-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for missing CSRF cookie, got %d", rec.Code)
	}
}

func TestCSRFValidation_WrongToken(t *testing.T) {
	middleware := CSRFValidation()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
	req.Header.Set(csrfHeaderName, "wrong-token")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "expected-token", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for wrong CSRF token, got %d", rec.Code)
	}
}

func TestCSRFValidation_FormValueFallback(t *testing.T) {
	middleware := CSRFValidation()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := "method=POST&_csrf=form-token"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "form-token", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 for form-value CSRF token, got %d", rec.Code)
	}
}

func TestCSRFValidation_InvalidBase64HeaderToken(t *testing.T) {
	middleware := CSRFValidation()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
	req.Header.Set(csrfHeaderName, "!!!invalid-base64!!!")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "valid-token", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for invalid header token, got %d", rec.Code)
	}
}

func TestCSRFValidation_PUTRequest(t *testing.T) {
	middleware := CSRFValidation()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/", nil)
	req.Header.Set(csrfHeaderName, "valid-token")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "valid-token", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 for PUT with valid CSRF token, got %d", rec.Code)
	}
}

func TestCSRFValidation_DELETERequest(t *testing.T) {
	middleware := CSRFValidation()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/", nil)
	req.Header.Set(csrfHeaderName, "valid-token")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "valid-token", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 for DELETE with valid CSRF token, got %d", rec.Code)
	}
}

func TestCSRFValidation_RejectsHostileBrowserOrigins(t *testing.T) {
	for _, tc := range []struct {
		name      string
		origin    string
		fetchSite string
	}{
		{name: "foreign origin", origin: "https://evil.example", fetchSite: "cross-site"},
		{name: "same-site sibling", origin: "http://sibling.example.test", fetchSite: "same-site"},
		{name: "cross-site marker", fetchSite: "cross-site"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			mw := CSRFValidation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://admin.example.test/api/change", nil)
			req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			req.Header.Set(csrfHeaderName, "token")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			}
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || called {
				t.Fatalf("hostile browser request: status=%d called=%v; want 403/not called", rec.Code, called)
			}
		})
	}
}

func TestCSRFValidation_AllowsAPIClientWithoutBrowserMarkers(t *testing.T) {
	mw := CSRFValidation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://admin.example.test/api/change", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	req.Header.Set(csrfHeaderName, "token")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("browser-marker-free API request: got %d, want 204", rec.Code)
	}
}

// --- Cookie Hardening Tests ---

func TestCreateAdminSessionCookie_SameSiteStrict(t *testing.T) {
	session := AdminSession{
		UserID:    "user-1",
		Email:     "admin@example.com",
		IsRoot:    true,
		SessionID: "sess-abc",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	cookie, err := CreateAdminSessionCookie(session, "secret")
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie error: %v", err)
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite %v, got %v", http.SameSiteStrictMode, cookie.SameSite)
	}
}

func TestCreateAdminSessionCookie_SecureTrue(t *testing.T) {
	session := AdminSession{
		UserID:    "user-1",
		Email:     "admin@example.com",
		IsRoot:    true,
		SessionID: "sess-abc",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	cookie, err := CreateAdminSessionCookie(session, "secret")
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie error: %v", err)
	}
	if !cookie.Secure {
		t.Error("expected Secure to be true on session cookie")
	}
}

func TestClearSessionCookie_SameSiteStrict(t *testing.T) {
	cookie := ClearSessionCookie()
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite %v, got %v", http.SameSiteStrictMode, cookie.SameSite)
	}
	if !cookie.Secure {
		t.Error("expected Secure to be true on clear session cookie")
	}
}

// TP-02: with a revalidator wired, the live store decides existence and
// role; the cookie's stale IsRoot must not survive a demotion or deletion.
func TestChiAuthMiddleware_SessionRevalidation(t *testing.T) {
	secret := "test-secret"
	newCookie := func(isRoot bool) *http.Cookie {
		session := AdminSession{
			UserID:    "user-1",
			Email:     "admin@example.com",
			IsRoot:    isRoot,
			SessionID: "sess-abc",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		cookie, err := CreateAdminSessionCookie(session, secret)
		if err != nil {
			t.Fatalf("CreateAdminSessionCookie error: %v", err)
		}
		return cookie
	}
	run := func(t *testing.T, revalidate SessionRevalidator, isRootCookie bool) *httptest.ResponseRecorder {
		t.Helper()
		handler := ChiAuthMiddleware(secret, revalidate)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.AddCookie(newCookie(isRootCookie))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	t.Run("deleted user lookup error fails closed", func(t *testing.T) {
		rec := run(t, func(context.Context, string) (bool, bool, error) {
			return false, false, errors.New("get admin user: no rows")
		}, true)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("deleted user with root cookie = %d, want 401", rec.Code)
		}
	})

	t.Run("deactivated user is rejected", func(t *testing.T) {
		rec := run(t, func(context.Context, string) (bool, bool, error) {
			return true, false, nil
		}, true)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("inactive user = %d, want 401", rec.Code)
		}
	})

	t.Run("demoted root loses the root flag from the cookie", func(t *testing.T) {
		var sawRoot bool
		handler := ChiAuthMiddleware(secret, func(context.Context, string) (bool, bool, error) {
			return false, true, nil
		})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawRoot, _ = r.Context().Value(ContextKeyIsRoot{}).(bool)
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.AddCookie(newCookie(true))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("demoted but active user = %d, want 200", rec.Code)
		}
		if sawRoot {
			t.Error("context kept IsRoot=true from the cookie after DB demotion")
		}
	})

	t.Run("active root keeps access", func(t *testing.T) {
		rec := run(t, func(context.Context, string) (bool, bool, error) {
			return true, true, nil
		}, true)
		if rec.Code != http.StatusOK {
			t.Errorf("active root = %d, want 200", rec.Code)
		}
	})

	t.Run("without revalidator the cookie role is kept (back-compat)", func(t *testing.T) {
		handler := ChiAuthMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if root, _ := r.Context().Value(ContextKeyIsRoot{}).(bool); !root {
				t.Error("expected cookie IsRoot=true without revalidator")
			}
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.AddCookie(newCookie(true))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("plain middleware = %d, want 200", rec.Code)
		}
	})
}
