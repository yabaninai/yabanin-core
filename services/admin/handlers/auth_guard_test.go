package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminauth"
)

// watermarkStore records per-user invalidation times, standing in for the
// admin_users.sessions_changed_at column that the password-change write
// updates (migration 0024).
type watermarkStore struct {
	*csrfHashStore
	mu  sync.Mutex
	inv map[string]time.Time
}

type captureRevocationStore struct {
	sessionID string
	err       error
}

func (*captureRevocationStore) IsRevoked(context.Context, string) (bool, error) { return false, nil }
func (s *captureRevocationStore) Revoke(_ context.Context, id string, _ time.Time) error {
	s.sessionID = id
	return s.err
}

func TestLogoutWritesDurableRevocationStore(t *testing.T) {
	secret := strings.Join([]string{"logout", "durable", "store", "secret"}, "-")
	store := &captureRevocationStore{}
	h := New(nil, secret, "localhost", nil)
	h.sessionRevocations = store
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID: "admin", SessionID: "logout-durable-session", ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.HandleLogout().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || store.sessionID != "logout-durable-session" {
		t.Fatalf("logout status=%d persisted session=%q", rec.Code, store.sessionID)
	}
	cleared := false
	for _, setCookie := range rec.Result().Cookies() {
		if setCookie.Name == "yabanin_admin_session" && (setCookie.MaxAge < 0 || setCookie.Value == "") {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("successful logout did not clear the session cookie")
	}
}

func TestLogoutRevocationFailureKeepsCookieAndReturnsError(t *testing.T) {
	secret := strings.Join([]string{"logout", "durable", "failure", "secret"}, "-")
	store := &captureRevocationStore{err: context.DeadlineExceeded}
	h := New(nil, secret, "localhost", nil)
	h.sessionRevocations = store
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID: "admin", SessionID: "logout-failed-session", ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.HandleLogout().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("logout must fail closed with exactly 503, got %d", rec.Code)
	}
	if store.sessionID != "logout-failed-session" {
		t.Fatalf("persisted session=%q", store.sessionID)
	}
	for _, setCookie := range rec.Result().Cookies() {
		if setCookie.Name == "yabanin_admin_session" && (setCookie.MaxAge < 0 || setCookie.Value == "") {
			t.Fatalf("failed logout cleared session cookie: %+v", setCookie)
		}
	}
}

func (s *watermarkStore) GetAdminUserSessionsInvalidatedAt(ctx context.Context, userID string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inv == nil {
		return time.Time{}, nil
	}
	return s.inv[userID], nil
}

func (s *watermarkStore) markPasswordChanged(userID string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inv == nil {
		s.inv = make(map[string]time.Time)
	}
	s.inv[userID] = at
}

func newWatermarkTestHandlers(t *testing.T) (*AdminHandlers, *watermarkStore) {
	t.Helper()
	hash, err := adminauth.HashPassword("correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	st := &watermarkStore{csrfHashStore: &csrfHashStore{mockStore: newMockStore(), hash: hash}}
	if _, err := st.CreateAdminUser(t.Context(), "login-admin@example.com", "Login Admin", hash, true); err != nil {
		t.Fatal(err)
	}
	hh := New(st, sessionKey(), "", nil)
	hh.logger = quietLogger()
	return hh, st
}

func protectedRouter(hh *AdminHandlers) http.Handler {
	router := chi.NewRouter()
	router.Use(adminauth.ChiAuthMiddlewareGuarded(hh.sessionSecret, hh.adminSessionsInvalidatedAt))
	router.Get("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	return router
}

func loginSessionCookie(t *testing.T, hh *AdminHandlers) *http.Cookie {
	t.Helper()
	csrf, token, _ := loginPageGET(t, hh, "", "")
	form := url.Values{
		"email":    {"login-admin@example.com"},
		"password": {"correct-horse"},
		"_csrf":    {token},
	}
	rec := loginPOST(t, hh, form, csrf, "")
	if rec.Code != http.StatusFound {
		t.Fatalf("login: got %d, want 302", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "yabanin_admin_session" && c.Value != "" {
			return c
		}
	}
	t.Fatal("login did not set the session cookie")
	return nil
}

func TestPasswordChangeInvalidatesIssuedSession(t *testing.T) {
	hh, st := newWatermarkTestHandlers(t)
	router := protectedRouter(hh)

	cookie := loginSessionCookie(t, hh)
	parsed, err := adminauth.ParseAdminSessionCookie(cookie.Value, sessionKey())
	if err != nil {
		t.Fatalf("parse issued cookie: %v", err)
	}
	if parsed.IssuedAt.IsZero() {
		t.Fatal("issued cookie must carry a non-zero issued-at")
	}

	// Session issued before any invalidation is accepted.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fresh session: got %d, want 200", rec.Code)
	}

	// Password change records the watermark now().
	st.markPasswordChanged(parsed.UserID, time.Now())

	// The same cookie is now rejected.
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("session issued before password change: got %d, want 401", rec.Code)
	}

	// A fresh login is accepted again.
	fresh := loginSessionCookie(t, hh)
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(fresh)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("session issued after password change: got %d, want 200", rec.Code)
	}
}

func TestStoreWithoutWatermarkAccessorKeepsUnguardedBehavior(t *testing.T) {
	hh, _ := newWatermarkTestHandlers(t)
	// Strip the accessor: the plain store predates migration 0024.
	plain := hh.store.(*watermarkStore).csrfHashStore
	hh2 := New(plain, sessionKey(), "", nil)
	hh2.logger = quietLogger()
	router := protectedRouter(hh2)

	cookie := loginSessionCookie(t, hh2)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("store without watermark accessor: got %d, want 200 (legacy contract)", rec.Code)
	}
}

func TestLogoutRevokesReplayedSessionCookie(t *testing.T) {
	hh, _ := newWatermarkTestHandlers(t)
	cookie := loginSessionCookie(t, hh)

	logoutReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutRec := httptest.NewRecorder()
	hh.HandleLogout().ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusFound {
		t.Fatalf("logout: got %d, want 302", logoutRec.Code)
	}

	// Replay the saved cookie through a separately-constructed middleware
	// instance sharing the process revocation source, as another replica does.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	secondReplica := protectedRouter(hh)
	secondReplica.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session replay: got %d, want 401", rec.Code)
	}
}
