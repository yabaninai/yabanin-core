package handlers_test

// W-SECADM: self-service password change (POST /api/me/password).
//
// The store's UpdateAdminUserPasswordHash bumps admin_users.sessions_changed_
// at; the guarded session middleware turns that watermark into a revocation
// of every session issued before the change. The handler re-issues the
// caller's own cookie with a fresh issued-at, so THIS client survives while
// all older sessions (other browsers, stolen cookies) die.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminauth"
	adminstore "github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const pwSecret = "pwchange-test-session-secret" // #nosec G101 -- test-only HMAC key

// pwStore serves the credential surfaces the password-change flow touches.
type pwStore struct {
	stubStore
	email      string
	password   string // current stored hash material (bcrypted lazily)
	newHash    string // what UpdateAdminUserPasswordHash received
	watermark  time.Time
	capable    bool
	bumpCalled bool
}

func newPWStore(t *testing.T) *pwStore {
	t.Helper()
	hash, err := adminauth.HashPassword("correct-horse-12")
	require.NoError(t, err)
	return &pwStore{email: "admin@x.test", password: hash, capable: true}
}

func (s *pwStore) GetAdminUserByID(_ context.Context, id string) (*adminstore.AdminUser, error) {
	if id == "test-admin" {
		return &adminstore.AdminUser{ID: id, Email: s.email, DisplayName: "Admin", Active: true}, nil
	}
	return nil, adminstore.ErrNotFound
}

func (s *pwStore) GetUserOrgRoles(_ context.Context, _ string) (map[string]adminstore.OrgRole, error) {
	return map[string]adminstore.OrgRole{}, nil
}

func (s *pwStore) GetAdminUserByEmailWithHash(_ context.Context, email string) (*adminstore.AdminUserWithHash, error) {
	if email != s.email {
		return nil, adminstore.ErrNotFound
	}
	return &adminstore.AdminUserWithHash{
		ID: "test-admin", Email: s.email, PasswordHash: s.password,
		DisplayName: "Admin", Active: true,
	}, nil
}

func (s *pwStore) UpdateAdminUserPasswordHash(_ context.Context, _ string, passwordHash string) error {
	if !s.capable {
		return nil // never reached: the handler type-asserts before calling
	}
	s.newHash = passwordHash
	s.bumpCalled = true
	s.watermark = time.Now()
	return nil
}

func (s *pwStore) GetAdminUserSessionsInvalidatedAt(_ context.Context, _ string) (time.Time, error) {
	return s.watermark, nil
}

func pwRouter(t *testing.T, store handlers.StoreInterface) http.Handler {
	t.Helper()
	return handlers.New(store, pwSecret, "localhost", nil).SetupRouter()
}

func pwPost(t *testing.T, router http.Handler, cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/me/password", strings.NewReader(body))
	if cookie != "" {
		req.AddCookie(testCookie("yabanin_admin_session", cookie))
		req.AddCookie(testCookie("yabanin_csrf_token", keyHashCSRF))
		req.Header.Set("X-CSRF-Token", keyHashCSRF)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func pwSessionCookie(t *testing.T) string {
	t.Helper()
	return makeSessionCookie(t, "admin@x.test", false, pwSecret)
}

func TestChangeMyPassword_SuccessReissuesSessionAndRevokesOld(t *testing.T) {
	store := newPWStore(t)
	router := pwRouter(t, store)
	oldCookie := pwSessionCookie(t)

	w := pwPost(t, router, oldCookie,
		`{"current_password":"correct-horse-12","new_password":"brand-new-password-34"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// The new hash reached the store and the watermark was bumped.
	require.NotEmpty(t, store.newHash)
	require.NoError(t, adminauth.VerifyPassword("brand-new-password-34", store.newHash))
	require.Error(t, adminauth.VerifyPassword("correct-horse-12", store.newHash))
	require.True(t, store.bumpCalled, "sessions_changed_at must be bumped")

	// A fresh session cookie was issued with a post-watermark issued-at.
	var fresh *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" {
			fresh = c
		}
	}
	require.NotNil(t, fresh, "the caller's own session must be re-issued")
	parsed, err := adminauth.ParseAdminSessionCookie(fresh.Value, pwSecret)
	require.NoError(t, err)
	assert.False(t, parsed.IssuedAt.IsZero(), "re-issued cookie must carry a fresh issued-at")
	assert.True(t, parsed.IssuedAt.After(store.watermark.Add(-time.Second)), "issued-at must postdate the watermark")

	// The OLD cookie (issued before the change) no longer verifies.
	w = httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/me", nil)
	req.AddCookie(testCookie("yabanin_admin_session", oldCookie))
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "the pre-change session must be revoked")

	// The re-issued cookie keeps working.
	w = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/me", nil)
	req.AddCookie(fresh)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "the re-issued session must survive: %s", w.Body.String())
}

func TestChangeMyPassword_WrongCurrentPasswordRejected(t *testing.T) {
	store := newPWStore(t)
	router := pwRouter(t, store)

	w := pwPost(t, router, pwSessionCookie(t),
		`{"current_password":"totally-wrong","new_password":"brand-new-password-34"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Empty(t, store.newHash, "the store must be untouched")
	assert.False(t, store.bumpCalled, "no revocation on a failed verification")
}

func TestChangeMyPassword_ShortNewPasswordRejected(t *testing.T) {
	store := newPWStore(t)
	router := pwRouter(t, store)

	w := pwPost(t, router, pwSessionCookie(t),
		`{"current_password":"correct-horse-12","new_password":"short12char"}`) // 11 chars
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Empty(t, store.newHash)
	assert.False(t, store.bumpCalled)
}

func TestChangeMyPassword_Unauthenticated(t *testing.T) {
	store := newPWStore(t)
	router := pwRouter(t, store)

	w := pwPost(t, router, "", `{"current_password":"x","new_password":"brand-new-password-34"}`)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// noPwCapStore has the lookup surfaces but NOT the UpdateAdminUserPassword
// Hash capability (the stub base does not carry it either) → 501 path.
type noPwCapStore struct {
	stubStore
	hash string
}

func newNoPwCapStore(t *testing.T) *noPwCapStore {
	t.Helper()
	hash, err := adminauth.HashPassword("correct-horse-12")
	require.NoError(t, err)
	return &noPwCapStore{hash: hash}
}

func (s *noPwCapStore) GetAdminUserByID(_ context.Context, id string) (*adminstore.AdminUser, error) {
	if id == "test-admin" {
		return &adminstore.AdminUser{ID: id, Email: "admin@x.test", DisplayName: "Admin", Active: true}, nil
	}
	return nil, adminstore.ErrNotFound
}

func (s *noPwCapStore) GetAdminUserByEmailWithHash(_ context.Context, email string) (*adminstore.AdminUserWithHash, error) {
	if email != "admin@x.test" {
		return nil, adminstore.ErrNotFound
	}
	return &adminstore.AdminUserWithHash{
		ID: "test-admin", Email: email, PasswordHash: s.hash,
		DisplayName: "Admin", Active: true,
	}, nil
}

func (s *noPwCapStore) GetAdminUserSessionsInvalidatedAt(_ context.Context, _ string) (time.Time, error) {
	return time.Time{}, nil
}

func TestChangeMyPassword_UnsupportedStoreIs501(t *testing.T) {
	router := pwRouter(t, newNoPwCapStore(t))

	w := pwPost(t, router, pwSessionCookie(t),
		`{"current_password":"correct-horse-12","new_password":"brand-new-password-34"}`)
	assert.Equal(t, http.StatusNotImplemented, w.Code, w.Body.String())
}
