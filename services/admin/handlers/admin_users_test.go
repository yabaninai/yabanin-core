package handlers_test

// W-SECADM: CreateAdminUser validates the email format and enforces the
// password policy (min 12 / max 72) BEFORE hashing, so a bad credential is a
// 400 and never reaches the store (and never burns bcrypt work).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	adminstore "github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// adminUserCreateStore records CreateAdminUser calls.
type adminUserCreateStore struct {
	stubStore
	createCalls int
}

func (s *adminUserCreateStore) CreateAdminUser(_ context.Context, email, _ string, _ string, _ bool) (*adminstore.AdminUser, error) {
	s.createCalls++
	return &adminstore.AdminUser{ID: "new-admin", Email: email, Active: true}, nil
}

func auRouter(t *testing.T, store *adminUserCreateStore) http.Handler {
	t.Helper()
	return handlers.New(store, keyHashSecret, "localhost", nil).SetupRouter()
}

func auPost(t *testing.T, router http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/admin-users",
		strings.NewReader(body))
	req.AddCookie(testCookie("yabanin_admin_session", makeSessionCookie(t, "root@x.test", true, keyHashSecret)))
	req.AddCookie(testCookie("yabanin_csrf_token", keyHashCSRF))
	req.Header.Set("X-CSRF-Token", keyHashCSRF)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(handlers.OrgHeader, "org-1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestCreateAdminUser_RejectsInvalidCredentials(t *testing.T) {
	store := &adminUserCreateStore{}
	router := auRouter(t, store)

	cases := []struct {
		name string
		body string
	}{
		{"email missing", `{"email":"","password":"long-enough-password","name":"A"}`},
		{"email not an address", `{"email":"not-an-email","password":"long-enough-password","name":"A"}`},
		{"email with display name", `{"email":"Boss <boss@x.test>","password":"long-enough-password","name":"A"}`},
		{"password too short (11)", `{"email":"a@b.test","password":"short12char","name":"A"}`},
		{"password missing", `{"email":"a@b.test","name":"A"}`},
		{"password too long (73)", `{"email":"a@b.test","password":"` + strings.Repeat("x", 73) + `","name":"A"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := store.createCalls
			w := auPost(t, router, tc.body)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Equal(t, calls, store.createCalls, "the store must not be called for invalid input")
		})
	}
}

func TestCreateAdminUser_AcceptsValidCredentials(t *testing.T) {
	store := &adminUserCreateStore{}
	router := auRouter(t, store)

	w := auPost(t, router, `{"email":"a@b.test","password":"long-enough-password","name":"A"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Equal(t, 1, store.createCalls)

	// Surrounding whitespace is trimmed before validation (normalization,
	// not rejection).
	w = auPost(t, router, `{"email":" a@b.test ","password":"long-enough-password","name":"A"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// Boundary: exactly 12 and exactly 72 characters are fine.
	w = auPost(t, router, `{"email":"b@b.test","password":"exactly-12ch","name":"B"}`)
	assert.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	w = auPost(t, router, `{"email":"c@b.test","password":"`+strings.Repeat("x", 72)+`","name":"C"}`)
	assert.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Equal(t, 4, store.createCalls)
}
