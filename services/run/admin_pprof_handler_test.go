package run

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mintAdminSessionCookie mints a structurally valid signed admin session
// cookie for the given root flag.
func mintAdminSessionCookie(t *testing.T, secret string, isRoot bool) *http.Cookie {
	t.Helper()
	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID:    "1",
		Email:     "root@example.com",
		IsRoot:    isRoot,
		SessionID: "sess-test",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(adminauth.SessionDuration),
	}, secret)
	require.NoError(t, err)
	return cookie
}

// TestAdminPprofHandler_RootGate pins the root-only contract of the pprof
// endpoints: only a validly signed root session reaches pprof itself.
func TestAdminPprofHandler_RootGate(t *testing.T) {
	signingKey := "pprof-test-secret"
	handler := adminPprofHandler(signingKey)

	do := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/debug/pprof/", nil)
		require.NoError(t, err)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	t.Run("no cookie is rejected", func(t *testing.T) {
		rec := do(nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "root access required")
	})

	t.Run("forged signature is rejected", func(t *testing.T) {
		forged := mintAdminSessionCookie(t, "wrong-secret", true)
		rec := do(forged)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("non-root session is rejected", func(t *testing.T) {
		rec := do(mintAdminSessionCookie(t, signingKey, false))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("root session reaches pprof", func(t *testing.T) {
		rec := do(mintAdminSessionCookie(t, signingKey, true))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	})
}
