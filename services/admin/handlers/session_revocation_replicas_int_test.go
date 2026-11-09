//go:build integration

package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

func TestLogoutReplayRejectedByIndependentAdminHandlerInstance(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Postgres")
	}
	pool := testdb.Postgres(t)
	secret := "replica-session-revocation-test-secret"
	first := New(adminstore.New(pool, slog.Default(), nil), secret, "localhost", nil)
	second := New(adminstore.New(pool, slog.Default(), nil), secret, "localhost", nil)
	t.Cleanup(first.Stop)
	t.Cleanup(second.Stop)

	cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
		UserID: "replica-replay-admin", SessionID: "replica-replay-session",
		ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}, secret)
	require.NoError(t, err)

	logoutRequest := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/logout", nil)
	logoutRequest.AddCookie(cookie)
	logoutResponse := httptest.NewRecorder()
	first.HandleLogout().ServeHTTP(logoutResponse, logoutRequest)
	require.Equal(t, http.StatusFound, logoutResponse.Code)

	replayRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	replayRequest.AddCookie(cookie)
	replayResponse := httptest.NewRecorder()
	protectedRouter(second).ServeHTTP(replayResponse, replayRequest)
	require.Equal(t, http.StatusUnauthorized, replayResponse.Code)
}
