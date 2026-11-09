package adminauth

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestChiAuthMiddlewareGuarded_RevokedSessionIsRejectedAndCookieCleared(t *testing.T) {
	const secret = "revocation-test-secret"
	session := AdminSession{
		UserID: "admin-1", Email: "admin@example.test", SessionID: "revoked-session-test",
		ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}
	RevokeSessionID(session.SessionID, session.ExpiresAt)
	cookie, err := CreateAdminSessionCookie(session, secret)
	if err != nil {
		t.Fatal(err)
	}

	called := false
	handler := ChiAuthMiddlewareGuarded(secret, func(context.Context, string) (time.Time, error) {
		return time.Time{}, nil
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/admin", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("revoked session: status=%d handler_called=%v; want 401/not called", rec.Code, called)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge == -1 && c.Value == "" {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("revoked session response did not clear the session cookie")
	}
}

func TestRevokeSessionID_LogoutRevokesOnlyTargetAndExpires(t *testing.T) {
	target := "logout-target-test"
	other := "logout-other-test"
	RevokeSessionID("", time.Now().Add(time.Hour)) // an absent session is a no-op
	RevokeSessionID(target, time.Now().Add(time.Hour))
	RevokeSessionID(other, time.Now().Add(-time.Second))
	RevokeSessionID("logout-follow-up-test", time.Now().Add(time.Hour)) // prunes the expired logout record

	if !IsSessionIDRevoked(target) {
		t.Fatal("logged-out session should remain revoked until its expiry")
	}
	if IsSessionIDRevoked(other) {
		t.Fatal("expired session revocation should no longer be effective")
	}
	if IsSessionIDRevoked("unrelated-session-test") {
		t.Fatal("logout must not revoke an unrelated session")
	}
}

func TestOriginValidation_EnforcesBrowserOriginAndFetchMetadata(t *testing.T) {
	cases := []struct {
		name       string
		origin     string
		fetchSite  string
		forwarded  string
		wantStatus int
		tls        bool
	}{
		{name: "matching origin", origin: "https://admin.example.test", fetchSite: " SAME-ORIGIN ", forwarded: "https", wantStatus: http.StatusNoContent},
		{name: "proxy scheme", origin: "https://admin.example.test", forwarded: "https, http", wantStatus: http.StatusNoContent},
		{name: "direct HTTP request", origin: "http://admin.example.test", wantStatus: http.StatusNoContent},
		{name: "TLS request ignores unsupported forwarded scheme", origin: "https://admin.example.test", forwarded: "ftp", wantStatus: http.StatusNoContent, tls: true},
		{name: "no browser markers", wantStatus: http.StatusNoContent},
		{name: "cross origin", origin: "https://evil.example", wantStatus: http.StatusForbidden},
		{name: "cross site metadata", fetchSite: "cross-site", wantStatus: http.StatusForbidden},
		{name: "invalid origin", origin: "https://admin.example.test/path", wantStatus: http.StatusForbidden},
		{name: "origin credentials", origin: "https://user@admin.example.test", wantStatus: http.StatusForbidden},
		{name: "query origin", origin: "https://admin.example.test/?x=1", wantStatus: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			middleware := OriginValidation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://admin.example.test/api/change", nil)
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			}
			if tc.forwarded != "" {
				req.Header.Set("X-Forwarded-Proto", tc.forwarded)
			}
			rec := httptest.NewRecorder()
			middleware.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus || called != (tc.wantStatus == http.StatusNoContent) {
				t.Fatalf("status=%d handler_called=%v; want status=%d", rec.Code, called, tc.wantStatus)
			}
		})
	}
}

func TestChiAuthMiddlewareGuarded_InvalidationSourceErrorFailsClosed(t *testing.T) {
	secret := strings.Join([]string{"guard", "source", "test", "secret"}, "-")
	cookie, err := CreateAdminSessionCookie(AdminSession{
		UserID: "admin-2", Email: "admin@example.test", SessionID: "source-error-session-test",
		ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	handler := ChiAuthMiddlewareGuarded(secret, func(context.Context, string) (time.Time, error) {
		return time.Time{}, errors.New("revocation source unavailable")
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/admin", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "revocation source unavailable") {
		t.Fatalf("source error must fail closed without leaking details: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

type testRevocationStore struct {
	revoked bool
	err     error
}

func (s *testRevocationStore) IsRevoked(context.Context, string) (bool, error) {
	return s.revoked, s.err
}
func (*testRevocationStore) Revoke(context.Context, string, time.Time) error { return nil }

type sharedRevocationStore struct{ revoked map[string]bool }

func (s *sharedRevocationStore) IsRevoked(_ context.Context, id string) (bool, error) {
	return s.revoked[id], nil
}
func (s *sharedRevocationStore) Revoke(_ context.Context, id string, _ time.Time) error {
	s.revoked[id] = true
	return nil
}

func TestSeparateMiddlewareInstancesObserveSharedRevocation(t *testing.T) {
	secret := strings.Join([]string{"shared", "revocation", "middleware", "secret"}, "-")
	shared := &sharedRevocationStore{revoked: make(map[string]bool)}
	session := AdminSession{UserID: "admin", SessionID: "shared-session", ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now()}
	cookie, err := CreateAdminSessionCookie(session, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := shared.Revoke(context.Background(), session.SessionID, session.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	handler := ChiAuthMiddlewareGuardedWithRevocation(secret, nil, shared)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("second middleware instance status=%d; want 401", rec.Code)
	}
}

func TestChiAuthMiddlewareRevocationStoreErrorsFailClosed(t *testing.T) {
	secret := strings.Join([]string{"durable", "revocation", "error", "secret"}, "-")
	cookie, err := CreateAdminSessionCookie(AdminSession{
		UserID: "admin", SessionID: "durable-store-error", ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	middleware := ChiAuthMiddlewareGuardedWithRevocation(secret, nil, &testRevocationStore{err: errors.New("database unavailable")})
	called := false
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("store outage: status=%d called=%v; want 401/not called", rec.Code, called)
	}
}
