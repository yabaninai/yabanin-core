package adminauth

// Issued-at round-trip and the session-invalidation guard.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func ghandler(t *testing.T, guard SessionsInvalidatedAt) http.Handler {
	t.Helper()
	return ChiAuthMiddlewareGuarded("test-secret", guard)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func cissued(t *testing.T, iss time.Time) *http.Cookie {
	t.Helper()
	session := AdminSession{
		UserID:    "user-1",
		Email:     "admin@example.com",
		IsRoot:    true,
		SessionID: "sess-abc",
		IssuedAt:  iss,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	cookie, err := CreateAdminSessionCookie(session, "test-secret")
	if err != nil {
		t.Fatalf("CreateAdminSessionCookie: %v", err)
	}
	return cookie
}

func TestCookieIssuedAtRoundTrip(t *testing.T) {
	iss := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	cookie := cissued(t, iss)

	parsed, err := ParseAdminSessionCookie(cookie.Value, "test-secret")
	if err != nil {
		t.Fatalf("ParseAdminSessionCookie: %v", err)
	}
	if !parsed.IssuedAt.Equal(iss) {
		t.Errorf("issued-at = %v, want %v", parsed.IssuedAt, iss)
	}
}

func TestParseLegacyFivePartsHasZeroIssuedAt(t *testing.T) {
	secret := "test-secret"
	expires := time.Now().Add(24 * time.Hour)
	payload := fmt.Sprintf("user-1|admin@example.com|%t|sess-abc|%d", true, expires.Unix())
	mac := createHMAC(payload, secret)
	token := payload + "|" + base64.RawURLEncoding.EncodeToString(mac)

	parsed, err := ParseAdminSessionCookie(token, secret)
	if err != nil {
		t.Fatalf("legacy 5-part cookie must parse: %v", err)
	}
	if !parsed.IssuedAt.IsZero() {
		t.Errorf("legacy issued-at = %v, want zero", parsed.IssuedAt)
	}
}

func TestGuardedIssuedBeforeInvalidationRejected(t *testing.T) {
	inv := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	handler := ghandler(t, func(context.Context, string) (time.Time, error) {
		return inv, nil
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cissued(t, inv.Add(-time.Hour)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("issued before invalidation: got %d, want 401", rec.Code)
	}
}

func TestGuardedIssuedAfterInvalidationAccepted(t *testing.T) {
	inv := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	handler := ghandler(t, func(context.Context, string) (time.Time, error) {
		return inv, nil
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cissued(t, inv.Add(time.Hour)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("issued after invalidation: got %d, want 200", rec.Code)
	}
}

func TestGuardedNeverInvalidatedAccepted(t *testing.T) {
	handler := ghandler(t, func(context.Context, string) (time.Time, error) {
		return time.Time{}, nil // NULL sessions_changed_at
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cissued(t, time.Now().Add(-48*time.Hour)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("no invalidation recorded: got %d, want 200", rec.Code)
	}
}

func TestGuardedLegacyCookieInvalidatedAfterPasswordChange(t *testing.T) {
	// A pre-deploy cookie carries no issued-at: fail-closed once an
	// invalidation is recorded, accepted while none is.
	legacy := AdminSession{
		UserID:    "user-1",
		Email:     "admin@example.com",
		IsRoot:    true,
		SessionID: "sess-abc",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	cookie, err := CreateAdminSessionCookie(legacy, "test-secret")
	if err != nil {
		t.Fatal(err)
	}

	handler := ghandler(t, func(context.Context, string) (time.Time, error) {
		return time.Now().Add(-time.Hour), nil
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("legacy cookie after invalidation: got %d, want 401", rec.Code)
	}
}

func TestGuardedInvalidationLookupErrorFailsClosed(t *testing.T) {
	handler := ghandler(t, func(context.Context, string) (time.Time, error) {
		return time.Time{}, context.DeadlineExceeded
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cissued(t, time.Now()))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("invalidation lookup error: got %d, want 401 (fail-closed)", rec.Code)
	}
}

func TestGuardedNilMatchesUnguarded(t *testing.T) {
	handler := ghandler(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(cissued(t, time.Now()))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("nil guard must keep unguarded behavior: got %d, want 200", rec.Code)
	}
}
