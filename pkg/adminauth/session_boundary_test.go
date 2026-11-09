package adminauth

// N04-P01-T07 boundary regressions for the local session surface: the expiry
// comparison is strict (a session whose ExpiresAt has arrived is expired —
// there is no grace second), and the invalidation-watermark equality edge
// fails closed by design (a session issued in the same millisecond as the
// recorded change counts as pre-change).
//
// These run at the middleware boundary — the exact check a guarded request
// hits — not on a codec helper.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// guardedRoundTrip drives one request through the guarded middleware with a
// freshly minted session cookie; the wrapped handler writes 200 "ok".
func guardedRoundTrip(t *testing.T, invalidatedAt SessionsInvalidatedAt, session AdminSession) *httptest.ResponseRecorder {
	t.Helper()
	cookie, err := CreateAdminSessionCookie(session, "boundary-secret")
	if err != nil {
		t.Fatalf("create session cookie: %v", err)
	}
	mw := ChiAuthMiddlewareGuarded("boundary-secret", invalidatedAt)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/boundary", nil)
	req.AddCookie(cookie)
	mw(next).ServeHTTP(rec, req)
	return rec
}

func TestSessionBoundary_ExpiryExactlyAtArrivalIsExpired(t *testing.T) {
	// ExpiresAt == construction time: the request always lands strictly
	// after it, and the cookie stores whole seconds, so the first check
	// already sees a past expiry. Strict `After` semantics — no grace second.
	rec := guardedRoundTrip(t, nil, AdminSession{
		UserID:    "u-1",
		Email:     "root@test.io",
		SessionID: "boundary-expiry-exact",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now(),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expiry exactly at arrival: got %d, want 401", rec.Code)
	}
	if body := rec.Body.String(); body != `{"error":"session expired"}` {
		t.Fatalf("expiry boundary must report the diagnosable reason, got %q", body)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "yabanin_admin_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("expired boundary session did not clear the cookie")
	}
}

func TestSessionBoundary_ExpiryTwoSecondsAheadIsAccepted(t *testing.T) {
	// The positive edge of the same comparison: a session that has not
	// expired yet is not rejected early (no off-by-one in the other
	// direction). The in-process round trip lands well inside the window.
	rec := guardedRoundTrip(t, nil, AdminSession{
		UserID:    "u-1",
		Email:     "root@test.io",
		SessionID: "boundary-expiry-ahead",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(2 * time.Second),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("session with 2s left: got %d, want 200; body %q", rec.Code, rec.Body.String())
	}
}

func TestSessionBoundary_WatermarkEqualityFailsClosed(t *testing.T) {
	// sessionInvalidated is fail-closed on equality: a cookie issued in the
	// SAME truncated millisecond as the recorded invalidation counts as
	// pre-change. One millisecond later it is a post-change session.
	watermark := time.Now()
	lookup := func(context.Context, string) (time.Time, error) { return watermark, nil }

	t.Run("issued exactly at the watermark is rejected", func(t *testing.T) {
		rec := guardedRoundTrip(t, lookup, AdminSession{
			UserID:    "u-1",
			Email:     "root@test.io",
			SessionID: "boundary-watermark-equal",
			IssuedAt:  watermark.Truncate(time.Millisecond),
			ExpiresAt: time.Now().Add(time.Hour),
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("issuedAt == watermark: got %d, want 401 (equality fails closed)", rec.Code)
		}
	})
	t.Run("issued one millisecond after the watermark is accepted", func(t *testing.T) {
		rec := guardedRoundTrip(t, lookup, AdminSession{
			UserID:    "u-1",
			Email:     "root@test.io",
			SessionID: "boundary-watermark-after",
			IssuedAt:  watermark.Truncate(time.Millisecond).Add(2 * time.Millisecond),
			ExpiresAt: time.Now().Add(time.Hour),
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("issuedAt = watermark+2ms: got %d, want 200; body %q", rec.Code, rec.Body.String())
		}
	})
}
