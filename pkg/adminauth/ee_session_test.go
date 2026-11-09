package adminauth

// D-UI-4: tests for ValidateSessionCookieHeader, the fail-closed validation
// entry point behind POST /auth/ee/session. Two properties matter most:
//   1. Equivalence — the EE verdict is Valid exactly when the admin
//      middleware (identical wiring) would accept the same request, because
//      both run the same validateSession core.
//   2. No oracle — every rejection (malformed, bad signature, expired,
//      revoked, store error, watermark, inactive user) collapses into one
//      uniform invalid verdict: same fields, same zero values.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// eeTestStore is an in-memory RevocationStore with an error knob, mirroring
// the handler-package oidcRevocationTestStore pattern.
type eeTestStore struct {
	revoked map[string]bool
	err     error
}

func (s *eeTestStore) IsRevoked(_ context.Context, id string) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.revoked[id], nil
}

func (s *eeTestStore) Revoke(_ context.Context, id string, _ time.Time) error {
	if s.err != nil {
		return s.err
	}
	s.revoked[id] = true
	return nil
}

func eeSession(secret string) AdminSession {
	return AdminSession{
		UserID:    "admin-ee-1",
		Email:     "ee@example.test",
		IsRoot:    false,
		SessionID: "sess-ee-" + secret[:4],
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func eeCookieHeader(t *testing.T, session AdminSession, secret string) string {
	t.Helper()
	cookie, err := CreateAdminSessionCookie(session, secret)
	if err != nil {
		t.Fatal(err)
	}
	// The EE backend forwards the browser's raw Cookie header, which usually
	// carries other cookies around the session cookie.
	return "theme=dark; " + cookie.Name + "=" + cookie.Value + "; other=1"
}

func TestValidateSessionCookieHeader_ValidSession(t *testing.T) {
	const secret = "ee-valid-session-secret"
	session := eeSession(secret)
	header := eeCookieHeader(t, session, secret)

	verdict := ValidateSessionCookieHeader(t.Context(), header, secret, "", time.Time{}, 0, nil, nil)
	if !verdict.Valid {
		t.Fatalf("valid session: Valid=false, want true")
	}
	if verdict.Subject != session.UserID {
		t.Errorf("Subject = %q, want %q", verdict.Subject, session.UserID)
	}
	// The cookie payload carries expiry as unix seconds, so the round trip
	// truncates sub-second precision — compare at that granularity.
	if !verdict.ExpiresAt.Equal(time.Unix(session.ExpiresAt.Unix(), 0)) {
		t.Errorf("ExpiresAt = %v, want %v", verdict.ExpiresAt, session.ExpiresAt)
	}
	if verdict.UsedPrevious {
		t.Error("UsedPrevious = true, want false (signed with the current secret)")
	}
}

func TestValidateSessionCookieHeader_PreviousKeyGrace(t *testing.T) {
	const secret = "ee-rotation-new-secret" //nolint:gosec // G101: synthetic test session secret, not a credential
	const previous = "ee-rotation-old-secret"
	session := eeSession(secret)
	header := eeCookieHeader(t, session, previous)

	graceStarted := time.Now().Add(-time.Minute)
	verdict := ValidateSessionCookieHeader(t.Context(), header, secret, previous, graceStarted, 10*time.Minute, nil, nil)
	if !verdict.Valid || !verdict.UsedPrevious {
		t.Fatalf("previous-key cookie inside grace: Valid=%v UsedPrevious=%v, want true/true", verdict.Valid, verdict.UsedPrevious)
	}

	// Outside the rotation grace the previous key no longer validates.
	staleGrace := time.Now().Add(-2 * time.Hour)
	verdict = ValidateSessionCookieHeader(t.Context(), header, secret, previous, staleGrace, time.Hour, nil, nil)
	if verdict.Valid {
		t.Fatal("previous-key cookie outside grace must fail closed")
	}
}

func TestValidateSessionCookieHeader_FailClosedAndUniform(t *testing.T) {
	const secret = "ee-fail-closed-secret" //nolint:gosec // G101: synthetic test session secret, not a credential

	expiredSession := eeSession(secret + "-expired")
	expiredSession.ExpiresAt = time.Now().Add(-time.Minute)

	revokedSession := eeSession(secret + "-revoked")
	RevokeSessionID(revokedSession.SessionID, time.Now().Add(time.Hour))

	revokedStore := &eeTestStore{revoked: map[string]bool{}}
	revokedStore.revoked[eeSession(secret+"-store").SessionID] = true

	revalidateErr := func(context.Context, string) (bool, bool, error) {
		return false, false, errors.New("db down")
	}
	revalidateInactive := func(context.Context, string) (bool, bool, error) {
		return false, false, nil
	}
	watermarkFn := func(at time.Time) SessionsInvalidatedAt {
		return func(context.Context, string) (time.Time, error) { return at, nil }
	}

	cases := []struct {
		name        string
		header      string
		revocations RevocationStore
		invalidated SessionsInvalidatedAt
		revalidate  SessionRevalidator
	}{
		{name: "empty header", header: ""},
		{name: "no session cookie", header: "theme=dark; other=1"},
		{name: "empty session cookie value", header: sessionCookieName + "="},
		{name: "garbage cookie value", header: sessionCookieName + "=not-a-session-token"},
		{name: "wrong signing secret", header: eeCookieHeader(t, eeSession(secret+"-wrong"), "another-secret")},
		{name: "expired session", header: eeCookieHeader(t, expiredSession, secret)},
		{name: "process-local revoked", header: eeCookieHeader(t, revokedSession, secret)},
		{
			name:        "durable store revoked",
			header:      eeCookieHeader(t, eeSession(secret+"-store"), secret),
			revocations: revokedStore,
		},
		{
			name: "durable store error",
			header: func() string {
				s := eeSession(secret + "-store-err")
				return eeCookieHeader(t, s, secret)
			}(),
			revocations: &eeTestStore{err: errors.New("store down")},
		},
		{
			name: "watermark invalidated",
			header: func() string {
				s := eeSession(secret + "-wm")
				return eeCookieHeader(t, s, secret)
			}(),
			invalidated: watermarkFn(time.Now().Add(time.Minute)),
		},
		{
			name: "watermark lookup error",
			header: func() string {
				s := eeSession(secret + "-wm-err")
				return eeCookieHeader(t, s, secret)
			}(),
			invalidated: func(context.Context, string) (time.Time, error) {
				return time.Time{}, errors.New("watermark store down")
			},
		},
		{
			name: "revalidator error",
			header: func() string {
				s := eeSession(secret + "-rev-err")
				return eeCookieHeader(t, s, secret)
			}(),
			revalidate: revalidateErr,
		},
		{
			name: "revalidator inactive user",
			header: func() string {
				s := eeSession(secret + "-rev-off")
				return eeCookieHeader(t, s, secret)
			}(),
			revalidate: revalidateInactive,
		},
	}

	var reference EESessionVerdict
	for i, tc := range cases {
		verdict := ValidateSessionCookieHeader(t.Context(), tc.header, secret, "", time.Time{}, 0, tc.invalidated, tc.revocations, tc.revalidate)
		if verdict.Valid {
			t.Errorf("%s: Valid=true, want false", tc.name)
		}
		if verdict.Subject != "" {
			t.Errorf("%s: Subject=%q, want empty", tc.name, verdict.Subject)
		}
		if !verdict.ExpiresAt.IsZero() {
			t.Errorf("%s: ExpiresAt=%v, want zero time", tc.name, verdict.ExpiresAt)
		}
		// No oracle: every rejection must be byte-identical.
		if i > 0 && verdict != reference {
			t.Errorf("%s: verdict %+v differs from the uniform invalid verdict %+v", tc.name, verdict, reference)
		}
		reference = verdict
	}
}

// TestValidateSessionCookieHeader_MatchesMiddlewareVerdict locks the
// equivalence property: with identical wiring, the EE endpoint's Valid flag
// is true exactly when the admin middleware serves the request (200), and
// the EE subject is the identity the middleware puts into the context.
func TestValidateSessionCookieHeader_MatchesMiddlewareVerdict(t *testing.T) {
	const secret = "ee-equivalence-secret" //nolint:gosec // G101: synthetic test session secret, not a credential

	expired := eeSession(secret + "-expired")
	expired.ExpiresAt = time.Now().Add(-time.Minute)

	storeRevoked := eeSession(secret + "-store")
	durable := &eeTestStore{revoked: map[string]bool{storeRevoked.SessionID: true}}

	type wiring struct {
		revocations RevocationStore
		revalidate  SessionRevalidator
	}
	scenarios := []struct {
		name    string
		session AdminSession
		wiring  wiring
	}{
		{
			name:    "valid session",
			session: eeSession(secret + "-ok"),
			wiring: wiring{revalidate: func(context.Context, string) (bool, bool, error) {
				return false, true, nil
			}},
		},
		{name: "expired session", session: expired},
		{name: "durable store revoked", session: storeRevoked, wiring: wiring{revocations: durable}},
		{
			name:    "user deactivated",
			session: eeSession(secret + "-off"),
			wiring: wiring{revalidate: func(context.Context, string) (bool, bool, error) {
				return false, false, nil
			}},
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			header := eeCookieHeader(t, tc.session, secret)
			cookie, err := CreateAdminSessionCookie(tc.session, secret)
			if err != nil {
				t.Fatal(err)
			}

			verdict := ValidateSessionCookieHeader(t.Context(), header, secret, "", time.Time{}, 0, nil, tc.wiring.revocations, tc.wiring.revalidate)

			var ctxUserID any
			middleware := ChiAuthMiddlewareRotatingWithRevocation(secret, "", time.Time{}, 0, nil, nil, nil, tc.wiring.revocations, tc.wiring.revalidate)(
				http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					ctxUserID = r.Context().Value(ContextKeyUserID{})
				}))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/admin", nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			middleware.ServeHTTP(rec, req)

			accepted := rec.Code == http.StatusOK
			if verdict.Valid != accepted {
				t.Fatalf("EE verdict Valid=%v but middleware status=%d; they must agree", verdict.Valid, rec.Code)
			}
			if accepted && ctxUserID != tc.session.UserID {
				t.Errorf("middleware context userID=%v, want %q (the EE subject)", ctxUserID, tc.session.UserID)
			}
			if accepted && verdict.Subject != tc.session.UserID {
				t.Errorf("EE Subject=%q, want %q", verdict.Subject, tc.session.UserID)
			}
		})
	}
}

// TestValidateSessionCookieHeader_InvalidSessionsNeverDependOnWiring guards
// the fail-closed default: wiring pieces absent (nil store / nil watermark /
// nil revalidator) never turns an invalid session valid, and — equally —
// absence of the durable store does not crash the EE path.
func TestValidateSessionCookieHeader_InvalidSessionsNeverDependOnWiring(t *testing.T) {
	const secret = "ee-nil-wiring-secret"                            //nolint:gosec // G101: synthetic test session secret, not a credential
	header := eeCookieHeader(t, eeSession(secret), "not-the-secret") // bad signature

	if verdict := ValidateSessionCookieHeader(t.Context(), header, secret, "", time.Time{}, 0, nil, nil); verdict.Valid {
		t.Fatal("bad signature must be invalid with all wiring nil")
	}
	if verdict := ValidateSessionCookieHeader(t.Context(), "", secret, "", time.Time{}, 0, nil, nil); verdict.Valid {
		t.Fatal("empty header must be invalid with all wiring nil")
	}
}

// TestMiddlewareRunsOnPreviousBeforeRevalidateFails pins the pre-refactor
// audit position of the rotation hook: a cookie validated by the previous
// signing key triggers onPrevious even when the live revalidation then
// rejects the request. The EE core extraction must not move this hook.
func TestMiddlewareRunsOnPreviousBeforeRevalidateFails(t *testing.T) {
	const secret = "ee-prev-hook-new-secret" //nolint:gosec // G101: synthetic test session secret, not a credential
	const previous = "ee-prev-hook-old-secret"
	session := eeSession(secret)
	cookie, err := CreateAdminSessionCookie(session, previous)
	if err != nil {
		t.Fatal(err)
	}

	onPreviousCalled := false
	mw := ChiAuthMiddlewareRotatingWithRevocation(secret, previous, time.Now().Add(-time.Minute), 10*time.Minute, nil,
		func(_ *http.Request, _ *AdminSession) { onPreviousCalled = true },
		nil, nil,
		func(context.Context, string) (bool, bool, error) { return false, false, errors.New("revalidate down") })
	middleware := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/admin", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401 (revalidation failure)", rec.Code)
	}
	if !onPreviousCalled {
		t.Fatal("onPrevious must still fire (audit parity) when revalidation fails afterwards")
	}
}
