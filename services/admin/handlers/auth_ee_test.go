package handlers

// D-UI-4: handler-level tests for POST /auth/ee/session — the internal
// endpoint where the EE backend validates a browser session it relays.
// These lock the pinned wire contract: X-EE-Internal guard, always-200
// verdict shape, fail-closed behavior on every doubt, feature-dark 404
// when EE_INTERNAL_TOKEN is unset, and equivalence with what the admin
// console middleware would decide for the same cookie.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

const eeTestInternalToken = "ee-internal-token-test" //nolint:gosec // G101: synthetic guard token, not a credential
const eeTestSessionSecret = "ee-endpoint-test-secret-32b!!"

// eeWatermarkStore adds an invalidation-watermark knob on top of the
// durable revocation test store, so the handler's wiring of
// adminSessionsInvalidatedAt is observable end to end.
type eeWatermarkStore struct {
	*oidcRevocationTestStore
	sessionsInvalidatedAt time.Time
}

func (s *eeWatermarkStore) GetAdminUserSessionsInvalidatedAt(_ context.Context, _ string) (time.Time, error) {
	return s.sessionsInvalidatedAt, nil
}

func newEETestHandlers(t *testing.T) *AdminHandlers {
	t.Helper()
	store := newMockStore()
	revocations := &oidcRevocationTestStore{mockStore: store, revoked: make(map[string]bool)}
	h := New(revocations, eeTestSessionSecret, "localhost", []string{})
	h.sessionRevocations = revocations
	h.SetEEInternalToken(eeTestInternalToken)
	return h
}

func eePostRequest(t *testing.T, token, rawCookie string) *http.Request {
	t.Helper()
	body := `{"cookie":"` + rawCookie + `"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/ee/session", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-EE-Internal", token)
	}
	return req
}

// eeSessionCookieHeader builds the raw Cookie header value the EE backend
// forwards: the cookie name AND value, exactly as the browser sends it.
func eeSessionCookieHeader(t *testing.T, session adminauth.AdminSession) string {
	t.Helper()
	cookie, err := adminauth.CreateAdminSessionCookie(session, eeTestSessionSecret)
	if err != nil {
		t.Fatal(err)
	}
	return cookie.Name + "=" + cookie.Value
}

func eeLiveSessionCookie(t *testing.T) string {
	t.Helper()
	return eeSessionCookieHeader(t, adminauth.AdminSession{
		UserID:    "admin-1",
		Email:     "test@example.com",
		IsRoot:    false,
		SessionID: "sess-ee-live",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
}

// eeVerdictFromBody decodes a response body string. (Reading via
// json.Decoder directly on the recorder's buffer would drain it, hiding
// the body from later assertions.)
func eeVerdictFromBody(t *testing.T, body string) eeSessionResponse {
	t.Helper()
	var resp eeSessionResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%q)", err, body)
	}
	return resp
}

func eeVerdictFromRecorder(t *testing.T, rec *httptest.ResponseRecorder) (string, eeSessionResponse) {
	t.Helper()
	body := rec.Body.String()
	return body, eeVerdictFromBody(t, body)
}

func TestEESessionEndpoint_ValidSessionVerdict(t *testing.T) {
	h := newEETestHandlers(t)
	router := h.SetupRouter()

	rec := httptest.NewRecorder()
	// Realistic forwarded header: the browser sends several cookies, EE
	// relays the raw header verbatim.
	forwarded := "theme=dark; " + eeLiveSessionCookie(t) + "; locale=en"
	router.ServeHTTP(rec, eePostRequest(t, eeTestInternalToken, forwarded))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	_, resp := eeVerdictFromRecorder(t, rec)
	if !resp.Valid {
		t.Fatal("verdict valid=false, want true for a live session")
	}
	if resp.Subject != "admin-1" {
		t.Errorf("subject=%q, want admin-1 (stable UserID, not the email)", resp.Subject)
	}
	expires, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at not RFC3339: %q", resp.ExpiresAt)
	}
	if remaining := time.Until(expires); remaining < 23*time.Hour || remaining > 25*time.Hour {
		t.Errorf("expires_at=%v, want ~24h from now", resp.ExpiresAt)
	}
	// The endpoint answers EE, not the browser: it must never touch cookies.
	if setCookie := rec.Header().Values("Set-Cookie"); len(setCookie) != 0 {
		t.Errorf("response must not set cookies, got %v", setCookie)
	}
}

func TestEESessionEndpoint_FailClosedAndUniform(t *testing.T) {
	expiredCookie := eeSessionCookieHeader(t, adminauth.AdminSession{
		UserID: "admin-1", Email: "test@example.com", SessionID: "sess-ee-expired",
		IssuedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour),
	})
	liveCookie := eeSessionCookieHeader(t, adminauth.AdminSession{
		UserID: "admin-1", Email: "test@example.com", SessionID: "sess-ee-revoked",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})

	cases := []struct {
		name   string
		cookie string
		setup  func(h *AdminHandlers)
	}{
		{name: "revoked session", cookie: liveCookie, setup: func(h *AdminHandlers) {
			if err := h.sessionRevocations.Revoke(t.Context(), "sess-ee-revoked", time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "expired session", cookie: expiredCookie},
		{name: "malformed cookie", cookie: "not-a-session-token"},
		{name: "empty cookie", cookie: ""},
		{name: "wrong signing secret", cookie: func() string {
			cookie, err := adminauth.CreateAdminSessionCookie(adminauth.AdminSession{
				UserID: "admin-1", SessionID: "sess-ee-wrongkey", ExpiresAt: time.Now().Add(time.Hour),
			}, "a-completely-different-secret")
			if err != nil {
				t.Fatal(err)
			}
			return cookie.Value
		}()},
		{name: "revocation store error", cookie: liveCookie, setup: func(h *AdminHandlers) {
			store := h.sessionRevocations.(*oidcRevocationTestStore)
			store.err = errors.New("store outage")
		}},
		{name: "deactivated admin user", cookie: liveCookie, setup: func(h *AdminHandlers) {
			h.store.(*oidcRevocationTestStore).mockStore.adminUsers["admin-1"].Active = false
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newEETestHandlers(t)
			if tc.setup != nil {
				tc.setup(h)
			}
			router := h.SetupRouter()

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, eePostRequest(t, eeTestInternalToken, tc.cookie))

			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s; every session verdict must be 200", rec.Code, rec.Body.String())
			}
			body, resp := eeVerdictFromRecorder(t, rec)
			if resp.Valid {
				t.Fatal("valid=true, want false")
			}
			// Pinned degenerate fields + no oracle: byte-identical bodies.
			if want := `{"valid":false,"subject":"","expires_at":"0001-01-01T00:00:00Z"}` + "\n"; body != want {
				t.Fatalf("body=%s, want the pinned uniform invalid verdict %s", body, want)
			}
			if setCookie := rec.Header().Values("Set-Cookie"); len(setCookie) != 0 {
				t.Errorf("invalid verdict must not clear/leak cookies, got %v", setCookie)
			}
		})
	}
}

func TestEESessionEndpoint_WatermarkInvalidatedFailsClosed(t *testing.T) {
	store := newMockStore()
	revocations := &oidcRevocationTestStore{mockStore: store, revoked: make(map[string]bool)}
	watermarked := &eeWatermarkStore{oidcRevocationTestStore: revocations, sessionsInvalidatedAt: time.Now()}
	h := New(watermarked, eeTestSessionSecret, "localhost", []string{})
	h.sessionRevocations = revocations
	h.SetEEInternalToken(eeTestInternalToken)

	// Issued before the watermark → invalidated by an admin-side action.
	cookie := eeSessionCookieHeader(t, adminauth.AdminSession{
		UserID: "admin-1", Email: "test@example.com", SessionID: "sess-ee-watermark",
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour),
	})

	rec := httptest.NewRecorder()
	h.SetupRouter().ServeHTTP(rec, eePostRequest(t, eeTestInternalToken, cookie))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	if _, resp := eeVerdictFromRecorder(t, rec); resp.Valid {
		t.Fatal("watermark-invalidated session must fail closed")
	}
}

func TestEESessionEndpoint_InternalTokenGuard(t *testing.T) {
	h := newEETestHandlers(t)
	router := h.SetupRouter()

	cases := []struct {
		name  string
		token string
	}{
		{name: "missing token", token: ""},
		{name: "wrong token", token: "wrong-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Even with an unparseable body the guard must answer first.
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/ee/session", strings.NewReader("not json"))
			req.Header.Set("Content-Type", "application/json")
			if tc.token != "" {
				req.Header.Set("X-EE-Internal", tc.token)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d, want 401", rec.Code)
			}
		})
	}
}

func TestEESessionEndpoint_FeatureDarkWithoutToken(t *testing.T) {
	store := newMockStore()
	revocations := &oidcRevocationTestStore{mockStore: store, revoked: make(map[string]bool)}
	h := New(revocations, eeTestSessionSecret, "localhost", []string{})
	h.sessionRevocations = revocations
	// No SetEEInternalToken: the route must not be mounted at all.
	router := h.SetupRouter()

	for _, method := range []string{http.MethodPost, http.MethodGet} {
		req := httptest.NewRequestWithContext(t.Context(), method, "/auth/ee/session", strings.NewReader(`{"cookie":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-EE-Internal", eeTestInternalToken)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s without EE_INTERNAL_TOKEN: status=%d, want 404 (feature-dark)", method, rec.Code)
		}
	}
}

func TestEESessionEndpoint_MethodNotAllowed(t *testing.T) {
	h := newEETestHandlers(t)
	router := h.SetupRouter()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/ee/session", nil)
	req.Header.Set("X-EE-Internal", eeTestInternalToken)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rec.Code)
	}
}

func TestEESessionEndpoint_MalformedRequestBody(t *testing.T) {
	h := newEETestHandlers(t)
	router := h.SetupRouter()

	cases := []struct {
		name string
		body string
	}{
		{name: "not JSON", body: "not json"},
		{name: "empty body", body: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/ee/session", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-EE-Internal", eeTestInternalToken)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
			}
			var apiErr apiError
			if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil || apiErr.Error != "invalid request body" {
				t.Fatalf("body=%s, want invalid request body error", rec.Body.String())
			}
		})
	}
}

// A decodable body without a usable cookie is a session question, not a
// protocol error: the answer is the fail-closed verdict.
func TestEESessionEndpoint_DecodableBodyWithoutCookieIsInvalidVerdict(t *testing.T) {
	h := newEETestHandlers(t)
	router := h.SetupRouter()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/ee/session", strings.NewReader(`{"other":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-EE-Internal", eeTestInternalToken)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 verdict", rec.Code)
	}
	if _, resp := eeVerdictFromRecorder(t, rec); resp.Valid {
		t.Fatal("decodable body without a session cookie must yield valid=false")
	}
}

func TestEESessionEndpoint_EquivalentToAdminMiddleware(t *testing.T) {
	// The same cookie the EE endpoint accepts must also authenticate against
	// a real admin route through the session middleware — one validation
	// path, two consumers.
	h := newEETestHandlers(t)
	router := h.SetupRouter()
	cookie := makeSessionCookie(false, eeTestSessionSecret)

	// EE endpoint accepts.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, eePostRequest(t, eeTestInternalToken, "yabanin_admin_session="+cookie.Value))
	if _, verdict := eeVerdictFromRecorder(t, rec); rec.Code != http.StatusOK || !verdict.Valid {
		t.Fatalf("EE verdict: status=%d body=%s, want 200/valid", rec.Code, rec.Body.String())
	}

	// Middleware accepts the same session on an admin route. /api/teams is
	// root-only, so a non-root session yields 403 — the point is that the
	// middleware AUTHENTICATED it: a rejected session would be 401.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/teams", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("admin route with the same cookie: 401; middleware and EE endpoint must agree the session is valid")
	}
}

// No path of this endpoint may ever set a cookie: it answers a server,
// not a browser. The 200 verdict paths already assert this inline
// (ValidSessionVerdict for the valid verdict, FailClosedAndUniform for
// every invalid verdict); this test walks the whole status ladder —
// valid, invalid, malformed body, guard rejection, wrong method,
// feature-dark unmounted — so a refactor cannot reintroduce Set-Cookie
// anywhere. Each case pins the status first so the no-cookie assertion
// is known to inspect the intended path.
func TestEESessionEndpoint_NeverSetsCookiesOnAnyPath(t *testing.T) {
	validCookie := eeLiveSessionCookie(t)

	cases := []struct {
		name     string
		unarmed  bool
		wantCode int
		request  func(t *testing.T) *http.Request
	}{
		{name: "valid session verdict", wantCode: http.StatusOK, request: func(t *testing.T) *http.Request {
			t.Helper()
			return eePostRequest(t, eeTestInternalToken, validCookie)
		}},
		{name: "invalid session verdict", wantCode: http.StatusOK, request: func(t *testing.T) *http.Request {
			t.Helper()
			return eePostRequest(t, eeTestInternalToken, "not-a-session-token")
		}},
		{name: "malformed request body", wantCode: http.StatusBadRequest, request: func(t *testing.T) *http.Request {
			t.Helper()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/ee/session", strings.NewReader("not json"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-EE-Internal", eeTestInternalToken)
			return req
		}},
		{name: "missing guard token", wantCode: http.StatusUnauthorized, request: func(t *testing.T) *http.Request {
			t.Helper()
			return eePostRequest(t, "", "any")
		}},
		{name: "wrong guard token", wantCode: http.StatusUnauthorized, request: func(t *testing.T) *http.Request {
			t.Helper()
			return eePostRequest(t, "wrong-token", "any")
		}},
		{name: "wrong method", wantCode: http.StatusMethodNotAllowed, request: func(t *testing.T) *http.Request {
			t.Helper()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/ee/session", nil)
			req.Header.Set("X-EE-Internal", eeTestInternalToken)
			return req
		}},
		{name: "feature-dark unmounted", unarmed: true, wantCode: http.StatusNotFound, request: func(t *testing.T) *http.Request {
			t.Helper()
			return eePostRequest(t, eeTestInternalToken, "any")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newEETestHandlers(t)
			if tc.unarmed {
				h.SetEEInternalToken("") // feature-dark: route not mounted
			}
			router := h.SetupRouter()

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, tc.request(t))

			if rec.Code != tc.wantCode {
				t.Fatalf("status=%d, want %d (body=%s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if setCookie := rec.Header().Values("Set-Cookie"); len(setCookie) != 0 {
				t.Fatalf("Set-Cookie=%v, want none on every path of this endpoint", setCookie)
			}
		})
	}
}
