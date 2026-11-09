package adminauth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestPortalSessionRoundTrip(t *testing.T) {
	const secret = "portal-test-hmac" // #nosec G101 -- test-only HMAC key
	cookie, err := CreatePortalSessionCookie(PortalSession{
		UserID: "u-1", Email: "a@b.c", SessionID: "s-1", ExpiresAt: time.Now().Add(time.Hour),
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	if cookie.Name != PortalSessionCookieName || !cookie.HttpOnly || !cookie.Secure {
		t.Fatalf("cookie %+v", cookie)
	}
	sess, err := ParsePortalSessionCookie(cookie.Value, secret)
	if err != nil || sess.UserID != "u-1" || sess.Email != "a@b.c" {
		t.Fatalf("parse %+v %v", sess, err)
	}
	if _, err := ParsePortalSessionCookie(cookie.Value, "other"); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if _, err := ParsePortalSessionCookie("not-a-session", secret); err == nil {
		t.Fatal("garbage accepted")
	}
	cleared := ClearPortalSessionCookie()
	if cleared.MaxAge != -1 || cleared.Name != PortalSessionCookieName {
		t.Fatalf("clear %+v", cleared)
	}
}

func TestPortalAuthAndCSRF(t *testing.T) {
	const secret = "portal-test-hmac" // #nosec G101 -- test-only HMAC key
	cookie, err := CreatePortalSessionCookie(PortalSession{
		UserID: "u-1", Email: "a@b.c", SessionID: "s-1", ExpiresAt: time.Now().Add(time.Hour),
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	mw := PortalAuthMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if PortalUserID(r) != "u-1" {
			t.Fatalf("user %s", PortalUserID(r))
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	ok := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/me", nil)
	ok.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, ok)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("authed %d", rec.Code)
	}

	anon := httptest.NewRecorder()
	mw.ServeHTTP(anon, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/me", nil))
	if anon.Code != http.StatusUnauthorized {
		t.Fatalf("anon %d", anon.Code)
	}

	expired, err := CreatePortalSessionCookie(PortalSession{
		UserID: "u-1", Email: "a@b.c", SessionID: "s-1", ExpiresAt: time.Now().Add(-time.Minute),
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	old := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/me", nil)
	old.AddCookie(expired)
	rec = httptest.NewRecorder()
	mw.ServeHTTP(rec, old)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired %d", rec.Code)
	}

	csrfMW := PortalCSRFValidation()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	post := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/me/keys", nil)
	rec = httptest.NewRecorder()
	csrfMW.ServeHTTP(rec, post)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("csrf missing %d", rec.Code)
	}
	post = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/me/keys", nil)
	post.AddCookie(&http.Cookie{Name: "yabanin_portal_csrf", Value: "tok", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	post.Header.Set("X-CSRF-Token", "tok")
	rec = httptest.NewRecorder()
	csrfMW.ServeHTTP(rec, post)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("csrf ok %d", rec.Code)
	}
	get := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/me", nil)
	rec = httptest.NewRecorder()
	csrfMW.ServeHTTP(rec, get)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("csrf get %d", rec.Code)
	}

	issued := httptest.NewRecorder()
	if GeneratePortalCSRFToken(issued) == "" {
		t.Fatal("empty csrf")
	}
	flow, err := NewOIDCFlow()
	if err != nil {
		t.Fatal(err)
	}
	fc, err := NewPortalOIDCFlowCookie(flow)
	if err != nil || fc.Path != "/portal" || fc.Name != PortalOIDCFlowCookieName {
		t.Fatalf("flow cookie %+v %v", fc, err)
	}
	parsed, err := ParseOIDCFlowCookie(fc.Value)
	if err != nil || parsed.State != flow.State {
		t.Fatalf("flow parse %v", err)
	}
	if ClearPortalOIDCFlowCookie().Path != "/portal" {
		t.Fatal("clear path")
	}

	bad := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/me/keys", nil)
	bad.AddCookie(&http.Cookie{Name: "yabanin_portal_csrf", Value: "tok", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	bad.Header.Set("X-CSRF-Token", "other")
	rec = httptest.NewRecorder()
	csrfMW.ServeHTTP(rec, bad)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("csrf mismatch %d", rec.Code)
	}
	form := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/me/keys", nil)
	form.AddCookie(&http.Cookie{Name: "yabanin_portal_csrf", Value: "tok", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form.Body = http.NoBody
	form.Form = url.Values{"_csrf": {"tok"}}
	rec = httptest.NewRecorder()
	csrfMW.ServeHTTP(rec, form)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("csrf form %d", rec.Code)
	}

	payload := "a|b|c|not-a-time"
	token := payload + "|" + base64.RawURLEncoding.EncodeToString(createHMAC(payload, secret))
	if _, err := ParsePortalSessionCookie(token, secret); err == nil {
		t.Fatal("bad expiry accepted")
	}
	payload = "only|three"
	token = payload + "|" + base64.RawURLEncoding.EncodeToString(createHMAC(payload, secret))
	if _, err := ParsePortalSessionCookie(token, secret); err == nil {
		t.Fatal("short payload accepted")
	}
	if _, err := ParsePortalSessionCookie("a|b|c|1|%%%", secret); err == nil {
		t.Fatal("bad mac accepted")
	}
}

// TestParsePortalSessionCookie_RejectsNonCanonicalMac mirrors the AUTHFLAKESEC1
// admin-cookie finding for the portal session: a MAC whose base64 spelling ends
// in "XU" (about 1/1024 of tokens) re-spelled as "XX" decodes to the same MAC
// bytes under a lenient decoder and must not verify as a second spelling.
func TestParsePortalSessionCookie_RejectsNonCanonicalMac(t *testing.T) {
	const secret = "portal-test-hmac" // #nosec G101 -- test-only HMAC key
	var token string
	for i := 0; i < 200000; i++ {
		cookie, err := CreatePortalSessionCookie(PortalSession{
			UserID: "u-1", Email: "a@b.c", SessionID: fmt.Sprintf("s-%d", i),
			ExpiresAt: time.Unix(4102444800, 0),
		}, secret)
		if err != nil {
			t.Fatal(err)
		}
		if cookie.Value[len(cookie.Value)-2:] == "XU" {
			token = cookie.Value
			break
		}
	}
	if token == "" {
		t.Fatal("no XU-suffix token found in 200000 tries (expected ~1/1024)")
	}

	if _, err := ParsePortalSessionCookie(token, secret); err != nil {
		t.Fatalf("canonical token rejected: %v", err)
	}
	tampered := token[:len(token)-2] + "XX"
	if tampered == token {
		t.Fatal("test bug: tampered value equals the original")
	}
	if _, err := ParsePortalSessionCookie(tampered, secret); err == nil {
		t.Fatal("non-canonical MAC spelling of a valid token was accepted")
	}
}
