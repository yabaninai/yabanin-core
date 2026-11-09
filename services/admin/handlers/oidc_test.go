package handlers

// OIDC SSO tests against a fake OpenID provider: the full redirect→callback
// flow plus the fail-closed matrix (state, nonce, email_verified, unknown
// user, disabled user). The fake speaks real OIDC shapes — discovery
// document, JWKS, a token endpoint signing RS256 ID tokens with a test key —
// so pkg/adminauth's go-oidc verification runs for real, not stubbed.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// ---- fake OIDC provider ----------------------------------------------------

type fakeOIDCProvider struct {
	server *httptest.Server
	key    *rsa.PrivateKey

	clientID string

	// Token-time behavior knobs (set per test).
	nonceToEmbed   string
	email          string
	emailVerified  bool
	expirySkewSecs int64 // added to exp (negative = expired)
	wrongAudience  bool
	foreignIssuer  bool     // id_token carries a foreign iss claim
	groups         []string // `groups` claim embedded into the id_token (N04-P01 mapping input)

	tokenStatus    int  // non-zero: token endpoint answers with this status (IdP outage)
	singleUseCodes bool // replayed authorization code → invalid_grant, like a real IdP
	usedCodes      map[string]bool
}

func newFakeOIDCProvider(t *testing.T) *fakeOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	p := &fakeOIDCProvider{key: key, clientID: "yabanin-admin-test", email: "root@test.io", emailVerified: true, usedCodes: map[string]bool{}}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeOIDCJSON(w, map[string]any{
			"issuer":                                p.server.URL,
			"authorization_endpoint":                p.server.URL + "/auth",
			"token_endpoint":                        p.server.URL + "/token",
			"jwks_uri":                              p.server.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := &p.key.PublicKey
		writeOIDCJSON(w, map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if p.tokenStatus != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(p.tokenStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "temporarily_unavailable"})
			return
		}
		code := r.FormValue("code")
		if p.singleUseCodes {
			if p.usedCodes[code] {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant", "error_description": "authorization code already redeemed"})
				return
			}
			p.usedCodes[code] = true
		}
		iss := p.server.URL
		if p.foreignIssuer {
			iss = "https://foreign-issuer.invalid"
		}
		aud := p.clientID
		if p.wrongAudience {
			aud = "some-other-client"
		}
		claims := map[string]any{
			"iss":            iss,
			"aud":            aud,
			"sub":            "user-123",
			"email":          p.email,
			"email_verified": p.emailVerified,
			"exp":            time.Now().Unix() + 600 + p.expirySkewSecs,
			"iat":            time.Now().Unix(),
			"nonce":          p.nonceToEmbed,
		}
		if p.groups != nil {
			claims["groups"] = p.groups
		}
		idToken := p.signIDToken(t, claims)
		writeOIDCJSON(w, map[string]any{
			"access_token": "at-test",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

// signIDToken builds an RS256 JWT the way the fake provider would.
func (p *fakeOIDCProvider) signIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test-key"}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("jwt sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writeOIDCJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---- harness ---------------------------------------------------------------

// oidcRevocationTestStore exercises the same durable revocation capability
// that New wires from an adminstore.Store, without requiring a database.
type oidcRevocationTestStore struct {
	*mockStore
	revoked map[string]bool
	err     error
}

func (s *oidcRevocationTestStore) IsRevoked(_ context.Context, sessionID string) (bool, error) {
	return s.revoked[sessionID], s.err
}

func (s *oidcRevocationTestStore) Revoke(_ context.Context, sessionID string, _ time.Time) error {
	if s.err != nil {
		return s.err
	}
	s.revoked[sessionID] = true
	return nil
}

// newOIDCTestHandlers wires handlers against the mock store and the fake
// provider, plus a seeded admin user.
func newOIDCTestHandlers(t *testing.T, p *fakeOIDCProvider) (*testAdminHandlers, *mockStore) {
	t.Helper()
	store := newMockStore()
	revocations := &oidcRevocationTestStore{mockStore: store, revoked: make(map[string]bool)}
	store.adminUsers["u-1"] = &adminstore.AdminUser{
		ID: "u-1", Email: "root@test.io", DisplayName: "Root", IsRoot: true, Active: true,
	}
	// The OIDC client secret is the IdP-side credential; the session secret
	// is the console cookie key — different things, both "test-secret" here
	// only by coincidence of naming.
	h := &testAdminHandlers{
		AdminHandlers: New(revocations, "test-secret", "admin.test", []string{}),
		store:         store,
		revocations:   revocations,
	}
	client, err := adminauth.NewOIDCClient(context.Background(),
		p.server.URL, p.clientID, "idp-test-secret", "https://admin.test/auth/oidc/callback")
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}
	h.SetOIDCClient(client)
	return h, store
}

// startFlow drives GET /auth/oidc/login and returns the redirect target
// (with state/nonce/code_challenge) and the raw flow-cookie value.
func startFlow(t *testing.T, h *testAdminHandlers) (*url.URL, string) {
	t.Helper()
	return startFlowAt(t, h, "/auth/oidc/login")
}

func startFlowAt(t *testing.T, h *testAdminHandlers, loginURL string) (*url.URL, string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.OIDCLogin()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("login: got %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	var flowCookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == adminauth.OIDCFlowCookieName {
			flowCookie = c.Value
			if len(c.String()) >= 4096 {
				t.Fatalf("OIDC flow Set-Cookie exceeds browser limit: %d bytes", len(c.String()))
			}
		}
	}
	if flowCookie == "" {
		t.Fatal("login: no flow cookie set")
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("login redirect url: %v", err)
	}
	return u, flowCookie
}

// runCallback drives GET /auth/oidc/callback with the given query and cookie.
func runCallback(t *testing.T, h *testAdminHandlers, q url.Values, flowCookie string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/oidc/callback?"+q.Encode(), nil)
	if flowCookie != "" {
		req.AddCookie(&http.Cookie{
			Name: adminauth.OIDCFlowCookieName, Value: flowCookie,
			Path: "/auth/oidc", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
	}
	h.OIDCCallback()(w, req)
	return w
}

// happyFlow performs login→callback and asserts the session cookie.
func happyFlow(t *testing.T, h *testAdminHandlers, p *fakeOIDCProvider) *httptest.ResponseRecorder {
	t.Helper()
	target, flowCookie := startFlow(t, h)
	p.nonceToEmbed = target.Query().Get("nonce")
	q := url.Values{"state": {target.Query().Get("state")}, "code": {"auth-code-1"}}
	return runCallback(t, h, q, flowCookie)
}

// issuedSession returns the local admin session cookie issued by resp, or nil.
func issuedSession(resp *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range resp.Result().Cookies() {
		if c.Name == "yabanin_admin_session" {
			return c
		}
	}
	return nil
}

// flowCookieCleared reports whether the one-time OIDC flow cookie was expired
// by this response.
func flowCookieCleared(resp *httptest.ResponseRecorder) bool {
	for _, c := range resp.Result().Cookies() {
		if c.Name == adminauth.OIDCFlowCookieName {
			return c.MaxAge < 0
		}
	}
	return false
}

// assertFailedCallback pins the fail-closed shape shared by every OIDC
// failure outcome: generic error status, no redirect, no session, and the
// one-time flow cookie expired.
func assertFailedCallback(t *testing.T, resp *httptest.ResponseRecorder, wantCode int) {
	t.Helper()
	if resp.Code != wantCode {
		t.Fatalf("callback: got %d, want %d; body %s", resp.Code, wantCode, resp.Body.String())
	}
	if loc := resp.Header().Get("Location"); loc != "" {
		t.Fatalf("failed callback redirected to %q", loc)
	}
	if issuedSession(resp) != nil {
		t.Fatal("failed callback issued an admin session")
	}
	if !flowCookieCleared(resp) {
		t.Fatal("failed callback did not clear the one-time flow cookie")
	}
}

// ---- tests -----------------------------------------------------------------

func TestOIDC_FullFlow_IssuesSession(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)

	w := happyFlow(t, h, p)
	if w.Code != http.StatusFound {
		t.Fatalf("callback: got %d, want 302; body %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Fatalf("callback redirect: got %q, want %q", loc, "/")
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("callback: no session cookie issued")
	}
	// The session must be verifiable and carry the mapped user.
	sess, err := adminauth.ParseAdminSessionCookie(session.Value, "test-secret")
	if err != nil {
		t.Fatalf("session cookie does not verify: %v", err)
	}
	if sess.Email != "root@test.io" || !sess.IsRoot {
		t.Fatalf("session identity: got %+v", sess)
	}
	if sess.IssuedAt.IsZero() {
		t.Fatal("OIDC session must carry the issued-at watermark used by password-change invalidation")
	}
	watermark := time.Now().Add(-time.Minute)
	guard := adminauth.ChiAuthMiddlewareGuarded("test-secret", func(context.Context, string) (time.Time, error) {
		return watermark, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.AddCookie(session)
	protected := httptest.NewRecorder()
	guard.ServeHTTP(protected, req)
	if protected.Code != http.StatusOK {
		t.Fatalf("new OIDC session issued after password change watermark: got %d, want 200", protected.Code)
	}
	oldSession := *sess
	oldSession.IssuedAt = watermark.Add(-time.Second)
	oldSession.ExpiresAt = time.Now().Add(time.Hour)
	oldCookie, err := adminauth.CreateAdminSessionCookie(oldSession, "test-secret")
	if err != nil {
		t.Fatalf("create pre-change session cookie: %v", err)
	}
	oldRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	oldRequest.AddCookie(oldCookie)
	oldResponse := httptest.NewRecorder()
	guard.ServeHTTP(oldResponse, oldRequest)
	if oldResponse.Code != http.StatusUnauthorized {
		t.Fatalf("pre-change OIDC session: got %d, want 401", oldResponse.Code)
	}
}

func TestOIDC_FullFlow_PreservesDashboardDeepLink(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)
	next := "/#keys?org=acme"

	loginPage := httptest.NewRecorder()
	loginURL := "/auth/login?" + url.Values{"next": {next}}.Encode()
	h.LoginPage()(loginPage, httptest.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil))
	marker := `href="`
	_, after, ok := strings.Cut(loginPage.Body.String(), marker)
	if !ok {
		t.Fatal("configured login page has no SSO link")
	}
	link, _, ok := strings.Cut(after, `"`)
	if !ok {
		t.Fatal("configured login page has malformed SSO link")
	}
	loginLink, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse SSO link: %v", err)
	}
	if loginLink.Path != "/auth/oidc/login" || loginLink.Query().Get("next") != next {
		t.Fatalf("SSO link lost deep link: got %q, want next %q", link, next)
	}

	target, flowCookie := startFlowAt(t, h, link)
	flow, err := adminauth.ParseOIDCFlowCookie(flowCookie)
	if err != nil {
		t.Fatalf("parse flow cookie: %v", err)
	}
	if flow.Next != next {
		t.Fatalf("flow cookie return target: got %q, want %q", flow.Next, next)
	}
	if len(flowCookie) >= 4096 {
		t.Fatalf("OIDC flow cookie value is too large: %d bytes", len(flowCookie))
	}
	p.nonceToEmbed = target.Query().Get("nonce")
	q := url.Values{"state": {target.Query().Get("state")}, "code": {"auth-code-1"}}
	callback := runCallback(t, h, q, flowCookie)
	if callback.Code != http.StatusFound {
		t.Fatalf("callback: got %d, want 302; body %s", callback.Code, callback.Body.String())
	}
	if got := callback.Header().Get("Location"); got != next {
		t.Fatalf("callback redirect: got %q, want deep link %q", got, next)
	}
	redirectURL, err := url.Parse(callback.Header().Get("Location"))
	if err != nil || redirectURL.IsAbs() || redirectURL.Host != "" {
		t.Fatalf("callback returned a non-local redirect: %q", callback.Header().Get("Location"))
	}
	for _, cookie := range callback.Result().Cookies() {
		if cookie.Name == "yabanin_admin_session" {
			return
		}
	}
	t.Fatal("callback did not issue local admin session")
}

func TestOIDC_FlowCookieReturnTargetIsRevalidated(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)
	loginURL := "/auth/oidc/login?" + url.Values{"next": {"/admin-users"}}.Encode()
	target, flowCookie := startFlowAt(t, h, loginURL)
	flow, err := adminauth.ParseOIDCFlowCookie(flowCookie)
	if err != nil {
		t.Fatalf("parse flow cookie: %v", err)
	}
	flow.Next = "//attacker.invalid/steal"
	tampered, err := adminauth.NewOIDCFlowCookie(flow)
	if err != nil {
		t.Fatalf("encode altered client cookie: %v", err)
	}
	p.nonceToEmbed = target.Query().Get("nonce")
	q := url.Values{"state": {target.Query().Get("state")}, "code": {"auth-code-1"}}
	callback := runCallback(t, h, q, tampered.Value)
	if callback.Code != http.StatusFound {
		t.Fatalf("callback: got %d, want 302", callback.Code)
	}
	if got := callback.Header().Get("Location"); got != "/" {
		t.Fatalf("tampered return target was not rejected: Location=%q", got)
	}
	for _, cookie := range callback.Result().Cookies() {
		if cookie.Name == "yabanin_admin_session" {
			return
		}
	}
	t.Fatal("valid OIDC login should still issue the local session")
}

func TestOIDC_EncodedSeparatorsStaySameOrigin(t *testing.T) {
	for _, next := range []string{
		"/%2f%2fattacker.invalid/",
		"/%5c%5cattacker.invalid/",
	} {
		t.Run(next, func(t *testing.T) {
			p := newFakeOIDCProvider(t)
			h, _ := newOIDCTestHandlers(t, p)
			loginURL := "/auth/oidc/login?" + url.Values{"next": {next}}.Encode()
			target, flowCookie := startFlowAt(t, h, loginURL)
			p.nonceToEmbed = target.Query().Get("nonce")
			q := url.Values{"state": {target.Query().Get("state")}, "code": {"auth-code-1"}}
			callback := runCallback(t, h, q, flowCookie)
			if callback.Code != http.StatusFound {
				t.Fatalf("callback: got %d, want 302", callback.Code)
			}
			location := callback.Header().Get("Location")
			parsed, err := url.Parse(location)
			if err != nil || parsed.IsAbs() || parsed.Host != "" {
				t.Fatalf("encoded separator escaped the current origin: Location=%q", location)
			}
			if location != next {
				t.Fatalf("encoded local path changed: got %q, want %q", location, next)
			}
		})
	}
}

func TestOIDC_LoginPageRejectsExternalReturnTargets(t *testing.T) {
	for _, next := range []string{
		"https://attacker.invalid/",
		"//attacker.invalid/",
		"/\\attacker.invalid/",
		"/safe\nLocation: https://attacker.invalid/",
	} {
		t.Run(next, func(t *testing.T) {
			p := newFakeOIDCProvider(t)
			h, _ := newOIDCTestHandlers(t, p)
			loginURL := "/auth/login?" + url.Values{"next": {next}}.Encode()
			page := httptest.NewRecorder()
			h.LoginPage()(page, httptest.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil))
			_, after, ok := strings.Cut(page.Body.String(), `href="`)
			if !ok {
				t.Fatal("configured login page has no SSO link")
			}
			link, _, ok := strings.Cut(after, `"`)
			if !ok {
				t.Fatal("configured login page has malformed SSO link")
			}
			parsed, err := url.Parse(link)
			if err != nil || parsed.IsAbs() || parsed.Host != "" {
				t.Fatalf("login page emitted a non-local SSO link %q", link)
			}
			if parsed.Path != "/auth/oidc/login" || parsed.Query().Get("next") != "" {
				t.Fatalf("unsafe next was carried into OIDC login: %q", link)
			}
		})
	}
}

func TestOIDC_ReturnTargetBoundsAndFailure(t *testing.T) {
	t.Run("oversized target falls back before cookie creation", func(t *testing.T) {
		p := newFakeOIDCProvider(t)
		h, _ := newOIDCTestHandlers(t, p)
		tooLong := "/" + strings.Repeat("a", maxOIDCReturnTargetBytes)
		loginURL := "/auth/oidc/login?" + url.Values{"next": {tooLong}}.Encode()
		_, flowCookie := startFlowAt(t, h, loginURL)
		flow, err := adminauth.ParseOIDCFlowCookie(flowCookie)
		if err != nil {
			t.Fatalf("parse flow cookie: %v", err)
		}
		if flow.Next != "/" {
			t.Fatalf("oversized target was retained: %d bytes", len(flow.Next))
		}
		if len(flowCookie) >= 4096 {
			t.Fatalf("flow cookie value exceeds browser limit: %d bytes", len(flowCookie))
		}
	})

	t.Run("failed verification never redirects or creates session", func(t *testing.T) {
		p := newFakeOIDCProvider(t)
		p.wrongAudience = true
		h, _ := newOIDCTestHandlers(t, p)
		target, flowCookie := startFlowAt(t, h, "/auth/oidc/login?"+url.Values{"next": {"/#keys?org=acme"}}.Encode())
		p.nonceToEmbed = target.Query().Get("nonce")
		q := url.Values{"state": {target.Query().Get("state")}, "code": {"auth-code-1"}}
		callback := runCallback(t, h, q, flowCookie)
		if callback.Code != http.StatusUnauthorized {
			t.Fatalf("wrong audience callback: got %d, want 401", callback.Code)
		}
		if location := callback.Header().Get("Location"); location != "" {
			t.Fatalf("failed callback redirected to %q", location)
		}
		for _, cookie := range callback.Result().Cookies() {
			if cookie.Name == "yabanin_admin_session" {
				t.Fatal("failed verification issued an admin session")
			}
			if cookie.Name == adminauth.OIDCFlowCookieName && cookie.MaxAge != -1 {
				t.Fatal("failed callback did not clear the one-time flow cookie")
			}
		}
	})
}

// W-SECADM: the OIDC issuer must honor adminauth.SessionDuration (24h), not
// the legacy hardcoded week.
func TestOIDC_SessionUsesConfiguredDuration(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)

	w := happyFlow(t, h, p)
	if w.Code != http.StatusFound {
		t.Fatalf("callback: got %d, want 302; body %s", w.Code, w.Body.String())
	}

	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "yabanin_admin_session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("callback: no session cookie issued")
	}
	sess, err := adminauth.ParseAdminSessionCookie(session.Value, "test-secret")
	if err != nil {
		t.Fatalf("session cookie does not verify: %v", err)
	}

	lifetime := time.Until(sess.ExpiresAt)
	if lifetime < adminauth.SessionDuration-time.Minute || lifetime > adminauth.SessionDuration+time.Minute {
		t.Fatalf("session lifetime %s, want ~%s (adminauth.SessionDuration)", lifetime, adminauth.SessionDuration)
	}
}

func TestOIDC_StateMismatch_Forbidden(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)
	_, flowCookie := startFlow(t, h)
	p.nonceToEmbed = "whatever"

	w := runCallback(t, h, url.Values{"state": {"forged-state"}, "code": {"c"}}, flowCookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("forged state: got %d, want 403", w.Code)
	}
}

func TestOIDC_MissingFlowCookie_Forbidden(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)
	w := runCallback(t, h, url.Values{"state": {"x"}, "code": {"c"}}, "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("no cookie: got %d, want 403", w.Code)
	}
}

func TestOIDC_NonceMismatch_Forbidden(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)
	target, flowCookie := startFlow(t, h)
	// The provider embeds a DIFFERENT nonce than the one this flow issued.
	p.nonceToEmbed = "nonce-from-another-session"
	q := url.Values{"state": {target.Query().Get("state")}, "code": {"c"}}
	w := runCallback(t, h, q, flowCookie)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("replayed nonce: got %d, want 401", w.Code)
	}
}

func TestOIDC_WrongAudience_Rejected(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.wrongAudience = true
	h, _ := newOIDCTestHandlers(t, p)
	w := happyFlow(t, h, p)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong aud: got %d, want 401", w.Code)
	}
}

func TestOIDC_ExpiredToken_Rejected(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.expirySkewSecs = -1200
	h, _ := newOIDCTestHandlers(t, p)
	w := happyFlow(t, h, p)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired id_token: got %d, want 401", w.Code)
	}
}

func TestOIDC_EmailNotVerified_Forbidden(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.emailVerified = false
	h, _ := newOIDCTestHandlers(t, p)
	w := happyFlow(t, h, p)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unverified email: got %d, want 403", w.Code)
	}
}

func TestOIDC_UnknownEmail_Refused(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.email = "intruder@evil.io"
	h, _ := newOIDCTestHandlers(t, p)
	w := happyFlow(t, h, p)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unknown email: got %d, want 403", w.Code)
	}
}

func TestOIDC_DisabledUser_Refused(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, store := newOIDCTestHandlers(t, p)
	store.adminUsers["u-1"].Active = false
	w := happyFlow(t, h, p)
	if w.Code != http.StatusForbidden {
		t.Fatalf("disabled user: got %d, want 403", w.Code)
	}
}

func TestOIDC_ProviderError_Unauthorized(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)
	_, flowCookie := startFlow(t, h)
	q := url.Values{"state": {"x"}, "error": {"access_denied"}}
	w := runCallback(t, h, q, flowCookie)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("provider error: got %d, want 401", w.Code)
	}
}

func TestOIDC_Unconfigured_404(t *testing.T) {
	store := newMockStore()
	h := newTestAdminH(store) // no SetOIDCClient
	w := httptest.NewRecorder()
	h.OIDCLogin()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/oidc/login", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unconfigured login: got %d, want 404", w.Code)
	}
	w2 := httptest.NewRecorder()
	h.OIDCCallback()(w2, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/oidc/callback", nil))
	if w2.Code != http.StatusNotFound {
		t.Fatalf("unconfigured callback: got %d, want 404", w2.Code)
	}
}

func TestOIDC_LoginPage_ShowsSsoOnlyWhenConfigured(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)
	w := httptest.NewRecorder()
	h.LoginPage()(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/login", nil))
	if !strings.Contains(w.Body.String(), "/auth/oidc/login") {
		t.Fatal("configured login page must link the SSO flow")
	}

	store := newMockStore()
	plain := newTestAdminH(store)
	w2 := httptest.NewRecorder()
	plain.LoginPage()(w2, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/login", nil))
	if strings.Contains(w2.Body.String(), "oidc") {
		t.Fatal("unconfigured login page must not mention oidc")
	}
	if !strings.Contains(w2.Body.String(), "Sign in") {
		t.Fatal("password form must always stay")
	}
}

// Sanity for the flow primitives themselves (PKCE derivation, cookie codec).
func TestOIDCFlow_Primitives(t *testing.T) {
	f, err := adminauth.NewOIDCFlow()
	if err != nil {
		t.Fatalf("NewOIDCFlow: %v", err)
	}
	if len(f.State) != 64 || len(f.Nonce) != 64 {
		t.Fatalf("state/nonce length: %d/%d", len(f.State), len(f.Nonce))
	}
	if n := len(f.PKCEVerifier); n < 43 || n > 128 {
		t.Fatalf("pkce verifier length %d out of RFC 7636 range", n)
	}
	chal := f.PKCEChallengeS256()
	if chal == f.PKCEVerifier || len(chal) != 43 {
		t.Fatalf("challenge must be a 43-char S256 digest, got %q", chal)
	}
	c, err := adminauth.NewOIDCFlowCookie(f)
	if err != nil {
		t.Fatalf("cookie: %v", err)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie flags: %+v", c)
	}
	back, err := adminauth.ParseOIDCFlowCookie(c.Value)
	if err != nil || back != f {
		t.Fatalf("cookie round-trip: %v %+v", err, back)
	}
	if _, err := adminauth.ParseOIDCFlowCookie("!!!not-base64!!!"); err == nil {
		t.Fatal("malformed cookie must fail")
	}
	if _, err := adminauth.ParseOIDCFlowCookie(base64.RawURLEncoding.EncodeToString([]byte(`{"state":"x"}`))); err == nil {
		t.Fatal("incomplete cookie must fail")
	}
	// NewOIDCClient fails closed on a partial tuple.
	if _, err := adminauth.NewOIDCClient(context.Background(), "https://idp", "cid", "", ""); err == nil {
		t.Fatal("partial config must be rejected")
	}
	if _, err := adminauth.NewOIDCClient(context.Background(), "not a url", "cid", "s", "r"); err == nil {
		t.Fatal("unparsable issuer must be rejected")
	}
}

// foreign issuer must fail closed — issuer binding is part of verification,
// not an optional check.
func TestOIDC_WrongIssuer_Rejected(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.foreignIssuer = true
	h, _ := newOIDCTestHandlers(t, p)

	w := happyFlow(t, h, p)
	assertFailedCallback(t, w, http.StatusUnauthorized)
}

// trigger: expired cookie → 401 (with the machine-readable reason), full
// OIDC flow → fresh 24h session that the same guard accepts again.
func TestOIDC_ExpiredLocalSession_Reauthenticates(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, store := newOIDCTestHandlers(t, p)

	expired := adminauth.AdminSession{
		UserID:    store.adminUsers["u-1"].ID,
		Email:     "root@test.io",
		IsRoot:    true,
		SessionID: "expired-session",
		IssuedAt:  time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	expiredCookie, err := adminauth.CreateAdminSessionCookie(expired, "test-secret")
	if err != nil {
		t.Fatalf("create expired session cookie: %v", err)
	}

	middleware := adminauth.ChiAuthMiddlewareGuarded("test-secret", func(context.Context, string) (time.Time, error) {
		return time.Time{}, nil // no password-change watermark recorded
	})
	probe := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/whoami", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(rec, req)
		return rec
	}

	before := probe(expiredCookie)
	if before.Code != http.StatusUnauthorized {
		t.Fatalf("expired local session: got %d, want 401", before.Code)
	}
	if body := before.Body.String(); !strings.Contains(body, "session expired") {
		t.Fatalf("expired session must report a diagnosable reason, body: %s", body)
	}

	after := happyFlow(t, h, p)
	if after.Code != http.StatusFound {
		t.Fatalf("reauth callback: got %d, want 302; body %s", after.Code, after.Body.String())
	}
	fresh := issuedSession(after)
	if fresh == nil {
		t.Fatal("reauth did not issue a local session")
	}
	sess, err := adminauth.ParseAdminSessionCookie(fresh.Value, "test-secret")
	if err != nil {
		t.Fatalf("fresh session cookie does not verify: %v", err)
	}
	if lifetime := time.Until(sess.ExpiresAt); lifetime < adminauth.SessionDuration-time.Minute {
		t.Fatalf("reauth session lifetime %s, want ~%s", lifetime, adminauth.SessionDuration)
	}
	if probe(fresh).Code != http.StatusOK {
		t.Fatal("session issued by OIDC reauthentication must pass the auth guard")
	}
}

// replayed callback (cleared cookie resent, same state+code) must never mint
// a second session.
func TestOIDC_CodeReplay_SecondCallbackFails(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.singleUseCodes = true
	h, _ := newOIDCTestHandlers(t, p)

	target, flowCookie := startFlow(t, h)
	p.nonceToEmbed = target.Query().Get("nonce")
	q := url.Values{"state": {target.Query().Get("state")}, "code": {"auth-code-1"}}

	first := runCallback(t, h, q, flowCookie)
	if first.Code != http.StatusFound || issuedSession(first) == nil {
		t.Fatalf("first callback: got %d, want 302 with session; body %s", first.Code, first.Body.String())
	}

	replay := runCallback(t, h, q, flowCookie)
	assertFailedCallback(t, replay, http.StatusUnauthorized)
}

// context) must fail closed — no session, no redirect, cookie still cleared.
func TestOIDC_InterruptedExchange_FailsClosed(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)

	target, flowCookie := startFlow(t, h)
	p.nonceToEmbed = target.Query().Get("nonce")
	q := url.Values{"state": {target.Query().Get("state")}, "code": {"auth-code-1"}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/auth/oidc/callback?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{
		Name: adminauth.OIDCFlowCookieName, Value: flowCookie,
		Path: "/auth/oidc", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	w := httptest.NewRecorder()
	h.OIDCCallback()(w, req)
	assertFailedCallback(t, w, http.StatusUnauthorized)
}

// success — fail closed without a session or redirect.
func TestOIDC_TokenEndpointOutage_FailsClosed(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.tokenStatus = http.StatusServiceUnavailable
	h, _ := newOIDCTestHandlers(t, p)

	w := happyFlow(t, h, p)
	assertFailedCallback(t, w, http.StatusUnauthorized)
}

// retry blindly — 400 without side effects.
func TestOIDC_MissingCode_BadRequest(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)

	target, flowCookie := startFlow(t, h)
	q := url.Values{"state": {target.Query().Get("state")}}
	w := runCallback(t, h, q, flowCookie)
	assertFailedCallback(t, w, http.StatusBadRequest)
}

// carrying the code, token flow secrets, or state values.
func TestOIDC_FailureLogsCarryNoSecrets(t *testing.T) {
	p := newFakeOIDCProvider(t)
	p.wrongAudience = true
	h, _ := newOIDCTestHandlers(t, p)

	var logs bytes.Buffer
	h.logger = slog.New(slog.NewTextHandler(&logs, nil))

	target, flowCookie := startFlow(t, h)
	p.nonceToEmbed = target.Query().Get("nonce")
	q := url.Values{"state": {target.Query().Get("state")}, "code": {"auth-code-1"}}
	w := runCallback(t, h, q, flowCookie)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong audience callback: got %d, want 401", w.Code)
	}

	captured := logs.String()
	if !strings.Contains(captured, "verification failed") {
		t.Fatalf("failure cause must be logged for diagnosis, logs: %s", captured)
	}
	for _, secret := range []string{
		"auth-code-1", // authorization code
		flowCookie,    // flow cookie value (state/nonce/PKCE verifier)
		target.Query().Get("state"),
	} {
		if strings.Contains(captured, secret) {
			t.Fatalf("failure logs leaked a secret (%q…): %s", secret[:8], captured)
		}
	}
}

// scenario — the full cycle with no token refresh anywhere: OIDC login with
// a dashboard deep link → the guarded route accepts the issued session →
// local logout clears the session/CSRF cookies and redirects to the login
// page → SSO re-login ("refresh": the provider session is still active)
// issues a fresh 24h session for the same deep link that passes the guard.
func TestOIDC_FullCycle_LoginLogoutReauthentication(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)
	next := "/#keys?org=acme"

	middleware := adminauth.ChiAuthMiddlewareGuardedWithRevocation("test-secret", func(context.Context, string) (time.Time, error) {
		return time.Time{}, nil // no password-change watermark recorded
	}, h.revocations)
	probe := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/whoami", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(rec, req)
		return rec
	}
	// One SSO round trip against the same provider: login link → IdP
	// redirect → callback, returning the fresh local session cookie.
	oidcLogin := func() *http.Cookie {
		target, flowCookie := startFlowAt(t, h, "/auth/oidc/login?"+url.Values{"next": {next}}.Encode())
		flow, err := adminauth.ParseOIDCFlowCookie(flowCookie)
		if err != nil {
			t.Fatalf("parse flow cookie: %v", err)
		}
		if flow.Next != next {
			t.Fatalf("flow cookie lost the deep link: got %q, want %q", flow.Next, next)
		}
		p.nonceToEmbed = target.Query().Get("nonce")
		q := url.Values{"state": {target.Query().Get("state")}, "code": {"auth-code-1"}}
		callback := runCallback(t, h, q, flowCookie)
		if callback.Code != http.StatusFound || callback.Header().Get("Location") != next {
			t.Fatalf("callback: got %d → %q, want 302 → %q; body %s",
				callback.Code, callback.Header().Get("Location"), next, callback.Body.String())
		}
		session := issuedSession(callback)
		if session == nil {
			t.Fatal("callback did not issue the local session")
		}
		return session
	}

	// 1. login.
	first := oidcLogin()
	if probe(first).Code != http.StatusOK {
		t.Fatal("first login: guard rejected the freshly issued session")
	}
	firstSess, err := adminauth.ParseAdminSessionCookie(first.Value, "test-secret")
	if err != nil {
		t.Fatalf("first session cookie does not verify: %v", err)
	}
	if firstSess.Email != "root@test.io" || !firstSess.IsRoot {
		t.Fatalf("first login identity: got %+v", firstSess)
	}

	// 2. logout: durable revocation and both cookies cleared, redirect to login.
	logout := httptest.NewRecorder()
	logoutRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/logout", nil)
	logoutRequest.AddCookie(first)
	h.HandleLogout()(logout, logoutRequest)
	if logout.Code != http.StatusFound || logout.Header().Get("Location") != "/auth/login" {
		t.Fatalf("logout: got %d → %q, want 302 → /auth/login", logout.Code, logout.Header().Get("Location"))
	}
	cleared := map[string]bool{}
	for _, c := range logout.Result().Cookies() {
		if c.Name == "yabanin_admin_session" || c.Name == "yabanin_csrf_token" {
			cleared[c.Name] = c.MaxAge < 0
		}
	}
	if !cleared["yabanin_admin_session"] || !cleared["yabanin_csrf_token"] {
		t.Fatalf("logout did not clear both cookies: %v", cleared)
	}
	if !h.revocations.revoked[firstSess.SessionID] {
		t.Fatal("logout did not persist revocation for the OIDC session")
	}
	if got := probe(first).Code; got != http.StatusUnauthorized {
		t.Fatalf("logged-out session passed guarded middleware: got %d, want 401", got)
	}

	// 3. Re-authentication: interactive SSO again (IdP session still active),
	// deep link restored, fresh distinct 24h session accepted by the guard.
	fresh := oidcLogin()
	freshSess, err := adminauth.ParseAdminSessionCookie(fresh.Value, "test-secret")
	if err != nil {
		t.Fatalf("reauthenticated session cookie does not verify: %v", err)
	}
	if freshSess.SessionID == "" || freshSess.SessionID == firstSess.SessionID {
		t.Fatalf("reauthentication must mint a NEW session, got session_id %q", freshSess.SessionID)
	}
	if !freshSess.IssuedAt.After(firstSess.IssuedAt) {
		t.Fatalf("reauthentication issued-at %v not after first login %v", freshSess.IssuedAt, firstSess.IssuedAt)
	}
	if lifetime := time.Until(freshSess.ExpiresAt); lifetime < adminauth.SessionDuration-time.Minute {
		t.Fatalf("reauthenticated session lifetime %s, want ~%s", lifetime, adminauth.SessionDuration)
	}
	if probe(fresh).Code != http.StatusOK {
		t.Fatal("reauthentication: guard rejected the freshly issued session")
	}
}

// behavior under otherwise identical conditions. Each case flips exactly one
// failure knob (issuer / audience / nonce / expiry) on an otherwise valid
// flow and must fail closed; the control run with no knob flipped must still
// succeed. Flipping the knob back is the fixed behavior, so the pair proves
// the outcome is decided by the check, not by fixture differences.
func TestOIDC_VerificationGate_DiscriminatesBrokenFromFixed(t *testing.T) {
	cases := []struct {
		name  string
		knob  func(p *fakeOIDCProvider) // nil = control (valid token)
		valid bool
	}{
		{name: "control-valid-token", valid: true},
		{name: "wrong-issuer", knob: func(p *fakeOIDCProvider) { p.foreignIssuer = true }},
		{name: "wrong-audience", knob: func(p *fakeOIDCProvider) { p.wrongAudience = true }},
		{name: "nonce-mismatch", knob: func(p *fakeOIDCProvider) { p.nonceToEmbed = "nonce-from-another-session" }},
		{name: "expired-token", knob: func(p *fakeOIDCProvider) { p.expirySkewSecs = -1200 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeOIDCProvider(t)
			h, _ := newOIDCTestHandlers(t, p)
			target, flowCookie := startFlow(t, h)
			if tc.knob != nil {
				tc.knob(p)
			} else {
				p.nonceToEmbed = target.Query().Get("nonce")
			}
			q := url.Values{"state": {target.Query().Get("state")}, "code": {"auth-code-1"}}
			w := runCallback(t, h, q, flowCookie)

			if tc.valid {
				if w.Code != http.StatusFound {
					t.Fatalf("control run: got %d, want 302; body %s", w.Code, w.Body.String())
				}
				session := issuedSession(w)
				if session == nil {
					t.Fatal("control run issued no session")
				}
				sess, err := adminauth.ParseAdminSessionCookie(session.Value, "test-secret")
				if err != nil || sess.Email != "root@test.io" {
					t.Fatalf("control session identity: %v %+v", err, sess)
				}
				return
			}
			assertFailedCallback(t, w, http.StatusUnauthorized)
		})
	}
}
