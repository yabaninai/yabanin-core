//go:build integration

package handlers

// refresh cycle and the failure matrix driven through the ACTUAL HTTP entry
// point of the public (community) build: the router returned by SetupRouter()
// is served by a real net/http server on a loopback listener and exercised
// with a real HTTP client carrying a cookie jar — no handler method is ever
// called directly.
//
// The backing store is the real adminstore over a disposable, fully migrated
// Postgres container (pkg/testdb), the same composition services/run/admin.go
// wires: the OIDC client is enabled purely by the config tuple, with NO
// license or EntitlementSource anywhere in the admin plane — the flows below
// succeed with zero entitlement configuration, which is the card's
// "works without enterprise entitlement" check.
//
// The fake IdP follows the loopback-provider pattern of oidc_test.go and
// completes it with the pieces a real browser round trip needs: an
// authorization endpoint that enforces client_id/redirect_uri and issues a
// single-use code bound to the PKCE challenge, and a token endpoint that
// verifies the S256 verifier before signing the RS256 ID token.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/testdb"
)

const (
	e2eSessionSecret = "e2e-int-session-secret"
	e2eAdminEmail    = "root@test.io"
	e2eDeepLink      = "/#keys?org=acme"
)

// ---- e2e fake IdP (full authorization-code flow with PKCE) ------------------

type e2eCode struct {
	challenge   string
	nonce       string
	redirectURI string
}

type e2eOIDCProvider struct {
	server      *httptest.Server
	key         *rsa.PrivateKey
	clientID    string
	redirectURI string // enforced verbatim by the authorization endpoint

	// Failure knobs — set BEFORE the browser flow starts.
	nonceOverride  string // embed this nonce instead of the /auth one (replay)
	foreignIssuer  bool   // id_token carries a foreign iss
	wrongAudience  bool   // id_token aud belongs to another client
	expirySkewSecs int64  // added to exp (negative = expired)

	mu    sync.Mutex
	codes map[string]e2eCode
	used  map[string]bool
}

func newE2EOIDCProvider(t *testing.T) *e2eOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	p := &e2eOIDCProvider{key: key, clientID: "yabanin-admin-e2e", codes: map[string]e2eCode{}, used: map[string]bool{}}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeOIDCJSON(w, map[string]any{
			"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/auth",
			"token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := &p.key.PublicKey
		writeOIDCJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "e2e-key",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	// Authorization endpoint: what the browser hits on the redirect from the
	// console. Enforces the registered client/redirect pair, requires the
	// PKCE S256 challenge and issues a single-use code bound to it.
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != p.clientID || q.Get("redirect_uri") != p.redirectURI {
			http.Error(w, "unregistered client or redirect", http.StatusBadRequest)
			return
		}
		if q.Get("state") == "" || q.Get("nonce") == "" ||
			q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "incomplete authorization request", http.StatusBadRequest)
			return
		}
		code := fmt.Sprintf("e2e-code-%d-%d", time.Now().UnixNano(), len(p.codes))
		p.mu.Lock()
		p.codes[code] = e2eCode{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirectURI: q.Get("redirect_uri")}
		p.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
	})
	// Token endpoint: single-use code, redirect_uri and PKCE S256 verifier
	// checks, then the RS256 ID token (failure knobs applied).
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		p.mu.Lock()
		binding, ok := p.codes[code]
		replayed := p.used[code]
		p.used[code] = true
		p.mu.Unlock()
		if !ok || replayed || r.FormValue("redirect_uri") != binding.redirectURI {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != binding.challenge {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant", "error_description": "pkce verification failed"})
			return
		}
		nonce := binding.nonce
		if p.nonceOverride != "" {
			nonce = p.nonceOverride
		}
		iss := p.server.URL
		if p.foreignIssuer {
			iss = "https://foreign-issuer.invalid"
		}
		aud := p.clientID
		if p.wrongAudience {
			aud = "some-other-client"
		}
		writeOIDCJSON(w, map[string]any{
			"access_token": "at-e2e", "token_type": "Bearer", "expires_in": 3600,
			"id_token": p.signIDToken(t, map[string]any{
				"iss": iss, "aud": aud, "sub": "e2e-user-1",
				"email": e2eAdminEmail, "email_verified": true,
				"exp": time.Now().Unix() + 600 + p.expirySkewSecs,
				"iat": time.Now().Unix(), "nonce": nonce,
			}),
		})
	})

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *e2eOIDCProvider) signIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "e2e-key"})
	cb, _ := json.Marshal(claims)
	si := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	d := sha256.Sum256([]byte(si))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatalf("jwt sign: %v", err)
	}
	return si + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// ---- browser-equivalent client ----------------------------------------------

// localhostTrustJar stores every cookie the server sets (deleting on
// MaxAge<0) and sends them back per host/path. Unlike net/http/cookiejar it
// accepts Secure cookies over plain http: browsers treat localhost as a
// trustworthy origin and do exactly this, which lets the console's Secure
// cookies round-trip on a loopback test server.
type localhostTrustJar struct {
	mu      sync.Mutex
	cookies map[string]map[string]http.Cookie // host → name → cookie
}

func newLocalhostTrustJar() *localhostTrustJar {
	return &localhostTrustJar{cookies: map[string]map[string]http.Cookie{}}
}

func (j *localhostTrustJar) bucket(host string) map[string]http.Cookie {
	if _, ok := j.cookies[host]; !ok {
		j.cookies[host] = map[string]http.Cookie{}
	}
	return j.cookies[host]
}

func (j *localhostTrustJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	b := j.bucket(u.Hostname())
	for _, c := range cookies {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b, c.Name)
			continue
		}
		b[c.Name] = *c
	}
}

func (j *localhostTrustJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []*http.Cookie
	for _, c := range j.bucket(u.Hostname()) {
		if c.Path != "" && !strings.HasPrefix(u.Path, c.Path) {
			continue
		}
		cp := c
		out = append(out, &cp)
	}
	return out
}

// setInjected plants a cookie as if the browser had received it earlier
// (expired-session scenarios that cannot be produced by waiting).
func (j *localhostTrustJar) setInjected(u *url.URL, c http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.bucket(u.Hostname())[c.Name] = c
}

// hasSession reports whether the jar currently holds an admin session cookie.
func (j *localhostTrustJar) hasSession(u *url.URL) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	c, ok := j.bucket(u.Hostname())["yabanin_admin_session"]
	return ok && c.Value != ""
}

// ---- loopback admin server ---------------------------------------------------

// e2eServer is one fully wired community-build admin plane (SetupRouter over
// a real adminstore) served by a real net/http server on a loopback listener.
type e2eServer struct {
	baseURL *url.URL
	jar     *localhostTrustJar
	client  *http.Client
}

// e2eResponse is one HTTP hop: status, selected headers and the body.
type e2eResponse struct {
	status   int
	location string
	cookies  []*http.Cookie
	body     string
}

func (s *e2eServer) get(t *testing.T, rawURL string) e2eResponse {
	t.Helper()
	resp, err := s.client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s body: %v", rawURL, err)
	}
	return e2eResponse{
		status:   resp.StatusCode,
		location: resp.Header.Get("Location"),
		cookies:  resp.Cookies(),
		body:     string(b),
	}
}

// ssoLogin drives ONE full browser-style SSO round trip through the real
// boundary: console login route → IdP authorization endpoint → console
// callback. The callback response is returned to the caller for assertions.
func (s *e2eServer) ssoLogin(t *testing.T, idpURL, next string) e2eResponse {
	t.Helper()

	// 1. console: GET /auth/oidc/login → 302 to the IdP authorization endpoint.
	loginURL := s.baseURL.String() + "/auth/oidc/login"
	if next != "" {
		loginURL += "?" + url.Values{"next": {next}}.Encode()
	}
	login := s.get(t, loginURL)
	if login.status != http.StatusFound {
		t.Fatalf("oidc login: got %d, want 302; body %s", login.status, login.body)
	}
	loc, err := url.Parse(login.location)
	if err != nil {
		t.Fatalf("login location %q: %v", login.location, err)
	}
	if !strings.HasPrefix(loc.String(), idpURL+"/auth?") {
		t.Fatalf("login must redirect to the IdP authorization endpoint, got %q", login.location)
	}
	q := loc.Query()
	for _, k := range []string{"state", "nonce", "code_challenge", "client_id", "redirect_uri"} {
		if q.Get(k) == "" {
			t.Fatalf("authorization redirect missing %s: %q", k, login.location)
		}
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization must carry the S256 challenge, got %q", login.location)
	}

	// 2. IdP authorization endpoint (the browser follows the redirect).
	authz := s.get(t, loc.String())
	if authz.status != http.StatusFound {
		t.Fatalf("idp /auth: got %d, want 302; body %s", authz.status, authz.body)
	}
	cb, err := url.Parse(authz.location)
	if err != nil {
		t.Fatalf("idp return location %q: %v", authz.location, err)
	}
	if !strings.HasPrefix(cb.String(), s.baseURL.String()+"/auth/oidc/callback?") {
		t.Fatalf("idp must return to the console callback, got %q", authz.location)
	}
	if cb.Query().Get("code") == "" || cb.Query().Get("state") != q.Get("state") {
		t.Fatalf("idp return must carry the code and the original state, got %q", authz.location)
	}

	// 3. console callback: code exchange + ID-token verification → session
	// issuance or fail-closed.
	return s.get(t, cb.String())
}

// sessionCookie returns the admin session cookie on resp, or nil.
func sessionCookie(resp e2eResponse) *http.Cookie {
	for _, c := range resp.cookies {
		if c.Name == "yabanin_admin_session" && c.Value != "" {
			return c
		}
	}
	return nil
}

// clearCookieExpired reports whether the named cookie was expired by resp.
func clearCookieExpired(resp e2eResponse, name string) bool {
	for _, c := range resp.cookies {
		if c.Name == name {
			return c.MaxAge < 0
		}
	}
	return false
}

// assertFailedE2E pins the fail-closed shape at the HTTP boundary: generic
// error status, no redirect, no session (response or jar), the one-time flow
// cookie expired, and the guarded surface still closed.
func assertFailedE2E(t *testing.T, resp e2eResponse, s *e2eServer, wantCode int) {
	t.Helper()
	if resp.status != wantCode {
		t.Fatalf("callback: got %d, want %d; body %s", resp.status, wantCode, resp.body)
	}
	if resp.location != "" {
		t.Fatalf("failed callback redirected to %q", resp.location)
	}
	if sessionCookie(resp) != nil {
		t.Fatal("failed callback issued an admin session")
	}
	if s.jar.hasSession(s.baseURL) {
		t.Fatal("cookie jar ended up holding an admin session after a failed callback")
	}
	if !clearCookieExpired(resp, adminauth.OIDCFlowCookieName) {
		t.Fatal("failed callback did not clear the one-time flow cookie")
	}
	if probe := s.get(t, s.baseURL.String()+"/api/version"); probe.status != http.StatusUnauthorized {
		t.Fatalf("guarded route after failed SSO: got %d, want 401", probe.status)
	}
}

// ---- fixtures ----------------------------------------------------------------

// seedE2EAdminUser provisions the admin the fake IdP maps to through the
// REAL store path (the same store the community build uses), and removes the
// row when the test ends.
func seedE2EAdminUser(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	store := adminstore.New(pool, slog.Default(), nil)
	u, err := store.CreateAdminUser(context.Background(), e2eAdminEmail, "E2E Root", "unused-by-the-oidc-flow", true)
	if err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_users WHERE id = $1`, u.ID)
	})
	return u.ID
}

// newE2EAdminServer wires the community-build admin plane exactly like
// services/run/admin.go does for SSO (config tuple only — no entitlement) and
// serves SetupRouter() over a real loopback listener.
func newE2EAdminServer(t *testing.T, pool *pgxpool.Pool, p *e2eOIDCProvider) *e2eServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := &url.URL{Scheme: "http", Host: ln.Addr().String()}
	p.redirectURI = base.String() + "/auth/oidc/callback"

	client, err := adminauth.NewOIDCClient(context.Background(), p.server.URL, p.clientID, "e2e-idp-secret", p.redirectURI)
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}
	h := New(adminstore.New(pool, slog.Default(), nil), e2eSessionSecret, "localhost", nil)
	h.SetOIDCClient(client)

	srv := &http.Server{Handler: h.SetupRouter(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		h.Stop()
	})

	jar := newLocalhostTrustJar()
	return &e2eServer{
		baseURL: base,
		jar:     jar,
		client: &http.Client{
			Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // hop-by-hop control
			},
		},
	}
}

// ---- tests -------------------------------------------------------------------

// login → guarded routes → logout → SSO refresh — with the dashboard deep
// link preserved end to end.
func TestOIDCIntE2E_LoginLogoutRefreshCycle(t *testing.T) {
	pool := testdb.Postgres(t)
	seedE2EAdminUser(t, pool)
	p := newE2EOIDCProvider(t)
	s := newE2EAdminServer(t, pool, p)

	// The boundary is closed before any login.
	if probe := s.get(t, s.baseURL.String()+"/api/version"); probe.status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/version: got %d, want 401", probe.status)
	}

	// UI/API path compatibility: the login page links the SSO flow and
	// carries the deep link into it.
	page := s.get(t, s.baseURL.String()+"/auth/login?"+url.Values{"next": {e2eDeepLink}}.Encode())
	if page.status != http.StatusOK {
		t.Fatalf("login page: got %d, want 200; body %s", page.status, page.body)
	}
	wantLink := `href="/auth/oidc/login?` + url.Values{"next": {e2eDeepLink}}.Encode() + `"`
	if !strings.Contains(page.body, wantLink) {
		t.Fatalf("login page lost the SSO deep link %q; body %s", wantLink, page.body)
	}

	// 1. login: full redirect chain → session issued, deep link preserved.
	callback := s.ssoLogin(t, p.server.URL, e2eDeepLink)
	if callback.status != http.StatusFound {
		t.Fatalf("callback: got %d, want 302; body %s", callback.status, callback.body)
	}
	if callback.location != e2eDeepLink {
		t.Fatalf("callback redirect: got %q, want deep link %q", callback.location, e2eDeepLink)
	}
	sessCookie := sessionCookie(callback)
	if sessCookie == nil {
		t.Fatal("callback did not issue the admin session cookie")
	}
	if !clearCookieExpired(callback, adminauth.OIDCFlowCookieName) {
		t.Fatal("callback did not clear the one-time flow cookie")
	}
	sess, err := adminauth.ParseAdminSessionCookie(sessCookie.Value, e2eSessionSecret)
	if err != nil {
		t.Fatalf("issued session cookie does not verify: %v", err)
	}
	if sess.Email != e2eAdminEmail || !sess.IsRoot || sess.SessionID == "" {
		t.Fatalf("session identity: got %+v", sess)
	}
	if lifetime := time.Until(sess.ExpiresAt); lifetime < adminauth.SessionDuration-time.Minute || lifetime > adminauth.SessionDuration+time.Minute {
		t.Fatalf("session lifetime %s, want ~%s", lifetime, adminauth.SessionDuration)
	}

	// The issued session passes the real guard (session middleware + store
	// revalidation over Postgres).
	if probe := s.get(t, s.baseURL.String()+"/api/version"); probe.status != http.StatusOK {
		t.Fatalf("/api/version with fresh SSO session: got %d; body %s", probe.status, probe.body)
	}
	me := s.get(t, s.baseURL.String()+"/api/me")
	if me.status != http.StatusOK || !strings.Contains(me.body, e2eAdminEmail) || !strings.Contains(me.body, `"is_root":true`) {
		t.Fatalf("/api/me: got %d, want 200 with the mapped root identity; body %s", me.status, me.body)
	}
	if csrf := s.get(t, s.baseURL.String()+"/auth/csrf"); csrf.status != http.StatusOK {
		t.Fatalf("/auth/csrf with fresh SSO session: got %d, want 200", csrf.status)
	}

	// 2. logout: both cookies cleared through the real boundary; the guarded
	// surface closes again.
	logout := s.get(t, s.baseURL.String()+"/auth/logout")
	if logout.status != http.StatusFound || logout.location != "/auth/login" {
		t.Fatalf("logout: got %d → %q, want 302 → /auth/login", logout.status, logout.location)
	}
	if !clearCookieExpired(logout, "yabanin_admin_session") || !clearCookieExpired(logout, "yabanin_csrf_token") {
		t.Fatalf("logout did not clear both cookies: %+v", logout.cookies)
	}
	if s.jar.hasSession(s.baseURL) {
		t.Fatal("cookie jar still holds the session after logout")
	}
	if probe := s.get(t, s.baseURL.String()+"/api/version"); probe.status != http.StatusUnauthorized {
		t.Fatalf("/api/version after logout: got %d, want 401", probe.status)
	}

	// 3. refresh: the IdP session is still active, so a second SSO round trip
	// must mint a NEW distinct session that the guard accepts.
	refresh := s.ssoLogin(t, p.server.URL, e2eDeepLink)
	if refresh.status != http.StatusFound || refresh.location != e2eDeepLink {
		t.Fatalf("refresh callback: got %d → %q, want 302 → %q; body %s",
			refresh.status, refresh.location, e2eDeepLink, refresh.body)
	}
	refreshCookie := sessionCookie(refresh)
	if refreshCookie == nil {
		t.Fatal("refresh did not issue the local session")
	}
	fresh, err := adminauth.ParseAdminSessionCookie(refreshCookie.Value, e2eSessionSecret)
	if err != nil {
		t.Fatalf("refreshed session cookie does not verify: %v", err)
	}
	if fresh.SessionID == sess.SessionID {
		t.Fatalf("refresh must mint a NEW session, got session_id %q twice", sess.SessionID)
	}
	if !fresh.IssuedAt.After(sess.IssuedAt) {
		t.Fatalf("refresh issued-at %v not after first login %v", fresh.IssuedAt, sess.IssuedAt)
	}
	if lifetime := time.Until(fresh.ExpiresAt); lifetime < adminauth.SessionDuration-time.Minute {
		t.Fatalf("refreshed session lifetime %s, want ~%s", lifetime, adminauth.SessionDuration)
	}
	if probe := s.get(t, s.baseURL.String()+"/api/version"); probe.status != http.StatusOK {
		t.Fatalf("/api/version with refreshed session: got %d, want 200", probe.status)
	}
}

// HTTP boundary. Each case flips exactly one IdP knob on an otherwise valid
// flow; the control run with no knob flipped must still succeed, proving the
// outcome is decided by the check, not by fixture differences.
func TestOIDCIntE2E_VerificationFailures(t *testing.T) {
	pool := testdb.Postgres(t)
	seedE2EAdminUser(t, pool)

	cases := []struct {
		name string
		knob func(p *e2eOIDCProvider) // nil = control (valid token)
		want int
	}{
		{name: "control-valid-token", want: http.StatusFound},
		{name: "wrong-issuer", knob: func(p *e2eOIDCProvider) { p.foreignIssuer = true }, want: http.StatusUnauthorized},
		{name: "wrong-audience", knob: func(p *e2eOIDCProvider) { p.wrongAudience = true }, want: http.StatusUnauthorized},
		{name: "wrong-nonce", knob: func(p *e2eOIDCProvider) { p.nonceOverride = "nonce-from-another-browser" }, want: http.StatusUnauthorized},
		{name: "expired-id-token", knob: func(p *e2eOIDCProvider) { p.expirySkewSecs = -1200 }, want: http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newE2EOIDCProvider(t)
			if tc.knob != nil {
				tc.knob(p)
			}
			s := newE2EAdminServer(t, pool, p)
			resp := s.ssoLogin(t, p.server.URL, "")
			if tc.want == http.StatusFound {
				if resp.status != http.StatusFound {
					t.Fatalf("control run: got %d, want 302; body %s", resp.status, resp.body)
				}
				if sessionCookie(resp) == nil || !s.jar.hasSession(s.baseURL) {
					t.Fatal("control run issued no session")
				}
				if probe := s.get(t, s.baseURL.String()+"/api/version"); probe.status != http.StatusOK {
					t.Fatalf("control session rejected by the guard: got %d, want 200", probe.status)
				}
				return
			}
			assertFailedE2E(t, resp, s, tc.want)
		})
	}
}

// locally issued, correctly signed cookie past its ExpiresAt must be
// rejected by the guard with a diagnosable reason, the cookie cleared, and
// recovery must be a fresh SSO login through the same boundary.
func TestOIDCIntE2E_ExpiredLocalSession(t *testing.T) {
	pool := testdb.Postgres(t)
	uid := seedE2EAdminUser(t, pool)
	p := newE2EOIDCProvider(t)
	s := newE2EAdminServer(t, pool, p)

	// Sanity: a fresh login works, then swap in an expired signed session.
	first := s.ssoLogin(t, p.server.URL, "")
	if first.status != http.StatusFound || !s.jar.hasSession(s.baseURL) {
		t.Fatalf("initial login failed: got %d", first.status)
	}

	expired := adminauth.AdminSession{
		UserID:    uid,
		Email:     e2eAdminEmail,
		IsRoot:    true,
		SessionID: "expired-e2e-session",
		IssuedAt:  time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	expiredCookie, err := adminauth.CreateAdminSessionCookie(expired, e2eSessionSecret)
	if err != nil {
		t.Fatalf("create expired session cookie: %v", err)
	}
	s.jar.setInjected(s.baseURL, *expiredCookie)

	probe := s.get(t, s.baseURL.String()+"/api/version")
	if probe.status != http.StatusUnauthorized {
		t.Fatalf("expired local session: got %d, want 401", probe.status)
	}
	if !strings.Contains(probe.body, "session expired") {
		t.Fatalf("expired session must report a diagnosable reason; body: %s", probe.body)
	}
	if !clearCookieExpired(probe, "yabanin_admin_session") {
		t.Fatal("expired session was not cleared by the guard")
	}

	// Recovery: a fresh SSO round trip re-authenticates.
	again := s.ssoLogin(t, p.server.URL, "")
	if again.status != http.StatusFound || sessionCookie(again) == nil {
		t.Fatalf("reauth login: got %d, want 302 with a session; body %s", again.status, again.body)
	}
	if probe := s.get(t, s.baseURL.String()+"/api/version"); probe.status != http.StatusOK {
		t.Fatalf("guard rejected the reauthenticated session: got %d, want 200", probe.status)
	}
}

// community build with ZERO license/entitlement configuration — SSO is
// enabled by the config tuple alone.
func TestOIDCIntE2E_MountedWithoutEntitlement(t *testing.T) {
	lic := config.LicenseFromEnv()
	if lic.File != "" || lic.RootPubKey != "" || lic.CRLFile != "" || lic.IntermediateCert != "" {
		t.Skip("license env present in the test process; the no-entitlement precondition cannot be met")
	}

	pool := testdb.Postgres(t)
	seedE2EAdminUser(t, pool)
	p := newE2EOIDCProvider(t)
	s := newE2EAdminServer(t, pool, p)

	// The public login page advertises SSO and the routes answer: mounted by
	// the config tuple alone, no entitlement gate anywhere in the chain.
	page := s.get(t, s.baseURL.String()+"/auth/login")
	if page.status != http.StatusOK || !strings.Contains(page.body, "/auth/oidc/login") {
		t.Fatalf("no-entitlement login page: got %d, want 200 with an SSO link; body %s", page.status, page.body)
	}
	resp := s.ssoLogin(t, p.server.URL, "")
	if resp.status != http.StatusFound || sessionCookie(resp) == nil {
		t.Fatalf("no-entitlement SSO login: got %d, want 302 with a session; body %s", resp.status, resp.body)
	}
	if probe := s.get(t, s.baseURL.String()+"/api/version"); probe.status != http.StatusOK {
		t.Fatalf("no-entitlement guarded route: got %d, want 200", probe.status)
	}
}
