//go:build integration

package adminauth_test

// N04-P01 T09 — consumer-compatibility matrix against the REAL local
// Keycloak stand (owner decision 2026-10). The mock- and unit-level compat
// evidence lives in services/admin/handlers (routes goldens, guard-chain
// tests, oidc_test.go); this file closes the live remainder: what happens
// when old and new consumers share one realm and one console base.
//
//   1. old config (password-only community build): every unmounted SSO
//      route is indistinguishable from any other unknown route (no oracle)
//      and never issues a session, the password flow still works;
//   2. new config (admin OIDC + portal on ONE console base, ONE realm, two
//      per-consumer clients): both consumers log in, neither leaks into the
//      other — flow cookies are path-scoped, callback replays fail closed,
//      codes and tokens are audience-bound;
//   3. groups mapping (ENT/SSO rules) stay scoped to the OIDC consumer:
//      SAML and portal logins NEVER reconcile org memberships while the
//      same realm user with the same groups claims is reconciled by OIDC;
//   4. token material: per-consumer audiences, key rotation adoption,
//      retired-key rejection and a real foreign-issuer (master realm) token
//      are rejected by every realm consumer.
//
// Everything here is real: real discovery/JWKS, real RS256 tokens, real
// Keycloak login forms, real Postgres (except test 4, which needs no store).
// Skip discipline follows KeycloakLiveStand: a missing Docker daemon is an
// explicit SKIP, never a silent pass.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// kcCompatConsolePassword is the password every kcLiveWorld admin user is
// created with (the third CreateAdminUser argument) — the old community
// password flow must keep accepting it.
const kcCompatConsolePassword = "unused-by-sso"

// kcCompatPortalClient is the SECOND per-consumer OIDC client this file
// registers in the live realm (distinct audience, same issuer). Each test
// ensures and deletes it — the file may run before every other suite.
const (
	kcCompatPortalClient   = "yabanin-portal"
	kcCompatPortalSecret   = "n04-portal-secret"
	kcCompatForeignClient  = "n04-foreign-cli"
	kcCompatForeignSecret  = "n04-foreign-cli-secret"
	kcCompatPortalRedirect = "http://localhost:9/portal/callback"

	// Dedicated portal identity: never admit shared users through the
	// portal (see kcCompatEnsurePortalUser).
	kcCompatPortalUser  = "sso-portal"
	kcCompatPortalEmail = "sso-portal@test.io"
	kcCompatPortalPass  = "n04-compat-portal-pass"

	// Dual-session identity: both an admin row and a portal-admissible
	// developer, owned by this suite (see the cell E note).
	kcCompatDualUser  = "sso-dual"
	kcCompatDualEmail = "sso-dual@test.io"
	kcCompatDualPass  = "n04-compat-dual-pass"

	// kcCompatSentinelHash mirrors kcLiveWorld's SSO-only account convention:
	// a non-bcrypt hash column value no password can match.
	kcCompatSentinelHash = "unused-by-sso"
)

// kcCompatEnsurePortalClient registers the portal consumer client in the
// realm and deletes it when the test ends (idempotent cleanup).
func kcCompatEnsurePortalClient(t *testing.T, stand *adminauth.KCStand) {
	t.Helper()
	ctx := context.Background()
	if err := stand.EnsureOIDCClient(ctx, stand.Realm, kcCompatPortalClient, kcCompatPortalSecret,
		[]string{"http://127.0.0.1/*", kcCompatPortalRedirect}); err != nil {
		t.Fatalf("ensure %s client: %v", kcCompatPortalClient, err)
	}
	t.Cleanup(func() {
		if err := stand.DeleteOIDCClient(ctx, stand.Realm, kcCompatPortalClient); err != nil {
			t.Errorf("cleanup: delete %s client: %v", kcCompatPortalClient, err)
		}
	})
}

// kcCompatEnsurePortalUser provisions the compat suite's DEDICATED portal
// identity. Portal provisioning binds the global developer row (keyed by
// email) to the FIRST portal org that admits it, so this suite must never
// admit shared users like the root admin — the lifecycle suite relies on
// being the first to admit root itself.
func kcCompatEnsurePortalUser(t *testing.T, stand *adminauth.KCStand) {
	t.Helper()
	if err := stand.EnsureRealmUser(context.Background(), kcCompatPortalUser, "Compat Portal", kcCompatPortalEmail, kcCompatPortalPass); err != nil {
		t.Fatalf("ensure %s realm user: %v", kcCompatPortalUser, err)
	}
}

// kcCompatCaptureIDToken is CaptureIDToken parameterized per consumer: a
// real authorization-code + PKCE round trip against an arbitrary issuer /
// client pair, returning the raw ID token and its claims.
func kcCompatCaptureIDToken(t *testing.T, issuerURL, clientID, clientSecret, redirectURI, username, password string) (string, map[string]any) {
	t.Helper()
	flow, err := adminauth.NewOIDCFlow()
	if err != nil {
		t.Fatalf("oidc flow: %v", err)
	}
	q := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"redirect_uri":          {redirectURI},
		"state":                 {flow.State},
		"nonce":                 {flow.Nonce},
		"code_challenge":        {flow.PKCEChallengeS256()},
		"code_challenge_method": {"S256"},
	}
	browser := adminauth.NewKCBrowser()
	hops := browser.DriveSSO(t, issuerURL+"/protocol/openid-connect/auth?"+q.Encode(), username, password, redirectURI)
	last := hops[len(hops)-1]
	if last.Status != http.StatusFound || !strings.HasPrefix(last.Location, redirectURI) {
		t.Fatalf("capture flow %s: expected redirect to %s, got %d → %q", clientID, redirectURI, last.Status, last.Location)
	}
	code := kcLCQueryValue(t, last.Location, "code")
	if flow.State != kcLCQueryValue(t, last.Location, "state") {
		t.Fatalf("capture flow %s: state mismatch", clientID)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {flow.PKCEVerifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		issuerURL+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange: status %d: %s", resp.StatusCode, kcSnippet(string(raw)))
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil || tok.IDToken == "" {
		t.Fatalf("token exchange carried no id_token")
	}
	return tok.IDToken, kcCompatJWTClaims(t, tok.IDToken)
}

// kcCompatJWTClaims decodes the payload segment of a raw JWT.
func kcCompatJWTClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("id_token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		t.Fatalf("decode id_token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("id_token claims: %v", err)
	}
	return claims
}

// kcCompatRedeemCode offers an authorization code to the token endpoint
// under a CHOSEN client and returns the raw HTTP status — used to prove a
// code issued for one relying party is refused by another (client binding).
func kcCompatRedeemCode(t *testing.T, issuerURL, clientID, clientSecret, redirectURI, code string) int {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {"no-verifier-can-rescue-a-foreign-code"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		issuerURL+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("redeem code as %s: status %d: %s", clientID, resp.StatusCode, kcSnippet(string(raw)))
	return resp.StatusCode
}

// kcCompatSignJWT forges an RS256 token that carries a REAL realm kid in
// its header but is signed by the test's own key — the signature check must
// reject it even though the kid looks trusted.
func kcCompatSignJWT(t *testing.T, kid string, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatalf("jwt header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("jwt payload: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// kcCompatAudContains reports whether the token's aud claim (string or
// array) names the client.
func kcCompatAudContains(t *testing.T, claims map[string]any, clientID string, want bool) {
	t.Helper()
	named := false
	switch aud := claims["aud"].(type) {
	case string:
		named = aud == clientID
	case []any:
		for _, a := range aud {
			if s, _ := a.(string); s == clientID {
				named = true
			}
		}
	}
	if named != want {
		t.Fatalf("aud claim %v names %q: got %v, want %v", claims["aud"], clientID, named, want)
	}
}

// kcCompatMaskCSRF blanks the per-request CSRF token so two renderings of
// the same page can be compared byte-for-byte.
func kcCompatMaskCSRF(body string) string {
	return regexp.MustCompile(`(name="_csrf"[^>]*value=")[^"]*(")`).ReplaceAllString(body, `${1}MASKED${2}`)
}

// kcCompatPostJSON performs an authenticated JSON mutation on the console
// with the CSRF double-submit pair (cookie already in the jar + header).
func kcCompatPostJSON(t *testing.T, console *kcConsole, browser *adminauth.KCBrowser, path string, payload any, csrf string) kcResp {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s payload: %v", path, err)
	}
	req, err := http.NewRequest(http.MethodPost, console.base.String()+path, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("build %s request: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := browser.Client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return kcResp{status: resp.StatusCode, location: resp.Header.Get("Location"), body: string(raw), cookies: resp.Cookies()}
}

// kcCompatWaitKidGone polls the realm JWKS until the retired kid stops
// being published (Keycloak rebuilds its key cache asynchronously).
func kcCompatWaitKidGone(t *testing.T, stand *adminauth.KCStand, kid string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		kids, err := stand.JWKSKids(context.Background())
		if err == nil {
			published := false
			for _, k := range kids {
				if k == kid {
					published = true
				}
			}
			if !published {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("kid %q still published after retirement: %v", kid, kids)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// kcCompatPasswordLogin drives the community password flow through the real
// login page (fresh CSRF token per attempt) and returns the POST response.
func kcCompatPasswordLogin(t *testing.T, console *kcConsole, browser *adminauth.KCBrowser, email, password, next string) kcResp {
	t.Helper()
	page := console.get(t, browser, console.base.String()+"/auth/login?"+url.Values{"next": {next}}.Encode())
	if page.status != http.StatusOK {
		t.Fatalf("GET /auth/login: got %d, want 200; body %s", page.status, kcSnippet(page.body))
	}
	m := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindStringSubmatch(page.body)
	if m == nil {
		t.Fatalf("login page carries no csrf token: %s", kcSnippet(page.body))
	}
	return console.postForm(t, browser, console.base.String()+"/auth/login", url.Values{
		"email":    {email},
		"password": {password},
		"_csrf":    {m[1]},
		"next":     {next},
	})
}

// portalLoginOn drives one full portal login (real IdP) on the given
// browser and asserts the callback contract (302 → /portal, portal session,
// one-time flow cookie cleared).
func portalLoginOn(t *testing.T, console *kcConsole, browser *adminauth.KCBrowser, username, password string) kcResp {
	t.Helper()
	stop := console.base.String() + "/portal/callback"
	login := console.get(t, browser, console.base.String()+"/portal/login")
	if login.status != http.StatusFound {
		t.Fatalf("portal login: got %d, want 302; body %s", login.status, kcSnippet(login.body))
	}
	hops := browser.DriveSSO(t, login.location, username, password, stop)
	last := hops[len(hops)-1]
	if last.Status != http.StatusFound || !strings.HasPrefix(last.Location, stop) {
		t.Fatalf("real IdP did not return to the portal callback: %d → %q", last.Status, last.Location)
	}
	done := console.get(t, browser, last.Location)
	if done.status != http.StatusFound || done.location != "/portal" {
		t.Fatalf("portal callback: got %d → %q, want 302 → /portal; body %s", done.status, done.location, kcSnippet(done.body))
	}
	if !console.flowCookieCleared(t, done, adminauth.PortalOIDCFlowCookieName) {
		t.Fatal("portal callback did not clear the one-time flow cookie")
	}
	if browser.Jar.Cookie(console.base, adminauth.PortalSessionCookieName) == "" {
		t.Fatal("portal callback issued no portal session")
	}
	return done
}

// ---- 1. old config: the password-only community build must keep working ----

func TestKeycloakLiveCompat_CommunityPasswordFlowStandalone(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	store, _ := kcLiveWorld(t, pool)

	// JWKS sanity: the stand publishes unique RS256 kids (consumers build
	// verifiers from exactly this document).
	kids, err := stand.JWKSKids(context.Background())
	if err != nil {
		t.Fatalf("realm JWKS: %v", err)
	}
	if len(kids) == 0 {
		t.Fatal("realm publishes no signing keys")
	}
	seen := map[string]bool{}
	for _, k := range kids {
		if seen[k] {
			t.Fatalf("realm JWKS repeats kid %q: %v", k, kids)
		}
		seen[k] = true
	}

	// A console built from the community defaults: NO SSO mounts at all.
	console := kcStartConsole(t, pool, func(string) ([]func(*handlers.AdminHandlers), error) { return nil, nil })

	// Every unmounted SSO route is indistinguishable from any other unknown
	// route (no oracle about the SSO feature), and no route issues a
	// session. End-to-end the unconfigured routes are simply not
	// registered: the SPA catch-all guard answers them exactly like any
	// other unknown path (401 login page for this build — requiring a
	// session even to learn a route exists fails closed).
	baselineGET := console.get(t, adminauth.NewKCBrowser(), console.base.String()+"/definitely-not-a-route")
	if baselineGET.status != http.StatusUnauthorized {
		t.Fatalf("baseline unknown GET: got %d, want 401 (SPA guard); body %s", baselineGET.status, kcSnippet(baselineGET.body))
	}
	baselinePOST := console.postForm(t, adminauth.NewKCBrowser(), console.base.String()+"/definitely-not-a-route", url.Values{})
	if baselinePOST.status != baselineGET.status {
		t.Fatalf("baseline unknown POST: got %d, want the same as GET (%d); body %s", baselinePOST.status, baselineGET.status, kcSnippet(baselinePOST.body))
	}
	// The unknown-route response differs by route family: misses inside the
	// mounted /auth subrouter produce the subrouter's own 404 (chi's plain
	// "page not found"), while every other unknown path falls through to the
	// root catch-all (the 401 login page). Each unmounted consumer must be
	// indistinguishable from a typo within its own family — no oracle, no
	// session, no difference between GET and POST.
	authBaselineGET := console.get(t, adminauth.NewKCBrowser(), console.base.String()+"/auth/definitely-not-a-route")
	for _, probe := range []struct {
		route      string
		method     string
		familyAuth bool // true: compare against the /auth-family baseline
	}{
		{"/auth/oidc/login", http.MethodGet, true},
		{"/auth/oidc/callback", http.MethodGet, true},
		{"/auth/oidc/callback", http.MethodPost, true},
		{"/auth/saml/metadata", http.MethodGet, true},
		{"/auth/saml/login", http.MethodGet, true},
		{"/auth/saml/acs", http.MethodPost, true},
		{"/portal/login", http.MethodGet, false},
		{"/portal/callback", http.MethodGet, false},
	} {
		browser := adminauth.NewKCBrowser()
		var resp kcResp
		if probe.method == http.MethodPost {
			resp = console.postForm(t, browser, console.base.String()+probe.route, url.Values{})
		} else {
			resp = console.get(t, browser, console.base.String()+probe.route)
		}
		want := baselineGET
		family := "root"
		if probe.familyAuth {
			want = authBaselineGET
			family = "auth"
		}
		if resp.status != want.status {
			t.Fatalf("unmounted %s (%s): got %d, want the unknown-%s-route status %d; body %s", probe.route, probe.method, resp.status, family, want.status, kcSnippet(resp.body))
		}
		if kcCompatMaskCSRF(resp.body) != kcCompatMaskCSRF(want.body) {
			t.Fatalf("unmounted %s: body differs from an unknown route:\n%s\nvs\n%s", probe.route, kcSnippet(resp.body), kcSnippet(want.body))
		}
		if console.hasSession(browser.Jar) {
			t.Fatalf("unmounted %s issued a session", probe.route)
		}
	}

	// The password flow is untouched: real login through the real page. The
	// shared world users carry a sentinel hash (they are SSO-only), so the
	// password consumer gets its own account with a genuine bcrypt hash.
	pwHash, err := adminauth.HashPassword(kcCompatConsolePassword)
	if err != nil {
		t.Fatalf("hash console password: %v", err)
	}
	if _, err := store.CreateAdminUser(context.Background(), "password-flow@test.io", "N04 Password Flow", pwHash, false); err != nil {
		t.Fatalf("create password-flow user: %v", err)
	}
	browser := adminauth.NewKCBrowser()
	done := kcCompatPasswordLogin(t, console, browser, "password-flow@test.io", kcCompatConsolePassword, kcDeepLink)
	if done.status != http.StatusFound || done.location != kcDeepLink {
		t.Fatalf("password login: got %d → %q, want 302 → %s; body %s", done.status, done.location, kcDeepLink, kcSnippet(done.body))
	}
	sess := console.sessionOf(t, done)
	if sess == nil || sess.Email != "password-flow@test.io" || sess.IsRoot {
		t.Fatalf("password login session: got %+v", sess)
	}
	if !console.hasSession(browser.Jar) {
		t.Fatal("password login issued no session cookie")
	}
	if browser.Jar.Cookie(console.base, "yabanin_csrf_token") == "" {
		t.Fatal("login page issued no csrf cookie")
	}
	me := console.get(t, browser, console.base.String()+"/api/me")
	if me.status != http.StatusOK || !strings.Contains(me.body, "password-flow@test.io") {
		t.Fatalf("/api/me after password login: got %d; body %s", me.status, kcSnippet(me.body))
	}
	if version := console.get(t, browser, console.base.String()+"/api/version"); version.status != http.StatusOK {
		t.Fatalf("/api/version after password login: got %d", version.status)
	}

	// Wrong credentials: the generic 401 login page, never a session.
	wrongBrowser := adminauth.NewKCBrowser()
	wrong := kcCompatPasswordLogin(t, console, wrongBrowser, "password-flow@test.io", "not-the-password", "/")
	if wrong.status != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d, want 401; body %s", wrong.status, kcSnippet(wrong.body))
	}
	if console.hasSession(wrongBrowser.Jar) {
		t.Fatal("wrong password produced a session")
	}
}

// ---- 2. new config: both consumers on ONE console base, ONE realm -----------

func TestKeycloakLiveCompat_NewConfigBothConsumersOneConsole(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	store, _ := kcLiveWorld(t, pool)
	ctx := context.Background()
	kcCompatEnsurePortalClient(t, stand)
	kcCompatEnsurePortalUser(t, stand)

	org, err := store.CreateOrganization(ctx, "N04 Compat Org", "n04-compat")
	if err != nil {
		t.Fatalf("create compat org: %v", err)
	}
	team, err := store.CreateTeam(ctx, org.ID, "Compat Team", "n04-compat-team", nil)
	if err != nil {
		t.Fatalf("create compat team: %v", err)
	}

	console := kcStartConsole(t, pool, func(base string) ([]func(*handlers.AdminHandlers), error) {
		adminClient, err := adminauth.NewOIDCClient(ctx, stand.RealmURL,
			adminauth.KCLiveOIDCClientID, adminauth.KCLiveOIDCClientSecret, base+"/auth/oidc/callback")
		if err != nil {
			return nil, err
		}
		portalClient, err := adminauth.NewOIDCClient(ctx, stand.RealmURL,
			kcCompatPortalClient, kcCompatPortalSecret, base+"/portal/callback")
		if err != nil {
			return nil, err
		}
		return []func(*handlers.AdminHandlers){
			func(h *handlers.AdminHandlers) { h.SetOIDCClient(adminClient) },
			func(h *handlers.AdminHandlers) {
				h.SetPortal(handlers.PortalOptions{
					Enabled:        true,
					Provisioning:   "domain",
					AllowedDomains: []string{"test.io"},
					DefaultOrg:     org.ID,
					DefaultTeam:    team.ID,
					Client:         portalClient,
					Store:          store,
				})
			},
		}, nil
	})
	adminCallback := console.base.String() + "/auth/oidc/callback"

	// (A) the admin console consumer logs in through the REAL provider.
	aBrowser := adminauth.NewKCBrowser()
	aResp := console.kcSSOLogin(t, aBrowser, "/auth/oidc/login?"+url.Values{"next": {kcDeepLink}}.Encode(),
		adminauth.KCUserRoot, adminauth.KCPassRoot, adminCallback)
	if aResp.status != http.StatusFound || aResp.location != kcDeepLink {
		t.Fatalf("admin oidc login: got %d → %q, want 302 → %s; body %s", aResp.status, aResp.location, kcDeepLink, kcSnippet(aResp.body))
	}
	if sess := console.sessionOf(t, aResp); sess == nil || sess.Email != kcAdminEmail {
		t.Fatalf("admin oidc session: got %+v", sess)
	}
	if !console.flowCookieCleared(t, aResp, adminauth.OIDCFlowCookieName) {
		t.Fatal("admin callback did not clear its flow cookie")
	}
	if aBrowser.Jar.Cookie(console.base, adminauth.PortalSessionCookieName) != "" {
		t.Fatal("admin oidc login must not issue a portal session")
	}

	// (B) the portal consumer logs in through ITS client on the same base —
	// with the suite's own identity (never the shared root admin).
	bBrowser := adminauth.NewKCBrowser()
	portalLoginOn(t, console, bBrowser, kcCompatPortalUser, kcCompatPortalPass)
	if console.hasSession(bBrowser.Jar) {
		t.Fatal("portal login must not create an admin console session")
	}
	if me := console.get(t, bBrowser, console.base.String()+"/api/me"); me.status != http.StatusOK || !strings.Contains(me.body, kcCompatPortalEmail) {
		t.Fatalf("portal /api/me: got %d; body %s", me.status, kcSnippet(me.body))
	}
	if _, err := store.GetDeveloperByEmail(ctx, kcCompatPortalEmail); err != nil {
		t.Fatalf("portal login did not leave a developer row: %v", err)
	}
	if home := console.get(t, bBrowser, console.base.String()+"/portal"); home.status != http.StatusOK {
		t.Fatalf("GET /portal with a portal session: got %d; body %s", home.status, kcSnippet(home.body))
	}

	// (C1) an ADMIN flow cookie cannot satisfy the PORTAL callback: the
	// cookies are path-scoped, so the portal route never even sees it and
	// fails closed on the missing one-time cookie.
	c1 := adminauth.NewKCBrowser()
	if start := console.get(t, c1, console.base.String()+"/auth/oidc/login"); start.status != http.StatusFound {
		t.Fatalf("admin flow start: got %d, want 302", start.status)
	}
	cross := console.get(t, c1, console.base.String()+"/portal/callback?"+url.Values{"code": {"x"}, "state": {"y"}}.Encode())
	if cross.status != http.StatusForbidden {
		t.Fatalf("portal callback with a foreign (admin) flow cookie: got %d, want 403; body %s", cross.status, kcSnippet(cross.body))
	}
	if console.hasSession(c1.Jar) || c1.Jar.Cookie(console.base, adminauth.PortalSessionCookieName) != "" {
		t.Fatal("cross-consumer callback produced a session")
	}

	// (C2) a portal-only browser replaying a REAL admin callback is refused
	// as well — stolen callback URLs are worthless across consumers.
	scratch := adminauth.NewKCBrowser()
	sLogin := console.get(t, scratch, console.base.String()+"/auth/oidc/login")
	if sLogin.status != http.StatusFound {
		t.Fatalf("admin flow start 2: got %d, want 302", sLogin.status)
	}
	hops := scratch.DriveSSO(t, sLogin.location, adminauth.KCUserRoot, adminauth.KCPassRoot, adminCallback)
	last := hops[len(hops)-1]
	if last.Status != http.StatusFound || !strings.HasPrefix(last.Location, adminCallback) {
		t.Fatalf("real IdP did not return to the admin callback: %d → %q", last.Status, last.Location)
	}
	replayed := console.get(t, bBrowser, last.Location)
	if replayed.status != http.StatusForbidden {
		t.Fatalf("admin callback replayed on a portal browser: got %d, want 403; body %s", replayed.status, kcSnippet(replayed.body))
	}
	if console.hasSession(bBrowser.Jar) {
		t.Fatal("replayed admin callback produced an admin session")
	}

	// (D) consumer binding of code and token material, enforced by the REAL
	// provider and the audience-bound verifiers. The code below was issued
	// for the admin client with redirect_uri = adminCallback; the portal
	// client ALSO accepts that path family (127.0.0.1/*), so the redeem
	// below matches the redirect and still fails — isolating the CLIENT
	// binding of the code, not a redirect mismatch.
	code := kcLCQueryValue(t, last.Location, "code")
	if status := kcCompatRedeemCode(t, stand.RealmURL, kcCompatPortalClient, kcCompatPortalSecret,
		adminCallback, code); status != http.StatusBadRequest && status != http.StatusUnauthorized {
		t.Fatalf("admin code redeemed at the portal client: got %d, want 400/401", status)
	}

	adminTok, adminClaims := kcCompatCaptureIDToken(t, stand.RealmURL,
		adminauth.KCLiveOIDCClientID, adminauth.KCLiveOIDCClientSecret, "http://localhost:9/auth/oidc/callback",
		adminauth.KCUserRoot, adminauth.KCPassRoot)
	portalTok, portalClaims := kcCompatCaptureIDToken(t, stand.RealmURL,
		kcCompatPortalClient, kcCompatPortalSecret, kcCompatPortalRedirect,
		adminauth.KCUserRoot, adminauth.KCPassRoot)
	kcCompatAudContains(t, adminClaims, adminauth.KCLiveOIDCClientID, true)
	kcCompatAudContains(t, adminClaims, kcCompatPortalClient, false)
	kcCompatAudContains(t, portalClaims, kcCompatPortalClient, true)
	kcCompatAudContains(t, portalClaims, adminauth.KCLiveOIDCClientID, false)
	vAdmin := kcLCVerifierFor(t, stand.RealmURL, adminauth.KCLiveOIDCClientID)
	vPortal := kcLCVerifierFor(t, stand.RealmURL, kcCompatPortalClient)
	if _, err := vAdmin.Verify(ctx, adminTok); err != nil {
		t.Fatalf("admin verifier must accept the admin token: %v", err)
	}
	if _, err := vAdmin.Verify(ctx, portalTok); err == nil {
		t.Fatal("admin verifier must reject the portal token (audience binding)")
	}
	if _, err := vPortal.Verify(ctx, portalTok); err != nil {
		t.Fatalf("portal verifier must accept the portal token: %v", err)
	}
	if _, err := vPortal.Verify(ctx, adminTok); err == nil {
		t.Fatal("portal verifier must reject the admin token (audience binding)")
	}

	// (E) one browser may hold BOTH sessions at once — the consumers are
	// independent; neither invalidates the other. The identity must be an
	// admin user AND portal-admissible, and it must be DEDICATED: the
	// browser's realm SSO session decides who the portal half admits (the
	// submitted credentials are ignored once SSO is warm), so shared users
	// like root would be admitted through the portal and poison the
	// lifecycle suite's developer fixtures. /api/me answers with the portal
	// identity because the portal mount wins the shadowed route
	// (router_portal.go).
	if err := stand.EnsureRealmUser(ctx, kcCompatDualUser, "Dual Session", kcCompatDualEmail, kcCompatDualPass); err != nil {
		t.Fatalf("ensure %s realm user: %v", kcCompatDualUser, err)
	}
	if _, err := store.CreateAdminUser(ctx, kcCompatDualEmail, "N04 Dual Session", kcCompatSentinelHash, false); err != nil {
		t.Fatalf("create dual-session admin user: %v", err)
	}
	e := adminauth.NewKCBrowser()
	eAdmin := console.kcSSOLogin(t, e, "/auth/oidc/login", kcCompatDualUser, kcCompatDualPass, adminCallback)
	if eAdmin.status != http.StatusFound || console.sessionOf(t, eAdmin) == nil {
		t.Fatalf("dual-session admin login: got %d; body %s", eAdmin.status, kcSnippet(eAdmin.body))
	}
	portalLoginOn(t, console, e, kcCompatDualUser, kcCompatDualPass)
	if !console.hasSession(e.Jar) || e.Jar.Cookie(console.base, adminauth.PortalSessionCookieName) == "" {
		t.Fatal("dual-session browser lost one of the two sessions")
	}
	if version := console.get(t, e, console.base.String()+"/api/version"); version.status != http.StatusOK {
		t.Fatalf("/api/version with dual sessions: got %d", version.status)
	}
	if me := console.get(t, e, console.base.String()+"/api/me"); me.status != http.StatusOK || !strings.Contains(me.body, kcCompatDualEmail) {
		t.Fatalf("/api/me with dual sessions: got %d; body %s", me.status, kcSnippet(me.body))
	}
	if home := console.get(t, e, console.base.String()+"/portal"); home.status != http.StatusOK {
		t.Fatalf("/portal with dual sessions: got %d; body %s", home.status, kcSnippet(home.body))
	}

	// (F) a portal-only console keeps unsupported consumers indistinguishable
	// from unknown routes (no oracle) — and the password page still renders.
	pOnly := kcStartConsole(t, pool, func(base string) ([]func(*handlers.AdminHandlers), error) {
		portalClient, err := adminauth.NewOIDCClient(ctx, stand.RealmURL,
			kcCompatPortalClient, kcCompatPortalSecret, base+"/portal/callback")
		if err != nil {
			return nil, err
		}
		return []func(*handlers.AdminHandlers){func(h *handlers.AdminHandlers) {
			h.SetPortal(handlers.PortalOptions{
				Enabled:        true,
				Provisioning:   "domain",
				AllowedDomains: []string{"test.io"},
				DefaultOrg:     org.ID,
				DefaultTeam:    team.ID,
				Client:         portalClient,
				Store:          store,
			})
		}}, nil
	})
	f := adminauth.NewKCBrowser()
	portalLoginOn(t, pOnly, f, kcCompatPortalUser, kcCompatPortalPass)
	pAuthBaseline := pOnly.get(t, adminauth.NewKCBrowser(), pOnly.base.String()+"/auth/definitely-not-a-route")
	// Unsupported consumers under /auth: the subrouter's plain 404, matching
	// any typo inside the family (see the Test 1 note on chi's mount 404s).
	for _, route := range []string{"/auth/oidc/login", "/auth/oidc/callback", "/auth/saml/login", "/auth/saml/metadata"} {
		resp := pOnly.get(t, adminauth.NewKCBrowser(), pOnly.base.String()+route)
		if resp.status != pAuthBaseline.status || kcCompatMaskCSRF(resp.body) != kcCompatMaskCSRF(pAuthBaseline.body) {
			t.Fatalf("portal-only console %s: got %d/%q, want the unknown-auth-route response %d; body %s",
				route, resp.status, kcSnippet(resp.body), pAuthBaseline.status, kcSnippet(pAuthBaseline.body))
		}
	}
	if page := pOnly.get(t, adminauth.NewKCBrowser(), pOnly.base.String()+"/auth/login"); page.status != http.StatusOK {
		t.Fatalf("portal-only console /auth/login: got %d, want 200", page.status)
	}
}

// ---- 3. groups mapping stays scoped to the OIDC consumer ---------------------

func TestKeycloakLiveCompat_GroupsFeatureConsumerScope(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	store, worldOrg := kcLiveWorld(t, pool)
	ctx := context.Background()
	kcCompatEnsurePortalClient(t, stand)
	kcCompatEnsurePortalUser(t, stand)

	denyUser, err := store.GetAdminUserByEmail(ctx, kcDenyEmail)
	if err != nil {
		t.Fatalf("lookup deny user: %v", err)
	}
	// Deterministic pre-grant state: deny user is a plain reader with no
	// contractors group and no mapping provenance.
	kcLCDenyNormalize(t, stand, store, worldOrg, denyUser.ID)
	grantBase := kcLCCountSSOAudit(t, store, "sso_role_grant", denyUser.ID)
	revokeBase := kcLCCountSSOAudit(t, store, "sso_role_revoke", denyUser.ID)
	loginBase := kcLCCountSSOAudit(t, store, "login", denyUser.ID)
	// The same realm user now carries the DENIED group — every consumer
	// below sees identical group claims.
	if err := stand.AddUserToGroup(ctx, adminauth.KCUserDeny, "contractors"); err != nil {
		t.Fatalf("add contractors group: %v", err)
	}
	t.Cleanup(func() {
		_ = stand.RemoveUserFromGroup(ctx, adminauth.KCUserDeny, "contractors")
		kcLCDenyNormalize(t, stand, store, worldOrg, denyUser.ID)
	})

	// A separate org for the portal consumer's provisioning target: the
	// portal NEVER reconciles memberships, so the assertion is crisp even
	// though the OIDC control below reconciles the world org.
	compatOrg, err := store.CreateOrganization(ctx, "N04 Compat Groups", "n04-compat-groups")
	if err != nil {
		t.Fatalf("create compat groups org: %v", err)
	}
	compatTeam, err := store.CreateTeam(ctx, compatOrg.ID, "Compat Groups Team", "n04-compat-groups-team", nil)
	if err != nil {
		t.Fatalf("create compat groups team: %v", err)
	}

	console := kcStartConsole(t, pool, func(base string) ([]func(*handlers.AdminHandlers), error) {
		if err := stand.ConfigureSAMLClient(ctx, base, base+"/auth/saml/acs"); err != nil {
			return nil, err
		}
		sp, err := adminauth.NewSAMLSP(ctx, adminauth.SAMLOptions{
			IDPMetadataURL: stand.RealmURL + "/protocol/saml/descriptor",
			EntityID:       base,
			ACSURL:         base + "/auth/saml/acs",
		})
		if err != nil {
			return nil, err
		}
		adminClient, err := adminauth.NewOIDCClient(ctx, stand.RealmURL,
			adminauth.KCLiveOIDCClientID, adminauth.KCLiveOIDCClientSecret, base+"/auth/oidc/callback")
		if err != nil {
			return nil, err
		}
		portalClient, err := adminauth.NewOIDCClient(ctx, stand.RealmURL,
			kcCompatPortalClient, kcCompatPortalSecret, base+"/portal/callback")
		if err != nil {
			return nil, err
		}
		return []func(*handlers.AdminHandlers){
			func(h *handlers.AdminHandlers) { h.SetSAMLSP(sp) },
			func(h *handlers.AdminHandlers) { h.SetOIDCClient(adminClient) },
			func(h *handlers.AdminHandlers) {
				h.SetPortal(handlers.PortalOptions{
					Enabled:        true,
					Provisioning:   "domain",
					AllowedDomains: []string{"test.io"},
					DefaultOrg:     compatOrg.ID,
					DefaultTeam:    compatTeam.ID,
					Client:         portalClient,
					Store:          store,
				})
			},
		}, nil
	})
	adminCallback := console.base.String() + "/auth/oidc/callback"

	// (S) SAML login for the deny user WITH the denied group: the session is
	// still issued (mapping-only consumer), but NOTHING is reconciled — the
	// reader membership stays, no provenance is written, the grant/revoke
	// audit trail stays silent, and exactly one sso=saml login row appears.
	sBrowser := adminauth.NewKCBrowser()
	sLogin := console.get(t, sBrowser, console.base.String()+adminauth.SAMLLoginPath)
	if sLogin.status != http.StatusFound || !strings.HasPrefix(sLogin.location, stand.BaseURL) {
		t.Fatalf("saml login: got %d → %q, want 302 to Keycloak", sLogin.status, sLogin.location)
	}
	sHops := sBrowser.DriveSSO(t, sLogin.location, adminauth.KCUserDeny, adminauth.KCPassDeny, "")
	sOffer := sBrowser.SAMLOffer(t, sHops)
	samlResp := console.postForm(t, sBrowser, sOffer.PostURL, url.Values{"SAMLResponse": {sOffer.SAMLResponse}})
	if samlResp.status != http.StatusFound || samlResp.location != "/" {
		t.Fatalf("saml acs: got %d → %q, want 302 → /; body %s", samlResp.status, samlResp.location, kcSnippet(samlResp.body))
	}
	if sess := console.sessionOf(t, samlResp); sess == nil || sess.Email != kcDenyEmail {
		t.Fatalf("saml session for the deny user: got %+v", sess)
	}
	if !console.flowCookieCleared(t, samlResp, adminauth.SAMLFlowCookieName) {
		t.Fatal("saml acs did not clear the flow cookie")
	}
	roles, err := store.GetUserOrgRoles(ctx, denyUser.ID)
	if err != nil {
		t.Fatalf("org roles after saml login: %v", err)
	}
	if roles[worldOrg] != adminstore.RoleReader {
		t.Fatalf("saml login must not touch memberships: world org role %q, want reader", roles[worldOrg])
	}
	if _, ok, _ := store.GetSSOGrantedRole(ctx, worldOrg, denyUser.ID); ok {
		t.Fatal("saml login must not write mapping provenance")
	}
	if got := kcLCCountSSOAudit(t, store, "sso_role_grant", denyUser.ID); got != grantBase {
		t.Fatalf("saml login wrote %d grant audit rows, want 0 new", got-grantBase)
	}
	if got := kcLCCountSSOAudit(t, store, "sso_role_revoke", denyUser.ID); got != revokeBase {
		t.Fatalf("saml login wrote %d revoke audit rows, want 0 new", got-revokeBase)
	}
	if got := kcLCCountSSOAudit(t, store, "login", denyUser.ID); got != loginBase+1 {
		t.Fatalf("saml login audit rows: got %d, want exactly one new", got-loginBase)
	}
	// The SAML session is accepted by the console APIs. On a portal-enabled
	// console /api/me is served to PORTAL sessions by design (the static
	// portal route wins over the console mount — see router_portal.go), so
	// the admin session is probed via /api/version, which is not shadowed.
	if ver := console.get(t, sBrowser, console.base.String()+"/api/version"); ver.status != http.StatusOK {
		t.Fatalf("/api/version with a saml session: got %d; body %s", ver.status, kcSnippet(ver.body))
	}

	// (P) portal login for the SAME user with the SAME denied group: the
	// developer row is provisioned (its own scope) and memberships are
	// untouched — the portal has no group rules at all.
	pBrowser := adminauth.NewKCBrowser()
	portalLoginOn(t, console, pBrowser, adminauth.KCUserDeny, adminauth.KCPassDeny)
	dev, err := store.GetDeveloperByEmail(ctx, kcDenyEmail)
	if err != nil {
		t.Fatalf("portal login did not provision the deny user: %v", err)
	}
	compatDevs, err := store.ListDevelopers(ctx, compatOrg.ID)
	if err != nil {
		t.Fatalf("list compat developers: %v", err)
	}
	matches := 0
	for _, d := range compatDevs {
		if d.ID == dev.ID {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("deny developer bound %d times in the portal org, want exactly 1", matches)
	}
	roles, err = store.GetUserOrgRoles(ctx, denyUser.ID)
	if err != nil {
		t.Fatalf("org roles after portal login: %v", err)
	}
	if roles[worldOrg] != adminstore.RoleReader {
		t.Fatalf("portal login must not touch memberships: world org role %q, want reader", roles[worldOrg])
	}
	if _, present := roles[compatOrg.ID]; present {
		t.Fatal("portal login must not create org memberships, even in its own org")
	}
	if _, ok, _ := store.GetSSOGrantedRole(ctx, worldOrg, denyUser.ID); ok {
		t.Fatal("portal login must not write mapping provenance")
	}
	if got := kcLCCountSSOAudit(t, store, "sso_role_grant", denyUser.ID); got != grantBase {
		t.Fatalf("portal login wrote %d grant audit rows, want 0 new", got-grantBase)
	}
	if got := kcLCCountSSOAudit(t, store, "sso_role_revoke", denyUser.ID); got != revokeBase {
		t.Fatalf("portal login wrote %d revoke audit rows, want 0 new", got-revokeBase)
	}

	// (O) control: the OIDC consumer on the SAME console is the ONLY one
	// that reconciles. Deny-wins revocation only relinquishes MAPPING-granted
	// state (oidc_groups.go: an admin's manual membership is never clobbered
	// and no-provenance logins are no-ops), so the control first earns a
	// mapping grant (platform-team → operator, contractors parked) and then
	// re-adds the denied group: the second OIDC login revokes the mapped
	// role, clears the provenance and audits the revoke — while the login
	// itself still succeeds.
	if err := stand.RemoveUserFromGroup(ctx, adminauth.KCUserDeny, "contractors"); err != nil {
		t.Fatalf("park contractors group: %v", err)
	}
	oBrowser := adminauth.NewKCBrowser()
	oResp := console.kcSSOLogin(t, oBrowser, "/auth/oidc/login", adminauth.KCUserDeny, adminauth.KCPassDeny, adminCallback)
	if oResp.status != http.StatusFound || console.sessionOf(t, oResp) == nil {
		t.Fatalf("oidc grant login must still log in: got %d; body %s", oResp.status, kcSnippet(oResp.body))
	}
	roles, err = store.GetUserOrgRoles(ctx, denyUser.ID)
	if err != nil {
		t.Fatalf("org roles after oidc grant login: %v", err)
	}
	if roles[worldOrg] != adminstore.RoleOperator {
		t.Fatalf("oidc grant login must map platform-team to operator: got %q", roles[worldOrg])
	}
	if role, ok, _ := store.GetSSOGrantedRole(ctx, worldOrg, denyUser.ID); !ok || role != adminstore.RoleOperator {
		t.Fatalf("oidc grant login must write provenance: got role=%q ok=%t", role, ok)
	}
	// The denied group returns: the next OIDC login is deny-wins.
	if err := stand.AddUserToGroup(ctx, adminauth.KCUserDeny, "contractors"); err != nil {
		t.Fatalf("restore contractors group: %v", err)
	}
	oDenyBrowser := adminauth.NewKCBrowser()
	oDenyResp := console.kcSSOLogin(t, oDenyBrowser, "/auth/oidc/login", adminauth.KCUserDeny, adminauth.KCPassDeny, adminCallback)
	if oDenyResp.status != http.StatusFound || console.sessionOf(t, oDenyResp) == nil {
		t.Fatalf("deny-wins oidc login must still log in: got %d; body %s", oDenyResp.status, kcSnippet(oDenyResp.body))
	}
	roles, err = store.GetUserOrgRoles(ctx, denyUser.ID)
	if err != nil {
		t.Fatalf("org roles after oidc deny-wins login: %v", err)
	}
	if _, present := roles[worldOrg]; present {
		t.Fatal("oidc deny-wins must remove the mapping-granted membership; role map still contains the world org")
	}
	if _, ok, _ := store.GetSSOGrantedRole(ctx, worldOrg, denyUser.ID); ok {
		t.Fatal("oidc deny-wins left mapping provenance behind")
	}
	if got := kcLCCountSSOAudit(t, store, "sso_role_revoke", denyUser.ID); got != revokeBase+1 {
		t.Fatalf("oidc deny-wins revoke audit rows: got %d, want exactly one new", got-revokeBase)
	}
	if got := kcLCCountSSOAudit(t, store, "sso_role_grant", denyUser.ID); got != grantBase+1 {
		t.Fatalf("oidc mapping audit rows: got %d grant rows, want exactly one new (the operator grant)", got-grantBase)
	}

	// (W) FIXED (wave 19, T09-saml-issuedat-fix) — the password-change
	// watermark vs the SAML session. The SAML ACS previously omitted
	// IssuedAt (auth_saml.go), leaving sessions with issued-at zero, which
	// adminauth.sessionInvalidated rejects once
	// admin_users.sessions_changed_at is non-zero — after ANY password
	// change every fresh SAML login was dead-on-arrival 401 until a
	// password or OIDC re-login. The ACS now stamps IssuedAt like oidc.go,
	// so a FRESH SAML login after a password change is accepted (200),
	// while sessions minted BEFORE the change (earlier issued-at) still
	// fail the watermark — fail-closed preserved (unit regression in
	// services/admin/handlers/auth_saml_test.go).
	// The deny user's console password must be REAL for the change below,
	// but the store's hash setter also writes the watermark — which would
	// invalidate the SAML session before it can act. Seed the hash directly
	// (setup only; the watermark stays NULL until the handler writes it).
	wHash, err := adminauth.HashPassword("n04-compat-watermark-current")
	if err != nil {
		t.Fatalf("hash watermark-cell password: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE admin_users SET password_hash = $1 WHERE id = $2`, wHash, denyUser.ID); err != nil {
		t.Fatalf("seed watermark-cell password: %v", err)
	}
	wPage := console.get(t, sBrowser, console.base.String()+"/auth/login")
	if wPage.status != http.StatusOK {
		t.Fatalf("watermark cell: GET /auth/login: got %d; body %s", wPage.status, kcSnippet(wPage.body))
	}
	wCSRF := sBrowser.Jar.Cookie(console.base, "yabanin_csrf_token")
	if wCSRF == "" {
		t.Fatal("watermark cell: /auth/login issued no csrf cookie")
	}
	// The console password (seeded above) is changed with the CURRENT
	// session: the handler verifies it, writes the watermark, and re-issues
	// THIS session with a fresh issued-at.
	wChg := kcCompatPostJSON(t, console, sBrowser, "/api/me/password",
		map[string]string{"current_password": "n04-compat-watermark-current", "new_password": "n04-compat-watermark-pass"}, wCSRF)
	if wChg.status != http.StatusOK {
		t.Fatalf("watermark cell: password change: got %d; body %s", wChg.status, kcSnippet(wChg.body))
	}
	if v := console.get(t, sBrowser, console.base.String()+"/api/version"); v.status != http.StatusOK {
		t.Fatalf("watermark cell: the re-issued session must survive its own watermark: got %d; body %s", v.status, kcSnippet(v.body))
	}
	// A fresh SAML login still authenticates at the IdP (the IdP password is
	// independent of the console password) and now mints an issued-at-stamped
	// session — accepted on the first guarded request.
	wLogin := console.get(t, sBrowser, console.base.String()+adminauth.SAMLLoginPath)
	if wLogin.status != http.StatusFound {
		t.Fatalf("watermark cell: saml re-login start: got %d; body %s", wLogin.status, kcSnippet(wLogin.body))
	}
	wHops := sBrowser.DriveSSO(t, wLogin.location, adminauth.KCUserDeny, adminauth.KCPassDeny, "")
	wOffer := sBrowser.SAMLOffer(t, wHops)
	wResp := console.postForm(t, sBrowser, wOffer.PostURL, url.Values{"SAMLResponse": {wOffer.SAMLResponse}})
	if wResp.status != http.StatusFound || console.sessionOf(t, wResp) == nil {
		t.Fatalf("watermark cell: saml re-login must still issue the session: got %d → %q; body %s",
			wResp.status, wResp.location, kcSnippet(wResp.body))
	}
	if v := console.get(t, sBrowser, console.base.String()+"/api/version"); v.status != http.StatusOK {
		t.Fatalf("watermark cell (fixed: SAML ACS stamps IssuedAt): "+
			"saml session issued after a password-change watermark: got %d, want 200; body %s", v.status, kcSnippet(v.body))
	}
}

// ---- 4. token material: audiences, rotation, retirement, foreign issuer -------

func TestKeycloakLiveCompat_TokenMaterialConsumerIsolation(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	ctx := context.Background()
	kcCompatEnsurePortalClient(t, stand)
	kcCompatEnsurePortalUser(t, stand)

	adminTok, adminClaims := kcCompatCaptureIDToken(t, stand.RealmURL,
		adminauth.KCLiveOIDCClientID, adminauth.KCLiveOIDCClientSecret, "http://localhost:9/auth/oidc/callback",
		adminauth.KCUserRoot, adminauth.KCPassRoot)
	portalTok, portalClaims := kcCompatCaptureIDToken(t, stand.RealmURL,
		kcCompatPortalClient, kcCompatPortalSecret, kcCompatPortalRedirect,
		adminauth.KCUserRoot, adminauth.KCPassRoot)

	// One realm, one active signer: both consumers receive tokens signed by
	// the SAME key, distinguished ONLY by the audience.
	kidA := kcLCJWTHeaderKid(t, adminTok)
	kidP := kcLCJWTHeaderKid(t, portalTok)
	if kidA == "" || kidP == "" {
		t.Fatalf("captured tokens carry no kid: %q / %q", kidA, kidP)
	}
	if kidA != kidP {
		t.Fatalf("one active key must sign both consumers: %q vs %q", kidA, kidP)
	}
	kcCompatAudContains(t, adminClaims, adminauth.KCLiveOIDCClientID, true)
	kcCompatAudContains(t, adminClaims, kcCompatPortalClient, false)
	kcCompatAudContains(t, portalClaims, kcCompatPortalClient, true)
	kcCompatAudContains(t, portalClaims, adminauth.KCLiveOIDCClientID, false)

	vAdmin := kcLCVerifierFor(t, stand.RealmURL, adminauth.KCLiveOIDCClientID)
	vPortal := kcLCVerifierFor(t, stand.RealmURL, kcCompatPortalClient)
	if _, err := vAdmin.Verify(ctx, adminTok); err != nil {
		t.Fatalf("admin verifier must accept its own token: %v", err)
	}
	if _, err := vAdmin.Verify(ctx, portalTok); err == nil {
		t.Fatal("admin verifier must reject the portal consumer's token")
	}
	if _, err := vPortal.Verify(ctx, portalTok); err != nil {
		t.Fatalf("portal verifier must accept its own token: %v", err)
	}
	if _, err := vPortal.Verify(ctx, adminTok); err == nil {
		t.Fatal("portal verifier must reject the admin consumer's token")
	}

	// Rotation: a second key takes signing; BOTH consumers must adopt it
	// through their own verifier (fresh discovery sees both keys).
	basePriority, err := stand.PrimaryRSAPriority(ctx)
	if err != nil {
		t.Fatalf("primary key priority: %v", err)
	}
	kcLCAddKey(t, stand, "n04-compat-key", basePriority+100)
	adminK, _ := kcCompatCaptureIDToken(t, stand.RealmURL,
		adminauth.KCLiveOIDCClientID, adminauth.KCLiveOIDCClientSecret, "http://localhost:9/auth/oidc/callback",
		adminauth.KCUserRoot, adminauth.KCPassRoot)
	portalK, _ := kcCompatCaptureIDToken(t, stand.RealmURL,
		kcCompatPortalClient, kcCompatPortalSecret, kcCompatPortalRedirect,
		adminauth.KCUserRoot, adminauth.KCPassRoot)
	kidK := kcLCJWTHeaderKid(t, adminK)
	if kidK == "" || kidK == kidA {
		t.Fatalf("second key must take signing: kidK %q (kidA %q)", kidK, kidA)
	}
	if got := kcLCJWTHeaderKid(t, portalK); got != kidK {
		t.Fatalf("portal consumer must receive the new signer too: %q, want %q", got, kidK)
	}
	freshAdmin := kcLCVerifierFor(t, stand.RealmURL, adminauth.KCLiveOIDCClientID)
	freshPortal := kcLCVerifierFor(t, stand.RealmURL, kcCompatPortalClient)
	if _, err := freshAdmin.Verify(ctx, adminK); err != nil {
		t.Fatalf("admin consumer must adopt the rotated key: %v", err)
	}
	if _, err := freshPortal.Verify(ctx, portalK); err != nil {
		t.Fatalf("portal consumer must adopt the rotated key: %v", err)
	}
	if _, err := freshAdmin.Verify(ctx, portalK); err == nil {
		t.Fatal("audience binding must survive rotation")
	}

	// Retirement: DELETE the key provider — a priority demotion only picks
	// the signer, it never unpublishes the key. Deletion drops the kid from
	// the realm JWKS.
	if err := stand.DeleteRSAKeyProvider(ctx, "n04-compat-key"); err != nil {
		t.Fatalf("retire key: %v", err)
	}
	kcCompatWaitKidGone(t, stand, kidK)
	// A fresh capture carries the original signer's kid again. Its unknown
	// kid also forces the persistent verifier to refetch the keyset, which
	// evicts the retired key from the verifier's cache — the documented
	// cached-key transient (see the lifecycle suite) — and only THEN must
	// the retired material be refused.
	adminFresh, _ := kcCompatCaptureIDToken(t, stand.RealmURL,
		adminauth.KCLiveOIDCClientID, adminauth.KCLiveOIDCClientSecret, "http://localhost:9/auth/oidc/callback",
		adminauth.KCUserRoot, adminauth.KCPassRoot)
	if got := kcLCJWTHeaderKid(t, adminFresh); got != kidA {
		t.Fatalf("after retirement the original signer must take over: got kid %q, want %q", got, kidA)
	}
	if _, err := freshAdmin.Verify(ctx, adminFresh); err != nil {
		t.Fatalf("verifier must accept tokens from the restored signer: %v", err)
	}
	// Keycloak serves the certs document through its own cache, so the first
	// refetch may still hand back the retired key. Poll with a FRESH verifier
	// per attempt (each performs its own discovery and keyset fetch — no
	// cached-kid shortcut) until the retired material is refused.
	refused := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if _, err := kcLCVerifierFor(t, stand.RealmURL, adminauth.KCLiveOIDCClientID).Verify(ctx, adminK); err != nil {
			refused = true
			break
		}
	}
	if !refused {
		t.Fatal("verifier must stop trusting the retired key once the realm keyset drops it")
	}

	// Forgery: a token carrying the REAL realm kid but signed by the test's
	// own key is rejected on the signature alone.
	forged := kcCompatSignJWT(t, kidA, mustTestRSAKey(t), map[string]any{
		"iss":            stand.RealmURL,
		"aud":            adminauth.KCLiveOIDCClientID,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"email":          kcAdminEmail,
		"email_verified": true,
	})
	if _, err := vAdmin.Verify(ctx, forged); err == nil {
		t.Fatal("forged token with a real kid must be rejected")
	}

	// Foreign issuer: a REAL token from the master realm (real login of the
	// bootstrap admin through a dedicated client) is worthless at the realm
	// consumers — and vice versa (issuer binding).
	if err := stand.EnsureOIDCClient(ctx, "master", kcCompatForeignClient, kcCompatForeignSecret,
		[]string{"http://localhost:9/cb"}); err != nil {
		t.Fatalf("ensure master client: %v", err)
	}
	t.Cleanup(func() {
		if err := stand.DeleteOIDCClient(ctx, "master", kcCompatForeignClient); err != nil {
			t.Errorf("cleanup: delete master client: %v", err)
		}
	})
	bootUser, bootPass := stand.BootstrapAdminCredentials()
	masterTok, masterClaims := kcCompatCaptureIDToken(t, stand.BaseURL+"/realms/master",
		kcCompatForeignClient, kcCompatForeignSecret, "http://localhost:9/cb", bootUser, bootPass)
	if iss, _ := masterClaims["iss"].(string); iss != stand.BaseURL+"/realms/master" {
		t.Fatalf("master token issuer: %q", iss)
	}
	kcCompatAudContains(t, masterClaims, kcCompatForeignClient, true)
	vMaster := kcLCVerifierFor(t, stand.BaseURL+"/realms/master", kcCompatForeignClient)
	if _, err := vMaster.Verify(ctx, masterTok); err != nil {
		t.Fatalf("master verifier must accept the master token: %v", err)
	}
	if _, err := vAdmin.Verify(ctx, masterTok); err == nil {
		t.Fatal("realm consumer must reject the master-realm token (issuer binding)")
	}
	if _, err := vMaster.Verify(ctx, adminTok); err == nil {
		t.Fatal("master verifier must reject the realm token (issuer binding)")
	}
}

// mustTestRSAKey is the adversary key for the forgery cell (generated once
// per test run; the IdP never sees it).
func mustTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate adversary key: %v", err)
	}
	return key
}
