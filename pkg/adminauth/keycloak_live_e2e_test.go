//go:build integration

package adminauth_test

// N04 live-IdP e2e: the REAL authorization-code and SAML SP-initiated flows
// of the admin console driven end to end against a REAL local Keycloak
// (owner decision 2026-10 — the local Keycloak stand is the approved "Real
// IdP flow" evidence for N04-P01 T06 and N04-P02 T06).
//
// Everything here is real: real discovery/JWKS, real RS256 ID tokens with
// real groups claims, real Keycloak login forms, real SAML document
// signatures, real HTTP round trips through SetupRouter() over a real
// adminstore on a disposable Postgres (pkg/testdb). Mock-based evidence is
// pinned separately in oidc_test.go / saml_test.go and in
// services/admin/handlers/oidc_e2e_int_test.go — this file does not replace
// it, it closes the live-IdP remainder.
//
// Skip discipline: with the Docker daemon down the stand skips explicitly;
// nothing here can silently pass without the IdP.

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

const (
	kcSessionSecret = "kc-live-e2e-session-secret"
	kcDeepLink      = "/#keys?org=n04-live"
	kcAdminEmail    = "sso-root@test.io"
	kcDenyEmail     = "sso-deny@test.io"
	kcConflictEmail = "sso-conflict@test.io"
)

// ---- shared live world (one org, three mapped users, declared rules) ----------

var (
	kcWorldOnce sync.Once
	kcWorldOrg  string
	kcWorldErr  error
)

func kcLiveWorld(t *testing.T, pool *pgxpool.Pool) (store *adminstore.Store, orgID string) {
	t.Helper()
	kcWorldOnce.Do(func() {
		store = adminstore.New(pool, slog.Default(), nil)
		ctx := context.Background()
		for _, u := range []struct {
			email string
			root  bool
		}{
			{kcAdminEmail, true},
			{kcDenyEmail, false},
			{kcConflictEmail, false},
		} {
			if _, err := store.CreateAdminUser(ctx, u.email, "N04 Live SSO", "unused-by-sso", u.root); err != nil {
				kcWorldErr = err
				return
			}
		}
		org, err := store.CreateOrganization(ctx, "N04 Live Org", "n04-live")
		if err != nil {
			kcWorldErr = err
			return
		}
		kcWorldOrg = org.ID
		// Memberships the mapping reconciles (never provisions).
		for _, u := range []string{kcDenyEmail, kcConflictEmail} {
			user, err := store.GetAdminUserByEmail(ctx, u)
			if err != nil {
				kcWorldErr = err
				return
			}
			if _, err := store.SetOrgMembership(ctx, user.ID, org.ID, adminstore.RoleReader); err != nil {
				kcWorldErr = err
				return
			}
		}
		rules := []adminstore.SSOGroupRoleRule{
			{Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator},
			{Group: "contractors", Effect: adminstore.SSODenyRuleEffect},
			{Group: "team-a", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator},
			{Group: "team-b", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOrgAdmin},
		}
		for _, r := range rules {
			if _, err := store.SetSSOGroupRoleRule(ctx, org.ID, r); err != nil {
				kcWorldErr = err
				return
			}
		}
	})
	if kcWorldErr != nil {
		t.Fatalf("seed live world: %v", kcWorldErr)
	}
	return adminstore.New(pool, slog.Default(), nil), kcWorldOrg
}

// ---- console harness -----------------------------------------------------------

type kcConsole struct {
	base *url.URL
	h    *handlers.AdminHandlers
}

// kcStartConsole wires the community-build admin plane exactly like
// services/run/admin.go does for SSO and serves SetupRouter() over a real
// loopback listener. `configure` runs once the console base URL is known and
// returns the mounts (OIDC client / SAML SP built against that base).
func kcStartConsole(t *testing.T, pool *pgxpool.Pool, configure func(base string) ([]func(*handlers.AdminHandlers), error)) *kcConsole {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := &url.URL{Scheme: "http", Host: ln.Addr().String()}
	mounts, err := configure(base.String())
	if err != nil {
		t.Fatalf("configure console: %v", err)
	}
	h := handlers.New(adminstore.New(pool, slog.Default(), nil), kcSessionSecret, "127.0.0.1", nil)
	for _, mount := range mounts {
		mount(h)
	}
	srv := &http.Server{Handler: h.SetupRouter(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		h.Stop()
	})
	return &kcConsole{base: base, h: h}
}

func kcOIDCMounts(stand *adminauth.KCStand) func(base string) ([]func(*handlers.AdminHandlers), error) {
	return func(base string) ([]func(*handlers.AdminHandlers), error) {
		client, err := adminauth.NewOIDCClient(context.Background(), stand.RealmURL,
			adminauth.KCLiveOIDCClientID, adminauth.KCLiveOIDCClientSecret, base+"/auth/oidc/callback")
		if err != nil {
			return nil, err
		}
		return []func(*handlers.AdminHandlers){func(h *handlers.AdminHandlers) { h.SetOIDCClient(client) }}, nil
	}
}

type kcResp struct {
	status   int
	location string
	body     string
	cookies  []*http.Cookie
}

func (c *kcConsole) get(t *testing.T, b *adminauth.KCBrowser, rawURL string) kcResp {
	t.Helper()
	resp, err := b.Client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s body: %v", rawURL, err)
	}
	resp.Body.Close()
	return kcResp{status: resp.StatusCode, location: resp.Header.Get("Location"), body: string(raw), cookies: resp.Cookies()}
}

func (c *kcConsole) postForm(t *testing.T, b *adminauth.KCBrowser, rawURL string, form url.Values) kcResp {
	t.Helper()
	resp, err := b.Client.Post(rawURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("POST %s body: %v", rawURL, err)
	}
	resp.Body.Close()
	return kcResp{status: resp.StatusCode, location: resp.Header.Get("Location"), body: string(raw), cookies: resp.Cookies()}
}

func (c *kcConsole) hasSession(jar *adminauth.KCCookieJar) bool {
	return jar.Cookie(c.base, "yabanin_admin_session") != ""
}

func (c *kcConsole) sessionOf(t *testing.T, resp kcResp) *adminauth.AdminSession {
	t.Helper()
	for _, ck := range resp.cookies {
		if ck.Name != "yabanin_admin_session" || ck.Value == "" {
			continue
		}
		sess, err := adminauth.ParseAdminSessionCookie(ck.Value, kcSessionSecret)
		if err != nil {
			t.Fatalf("issued session cookie does not verify: %v", err)
		}
		return sess
	}
	return nil
}

func (c *kcConsole) flowCookieCleared(t *testing.T, resp kcResp, name string) bool {
	t.Helper()
	for _, ck := range resp.cookies {
		if ck.Name == name {
			return ck.MaxAge < 0
		}
	}
	return false
}

// kcSSOLogin runs one full browser-style login from the console's login
// route to the callback response.
func (c *kcConsole) kcSSOLogin(t *testing.T, b *adminauth.KCBrowser, route, username, password, stop string) kcResp {
	t.Helper()
	login := c.get(t, b, c.base.String()+route)
	if login.status != http.StatusFound {
		t.Fatalf("%s: got %d, want 302; body %s", route, login.status, kcSnippet(login.body))
	}
	hops := b.DriveSSO(t, login.location, username, password, stop)
	last := hops[len(hops)-1]
	if last.Status != http.StatusFound || !strings.HasPrefix(last.Location, stop) {
		t.Fatalf("%s flow: expected redirect to %s, got %d → %q", route, stop, last.Status, last.Location)
	}
	return c.get(t, b, last.Location)
}

// ---- OIDC live tests -------------------------------------------------------------

// TestKeycloakLive_OIDC_AdminConsoleAuthCodeFlow is the N04-P01 T06/T02 live
// evidence: real discovery + real RS256 ID token with real groups, resolved
// by ResolveSSORole (deny-wins) against real org rules, reauthentication
// after local-session expiry.
func TestKeycloakLive_OIDC_AdminConsoleAuthCodeFlow(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	store, orgID := kcLiveWorld(t, pool)
	ctx := context.Background()

	console := kcStartConsole(t, pool, kcOIDCMounts(stand))
	callback := console.base.String() + "/auth/oidc/callback"

	// 0. the guarded surface is closed before any login.
	if probe := console.get(t, adminauth.NewKCBrowser(), console.base.String()+"/api/version"); probe.status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/version: got %d, want 401", probe.status)
	}

	// 1. full login as the root-mapped user through the REAL provider.
	browser := adminauth.NewKCBrowser()
	page := console.get(t, browser, console.base.String()+"/auth/login?"+url.Values{"next": {kcDeepLink}}.Encode())
	if page.status != http.StatusOK || !strings.Contains(page.body, "/auth/oidc/login") {
		t.Fatalf("login page: got %d, want 200 with an SSO link; body %s", page.status, kcSnippet(page.body))
	}
	callbackResp := console.kcSSOLogin(t, browser, "/auth/oidc/login?"+url.Values{"next": {kcDeepLink}}.Encode(),
		adminauth.KCUserRoot, adminauth.KCPassRoot, callback)
	if callbackResp.status != http.StatusFound || callbackResp.location != kcDeepLink {
		t.Fatalf("callback: got %d → %q, want 302 → %q; body %s",
			callbackResp.status, callbackResp.location, kcDeepLink, kcSnippet(callbackResp.body))
	}
	sess := console.sessionOf(t, callbackResp)
	if sess == nil {
		t.Fatal("real IdP login issued no admin session")
	}
	if sess.Email != kcAdminEmail || !sess.IsRoot || sess.SessionID == "" {
		t.Fatalf("session identity from the real IdP: got %+v", sess)
	}
	if !console.flowCookieCleared(t, callbackResp, adminauth.OIDCFlowCookieName) {
		t.Fatal("callback did not clear the one-time flow cookie")
	}
	if probe := console.get(t, browser, console.base.String()+"/api/me"); probe.status != http.StatusOK || !strings.Contains(probe.body, kcAdminEmail) {
		t.Fatalf("/api/me with a real-IdP session: got %d; body %s", probe.status, kcSnippet(probe.body))
	}

	// 2. reauthentication: an expired LOCAL session is refused with a
	// diagnosable reason, and recovery is a fresh SSO round trip that mints a
	// NEW session (the Keycloak SSO session is still alive — no login form).
	expired := adminauth.AdminSession{
		UserID:    sess.UserID,
		Email:     kcAdminEmail,
		IsRoot:    true,
		SessionID: "expired-kc-live-session",
		IssuedAt:  time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	expiredCookie, err := adminauth.CreateAdminSessionCookie(expired, kcSessionSecret)
	if err != nil {
		t.Fatalf("create expired session: %v", err)
	}
	browser.Jar.SetInjected(console.base, *expiredCookie)
	probe := console.get(t, browser, console.base.String()+"/api/version")
	if probe.status != http.StatusUnauthorized || !strings.Contains(probe.body, "session expired") {
		t.Fatalf("expired local session: got %d, want 401 with reason; body %s", probe.status, kcSnippet(probe.body))
	}
	again := console.kcSSOLogin(t, browser, "/auth/oidc/login", adminauth.KCUserRoot, adminauth.KCPassRoot, callback)
	if again.status != http.StatusFound || console.sessionOf(t, again) == nil {
		t.Fatalf("reauth login: got %d, want 302 with a session; body %s", again.status, kcSnippet(again.body))
	}
	fresh := console.sessionOf(t, again)
	if fresh.SessionID == sess.SessionID {
		t.Fatal("reauth reused the old session id")
	}
	if probe := console.get(t, browser, console.base.String()+"/api/version"); probe.status != http.StatusOK {
		t.Fatalf("guard rejected the reauthenticated session: got %d", probe.status)
	}

	// 3. ResolveSSORole with REAL groups: grant on first login...
	denyBrowser := adminauth.NewKCBrowser()
	denyLogin := console.kcSSOLogin(t, denyBrowser, "/auth/oidc/login", adminauth.KCUserDeny, adminauth.KCPassDeny, callback)
	if denyLogin.status != http.StatusFound || console.sessionOf(t, denyLogin) == nil {
		t.Fatalf("deny-user login: got %d, want 302 with a session; body %s", denyLogin.status, kcSnippet(denyLogin.body))
	}
	denyUser, err := store.GetAdminUserByEmail(ctx, kcDenyEmail)
	if err != nil {
		t.Fatalf("lookup deny user: %v", err)
	}
	roles, err := store.GetUserOrgRoles(ctx, denyUser.ID)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if roles[orgID] != adminstore.RoleOperator {
		t.Fatalf("real groups=%v must grant operator via the declared rule, got role %q", roles, roles[orgID])
	}
	if granted, ok, err := store.GetSSOGrantedRole(ctx, orgID, denyUser.ID); err != nil || !ok || granted != adminstore.RoleOperator {
		t.Fatalf("mapping provenance: got (%q, %v, err %v), want operator recorded", granted, ok, err)
	}

	// 4. deny-wins with a REAL IdP group change: Keycloak puts the user into
	// the denied group; the next login strips the mapping grant.
	if err := stand.AddUserToGroup(ctx, adminauth.KCUserDeny, "contractors"); err != nil {
		t.Fatalf("add contractors group in Keycloak: %v", err)
	}
	if logout := console.get(t, denyBrowser, console.base.String()+"/auth/logout"); logout.status != http.StatusFound {
		t.Fatalf("logout: got %d, want 302", logout.status)
	}
	if console.hasSession(denyBrowser.Jar) {
		t.Fatal("jar still holds the session after logout")
	}
	denyLogin2 := console.kcSSOLogin(t, denyBrowser, "/auth/oidc/login", adminauth.KCUserDeny, adminauth.KCPassDeny, callback)
	if denyLogin2.status != http.StatusFound || console.sessionOf(t, denyLogin2) == nil {
		t.Fatalf("deny-wins login: got %d, want 302 (login must still work); body %s", denyLogin2.status, kcSnippet(denyLogin2.body))
	}
	roles2, err := store.GetUserOrgRoles(ctx, denyUser.ID)
	if err != nil {
		t.Fatalf("list memberships 2: %v", err)
	}
	if _, still := roles2[orgID]; still {
		t.Fatalf("deny-wins must revoke the mapping grant, membership still %q", roles2[orgID])
	}
	if _, hasPrev, err := store.GetSSOGrantedRole(ctx, orgID, denyUser.ID); err != nil || hasPrev {
		t.Fatalf("deny-wins must clear the provenance (err %v, hasPrev %v)", err, hasPrev)
	}

	// 5. conflicting grant rules deny — the membership keeps its base role
	// and no provenance appears, while the LOGIN itself still succeeds.
	conflictBrowser := adminauth.NewKCBrowser()
	conflictLogin := console.kcSSOLogin(t, conflictBrowser, "/auth/oidc/login", adminauth.KCUserConflict, adminauth.KCPassConflict, callback)
	if conflictLogin.status != http.StatusFound || console.sessionOf(t, conflictLogin) == nil {
		t.Fatalf("conflict-user login: got %d, want 302 with a session; body %s", conflictLogin.status, kcSnippet(conflictLogin.body))
	}
	conflictUser, err := store.GetAdminUserByEmail(ctx, kcConflictEmail)
	if err != nil {
		t.Fatalf("lookup conflict user: %v", err)
	}
	roles3, err := store.GetUserOrgRoles(ctx, conflictUser.ID)
	if err != nil {
		t.Fatalf("list memberships 3: %v", err)
	}
	if roles3[orgID] != adminstore.RoleReader {
		t.Fatalf("conflicting grants must deny (deny-wins), membership became %q", roles3[orgID])
	}
	if _, hasPrev, err := store.GetSSOGrantedRole(ctx, orgID, conflictUser.ID); err != nil || hasPrev {
		t.Fatalf("conflict must not record provenance (err %v, hasPrev %v)", err, hasPrev)
	}
}

// TestKeycloakLive_OIDC_FailClosed pins the live negative paths: an unknown
// issuer never constructs a client (fail-closed startup) and a tampered code
// never produces a session through the REAL token endpoint.
func TestKeycloakLive_OIDC_FailClosed(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	kcLiveWorld(t, pool)
	ctx := context.Background()

	// (a) unknown issuer: discovery against a realm that does not exist must
	// fail closed — the console would stay on the password flow.
	if _, err := adminauth.NewOIDCClient(ctx, stand.BaseURL+"/realms/no-such-realm", adminauth.KCLiveOIDCClientID, adminauth.KCLiveOIDCClientSecret, "http://127.0.0.1:9/auth/oidc/callback"); err == nil {
		t.Fatal("NewOIDCClient accepted an unknown issuer")
	}

	// (b) real console, REAL login, but the callback presents a garbage code:
	// the real token endpoint refuses the exchange and the callback fails
	// closed (no session, flow cookie cleared, guard still closed).
	console := kcStartConsole(t, pool, kcOIDCMounts(stand))
	callback := console.base.String() + "/auth/oidc/callback"

	browser := adminauth.NewKCBrowser()
	login := console.get(t, browser, console.base.String()+"/auth/oidc/login")
	if login.status != http.StatusFound {
		t.Fatalf("oidc login: got %d, want 302", login.status)
	}
	if browser.Jar.Cookie(console.base, adminauth.OIDCFlowCookieName) == "" {
		t.Fatal("login did not set the flow cookie")
	}
	hops := browser.DriveSSO(t, login.location, adminauth.KCUserRoot, adminauth.KCPassRoot, callback)
	last := hops[len(hops)-1]
	if last.Status != http.StatusFound || !strings.HasPrefix(last.Location, callback) {
		t.Fatalf("real IdP did not return to the callback: %d → %q", last.Status, last.Location)
	}
	tampered := last.Location
	if u, err := url.Parse(tampered); err == nil {
		q := u.Query()
		q.Set("code", "forged-by-the-test")
		u.RawQuery = q.Encode()
		tampered = u.String()
	}
	resp := console.get(t, browser, tampered)
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("forged code callback: got %d, want 401; body %s", resp.status, kcSnippet(resp.body))
	}
	if console.hasSession(browser.Jar) {
		t.Fatal("forged code produced a session")
	}
	if !console.flowCookieCleared(t, resp, adminauth.OIDCFlowCookieName) {
		t.Fatal("failed callback did not clear the one-time flow cookie")
	}
	if probe := console.get(t, browser, console.base.String()+"/api/version"); probe.status != http.StatusUnauthorized {
		t.Fatalf("guarded route after failed exchange: got %d, want 401", probe.status)
	}
}

// ---- SAML live tests --------------------------------------------------------------

// kcSAMLConsole wires a console with a REAL crewjam SP pointed at the
// Keycloak realm metadata and patches the realm's SAML client to the console
// endpoints. Returns the console and the SP.
func kcSAMLConsole(t *testing.T, stand *adminauth.KCStand, pool *pgxpool.Pool) (*kcConsole, *adminauth.SAMLSP) {
	t.Helper()
	ctx := context.Background()
	var sp *adminauth.SAMLSP
	console := kcStartConsole(t, pool, func(base string) ([]func(*handlers.AdminHandlers), error) {
		entityID, acsURL := base, base+"/auth/saml/acs"
		if err := stand.ConfigureSAMLClient(ctx, entityID, acsURL); err != nil {
			return nil, err
		}
		provider, err := adminauth.NewSAMLSP(ctx, adminauth.SAMLOptions{
			IDPMetadataURL: stand.RealmURL + "/protocol/saml/descriptor",
			EntityID:       entityID,
			ACSURL:         acsURL,
		})
		if err != nil {
			return nil, err
		}
		sp = provider
		return []func(*handlers.AdminHandlers){func(h *handlers.AdminHandlers) { h.SetSAMLSP(provider) }}, nil
	})
	return console, sp
}

// TestKeycloakLive_SAML_SPInitiatedLogin is the N04-P02 T06 live evidence
// part 1: a real SP-initiated login — signed AuthnRequest, real Keycloak
// document signature over the POST-binding response, fail-closed mapping —
// plus the negative matrix (tampered response, unsigned response, missing
// flow cookie) issues no session.
func TestKeycloakLive_SAML_SPInitiatedLogin(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	kcLiveWorld(t, pool)
	console, _ := kcSAMLConsole(t, stand, pool)

	// Positive: full SP-initiated round trip issues a session.
	browser := adminauth.NewKCBrowser()
	login := console.get(t, browser, console.base.String()+adminauth.SAMLLoginPath)
	if login.status != http.StatusFound || !strings.HasPrefix(login.location, stand.BaseURL) {
		t.Fatalf("saml login: got %d → %q, want 302 to Keycloak", login.status, login.location)
	}
	if browser.Jar.Cookie(console.base, adminauth.SAMLFlowCookieName) == "" {
		t.Fatal("saml login did not set the flow cookie")
	}
	hops := browser.DriveSSO(t, login.location, adminauth.KCUserRoot, adminauth.KCPassRoot, "")
	offer := browser.SAMLOffer(t, hops)
	callback := console.postForm(t, browser, offer.PostURL, url.Values{"SAMLResponse": {offer.SAMLResponse}})
	if callback.status != http.StatusFound || callback.location != "/" {
		t.Fatalf("acs: got %d → %q, want 302 → /; body %s", callback.status, callback.location, kcSnippet(callback.body))
	}
	sess := console.sessionOf(t, callback)
	if sess == nil || sess.Email != kcAdminEmail {
		t.Fatalf("real SAML login session: got %+v", sess)
	}
	if !console.flowCookieCleared(t, callback, adminauth.SAMLFlowCookieName) {
		t.Fatal("acs did not clear the one-time flow cookie")
	}
	if probe := console.get(t, browser, console.base.String()+"/api/me"); probe.status != http.StatusOK || !strings.Contains(probe.body, kcAdminEmail) {
		t.Fatalf("/api/me with a real SAML session: got %d; body %s", probe.status, kcSnippet(probe.body))
	}

	// Negative A: tampered response — the assertion is modified after
	// signing; the document signature no longer validates and no session is
	// issued. The flow cookie is single-use, so the repost without it is
	// refused as well.
	browser2 := adminauth.NewKCBrowser()
	login2 := console.get(t, browser2, console.base.String()+adminauth.SAMLLoginPath)
	if login2.status != http.StatusFound {
		t.Fatalf("saml login 2: got %d, want 302", login2.status)
	}
	hops2 := browser2.DriveSSO(t, login2.location, adminauth.KCUserRoot, adminauth.KCPassRoot, "")
	offer2 := browser2.SAMLOffer(t, hops2)
	tamperedXML, err := base64.StdEncoding.DecodeString(offer2.SAMLResponse)
	if err != nil {
		t.Fatalf("decode captured SAMLResponse: %v", err)
	}
	mutated := strings.Replace(string(tamperedXML), "sso-root", "sso-hacker", 1)
	if mutated == string(tamperedXML) {
		t.Fatal("tamper was a no-op; the fixture must actually modify the signed XML")
	}
	tamperResp := console.postForm(t, browser2, offer2.PostURL, url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(mutated))}})
	if tamperResp.status != http.StatusUnauthorized {
		t.Fatalf("tampered response: got %d, want 401; body %s", tamperResp.status, kcSnippet(tamperResp.body))
	}
	if console.hasSession(browser2.Jar) {
		t.Fatal("tampered response produced a session")
	}
	replay := console.postForm(t, browser2, offer2.PostURL, url.Values{"SAMLResponse": {offer2.SAMLResponse}})
	if replay.status != http.StatusForbidden {
		t.Fatalf("repost without flow cookie: got %d, want 403; body %s", replay.status, kcSnippet(replay.body))
	}

	// Negative B: the IdP stops signing (both flags off); the unsigned
	// response must not yield a session either.
	ctx := context.Background()
	if err := stand.SetSAMLSignFlags(ctx, false, false); err != nil {
		t.Fatalf("disable signing in Keycloak: %v", err)
	}
	defer func() { _ = stand.SetSAMLSignFlags(ctx, true, true) }()
	browser3 := adminauth.NewKCBrowser()
	login3 := console.get(t, browser3, console.base.String()+adminauth.SAMLLoginPath)
	if login3.status != http.StatusFound {
		t.Fatalf("saml login 3: got %d, want 302", login3.status)
	}
	hops3 := browser3.DriveSSO(t, login3.location, adminauth.KCUserRoot, adminauth.KCPassRoot, "")
	offer3 := browser3.SAMLOffer(t, hops3)
	unsigned := console.postForm(t, browser3, offer3.PostURL, url.Values{"SAMLResponse": {offer3.SAMLResponse}})
	if unsigned.status != http.StatusUnauthorized {
		t.Fatalf("unsigned response: got %d, want 401; body %s", unsigned.status, kcSnippet(unsigned.body))
	}
	if console.hasSession(browser3.Jar) {
		t.Fatal("unsigned response produced a session")
	}
}

// kcSnippet collapses whitespace for failure messages.
func kcSnippet(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}
