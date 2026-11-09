//go:build integration

package adminauth_test

// N04-P01 T08 live-IdP lifecycle evidence: OIDC login interruption, retry
// and resume against a REAL local Keycloak, with no duplicate provisioning
// and no lost sessions or results.
//
// What this file pins (all through the real provider — real discovery, real
// RS256 tokens, real forms, real HTTP round trips over a real adminstore):
//
//	interruption  an abandoned login (flow cookie + IdP session) cannot
//	              hijack the retry: the stale state fails closed, the flow
//	              cookie is one-time, and a fresh login recovers completely;
//	replay        a REAL authorization code is single-use at the real token
//	              endpoint: the replayed callback is refused and the session
//	              minted by the first use is untouched;
//	resume        a signed admin session survives a console restart (a second
//	              console instance over the same durable store) — process
//	              interruption loses neither the session nor the mapping;
//	groups        the full mapping-recovery matrix for one user driven
//	              through grant → idempotent retry → crash-orphan heal →
//	              deny-wins revoke → no self-reprovisioning → admin
//	              re-membership, with audit deltas asserted after every step;
//	bindings      issuer and audience bindings fail closed against a REAL
//	              correctly-signed token (wrong client_id / wrong realm);
//	rotation      a PERSISTENT client recovers across a full key rotation
//	              cycle (adopt → signer switch → retire) with console logins
//	              never interrupted; the retired key stops trusting on the
//	              same client after the next keyset refresh (the bounded
//	              cache-retention window itself is documented, and the
//	              fresh-client fail-closed behavior is pinned in
//	              keycloak_live_boundary_test.go);
//	portal        domain-mode portal provisioning is idempotent under retry
//	              (one developer row, stable ID, no duplicates).
//
// File order: this file runs after keycloak_live_e2e_test.go (which leaves
// the deny user IN the contractors group) and before
// keycloak_live_rotation_test.go (whose phase 0 requires the pristine
// single-key realm). Every realm key added here is deleted again by
// t.Cleanup, and the deny user is left with the contractors group removed.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// ---- lifecycle helpers --------------------------------------------------------

func kcLCQueryValue(t *testing.T, rawURL, key string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Query().Get(key)
}

// kcLCVerifierFor mirrors the exact verifier construction of
// adminauth.NewOIDCClient (discovery + audience-bound verifier) — the
// unexported verifier is not reachable from this external test package.
func kcLCVerifierFor(t *testing.T, issuer, clientID string) *oidc.IDTokenVerifier {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("discovery %q: %v", issuer, err)
	}
	return provider.Verifier(&oidc.Config{ClientID: clientID})
}

func kcLCJWTHeaderKid(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("id_token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("jwt header: %v", err)
	}
	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("jwt header: %v", err)
	}
	return header.Kid
}

// kcLCAddKey adds a realm RSA signing key and guarantees its removal: the
// rotation suite (file order) requires the pristine single-key realm.
func kcLCAddKey(t *testing.T, stand *adminauth.KCStand, name string, priority int) {
	t.Helper()
	ctx := context.Background()
	_ = stand.DeleteRSAKeyProvider(ctx, name) // defensive: idempotent reruns
	before, err := stand.RSAKeyProviders(ctx)
	if err != nil {
		t.Fatalf("list key providers: %v", err)
	}
	if err := stand.AddRSAKeyProvider(ctx, name, priority); err != nil {
		t.Fatalf("add key %q: %v", name, err)
	}
	t.Cleanup(func() {
		deleted := false
		var lastErr error
		for attempt := 0; attempt < 5; attempt++ {
			err := stand.DeleteRSAKeyProvider(ctx, name)
			if err == nil {
				deleted = true
				lastErr = nil
				break
			}
			if strings.Contains(err.Error(), "not found in realm") {
				// The test body may have retired the key itself; gone is gone.
				deleted = true
				lastErr = nil
				break
			}
			lastErr = err
			time.Sleep(500 * time.Millisecond)
		}
		if !deleted {
			t.Errorf("cleanup: delete key %q: %v", name, lastErr)
			return
		}
		for attempt := 0; attempt < 5; attempt++ {
			kids, err := stand.JWKSKids(ctx)
			if err == nil && len(kids) == len(before) {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		kids, _ := stand.JWKSKids(ctx)
		t.Errorf("cleanup: realm JWKS not restored to %d keys, got %v", len(before), kids)
	})
}

// kcLCCountSSOAudit counts durable audit rows for one mapping action and
// user. Audit writes are synchronous (durable before the login response), so
// deltas are assertable immediately after each login.
func kcLCCountSSOAudit(t *testing.T, store *adminstore.Store, action, userID string) int {
	t.Helper()
	ctx := context.Background()
	count := 0
	for page := 1; page <= 50; page++ {
		entries, _, _, err := store.ListAuditLogEntries(ctx, adminstore.AuditLogQuery{Page: page, PageSize: 100})
		if err != nil {
			t.Fatalf("list audit page %d: %v", page, err)
		}
		for _, e := range entries {
			if e.Action == action && strings.Contains(e.Details, "user="+userID) {
				count++
			}
		}
		if len(entries) == 0 {
			break
		}
	}
	return count
}

// kcLCDenyNormalize forces the deny user into a deterministic pre-grant
// state regardless of what earlier suites left behind: no contractors group
// at the IdP, reader membership in the store, no mapping provenance.
func kcLCDenyNormalize(t *testing.T, stand *adminauth.KCStand, store *adminstore.Store, orgID, denyUserID string) {
	t.Helper()
	ctx := context.Background()
	_ = stand.RemoveUserFromGroup(ctx, adminauth.KCUserDeny, "contractors") // absent is fine
	if _, err := store.SetOrgMembership(ctx, denyUserID, orgID, adminstore.RoleReader); err != nil {
		t.Fatalf("normalize membership: %v", err)
	}
	if err := store.DeleteSSOGrantedRole(ctx, orgID, denyUserID); err != nil {
		t.Fatalf("normalize provenance: %v", err)
	}
	roles, err := store.GetUserOrgRoles(ctx, denyUserID)
	if err != nil {
		t.Fatalf("normalize: list memberships: %v", err)
	}
	if roles[orgID] != adminstore.RoleReader {
		t.Fatalf("normalize failed: membership is %q, want reader", roles[orgID])
	}
}

// ---- 1. interruption / retry / resume -----------------------------------------

func TestKeycloakLiveLifecycle_InterruptRetryResume(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	kcLiveWorld(t, pool)

	console := kcStartConsole(t, pool, kcOIDCMounts(stand))
	callback := console.base.String() + "/auth/oidc/callback"

	t.Run("abandoned flow and stale state cannot hijack the retry", func(t *testing.T) {
		browser := adminauth.NewKCBrowser()

		// Flow 1 is started and abandoned: the flow cookie is minted, the
		// IdP authorize URL is never followed.
		login1 := console.get(t, browser, console.base.String()+"/auth/oidc/login?"+url.Values{"next": {kcDeepLink}}.Encode())
		if login1.status != http.StatusFound {
			t.Fatalf("login1: got %d, want 302", login1.status)
		}
		state1 := kcLCQueryValue(t, login1.location, "state")
		if state1 == "" {
			t.Fatal("login1 redirect carries no state")
		}
		// Flow 2 replaces it in the same browser (the interrupted-login shape).
		login2 := console.get(t, browser, console.base.String()+"/auth/oidc/login")
		if login2.status != http.StatusFound {
			t.Fatalf("login2: got %d, want 302", login2.status)
		}

		// The abandoned flow's state is replayed at the callback: it must
		// fail closed (the live flow cookie holds flow2, not flow1) and
		// consume the one-time flow cookie with it.
		stale := console.get(t, browser, console.base.String()+"/auth/oidc/callback?"+url.Values{"state": {state1}, "code": {"never-exchanged"}}.Encode())
		if stale.status != http.StatusForbidden {
			t.Fatalf("stale state callback: got %d, want 403; body %s", stale.status, kcSnippet(stale.body))
		}
		if console.hasSession(browser.Jar) {
			t.Fatal("stale state produced a session")
		}
		if !console.flowCookieCleared(t, stale, adminauth.OIDCFlowCookieName) {
			t.Fatal("stale-state rejection did not clear the one-time flow cookie")
		}

		// The retry with a fresh flow completes and recovers fully.
		retry := console.kcSSOLogin(t, browser, "/auth/oidc/login?"+url.Values{"next": {kcDeepLink}}.Encode(),
			adminauth.KCUserRoot, adminauth.KCPassRoot, callback)
		if retry.status != http.StatusFound || retry.location != kcDeepLink {
			t.Fatalf("retry login: got %d → %q, want 302 → %q; body %s",
				retry.status, retry.location, kcDeepLink, kcSnippet(retry.body))
		}
		sess := console.sessionOf(t, retry)
		if sess == nil || sess.Email != kcAdminEmail {
			t.Fatalf("retry login issued no usable session: %+v", sess)
		}
		sessionCookies := 0
		for _, ck := range retry.cookies {
			if ck.Name == "yabanin_admin_session" && ck.Value != "" {
				sessionCookies++
			}
		}
		if sessionCookies != 1 {
			t.Fatalf("retry login issued %d session cookies, want exactly 1", sessionCookies)
		}
		if me := console.get(t, browser, console.base.String()+"/api/me"); me.status != http.StatusOK || !strings.Contains(me.body, kcAdminEmail) {
			t.Fatalf("post-recovery /api/me: got %d; body %s", me.status, kcSnippet(me.body))
		}
	})

	t.Run("a REAL authorization code replays exactly once", func(t *testing.T) {
		browser := adminauth.NewKCBrowser()
		login := console.get(t, browser, console.base.String()+"/auth/oidc/login")
		if login.status != http.StatusFound {
			t.Fatalf("login: got %d, want 302", login.status)
		}
		flowVal := browser.Jar.Cookie(console.base, adminauth.OIDCFlowCookieName)
		if flowVal == "" {
			t.Fatal("login did not set the flow cookie")
		}
		hops := browser.DriveSSO(t, login.location, adminauth.KCUserRoot, adminauth.KCPassRoot, callback)
		last := hops[len(hops)-1]
		if last.Status != http.StatusFound || !strings.HasPrefix(last.Location, callback) {
			t.Fatalf("real IdP did not return to the callback: %d → %q", last.Status, last.Location)
		}
		if code := kcLCQueryValue(t, last.Location, "code"); code == "" {
			t.Fatal("callback URL carries no code")
		}

		first := console.get(t, browser, last.Location)
		if first.status != http.StatusFound || console.sessionOf(t, first) == nil {
			t.Fatalf("first callback use: got %d, want 302 with a session; body %s", first.status, kcSnippet(first.body))
		}
		sessionVal := browser.Jar.Cookie(console.base, "yabanin_admin_session")
		if sessionVal == "" {
			t.Fatal("jar lost the session after the first callback")
		}

		// Replant the captured flow cookie and replay the byte-identical
		// callback URL: the REAL token endpoint refuses the second exchange
		// of the same code.
		browser.Jar.SetInjected(console.base, http.Cookie{Name: adminauth.OIDCFlowCookieName, Value: flowVal})
		replay := console.get(t, browser, last.Location)
		if replay.status != http.StatusUnauthorized {
			t.Fatalf("replayed code: got %d, want 401; body %s", replay.status, kcSnippet(replay.body))
		}
		if got := browser.Jar.Cookie(console.base, "yabanin_admin_session"); got != sessionVal {
			t.Fatal("failed replay disturbed the session minted by the first use")
		}
		if !console.flowCookieCleared(t, replay, adminauth.OIDCFlowCookieName) {
			t.Fatal("replayed callback did not clear the one-time flow cookie")
		}
		// The legitimate session keeps working — a replay attack neither
		// mints a second session nor logs the victim out.
		if me := console.get(t, browser, console.base.String()+"/api/me"); me.status != http.StatusOK {
			t.Fatalf("session after replay attack: got %d, want 200", me.status)
		}
	})

	t.Run("lost flow cookie fails closed and a fresh login recovers", func(t *testing.T) {
		browser := adminauth.NewKCBrowser()
		login := console.get(t, browser, console.base.String()+"/auth/oidc/login")
		if login.status != http.StatusFound {
			t.Fatalf("login: got %d, want 302", login.status)
		}
		hops := browser.DriveSSO(t, login.location, adminauth.KCUserRoot, adminauth.KCPassRoot, callback)
		last := hops[len(hops)-1]
		if last.Status != http.StatusFound || !strings.HasPrefix(last.Location, callback) {
			t.Fatalf("real IdP did not return to the callback: %d → %q", last.Status, last.Location)
		}
		browser.Jar.Delete(console.base, adminauth.OIDCFlowCookieName)

		orphan := console.get(t, browser, last.Location)
		if orphan.status != http.StatusForbidden {
			t.Fatalf("callback without flow cookie: got %d, want 403; body %s", orphan.status, kcSnippet(orphan.body))
		}
		if console.hasSession(browser.Jar) {
			t.Fatal("orphan callback produced a session")
		}

		again := console.kcSSOLogin(t, browser, "/auth/oidc/login", adminauth.KCUserRoot, adminauth.KCPassRoot, callback)
		if again.status != http.StatusFound || console.sessionOf(t, again) == nil {
			t.Fatalf("recovery login: got %d, want 302 with a session; body %s", again.status, kcSnippet(again.body))
		}
		if me := console.get(t, browser, console.base.String()+"/api/me"); me.status != http.StatusOK || !strings.Contains(me.body, kcAdminEmail) {
			t.Fatalf("post-recovery /api/me: got %d; body %s", me.status, kcSnippet(me.body))
		}
	})

	// The signed session plus the durable store survive a process restart:
	// console2 is a fully independent handler stack over the same Postgres —
	// exactly what comes back up after the first one dies.
	t.Run("session and mapping survive a console restart", func(t *testing.T) {
		browser := adminauth.NewKCBrowser()
		before := console.kcSSOLogin(t, browser, "/auth/oidc/login", adminauth.KCUserRoot, adminauth.KCPassRoot, callback)
		if before.status != http.StatusFound || console.sessionOf(t, before) == nil {
			t.Fatalf("pre-restart login: got %d; body %s", before.status, kcSnippet(before.body))
		}
		sessionVal := browser.Jar.Cookie(console.base, "yabanin_admin_session")
		if sessionVal == "" {
			t.Fatal("no session to carry across the restart")
		}

		console2 := kcStartConsole(t, pool, kcOIDCMounts(stand))
		restart := adminauth.NewKCBrowser()
		restart.Jar.SetInjected(console2.base, http.Cookie{Name: "yabanin_admin_session", Value: sessionVal})
		if me := console2.get(t, restart, console2.base.String()+"/api/me"); me.status != http.StatusOK || !strings.Contains(me.body, kcAdminEmail) {
			t.Fatalf("post-restart /api/me: got %d; body %s", me.status, kcSnippet(me.body))
		}
		if version := console2.get(t, restart, console2.base.String()+"/api/version"); version.status != http.StatusOK {
			t.Fatalf("post-restart /api/version: got %d", version.status)
		}
	})
}

// ---- 2. group-mapping recovery matrix -----------------------------------------

// The whole matrix runs against ONE user (the deny user) in strict order:
// grant → idempotent retry → crash-orphan heal → deny-wins revoke → no
// self-reprovisioning → admin re-membership. Every step asserts the durable
// state AND the audit delta, so a silent double-provision or a lost revoke
// cannot pass.
func TestKeycloakLiveLifecycle_GroupMappingRecoveryMatrix(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	store, orgID := kcLiveWorld(t, pool)
	ctx := context.Background()

	denyUser, err := store.GetAdminUserByEmail(ctx, kcDenyEmail)
	if err != nil {
		t.Fatalf("lookup deny user: %v", err)
	}
	kcLCDenyNormalize(t, stand, store, orgID, denyUser.ID)
	var (
		grants0  int
		revokes0 int
	)
	baseline := func() {
		grants0 = kcLCCountSSOAudit(t, store, "sso_role_grant", denyUser.ID)
		revokes0 = kcLCCountSSOAudit(t, store, "sso_role_revoke", denyUser.ID)
	}
	baseline()

	console := kcStartConsole(t, pool, kcOIDCMounts(stand))
	callback := console.base.String() + "/auth/oidc/callback"

	// check verifies the durable state; provRole is the expected provenance
	// value ("" = cleared). Decoupled from the membership role because the
	// crash-orphan state holds provenance for a role the membership lost.
	check := func(wantRole, provRole adminstore.OrgRole) {
		t.Helper()
		roles, err := store.GetUserOrgRoles(ctx, denyUser.ID)
		if err != nil {
			t.Fatalf("list memberships: %v", err)
		}
		role, has := roles[orgID]
		if wantRole == "" {
			if has {
				t.Fatalf("membership must be absent, got %q", role)
			}
		} else if !has || role != wantRole {
			t.Fatalf("membership is (%q, %v), want %q", role, has, wantRole)
		}
		granted, hasPrev, err := store.GetSSOGrantedRole(ctx, orgID, denyUser.ID)
		if err != nil {
			t.Fatalf("read provenance: %v", err)
		}
		if provRole == "" {
			if hasPrev {
				t.Fatalf("provenance must be cleared, got %q", granted)
			}
		} else if !hasPrev || granted != provRole {
			t.Fatalf("provenance is (%q, %v), want %q", granted, hasPrev, provRole)
		}
	}

	// expectAuditDelta asserts the audit churn of the step that just ran and
	// re-baselines, so every step accounts exactly its own rows.
	expectAuditDelta := func(wantGrants, wantRevokes int) {
		t.Helper()
		g := kcLCCountSSOAudit(t, store, "sso_role_grant", denyUser.ID) - grants0
		r := kcLCCountSSOAudit(t, store, "sso_role_revoke", denyUser.ID) - revokes0
		if g != wantGrants || r != wantRevokes {
			t.Fatalf("audit delta: grants +%d revokes +%d, want +%d/+%d", g, r, wantGrants, wantRevokes)
		}
		baseline()
	}

	loginDeny := func() {
		t.Helper()
		browser := adminauth.NewKCBrowser()
		resp := console.kcSSOLogin(t, browser, "/auth/oidc/login", adminauth.KCUserDeny, adminauth.KCPassDeny, callback)
		if resp.status != http.StatusFound || console.sessionOf(t, resp) == nil {
			t.Fatalf("deny-user login: got %d, want 302 with a session; body %s", resp.status, kcSnippet(resp.body))
		}
	}

	t.Run("first login grants operator once", func(t *testing.T) {
		loginDeny()
		check(adminstore.RoleOperator, adminstore.RoleOperator)
		expectAuditDelta(1, 0)
	})

	t.Run("retry login is idempotent", func(t *testing.T) {
		loginDeny()
		check(adminstore.RoleOperator, adminstore.RoleOperator)
		expectAuditDelta(0, 0) // no duplicate provisioning, no audit churn
	})

	t.Run("interrupted sync orphan heals on the next login", func(t *testing.T) {
		// Simulate a crash between the provenance write and the membership
		// write: provenance stays operator, membership is back to reader.
		if _, err := store.SetOrgMembership(ctx, denyUser.ID, orgID, adminstore.RoleReader); err != nil {
			t.Fatalf("revert membership: %v", err)
		}
		check(adminstore.RoleReader, adminstore.RoleOperator)
		loginDeny()
		check(adminstore.RoleOperator, adminstore.RoleOperator)
		expectAuditDelta(1, 0)
	})

	t.Run("IdP deny group revokes on the next login without losing the login", func(t *testing.T) {
		if err := stand.AddUserToGroup(ctx, adminauth.KCUserDeny, "contractors"); err != nil {
			t.Fatalf("add contractors group in Keycloak: %v", err)
		}
		loginDeny() // the login itself must still succeed
		check("", "")
		expectAuditDelta(0, 1)
	})

	t.Run("revoked mapping never self-reprovisions", func(t *testing.T) {
		if err := stand.RemoveUserFromGroup(ctx, adminauth.KCUserDeny, "contractors"); err != nil {
			t.Fatalf("remove contractors group in Keycloak: %v", err)
		}
		loginDeny() // the IdP grant rule would match again — the mapping must NOT re-grant
		check("", "")
		expectAuditDelta(0, 0)
	})

	t.Run("admin re-membership re-enables the grant", func(t *testing.T) {
		if _, err := store.SetOrgMembership(ctx, denyUser.ID, orgID, adminstore.RoleReader); err != nil {
			t.Fatalf("admin membership: %v", err)
		}
		loginDeny()
		check(adminstore.RoleOperator, adminstore.RoleOperator)
		expectAuditDelta(1, 0)
	})
}

// ---- 3. issuer / audience bindings against a REAL token ------------------------

func TestKeycloakLiveLifecycle_TokenBindingsFailClosed(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	kcLiveWorld(t, testdb.Postgres(t))

	// A real, correctly signed ID token from the real realm.
	token, claims := stand.CaptureIDToken(t, adminauth.KCUserRoot, adminauth.KCPassRoot)
	if got := claims["iss"]; got != stand.RealmURL {
		t.Fatalf("token iss %v, want %v", got, stand.RealmURL)
	}
	if got := claims["aud"]; got != adminauth.KCLiveOIDCClientID {
		t.Fatalf("token aud %v, want %v", got, adminauth.KCLiveOIDCClientID)
	}

	// Control: the production binding accepts it.
	if _, err := kcLCVerifierFor(t, stand.RealmURL, adminauth.KCLiveOIDCClientID).Verify(context.Background(), token); err != nil {
		t.Fatalf("control verifier must accept the real token: %v", err)
	}

	// Audience binding: the same real token offered to a client bound to a
	// DIFFERENT client_id is rejected — stolen tokens are worthless to
	// another relying party.
	if _, err := kcLCVerifierFor(t, stand.RealmURL, "admin-cli").Verify(context.Background(), token); err == nil {
		t.Fatal("verifier bound to another client must reject the token (audience binding)")
	}

	// Issuer binding: a verifier built from the REAL /realms/master
	// discovery document rejects the token — a token from one realm is
	// worthless at another issuer, even with the same key material trust
	// chain behind it.
	if _, err := kcLCVerifierFor(t, stand.BaseURL+"/realms/master", adminauth.KCLiveOIDCClientID).Verify(context.Background(), token); err == nil {
		t.Fatal("verifier bound to another issuer must reject the token (issuer binding)")
	}
}

// ---- 4. rotation recovery on a persistent client -------------------------------

// The rotation suite pins the fresh-client fail-closed behavior after
// retirement (keycloak_live_boundary_test.go). THIS test pins the other half
// of the lifecycle: ONE persistent production client (constructed once, as
// the console does) rides through adopt → signer switch → retire → next
// rotation with logins never interrupted, and the retired key stops trusting
// on that same client after the next keyset refresh. The transient window
// where the still-cached retired key keeps validating between the JWKS
// change and the next refetch is go-oidc's documented remote-keyset behavior;
// it is asserted explicitly here so any change to it is a conscious one.
func TestKeycloakLiveLifecycle_RotationRecoveryOnPersistentClient(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	kcLiveWorld(t, pool)
	ctx := context.Background()

	verifier := kcLCVerifierFor(t, stand.RealmURL, adminauth.KCLiveOIDCClientID) // ONE client for the whole cycle
	console := kcStartConsole(t, pool, kcOIDCMounts(stand))
	callback := console.base.String() + "/auth/oidc/callback"

	basePriority, err := stand.PrimaryRSAPriority(ctx)
	if err != nil {
		t.Fatalf("primary key priority: %v", err)
	}

	// Baseline: the pre-rotation token verifies and warms the keyset cache.
	tokenA, _ := stand.CaptureIDToken(t, adminauth.KCUserRoot, adminauth.KCPassRoot)
	kidA := kcLCJWTHeaderKid(t, tokenA)
	if _, err := verifier.Verify(ctx, tokenA); err != nil {
		t.Fatalf("pre-rotation token must verify: %v", err)
	}

	// Rotation step 1: a new key takes over signing.
	kcLCAddKey(t, stand, "n04-lifecycle-key-a", basePriority+100)
	tokenB, _ := stand.CaptureIDToken(t, adminauth.KCUserRoot, adminauth.KCPassRoot)
	kidB := kcLCJWTHeaderKid(t, tokenB)
	if kidB == "" || kidB == kidA {
		t.Fatalf("signer did not switch: kidB %q must differ from kidA %q", kidB, kidA)
	}
	if _, err := verifier.Verify(ctx, tokenB); err != nil {
		t.Fatalf("same persistent client must adopt the new kid via keyset refetch: %v", err)
	}
	if kids, err := stand.JWKSKids(ctx); err != nil {
		t.Fatalf("jwks: %v", err)
	} else {
		published := false
		for _, k := range kids {
			if k == kidB {
				published = true
			}
		}
		if !published {
			t.Fatalf("new kid %q not published during the dual window: %v", kidB, kids)
		}
	}
	// A console login across the rotation must be untouched by the key change.
	loginB := console.kcSSOLogin(t, adminauth.NewKCBrowser(), "/auth/oidc/login", adminauth.KCUserRoot, adminauth.KCPassRoot, callback)
	if loginB.status != http.StatusFound || console.sessionOf(t, loginB) == nil {
		t.Fatalf("login across rotation: got %d, want 302 with a session; body %s", loginB.status, kcSnippet(loginB.body))
	}

	// Rotation step 2: retire the new key (the classic "key compromised /
	// rotated out" event). The JWKS drops it.
	if err := stand.DeleteRSAKeyProvider(ctx, "n04-lifecycle-key-a"); err != nil {
		t.Fatalf("retire key-a: %v", err)
	}
	if kids, err := stand.JWKSKids(ctx); err != nil {
		t.Fatalf("jwks: %v", err)
	} else {
		for _, k := range kids {
			if k == kidB {
				t.Fatalf("retired kid %q still published: %v", kidB, kids)
			}
		}
	}
	// Documented transient window: the key is still in the client's cache,
	// so the token verifies until the next refetch. Asserted deliberately —
	// the fresh-client fail-closed counterpart lives in the boundary suite.
	if _, err := verifier.Verify(ctx, tokenB); err != nil {
		t.Fatalf("cached-key window: tokenB must still verify before the next refetch (documented go-oidc remote-keyset behavior): %v", err)
	}

	// Rotation step 3: the NEXT rotation event (a third key takes signing)
	// forces the refetch that evicts the retired key.
	kcLCAddKey(t, stand, "n04-lifecycle-key-b", basePriority+200)
	tokenC, _ := stand.CaptureIDToken(t, adminauth.KCUserRoot, adminauth.KCPassRoot)
	kidC := kcLCJWTHeaderKid(t, tokenC)
	if kidC == "" || kidC == kidB || kidC == kidA {
		t.Fatalf("third key must take signing: kidC %q (kidA %q, kidB %q)", kidC, kidA, kidB)
	}
	if _, err := verifier.Verify(ctx, tokenC); err != nil {
		t.Fatalf("persistent client must adopt the third key: %v", err)
	}
	// Recovery complete: the retired key now fails closed on the SAME client.
	if _, err := verifier.Verify(ctx, tokenB); err == nil {
		t.Fatal("retired key must stop trusting on the persistent client after the next keyset refresh")
	}
	// And the console keeps issuing sessions after the whole cycle.
	loginC := console.kcSSOLogin(t, adminauth.NewKCBrowser(), "/auth/oidc/login", adminauth.KCUserRoot, adminauth.KCPassRoot, callback)
	if loginC.status != http.StatusFound || console.sessionOf(t, loginC) == nil {
		t.Fatalf("login after rotation recovery: got %d, want 302 with a session; body %s", loginC.status, kcSnippet(loginC.body))
	}
}

// ---- 5. portal provisioning idempotency ----------------------------------------

// Domain-mode portal provisioning is the only path that CREATES accounts
// from a login. Interruption/retry must not duplicate them: the first login
// creates the developer, a full retry binds the SAME row, and the org holds
// exactly one developer with that email.
func TestKeycloakLiveLifecycle_PortalProvisioningIdempotent(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	store, _ := kcLiveWorld(t, pool)
	ctx := context.Background()

	org, err := store.CreateOrganization(ctx, "N04 Portal Org", "n04-portal-lc")
	if err != nil {
		t.Fatalf("create portal org: %v", err)
	}
	team, err := store.CreateTeam(ctx, org.ID, "Portal Team", "portal-team-lc", nil)
	if err != nil {
		t.Fatalf("create portal team: %v", err)
	}

	console := kcStartConsole(t, pool, func(base string) ([]func(*handlers.AdminHandlers), error) {
		client, err := adminauth.NewOIDCClient(ctx, stand.RealmURL,
			adminauth.KCLiveOIDCClientID, adminauth.KCLiveOIDCClientSecret, base+"/portal/callback")
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
				Client:         client,
				Store:          store,
			})
		}}, nil
	})
	stop := console.base.String() + "/portal/callback"

	portalLogin := func() string {
		t.Helper()
		browser := adminauth.NewKCBrowser()
		login := console.get(t, browser, console.base.String()+"/portal/login")
		if login.status != http.StatusFound {
			t.Fatalf("portal login: got %d, want 302", login.status)
		}
		hops := browser.DriveSSO(t, login.location, adminauth.KCUserRoot, adminauth.KCPassRoot, stop)
		last := hops[len(hops)-1]
		if last.Status != http.StatusFound || !strings.HasPrefix(last.Location, stop) {
			t.Fatalf("real IdP did not return to the portal callback: %d → %q", last.Status, last.Location)
		}
		done := console.get(t, browser, last.Location)
		if done.status != http.StatusFound || done.location != "/portal" {
			t.Fatalf("portal callback: got %d → %q, want 302 → /portal; body %s", done.status, done.location, kcSnippet(done.body))
		}
		if browser.Jar.Cookie(console.base, adminauth.PortalSessionCookieName) == "" {
			t.Fatal("portal callback issued no portal session")
		}
		me := console.get(t, browser, console.base.String()+"/api/me")
		if me.status != http.StatusOK || !strings.Contains(me.body, kcAdminEmail) {
			t.Fatalf("portal /api/me: got %d; body %s", me.status, kcSnippet(me.body))
		}
		dev, err := store.GetDeveloperByEmail(ctx, kcAdminEmail)
		if err != nil {
			t.Fatalf("portal login did not leave a developer row: %v", err)
		}
		return dev.ID
	}

	first := portalLogin()
	if first == "" {
		t.Fatal("first portal login created no developer")
	}
	// Full retry after an (imagined) interruption: same identity, same row.
	second := portalLogin()
	if second != first {
		t.Fatalf("retry created a duplicate developer: first %q, second %q", first, second)
	}
	devs, err := store.ListDevelopers(ctx, org.ID)
	if err != nil {
		t.Fatalf("list developers: %v", err)
	}
	matches := 0
	for _, d := range devs {
		if strings.EqualFold(d.Email, kcAdminEmail) {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("org holds %d developers with email %s, want exactly 1", matches, kcAdminEmail)
	}
}
