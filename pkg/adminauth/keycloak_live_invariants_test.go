//go:build integration

package adminauth_test

// N04-P01 T10 — the escalation invariants against the REAL stack (live
// Keycloak + real Postgres + the real console wiring), independent of the
// behaviour matrices in the e2e/compat/lifecycle suites:
//
//  1. Groups never provision. A real IdP login whose groups match declared
//     grant rules must leave a membership-less user membership-less: rules
//     decide the ROLE of a membership the DB already holds, nothing else.
//     Knowing the group names admits an attacker to no org.
//  2. The mapped role has a ceiling, and so does the session. A group grant
//     promotes an existing membership to exactly the declared role (never
//     further, never root); the issued session keeps the DB user's root
//     flag, so a mapped org-admin still cannot read the root-only audit
//     journal — while a DB-root session can.
//
// The token-layer negatives (stale/retired key, forged signature, foreign
// issuer, audience binding) have their own live evidence in
// oidc_boundary_test.go (stub IdP) and keycloak_live_compat_test.go (real
// IdP); this file owns the DATA-layer invariants the other suites do not
// pin. Skip discipline follows KeycloakLiveStand: no Docker daemon is an
// explicit SKIP, never a silent pass.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
)

const (
	kcInvUser  = "sso-inv"
	kcInvEmail = "sso-inv@test.io"
	kcInvPass  = "n04-inv-pass"

	kcCeilUser  = "sso-ceil"
	kcCeilEmail = "sso-ceil@test.io"
	kcCeilPass  = "n04-ceil-pass"
)

func TestKeycloakLive_Invariants_GroupsNeverProvision(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	store, worldOrg := kcLiveWorld(t, pool)
	ctx := context.Background()

	// A second org whose declared rule matches a group the user WILL hold:
	// without a membership there, its rule must stay equally inert — the
	// invariant is per-org, not an artefact of the world org.
	invOrg, err := store.CreateOrganization(ctx, "N04 Invariants Org", "n04-inv-org")
	if err != nil {
		t.Fatalf("create second org: %v", err)
	}
	if _, err := store.SetSSOGroupRoleRule(ctx, invOrg.ID, adminstore.SSOGroupRoleRule{
		Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator,
	}); err != nil {
		t.Fatalf("declare second-org rule: %v", err)
	}

	// The identity: a real realm user inside team-b (the world org's rule
	// grants org-admin for it) with a console account that belongs to NO
	// org — the shape the anti-provisioning invariant protects. (An unknown
	// email never even reaches the mapping: the fail-closed user lookup
	// refuses the login first.)
	if err := stand.EnsureRealmUser(ctx, kcInvUser, "Inv User", kcInvEmail, kcInvPass); err != nil {
		t.Fatalf("ensure %s: %v", kcInvUser, err)
	}
	if _, err := store.CreateAdminUser(ctx, kcInvEmail, "Inv User", "unused-by-sso", false); err != nil {
		t.Fatalf("create console user: %v", err)
	}
	if err := stand.AddUserToGroup(ctx, kcInvUser, "team-b"); err != nil {
		t.Fatalf("add %s to team-b: %v", kcInvUser, err)
	}

	console := kcStartConsole(t, pool, kcOIDCMounts(stand))
	callback := console.base.String() + "/auth/oidc/callback"
	browser := adminauth.NewKCBrowser()
	done := console.kcSSOLogin(t, browser, "/auth/oidc/login", kcInvUser, kcInvPass, callback)
	if done.status != http.StatusFound || console.sessionOf(t, done) == nil {
		t.Fatalf("invariant-user login: got %d, want 302 with a session (the login itself must succeed); body %s",
			done.status, kcSnippet(done.body))
	}

	invUser, err := store.GetAdminUserByEmail(ctx, kcInvEmail)
	if err != nil {
		t.Fatalf("lookup %s: %v", kcInvEmail, err)
	}
	roles, err := store.GetUserOrgRoles(ctx, invUser.ID)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("groups must never create a first membership: %s gained %v", kcInvUser, roles)
	}
	for _, org := range []string{worldOrg, invOrg.ID} {
		if _, hasPrev, err := store.GetSSOGrantedRole(ctx, org, invUser.ID); err != nil || hasPrev {
			t.Fatalf("org %s must carry no mapping provenance (hasPrev %v, err %v)", org, hasPrev, err)
		}
	}

	// The session is real and scoped to exactly the DB user: authenticated,
	// but member of nothing.
	me := console.get(t, browser, console.base.String()+"/api/me")
	if me.status != http.StatusOK || !strings.Contains(me.body, kcInvEmail) {
		t.Fatalf("/api/me: got %d; body %s", me.status, kcSnippet(me.body))
	}

	// Second login: still nothing (the sync stays a no-op, no drift).
	again := console.kcSSOLogin(t, browser, "/auth/oidc/login", kcInvUser, kcInvPass, callback)
	if again.status != http.StatusFound || console.sessionOf(t, again) == nil {
		t.Fatalf("second login: got %d, want 302 with a session; body %s", again.status, kcSnippet(again.body))
	}
	roles2, err := store.GetUserOrgRoles(ctx, invUser.ID)
	if err != nil {
		t.Fatalf("list memberships 2: %v", err)
	}
	if len(roles2) != 0 {
		t.Fatalf("repeated logins must stay a provisioning no-op: %v", roles2)
	}
}

func TestKeycloakLive_Invariants_MappedRoleCeiling(t *testing.T) {
	stand := adminauth.KeycloakLiveStand(t)
	pool := testdb.Postgres(t)
	store, worldOrg := kcLiveWorld(t, pool)
	ctx := context.Background()

	// A real realm user in team-a (world rule: operator) with an existing
	// reader membership — the shape the mapping is allowed to act on.
	if err := stand.EnsureRealmUser(ctx, kcCeilUser, "Ceil User", kcCeilEmail, kcCeilPass); err != nil {
		t.Fatalf("ensure %s: %v", kcCeilUser, err)
	}
	if err := stand.AddUserToGroup(ctx, kcCeilUser, "team-a"); err != nil {
		t.Fatalf("add %s to team-a: %v", kcCeilUser, err)
	}
	ceilUser, err := store.CreateAdminUser(ctx, kcCeilEmail, "Ceil User", "unused-by-sso", false)
	if err != nil {
		t.Fatalf("create console user: %v", err)
	}
	if _, err := store.SetOrgMembership(ctx, ceilUser.ID, worldOrg, adminstore.RoleReader); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	console := kcStartConsole(t, pool, kcOIDCMounts(stand))
	callback := console.base.String() + "/auth/oidc/callback"
	browser := adminauth.NewKCBrowser()
	done := console.kcSSOLogin(t, browser, "/auth/oidc/login", kcCeilUser, kcCeilPass, callback)
	sess := console.sessionOf(t, done)
	if done.status != http.StatusFound || sess == nil {
		t.Fatalf("ceiling-user login: got %d, want 302 with a session; body %s", done.status, kcSnippet(done.body))
	}

	// The grant applied — to EXACTLY the declared role. team-b (org-admin)
	// is declared for the same org but the user does not hold it: the
	// ceiling is the matched rule, not the strongest rule in the table.
	roles, err := store.GetUserOrgRoles(ctx, ceilUser.ID)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if roles[worldOrg] != adminstore.RoleOperator {
		t.Fatalf("mapped role must be exactly the declared rule's role, got %q", roles[worldOrg])
	}
	granted, hasPrev, err := store.GetSSOGrantedRole(ctx, worldOrg, ceilUser.ID)
	if err != nil || !hasPrev || granted != adminstore.RoleOperator {
		t.Fatalf("provenance: got (%q, %v, err %v), want operator recorded", granted, hasPrev, err)
	}

	// The session ceiling: the issued session's root flag is the DB user's
	// flag. A mapped operator is NOT root, whatever the IdP claims.
	if sess.IsRoot {
		t.Fatalf("session root flag %v must stay the DB user's flag (false)", sess.IsRoot)
	}
	denied := console.get(t, browser, console.base.String()+"/api/audit-logs")
	if denied.status != http.StatusForbidden {
		t.Fatalf("mapped operator must not read the root-only audit journal: got %d, want 403; body %s",
			denied.status, kcSnippet(denied.body))
	}

	// The control: a DB-root session reads the same route — the 403 above
	// is the root ceiling, not a broken route.
	rootBrowser := adminauth.NewKCBrowser()
	rootDone := console.kcSSOLogin(t, rootBrowser, "/auth/oidc/login",
		adminauth.KCUserRoot, adminauth.KCPassRoot, callback)
	rootSess := console.sessionOf(t, rootDone)
	if rootDone.status != http.StatusFound || rootSess == nil || !rootSess.IsRoot {
		t.Fatalf("root login: got %d, want 302 with a root session; body %s", rootDone.status, kcSnippet(rootDone.body))
	}
	allowed := console.get(t, rootBrowser, console.base.String()+"/api/audit-logs")
	if allowed.status != http.StatusOK {
		t.Fatalf("DB-root session must read the audit journal: got %d; body %s", allowed.status, kcSnippet(allowed.body))
	}

	// Re-login idempotence at the live ceiling: the mapped role is stable
	// and no drift creeps in across syncs.
	again := console.kcSSOLogin(t, browser, "/auth/oidc/login", kcCeilUser, kcCeilPass, callback)
	if again.status != http.StatusFound || console.sessionOf(t, again) == nil {
		t.Fatalf("re-login: got %d, want 302 with a session; body %s", again.status, kcSnippet(again.body))
	}
	roles2, err := store.GetUserOrgRoles(ctx, ceilUser.ID)
	if err != nil {
		t.Fatalf("list memberships 2: %v", err)
	}
	if roles2[worldOrg] != adminstore.RoleOperator {
		t.Fatalf("re-login must be a no-op at the ceiling, role now %q", roles2[worldOrg])
	}
}
