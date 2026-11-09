package handlers

// N04-P01 T10 — independent invariant checks on the login-time SSO
// group→role mapping, beyond the behaviour matrix in oidc_groups_test.go:
//
//  1. SSO groups NEVER bootstrap a first membership (the anti-escalation
//     core of the model): rules can only re-shape a membership the DB
//     already holds, so knowing the group names admits an attacker to
//     nothing;
//  2. corrupted rule rows (roles the store would never declare, empty-role
//     grant rows migration-0012 permits, unknown effect values) cannot
//     widen or move a membership — the write-side ValidOrgRole gates refuse
//     them and the login still succeeds;
//  3. the IdP never mints console-root: a mapped org-admin grant yields an
//     org role, while the issued session's root flag stays exactly the DB
//     user's root flag.
//
// The mock store mirrors the real store's ValidOrgRole gates (see
// handler_test.go) so these tests exercise the production fail-closed
// order: provenance write FIRST, membership second — an invalid role aborts
// before either lands.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noWritesAnywhere asserts the strongest negative: zero memberships, zero
// mapping provenance, zero audit entries for the user.
func noWritesAnywhere(t *testing.T, store *mockStore, userID string) {
	t.Helper()
	roles, err := store.GetUserOrgRoles(context.Background(), userID)
	require.NoError(t, err)
	assert.Empty(t, roles, "no org may gain a membership for %s", userID)
	_, hasA, err := store.GetSSOGrantedRole(context.Background(), orgA, userID)
	require.NoError(t, err)
	assert.False(t, hasA, "org %s must carry no mapping provenance", orgA)
	_, hasB, err := store.GetSSOGrantedRole(context.Background(), orgB, userID)
	require.NoError(t, err)
	assert.False(t, hasB, "org %s must carry no mapping provenance", orgB)
	assert.Empty(t, store.ssoGrants, "no provenance rows anywhere")
	store.auditMu.Lock()
	defer store.auditMu.Unlock()
	assert.Empty(t, store.auditRecords, "no audit entries anywhere")
}

func TestSSOMapping_GroupsNeverBootstrapFirstMembership(t *testing.T) {
	t.Run("zero-membership user with rules matching in every org gains nothing", func(t *testing.T) {
		f := newMappingFixture(t,
			[]string{"platform-team", "team-b"},
			nil, // no memberships at all
			[]adminstore.SSOGroupRoleRule{
				{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator},
				{OrgID: orgB, Group: "team-b", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOrgAdmin},
				{OrgID: orgB, Group: "contractors", Effect: adminstore.SSODenyRuleEffect},
			},
		)

		f.login(t) // the login itself must succeed

		noWritesAnywhere(t, f.store, "u-1")
	})

	t.Run("matching rule in a non-member org never reaches that org", func(t *testing.T) {
		f := newMappingFixture(t,
			[]string{"platform-team"},
			map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
			[]adminstore.SSOGroupRoleRule{
				// orgB declares exactly what the user's group would satisfy.
				{OrgID: orgB, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOrgAdmin},
			},
		)

		f.login(t)

		role, ok := f.membershipRole(t, orgB)
		assert.False(t, ok, "orgB must not gain a membership (got role %q)", role)
		roleA, okA := f.membershipRole(t, orgA)
		require.True(t, okA, "orgA membership must survive")
		assert.Equal(t, adminstore.RoleReader, roleA, "orgA declares no rules: membership untouched")
		assert.Empty(t, f.store.ssoGrants, "no provenance anywhere")
		assert.Empty(t, f.ssoAuditEntries(t, "sso_role_grant"))
		assert.Empty(t, f.ssoAuditEntries(t, "sso_role_revoke"))
	})
}

func TestSSOMapping_CorruptedRuleRowsCannotEscalate(t *testing.T) {
	// Corrupted rows are written straight into the rule table the way an
	// out-of-band tool or a buggy migration would leave them (the store API
	// refuses such values; only the raw table accepts them).
	corruptRoot := adminstore.SSOGroupRoleRule{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: "root"}
	corruptCase := adminstore.SSOGroupRoleRule{OrgID: orgA, Group: "escalators", Effect: adminstore.SSOGrantRuleEffect, Role: "ORG-ADMIN"}
	corruptSnake := adminstore.SSOGroupRoleRule{OrgID: orgA, Group: "legacys", Effect: adminstore.SSOGrantRuleEffect, Role: "org_admin"}
	corruptEmpty := adminstore.SSOGroupRoleRule{OrgID: orgA, Group: "ghosts", Effect: adminstore.SSOGrantRuleEffect, Role: ""}

	t.Run("grant rule naming a non-local role is refused before any write", func(t *testing.T) {
		f := newMappingFixture(t,
			[]string{"platform-team"},
			map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
			[]adminstore.SSOGroupRoleRule{corruptRoot},
		)

		f.login(t) // sync failure never blocks the login

		role, ok := f.membershipRole(t, orgA)
		require.True(t, ok)
		assert.Equal(t, adminstore.RoleReader, role, "corrupted rule must leave the membership alone")
		assert.Empty(t, f.store.ssoGrants, "provenance-first write order: invalid role aborts at the gate")
		assert.Empty(t, f.ssoAuditEntries(t, "sso_role_grant"))
		assert.Empty(t, f.ssoAuditEntries(t, "sso_role_revoke"))
	})

	t.Run("empty-role grant row is refused", func(t *testing.T) {
		f := newMappingFixture(t,
			[]string{"ghosts"},
			map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
			[]adminstore.SSOGroupRoleRule{corruptEmpty},
		)

		f.login(t)

		role, ok := f.membershipRole(t, orgA)
		require.True(t, ok)
		assert.Equal(t, adminstore.RoleReader, role)
		assert.Empty(t, f.store.ssoGrants)
		assert.Empty(t, f.ssoAuditEntries(t, "sso_role_grant"))
	})

	t.Run("conflicting corrupted grants deny without touching the membership", func(t *testing.T) {
		f := newMappingFixture(t,
			[]string{"platform-team", "escalators", "legacys"},
			map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
			[]adminstore.SSOGroupRoleRule{corruptRoot, corruptCase, corruptSnake},
		)

		f.login(t)

		role, ok := f.membershipRole(t, orgA)
		require.True(t, ok)
		assert.Equal(t, adminstore.RoleReader, role, "deny-wins holds for corrupted role values too")
		assert.Empty(t, f.store.ssoGrants)
	})

	t.Run("held empty-role grant poisons a valid grant into a deny — never a partial grant", func(t *testing.T) {
		f := newMappingFixture(t,
			[]string{"platform-team", "ghosts"},
			map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
			[]adminstore.SSOGroupRoleRule{
				{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator},
				corruptEmpty, // "ghosts" IS held: Role "" is a different granted role…
			},
		)

		// …so the resolver sees two conflicting grants (operator vs empty)
		// and deny-wins BEFORE any store write: the reader membership
		// survives and no provenance appears. An ambiguous table must never
		// resolve to "whichever role came first".
		f.login(t)

		role, ok := f.membershipRole(t, orgA)
		require.True(t, ok)
		assert.Equal(t, adminstore.RoleReader, role, "a corrupted grant must poison the decision into a deny, not a partial grant")
		assert.Empty(t, f.store.ssoGrants)
		assert.Empty(t, f.ssoAuditEntries(t, "sso_role_grant"))
	})

	t.Run("healthy grant unaffected by corrupted rows for other groups", func(t *testing.T) {
		f := newMappingFixture(t,
			[]string{"platform-team"},
			map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
			[]adminstore.SSOGroupRoleRule{
				{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator},
				corruptCase, corruptSnake, // not held — inert
			},
		)

		f.login(t)

		role, ok := f.membershipRole(t, orgA)
		require.True(t, ok)
		assert.Equal(t, adminstore.RoleOperator, role, "the healthy rule must still apply")
		prev, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
		require.NoError(t, err)
		require.True(t, hasPrev)
		assert.Equal(t, adminstore.RoleOperator, prev)
	})
}

func TestSSOMapping_GroupClaimNeverMintsConsoleRoot(t *testing.T) {
	// A dedicated NON-root user: the fake IdP presents a group whose rule
	// grants org-admin — the strongest role the mapping can reach. The
	// issued session's root flag must stay the DB user's flag (false), i.e.
	// the identity provider cannot promote anyone to console-root through
	// group claims.
	p := newFakeOIDCProvider(t)
	p.groups = []string{"team-b"}
	p.email = "dev@test.io"
	h, store := newOIDCTestHandlers(t, p)
	store.adminUsers["u-2"] = &adminstore.AdminUser{
		ID: "u-2", Email: "dev@test.io", DisplayName: "Dev", IsRoot: false, Active: true,
	}
	store.orgMembers["u-2/"+orgA] = &adminstore.OrgMembership{ID: "mem-u-2", UserID: "u-2", OrgID: orgA, Role: adminstore.RoleReader}
	_, err := store.SetSSOGroupRoleRule(context.Background(), orgA, adminstore.SSOGroupRoleRule{
		OrgID: orgA, Group: "team-b", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOrgAdmin,
	})
	require.NoError(t, err)

	w := happyFlow(t, h, p)
	require.Equal(t, http.StatusFound, w.Code, "login must succeed; body %s", w.Body.String())

	cookie := issuedSession(w)
	require.NotNil(t, cookie, "login issued no session")
	sess, err := adminauth.ParseAdminSessionCookie(cookie.Value, "test-secret")
	require.NoError(t, err)
	assert.Equal(t, "u-2", sess.UserID)
	assert.False(t, sess.IsRoot, "session root flag must stay the DB user's flag, not the mapped org role")
	assert.False(t, store.adminUsers["u-2"].IsRoot, "the DB root flag is untouchable by group claims")

	// The mapping DID apply — at the org layer, which is its ceiling.
	roles, err := store.GetUserOrgRoles(context.Background(), "u-2")
	require.NoError(t, err)
	assert.Equal(t, adminstore.RoleOrgAdmin, roles[orgA], "org-admin is the ceiling a group grant reaches")
}

// TestSSORouting_FlowStartsShareLoginRateBudget pins the T10 resource-limit
// fix: the SSO flow-START endpoints mint state and redirect to the IdP, so
// each carries its own per-IP budget (ssoStartLimit, 30 per 15 min — looser
// than the password login's 5 because no credential guessing happens here,
// far under the global limiter's 1000/min). The routes golden deliberately
// ignores rate middleware — this test is its complement. The callbacks stay
// outside the budget: they are gated by the state-bound one-time flow cookie
// before any expensive work.
func TestSSORouting_FlowStartsShareLoginRateBudget(t *testing.T) {
	p := newFakeOIDCProvider(t)
	h, _ := newOIDCTestHandlers(t, p)
	router := h.SetupRouter()

	exhaust := func(path, ip string) int {
		t.Helper()
		last := 0
		for i := 0; i < ssoStartLimit+1; i++ {
			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			req.RemoteAddr = ip + ":1234"
			router.ServeHTTP(w, req)
			last = w.Code
		}
		return last
	}

	// Flow start ssoStartLimit+1 from one address is refused with a 429…
	assert.Equal(t, http.StatusTooManyRequests, exhaust("/auth/oidc/login", "9.9.9.9"),
		"OIDC flow start must have its own per-IP budget")
	// …while another address starts flows unaffected.
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/oidc/login", nil)
	req.RemoteAddr = "9.9.9.10:1234"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusFound, w.Code, "a different IP must still start an OIDC flow")

	// The callback is NOT behind the start budget: the same exhausted IP can
	// still reach it (it fails cheap and closed on the missing flow cookie).
	w = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/oidc/callback?state=x&code=y", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	router.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusTooManyRequests, w.Code,
		"the callback must not consume the start budget (state gate protects it)")
}

func TestSAMLRouting_FlowStartSharesLoginRateBudget(t *testing.T) {
	p := newFakeSAMLIdP(t)
	sh, _ := newSAMLTestHandlers(t, p)
	router := sh.SetupRouter()

	last := 0
	for i := 0; i < ssoStartLimit+1; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/saml/login", nil)
		req.RemoteAddr = "8.8.8.8:1234"
		router.ServeHTTP(w, req)
		last = w.Code
	}
	assert.Equal(t, http.StatusTooManyRequests, last,
		"SAML flow start must have its own per-IP budget")
}
