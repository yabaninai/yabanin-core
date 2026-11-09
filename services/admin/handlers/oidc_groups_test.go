package handlers

// N04-P01: the login-time SSO group → local-role mapping, driven through the
// REAL OIDC callback (fake provider issues id_tokens with a `groups` claim)
// against the mock store's migration-0012 semantics. Covers the remainder's
// acceptance matrix: org-level declared rules applied on login, deny-wins
// conflict resolution, revocation of previously granted roles on subsequent
// syncs, unmapped-group / cross-org negative cases, idempotent repeated
// logins, and the audit trail of grants/revocations.

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mappingFixture wires the fake provider + mock store with a seeded admin
// user ("u-1", root@test.io), an optional membership seed and declared rules.
type mappingFixture struct {
	p     *fakeOIDCProvider
	h     *testAdminHandlers
	store *mockStore
}

func newMappingFixture(t *testing.T, groups []string, memberships map[string]adminstore.OrgRole, rules []adminstore.SSOGroupRoleRule) *mappingFixture {
	t.Helper()
	p := newFakeOIDCProvider(t)
	p.groups = groups
	h, store := newOIDCTestHandlers(t, p)
	for orgID, role := range memberships {
		store.orgMembers["u-1/"+orgID] = &adminstore.OrgMembership{
			ID: "mem-u-1-" + orgID, UserID: "u-1", OrgID: orgID, Role: role,
		}
	}
	for _, rule := range rules {
		_, err := store.SetSSOGroupRoleRule(context.Background(), rule.OrgID, rule)
		require.NoError(t, err)
	}
	return &mappingFixture{p: p, h: h, store: store}
}

// login drives one full OIDC round trip and asserts the callback succeeded.
func (f *mappingFixture) login(t *testing.T) {
	t.Helper()
	w := happyFlow(t, f.h, f.p)
	require.Equal(t, http.StatusFound, w.Code, "login must succeed; body %s", w.Body.String())
}

// membershipRole returns the user's current role on orgID (absent = revoked).
func (f *mappingFixture) membershipRole(t *testing.T, orgID string) (adminstore.OrgRole, bool) {
	t.Helper()
	roles, err := f.store.GetUserOrgRoles(context.Background(), "u-1")
	require.NoError(t, err)
	role, ok := roles[orgID]
	return role, ok
}

// ssoAuditEntries returns the persisted audit entries for the given action.
func (f *mappingFixture) ssoAuditEntries(t *testing.T, action string) []adminstore.AuditLogEntryRecord {
	t.Helper()
	f.store.auditMu.Lock()
	defer f.store.auditMu.Unlock()
	var out []adminstore.AuditLogEntryRecord
	for _, rec := range f.store.auditRecords {
		if rec.Action == action {
			out = append(out, rec)
		}
	}
	return out
}

var (
	orgA = "org-aaa"
	orgB = "org-bbb"
)

func TestSSOMapping_GrantAppliedOnLogin(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"platform-team", "bystanders"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}},
	)

	f.login(t)

	role, ok := f.membershipRole(t, orgA)
	require.True(t, ok, "membership must survive a grant")
	assert.Equal(t, adminstore.RoleOperator, role, "declared rule must promote the membership on login")

	// Provenance records the mapping's own grant.
	prev, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
	require.NoError(t, err)
	require.True(t, hasPrev)
	assert.Equal(t, adminstore.RoleOperator, prev)

	// Audit trail: one grant entry naming the rule's group, and no email.
	grants := f.ssoAuditEntries(t, "sso_role_grant")
	require.Len(t, grants, 1)
	assert.Contains(t, grants[0].Details, "sso=oidc")
	assert.Contains(t, grants[0].Details, "org="+orgA)
	assert.Contains(t, grants[0].Details, "user=u-1")
	assert.Contains(t, grants[0].Details, "role=operator")
	assert.Contains(t, grants[0].Details, "group=platform-team")
	assert.NotContains(t, grants[0].Details, "root@test.io")
	assert.Empty(t, f.ssoAuditEntries(t, "sso_role_revoke"))
}

func TestSSOMapping_RepeatedLoginsAreIdempotent(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"platform-team"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}},
	)

	f.login(t)
	f.login(t)
	f.login(t)

	role, ok := f.membershipRole(t, orgA)
	require.True(t, ok)
	assert.Equal(t, adminstore.RoleOperator, role)
	assert.Len(t, f.ssoAuditEntries(t, "sso_role_grant"), 1, "repeated logins must not re-audit the grant")
	assert.Empty(t, f.ssoAuditEntries(t, "sso_role_revoke"))
}

func TestSSOMapping_RoleChangeWhenRuleMoves(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"platform-team"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}},
	)
	f.login(t)
	require.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA))

	// The org re-declares the grant at a lower role; the next login syncs.
	_, err := f.store.SetSSOGroupRoleRule(context.Background(), orgA, adminstore.SSOGroupRoleRule{
		Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleReader,
	})
	require.NoError(t, err)
	f.login(t)

	assert.Equal(t, adminstore.RoleReader, mustRole(t, f, orgA))
	prev, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
	require.NoError(t, err)
	assert.True(t, hasPrev)
	assert.Equal(t, adminstore.RoleReader, prev)
}

func TestSSOMapping_DenyWinsAndStripsPreviousGrant(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"platform-team"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}},
	)
	f.login(t)
	require.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA))

	// A deny rule for a group the caller holds beats the standing grant.
	_, err := f.store.SetSSOGroupRoleRule(context.Background(), orgA, adminstore.SSOGroupRoleRule{
		Group: "platform-team", Effect: adminstore.SSODenyRuleEffect,
	})
	require.NoError(t, err)
	f.login(t)

	_, ok := f.membershipRole(t, orgA)
	assert.False(t, ok, "deny-wins must revoke the previously granted role on the next sync")
	_, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
	require.NoError(t, err)
	assert.False(t, hasPrev, "provenance must be cleared with the grant")

	revokes := f.ssoAuditEntries(t, "sso_role_revoke")
	require.Len(t, revokes, 1)
	assert.Contains(t, revokes[0].Details, "role=operator")
	assert.Contains(t, revokes[0].Details, "denied=true")
}

func TestSSOMapping_ConflictingGrantsDeny(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"team-ops", "team-lead"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{
			{OrgID: orgA, Group: "team-ops", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator},
			{OrgID: orgA, Group: "team-lead", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOrgAdmin},
		},
	)

	f.login(t)

	assert.Equal(t, adminstore.RoleReader, mustRole(t, f, orgA),
		"a conflicting declaration must not resolve to either role")
	_, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
	require.NoError(t, err)
	assert.False(t, hasPrev)
	assert.Empty(t, f.ssoAuditEntries(t, "sso_role_grant"))
}

func TestSSOMapping_UnmappedGroupGrantsNothing(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"random-people"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}},
	)

	f.login(t)

	assert.Equal(t, adminstore.RoleReader, mustRole(t, f, orgA), "an unmapped group must not change anything")
	assert.Empty(t, f.ssoAuditEntries(t, "sso_role_grant"))
	assert.Empty(t, f.ssoAuditEntries(t, "sso_role_revoke"))
}

func TestSSOMapping_RuleRemovalRevokesOnNextSync(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"platform-team"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}},
	)
	f.login(t)
	require.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA))

	// The mapping is withdrawn entirely; the next SSO login revokes the
	// granted role.
	rules, err := f.store.ListSSOGroupRoleRules(context.Background(), orgA)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.NoError(t, f.store.DeleteSSOGroupRoleRule(context.Background(), orgA, rules[0].ID))
	f.login(t)

	_, ok := f.membershipRole(t, orgA)
	assert.False(t, ok, "mapping removal must revoke the previously granted role")
	require.Len(t, f.ssoAuditEntries(t, "sso_role_revoke"), 1)
}

func TestSSOMapping_GroupDropRevokesWithoutRuleChange(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"platform-team"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}},
	)
	f.login(t)
	require.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA))

	// The IdP stops placing the caller in the group; the same rules no longer
	// justify the grant.
	f.p.groups = []string{"some-other-team"}
	f.login(t)

	_, ok := f.membershipRole(t, orgA)
	assert.False(t, ok, "dropping the mapped group must revoke the granted role on the next sync")
}

func TestSSOMapping_CrossOrgIsolation(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"platform-team"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader, orgB: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{
			{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator},
			// org B declares the same group at a DIFFERENT role — org A's
			// decision must be independent of it, and vice versa.
			{OrgID: orgB, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOrgAdmin},
		},
	)

	f.login(t)

	assert.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA), "org A's rule decides org A only")
	assert.Equal(t, adminstore.RoleOrgAdmin, mustRole(t, f, orgB), "org B's rule decides org B only")
	assert.Len(t, f.ssoAuditEntries(t, "sso_role_grant"), 2, "one audited grant per mapped org")

	// Withdrawing org B's rule revokes only org B's grant; org A keeps its role.
	rulesB, err := f.store.ListSSOGroupRoleRules(context.Background(), orgB)
	require.NoError(t, err)
	require.Len(t, rulesB, 1)
	require.NoError(t, f.store.DeleteSSOGroupRoleRule(context.Background(), orgB, rulesB[0].ID))
	f.login(t)

	_, okB := f.membershipRole(t, orgB)
	assert.False(t, okB, "org B's revoked grant must not touch org A")
	assert.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA), "org A's grant survives org B's revocation")
}

func TestSSOMapping_NoRulesOrgUntouched(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"platform-team"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		nil,
	)

	f.login(t)
	assert.Equal(t, adminstore.RoleReader, mustRole(t, f, orgA), "an org with no declared rules must be untouched")
}

func TestSSOMapping_AdminEditedRoleIsNotRevokedByRuleRemoval(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"platform-team"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleReader}},
	)
	f.login(t)
	require.Equal(t, adminstore.RoleReader, mustRole(t, f, orgA))

	// An admin promotes the user by hand after the grant.
	f.store.orgMembers["u-1/"+orgA].Role = adminstore.RoleOrgAdmin

	// The rule disappears; the admin's own role is not the mapping's to strip.
	rules, err := f.store.ListSSOGroupRoleRules(context.Background(), orgA)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.NoError(t, f.store.DeleteSSOGroupRoleRule(context.Background(), orgA, rules[0].ID))
	f.login(t)

	assert.Equal(t, adminstore.RoleOrgAdmin, mustRole(t, f, orgA), "a manually edited role must survive mapping withdrawal")
	_, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
	require.NoError(t, err)
	assert.False(t, hasPrev, "the mapping must relinquish provenance")
	assert.Empty(t, f.ssoAuditEntries(t, "sso_role_revoke"), "no revocation happened — the role was no longer mapping-held")
}

func TestSSOMapping_MappingOutageDoesNotBlockLogin(t *testing.T) {
	f := newMappingFixture(t,
		[]string{"platform-team"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}},
	)
	f.store.ssoErr = assert.AnError

	// The store fails under the sync, but the verified login must still
	// issue its session — the sync converges at a later login.
	f.login(t)
	session := issuedSessionFromLast(t, f)
	assert.NotNil(t, session, "login must succeed even when the mapping sync fails")
}

func TestSSOMapping_GrantSplitFailureLeavesNoUnprovenancedGrant(t *testing.T) {
	// Review-required split-failure regression: the decision inputs read
	// fine, but the PROVENANCE write fails. The grant must not land — a role
	// granted without provenance would never be revoked (the sync never
	// adopts unprovenanced grants). Convergence is by write order: provenance
	// goes first, so failing it leaves the membership untouched.
	f := newMappingFixture(t,
		[]string{"platform-team"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleReader},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}},
	)

	f.store.ssoSetGrantErr = assert.AnError
	f.login(t)
	session := issuedSessionFromLast(t, f)
	assert.NotNil(t, session, "login must succeed even when the provenance write fails")

	role, ok := f.membershipRole(t, orgA)
	require.True(t, ok, "the pre-existing membership must survive the failed grant")
	assert.Equal(t, adminstore.RoleReader, role, "the membership role must NOT be granted without provenance")
	_, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
	require.NoError(t, err)
	assert.False(t, hasPrev)
	assert.Empty(t, f.ssoAuditEntries(t, "sso_role_grant"), "a half-applied grant must not be audited")

	// Retry cycle: the fault clears, the next login converges to the fully
	// provenanced grant.
	f.store.ssoSetGrantErr = nil
	f.login(t)
	assert.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA), "the retried grant must apply the mapped role")
	prev, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
	require.NoError(t, err)
	require.True(t, hasPrev, "the retried grant must carry provenance")
	assert.Equal(t, adminstore.RoleOperator, prev)
	assert.Len(t, f.ssoAuditEntries(t, "sso_role_grant"), 1, "exactly the converged grant is audited")
}

func TestSSOMapping_ProvenanceOrphanConverges(t *testing.T) {
	// Split failure the other way: provenance lands, the membership write
	// fails. The orphan (provenance without the role) must be strictly
	// convergent under retry: the next grant attempt heals it, and if the
	// rules stop justifying the role in between, the revoke path
	// relinquishes it without touching the untouched membership.
	rule := adminstore.SSOGroupRoleRule{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}

	t.Run("orphan heals on the next grant attempt", func(t *testing.T) {
		f := newMappingFixture(t, []string{"platform-team"},
			map[string]adminstore.OrgRole{orgA: adminstore.RoleReader}, []adminstore.SSOGroupRoleRule{rule})

		f.store.ssoSetMemberErr = assert.AnError
		f.login(t)
		role, ok := f.membershipRole(t, orgA)
		require.True(t, ok)
		assert.Equal(t, adminstore.RoleReader, role, "the failed membership write must leave the role untouched")
		prev, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
		require.NoError(t, err)
		require.True(t, hasPrev, "provenance is written first: a split failure strands an orphan, not an unprovenanced grant")
		assert.Equal(t, adminstore.RoleOperator, prev)
		assert.Empty(t, f.ssoAuditEntries(t, "sso_role_grant"))

		f.store.ssoSetMemberErr = nil
		f.login(t)
		assert.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA), "the next login must complete the interrupted grant")
		prev, hasPrev, err = f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
		require.NoError(t, err)
		require.True(t, hasPrev)
		assert.Equal(t, adminstore.RoleOperator, prev)
	})

	t.Run("orphan is relinquished when the rules stop justifying the role", func(t *testing.T) {
		f := newMappingFixture(t, []string{"platform-team"},
			map[string]adminstore.OrgRole{orgA: adminstore.RoleReader}, []adminstore.SSOGroupRoleRule{rule})

		f.store.ssoSetMemberErr = assert.AnError
		f.login(t)
		_, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
		require.NoError(t, err)
		require.True(t, hasPrev, "precondition: orphan provenance from the split failure")

		// The rule is withdrawn before any retry. The member fault stays
		// armed: the relinquish path must converge without any membership
		// write at all.
		rules, err := f.store.ListSSOGroupRoleRules(context.Background(), orgA)
		require.NoError(t, err)
		require.Len(t, rules, 1)
		require.NoError(t, f.store.DeleteSSOGroupRoleRule(context.Background(), orgA, rules[0].ID))
		f.login(t)

		role, ok := f.membershipRole(t, orgA)
		require.True(t, ok, "the membership was never mapping-changed — nothing to revoke")
		assert.Equal(t, adminstore.RoleReader, role)
		_, hasPrev, err = f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
		require.NoError(t, err)
		assert.False(t, hasPrev, "the revoke path must relinquish the orphan provenance")
		assert.Empty(t, f.ssoAuditEntries(t, "sso_role_revoke"), "no revocation — the role was never mapping-held")
	})
}

func TestSSOMapping_MembershipCreatedWithoutMappingStaysUntouchedByUnmatchedRules(t *testing.T) {
	// A coincidence case: the membership already holds exactly the granted
	// role without provenance. The mapping must not adopt it — removing the
	// rule later must NOT delete an admin's own grant.
	f := newMappingFixture(t,
		[]string{"platform-team"},
		map[string]adminstore.OrgRole{orgA: adminstore.RoleOperator},
		[]adminstore.SSOGroupRoleRule{{OrgID: orgA, Group: "platform-team", Effect: adminstore.SSOGrantRuleEffect, Role: adminstore.RoleOperator}},
	)

	f.login(t)
	assert.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA))
	_, hasPrev, err := f.store.GetSSOGrantedRole(context.Background(), orgA, "u-1")
	require.NoError(t, err)
	assert.False(t, hasPrev, "an existing same-role membership must not be adopted as mapping-provenance")

	rules, err := f.store.ListSSOGroupRoleRules(context.Background(), orgA)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.NoError(t, f.store.DeleteSSOGroupRoleRule(context.Background(), orgA, rules[0].ID))
	f.login(t)
	assert.Equal(t, adminstore.RoleOperator, mustRole(t, f, orgA), "the admin's own grant must survive rule removal")
}

// mustRole fetches the user's org role or fails the test when absent.
func mustRole(t *testing.T, f *mappingFixture, orgID string) adminstore.OrgRole {
	t.Helper()
	role, ok := f.membershipRole(t, orgID)
	require.True(t, ok, "expected a membership in %s", orgID)
	return role
}

// issuedSessionFromLast re-runs a lightweight login and returns its session
// cookie (happyFlow drives a fresh flow each call).
func issuedSessionFromLast(t *testing.T, f *mappingFixture) *http.Cookie {
	t.Helper()
	target, flowCookie := startFlow(t, f.h)
	f.p.nonceToEmbed = target.Query().Get("nonce")
	q := url.Values{"state": {target.Query().Get("state")}, "code": {"another-code"}}
	resp := runCallback(t, f.h, q, flowCookie)
	return issuedSession(resp)
}
