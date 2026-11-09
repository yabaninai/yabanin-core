package adminstore

// Pure decision-table tests for ResolveSSORole (no DB): the mapping engine's
// contract is deny-wins, conflict→deny, unmapped→nothing, exact group match.
// The DB-backed rule CRUD and provenance live in sso_groups_int_test.go; the
// login-time application is covered at handler level (oidc_groups_test.go).

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func ssoGrantRule(group string, role OrgRole) SSOGroupRoleRule {
	return SSOGroupRoleRule{Group: group, Effect: SSOGrantRuleEffect, Role: role}
}

func ssoDenyRule(group string) SSOGroupRoleRule {
	return SSOGroupRoleRule{Group: group, Effect: SSODenyRuleEffect}
}

func TestResolveSSORole_DecisionTable(t *testing.T) {
	rules := []SSOGroupRoleRule{
		ssoGrantRule("platform-team", RoleOperator),
		ssoGrantRule("ops-lead", RoleOrgAdmin),
		ssoGrantRule("viewers", RoleReader),
		ssoDenyRule("contractors"),
		ssoDenyRule("suspended"),
	}

	t.Run("single matching grant grants its role", func(t *testing.T) {
		dec := ResolveSSORole(rules, []string{"platform-team"})
		assert.True(t, dec.Granted)
		assert.False(t, dec.Denied)
		assert.Equal(t, RoleOperator, dec.Role)
		assert.Equal(t, "platform-team", dec.Group)
	})

	t.Run("unmatched groups grant nothing", func(t *testing.T) {
		dec := ResolveSSORole(rules, []string{"random-group", "another-unknown"})
		assert.False(t, dec.Granted)
		assert.False(t, dec.Denied)
	})

	t.Run("no groups at all grants nothing", func(t *testing.T) {
		dec := ResolveSSORole(rules, nil)
		assert.False(t, dec.Granted)
		assert.False(t, dec.Denied)
	})

	t.Run("deny wins over grant for the same login", func(t *testing.T) {
		dec := ResolveSSORole(rules, []string{"platform-team", "contractors"})
		assert.False(t, dec.Granted)
		assert.True(t, dec.Denied)
	})

	t.Run("conflicting grants deny instead of picking a winner", func(t *testing.T) {
		dec := ResolveSSORole(rules, []string{"platform-team", "ops-lead"})
		assert.False(t, dec.Granted, "operator+org-admin conflict must not resolve to either role")
		assert.True(t, dec.Denied)
	})

	t.Run("duplicate grants of the same role stay a grant", func(t *testing.T) {
		dup := append(append([]SSOGroupRoleRule{}, ssoGrantRule("team-a", RoleReader), ssoGrantRule("team-b", RoleReader)), rules...)
		dec := ResolveSSORole(dup, []string{"team-a", "team-b"})
		assert.True(t, dec.Granted)
		assert.Equal(t, RoleReader, dec.Role)
	})

	t.Run("deny with no matching grant denies without granting", func(t *testing.T) {
		dec := ResolveSSORole(rules, []string{"suspended"})
		assert.False(t, dec.Granted)
		assert.True(t, dec.Denied)
	})

	t.Run("case differences do not match — group matching is exact", func(t *testing.T) {
		dec := ResolveSSORole(rules, []string{"Platform-Team"})
		assert.False(t, dec.Granted, "silent normalization would widen the declared rule")
		assert.False(t, dec.Denied)
	})

	t.Run("prefix overlap does not match — admin is not administrators", func(t *testing.T) {
		withAdmin := append(append([]SSOGroupRoleRule{}, rules...), ssoGrantRule("admin", RoleOrgAdmin))
		dec := ResolveSSORole(withAdmin, []string{"administrators"})
		assert.False(t, dec.Granted, "exact byte equality: a rule for 'admin' must not match the longer group 'administrators'")
		assert.False(t, dec.Denied)

		dec = ResolveSSORole(withAdmin, []string{"admin"})
		assert.True(t, dec.Granted, "the exact group still grants")
		assert.Equal(t, RoleOrgAdmin, dec.Role)
		assert.Equal(t, "admin", dec.Group)
	})

	t.Run("empty rule set grants and denies nothing", func(t *testing.T) {
		dec := ResolveSSORole(nil, []string{"platform-team", "contractors"})
		assert.False(t, dec.Granted)
		assert.False(t, dec.Denied)
	})
}

func TestResolveSSORole_IsDeterministicAcrossRuleOrder(t *testing.T) {
	for _, groups := range [][]string{
		{"platform-team"},                  // single grant
		{"platform-team", "ops-lead"},      // conflicting grants
		{"platform-team", "contractors"},   // deny + grant
		{"platform-team", "ops-lead", "x"}, // conflict + noise
	} {
		forward := ResolveSSORole(rulesForOrderTest(), groups)
		reversed := ResolveSSORole(reverseRules(rulesForOrderTest()), groups)
		assert.Equal(t, forward, reversed, "decision for %v must not depend on rule iteration order", groups)
	}
}

func rulesForOrderTest() []SSOGroupRoleRule {
	return []SSOGroupRoleRule{
		ssoGrantRule("platform-team", RoleOperator),
		ssoGrantRule("ops-lead", RoleOrgAdmin),
		ssoDenyRule("contractors"),
	}
}

func reverseRules(rules []SSOGroupRoleRule) []SSOGroupRoleRule {
	out := make([]SSOGroupRoleRule, len(rules))
	for i, r := range rules {
		out[len(rules)-1-i] = r
	}
	return out
}

func TestValidSSOGroupRuleEffect(t *testing.T) {
	assert.True(t, ValidSSOGroupRuleEffect(SSOGrantRuleEffect))
	assert.True(t, ValidSSOGroupRuleEffect(SSODenyRuleEffect))
	assert.False(t, ValidSSOGroupRuleEffect("maybe"))
	assert.False(t, ValidSSOGroupRuleEffect(""))
}
