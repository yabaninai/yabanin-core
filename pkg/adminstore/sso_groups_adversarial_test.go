package adminstore

// N04-P01 T10 — adversarial edges of ResolveSSORole beyond the happy decision
// table (sso_groups_test.go): corrupted rule rows (unknown effect values,
// grant rows whose role column is empty or malformed) and hostile group-name
// lookalikes in the token's `groups` claim. The contract under verification:
// nothing a rule row can say and nothing a token can carry may widen a
// membership beyond a VALID declared role, and anything ambiguous fails
// closed (no grant, or an explicit deny). The write-side gates that back
// this (ValidOrgRole in SetSSOGrantedRole/SetOrgMembership) are pinned at
// handler level (services/admin/handlers/oidc_groups_adversarial_test.go)
// and against the real store in sso_groups_int_test.go.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveSSORole_AdversarialEdges(t *testing.T) {
	t.Run("unknown effect values are inert — no grant, no deny", func(t *testing.T) {
		// A corrupted row (effect written out-of-band as "Grant", "allow" or
		// the empty string) matches neither switch arm: it must never grant
		// and never deny — it must be as if the row did not exist.
		for _, effect := range []SSOGroupRuleEffect{"Grant", "allow", "GRANT", "deny ", ""} {
			dec := ResolveSSORole(
				[]SSOGroupRoleRule{{Group: "platform-team", Effect: effect, Role: RoleOrgAdmin}},
				[]string{"platform-team"},
			)
			assert.False(t, dec.Granted, "effect %q must not grant", effect)
			assert.False(t, dec.Denied, "effect %q must not deny", effect)
			assert.Equal(t, OrgRole(""), dec.Role, "effect %q must name no role", effect)
		}
	})

	t.Run("deny row carrying a role payload still denies", func(t *testing.T) {
		// The deny effect ignores whatever the role column holds (NULL in a
		// healthy table; anything at all in a corrupted one).
		dec := ResolveSSORole(
			[]SSOGroupRoleRule{{Group: "locked", Effect: SSODenyRuleEffect, Role: RoleOrgAdmin}},
			[]string{"locked"},
		)
		assert.True(t, dec.Denied)
		assert.False(t, dec.Granted)
		assert.Equal(t, SSORoleDecision{Denied: true}, dec, "a deny must carry no grant payload")
	})

	t.Run("corrupted empty-role grant alone stays a no-op grant decision", func(t *testing.T) {
		// migration-0012 permits a grant row with a NULL role (only
		// non-NULL is CHECKed); ListSSOGroupRoleRules surfaces it as Role "".
		// The resolver reports the match with the empty role — the ROLE
		// VALIDITY gate is the store's write path (SetSSOGrantedRole), which
		// refuses "". Pin the resolver contract exactly so the handler-level
		// end-to-end fail-closed test exercises the real gate, not a masked
		// decision.
		dec := ResolveSSORole([]SSOGroupRoleRule{ssoGrantRule("platform-team", "")}, []string{"platform-team"})
		assert.True(t, dec.Granted)
		assert.Equal(t, OrgRole(""), dec.Role)
		assert.False(t, dec.Denied)
	})

	t.Run("empty-role grant next to a valid grant conflicts into a deny", func(t *testing.T) {
		// Two matching grant rows with different roles (one corrupted to "")
		// deny-wins: the ambiguity must never resolve to the valid role.
		dec := ResolveSSORole(
			[]SSOGroupRoleRule{ssoGrantRule("platform-team", ""), ssoGrantRule("ops-lead", RoleOperator)},
			[]string{"platform-team", "ops-lead"},
		)
		assert.True(t, dec.Denied)
		assert.False(t, dec.Granted)
	})

	t.Run("invalid role values in grant rows are matched verbatim and never normalized", func(t *testing.T) {
		// "root", "ORG-ADMIN", "org_admin" are not local roles. The resolver
		// treats them as opaque role strings (the store's ValidOrgRole gate
		// refuses them at write time); it must not map any of them onto a
		// known role and must not treat case variants as equal.
		for _, role := range []OrgRole{"root", "ORG-ADMIN", "org_admin", "operator "} {
			dec := ResolveSSORole([]SSOGroupRoleRule{ssoGrantRule("g", role)}, []string{"g"})
			assert.True(t, dec.Granted)
			assert.Equal(t, role, dec.Role, "the resolver must pass the corrupted value through unchanged")
		}
		// …and a valid rule never collides with its corrupted lookalike into
		// an accidental conflict: the corrupted row must not even match the
		// same held group under a different name spelling.
		valid := ResolveSSORole(
			[]SSOGroupRoleRule{ssoGrantRule("g", RoleOperator), ssoGrantRule("G", "ORG-ADMIN")},
			[]string{"g"},
		)
		assert.Equal(t, SSORoleDecision{Granted: true, Role: RoleOperator, Group: "g"}, valid,
			"a corrupted rule for a DIFFERENT group name must stay out of the decision")
	})

	t.Run("byte-exact matching defeats hostile group lookalikes", func(t *testing.T) {
		rules := []SSOGroupRoleRule{ssoGrantRule("platform-team", RoleOperator), ssoDenyRule("contractors")}
		// Trailing/leading whitespace, case variants and unicode homoglyphs
		// in the token's groups claim must never match a declared rule.
		for _, hostile := range []string{
			"platform-team ", " platform-team", "Platform-Team", "PLATFORM-TEAM",
			"рlatform-team",       // leading Cyrillic 'р' (U+0440), not Latin 'p'
			"platform-teаm",       // trailing Cyrillic 'а' (U+0430), not Latin 'a'
			"platform\u00ad-team", // soft hyphen (U+00AD) inserted before the dash
		} {
			dec := ResolveSSORole(rules, []string{hostile})
			assert.False(t, dec.Granted, "group %q must not match the declared grant", hostile)
			assert.False(t, dec.Denied, "group %q must not match the declared deny", hostile)
		}
		// The mirror image: a token group that byte-equals a DENIED rule must
		// deny even when decorated lookalikes of the granted group are also
		// held (deny cannot be diluted by near-misses).
		dec := ResolveSSORole(rules, []string{"рlatform-team", "contractors"})
		assert.True(t, dec.Denied)
		assert.False(t, dec.Granted)
	})

	t.Run("duplicate group names in the token change nothing", func(t *testing.T) {
		rules := []SSOGroupRoleRule{ssoGrantRule("g", RoleOperator)}
		once := ResolveSSORole(rules, []string{"g"})
		many := ResolveSSORole(rules, []string{"g", "g", "g"})
		assert.Equal(t, once, many, "set semantics: repeating a group must not alter the decision")
	})

	t.Run("empty rules and empty groups are a clean no-op", func(t *testing.T) {
		assert.Equal(t, SSORoleDecision{}, ResolveSSORole(nil, nil))
		assert.Equal(t, SSORoleDecision{}, ResolveSSORole([]SSOGroupRoleRule{ssoGrantRule("g", RoleOperator)}, nil))
		assert.Equal(t, SSORoleDecision{}, ResolveSSORole(nil, []string{"g"}))
	})
}

func TestValidOrgRole_AdversarialValues(t *testing.T) {
	// The write-side gate: exactly the five declared roles are valid;
	// everything a corrupted row, a typo or an attacker might supply is not.
	for _, valid := range AllOrgRoles() {
		assert.True(t, ValidOrgRole(valid), "declared role %q must be valid", valid)
	}
	for _, invalid := range []OrgRole{
		"", "root", "superadmin", "ORG-ADMIN", "org_admin", "OrgAdmin", "admin",
		"operator ", " reader", "Owner", "owner", "member", "partner admin",
	} {
		assert.False(t, ValidOrgRole(invalid), "role %q must be rejected", invalid)
	}
}
