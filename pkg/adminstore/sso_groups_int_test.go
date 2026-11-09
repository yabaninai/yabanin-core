package adminstore

// DB-gated integration coverage for the SSO group→role mapping storage
// (migration 0012): rule CRUD upsert semantics, org-scoped rule visibility,
// cross-org isolation, and the provenance upsert/clear lifecycle. Requires a
// live Postgres via pkg/testdb (skipped in plain `go test ./...` runs).

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ssoGroupsFixture struct {
	store *Store
	pool  *pgxpool.Pool
	orgA  string
	orgB  string
}

func newSSOGroupsFixture(t *testing.T) *ssoGroupsFixture {
	t.Helper()
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()
	suffix := time.Now().UnixNano()
	orgA, err := store.CreateOrganization(ctx, fmt.Sprintf("sso-a-%d", suffix), fmt.Sprintf("sso-a-%d", suffix))
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx, fmt.Sprintf("sso-b-%d", suffix), fmt.Sprintf("sso-b-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		// Rules and grants cascade with the org; the provenance user is
		// deleted by email prefix (admin_users has no org FK to cascade).
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM admin_users WHERE email LIKE 'sso-prov-%'`)
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM organizations WHERE id::text = ANY($1)", []string{orgA.ID, orgB.ID})
	})
	return &ssoGroupsFixture{store: store, pool: pool, orgA: orgA.ID, orgB: orgB.ID}
}

func TestSSOGroupRuleCRUD_UpsertAndOrgIsolation_Integration(t *testing.T) {
	fx := newSSOGroupsFixture(t)
	ctx := context.Background()

	// Create: a grant rule round-trips with its role.
	rule, err := fx.store.SetSSOGroupRoleRule(ctx, fx.orgA, SSOGroupRoleRule{
		Group: "platform-team", Effect: SSOGrantRuleEffect, Role: RoleOperator,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, rule.ID)
	assert.Equal(t, fx.orgA, rule.OrgID)
	assert.Equal(t, RoleOperator, rule.Role)

	// Upsert by (org, group, effect): changing the role updates the same row.
	updated, err := fx.store.SetSSOGroupRoleRule(ctx, fx.orgA, SSOGroupRoleRule{
		Group: "platform-team", Effect: SSOGrantRuleEffect, Role: RoleReader,
	})
	require.NoError(t, err)
	assert.Equal(t, rule.ID, updated.ID, "same (org, group, effect) must upsert one row")
	assert.Equal(t, RoleReader, updated.Role)

	listA, err := fx.store.ListSSOGroupRoleRules(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, listA, 1)
	assert.Equal(t, RoleReader, listA[0].Role)

	// Deny rule: valid without a role, listed alongside the grant.
	_, err = fx.store.SetSSOGroupRoleRule(ctx, fx.orgA, SSOGroupRoleRule{Group: "contractors", Effect: SSODenyRuleEffect})
	require.NoError(t, err)

	// Validation: grant without a role, deny with a role, bad effect, bad group.
	_, err = fx.store.SetSSOGroupRoleRule(ctx, fx.orgA, SSOGroupRoleRule{Group: "g", Effect: SSOGrantRuleEffect})
	require.Error(t, err)
	_, err = fx.store.SetSSOGroupRoleRule(ctx, fx.orgA, SSOGroupRoleRule{Group: "g", Effect: SSODenyRuleEffect, Role: RoleReader})
	require.Error(t, err)
	_, err = fx.store.SetSSOGroupRoleRule(ctx, fx.orgA, SSOGroupRoleRule{Group: "g", Effect: "maybe", Role: RoleReader})
	require.Error(t, err)
	_, err = fx.store.SetSSOGroupRoleRule(ctx, fx.orgA, SSOGroupRoleRule{Group: "  ", Effect: SSODenyRuleEffect})
	require.Error(t, err)

	// Cross-org isolation: org B sees none of org A's rules; a rule declared
	// for B is invisible in A's list; A's rule id is undeletable from B.
	_, err = fx.store.SetSSOGroupRoleRule(ctx, fx.orgB, SSOGroupRoleRule{
		Group: "platform-team", Effect: SSOGrantRuleEffect, Role: RoleOrgAdmin,
	})
	require.NoError(t, err)
	listB, err := fx.store.ListSSOGroupRoleRules(ctx, fx.orgB)
	require.NoError(t, err)
	require.Len(t, listB, 1)
	assert.Equal(t, RoleOrgAdmin, listB[0].Role, "org B's rule must carry B's role, not org A's")

	listA, err = fx.store.ListSSOGroupRoleRules(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, listA, 2)
	for _, r := range listA {
		assert.NotEqual(t, RoleOrgAdmin, r.Role, "org B's rule must not leak into org A")
	}

	require.ErrorIs(t, fx.store.DeleteSSOGroupRoleRule(ctx, fx.orgB, rule.ID), ErrNotFound,
		"a foreign org's rule id must resolve as not-found")
	require.NoError(t, fx.store.DeleteSSOGroupRoleRule(ctx, fx.orgA, rule.ID))
	listA, err = fx.store.ListSSOGroupRoleRules(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, listA, 1)
}

func TestSSOGrantedRoleProvenance_Integration(t *testing.T) {
	fx := newSSOGroupsFixture(t)
	ctx := context.Background()
	var userID string
	require.NoError(t, fx.pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, display_name, active)
		 VALUES ($1, '', 'SSO Provenance User', true) RETURNING id::text`,
		fmt.Sprintf("sso-prov-%d@example.com", time.Now().UnixNano())).Scan(&userID))

	// Absent grant reads as (empty, false), not an error.
	role, ok, err := fx.store.GetSSOGrantedRole(ctx, fx.orgA, userID)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, role)

	require.NoError(t, fx.store.SetSSOGrantedRole(ctx, fx.orgA, userID, RoleReader))
	role, ok, err = fx.store.GetSSOGrantedRole(ctx, fx.orgA, userID)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, RoleReader, role)

	// Same-role re-grant is a no-op upsert (idempotent logins must not churn).
	require.NoError(t, fx.store.SetSSOGrantedRole(ctx, fx.orgA, userID, RoleReader))
	role, ok, err = fx.store.GetSSOGrantedRole(ctx, fx.orgA, userID)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, RoleReader, role)

	// Role change refreshes the provenance.
	require.NoError(t, fx.store.SetSSOGrantedRole(ctx, fx.orgA, userID, RoleOperator))
	role, ok, err = fx.store.GetSSOGrantedRole(ctx, fx.orgA, userID)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, RoleOperator, role)

	// Cross-org isolation: the provenance is per (org, user) — org B has none.
	_, ok, err = fx.store.GetSSOGrantedRole(ctx, fx.orgB, userID)
	require.NoError(t, err)
	assert.False(t, ok)

	require.NoError(t, fx.store.DeleteSSOGrantedRole(ctx, fx.orgA, userID))
	_, ok, err = fx.store.GetSSOGrantedRole(ctx, fx.orgA, userID)
	require.NoError(t, err)
	assert.False(t, ok)
	// Clearing an absent grant is an idempotent no-op.
	require.NoError(t, fx.store.DeleteSSOGrantedRole(ctx, fx.orgA, userID))

	// Invalid role values are rejected before the DB sees them.
	require.Error(t, fx.store.SetSSOGrantedRole(ctx, fx.orgA, userID, OrgRole("root-the-world")))
}
