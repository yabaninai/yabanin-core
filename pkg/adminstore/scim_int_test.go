package adminstore

// -short): SCIM token lifecycle, provisioning idempotency, the no-RLS org
// isolation posture (explicit org predicates), group→membership semantics,
// the synced-fields/deactivation sync, and the migration 0012 up/down pair.
// Secrets posture: only the sha256 of a token may exist at rest.

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scimFixture struct {
	store     *Store
	pool      *pgxpool.Pool
	orgA      string
	orgB      string
	creatorID string // a real admin_users row (scim_tokens.created_by FK)
}

func newScimFixture(t *testing.T) scimFixture {
	t.Helper()
	pool := openAdminTestPool(t)
	store := New(pool, slog.New(slog.DiscardHandler), nil)
	ctx := context.Background()
	suffix := time.Now().UnixNano()
	var creatorID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO admin_users (email, password_hash, display_name, active)
		 VALUES ($1, '', 'SCIM IT Creator', true) RETURNING id::text`,
		fmt.Sprintf("scim-it-creator-%d@example.com", suffix)).Scan(&creatorID))
	orgA, err := store.CreateOrganization(ctx, fmt.Sprintf("scim-a-%d", suffix), fmt.Sprintf("scim-a-%d", suffix))
	require.NoError(t, err)
	orgB, err := store.CreateOrganization(ctx, fmt.Sprintf("scim-b-%d", suffix), fmt.Sprintf("scim-b-%d", suffix))
	require.NoError(t, err)
	t.Cleanup(func() {
		// Memberships + identities + tokens cascade with the org; the
		// SCIM-provisioned admin users are deleted by their test email
		// prefix (admin_users has no org FK to cascade).
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM admin_users WHERE email LIKE 'scim-it-%'`)
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM organizations WHERE id::text = ANY($1)", []string{orgA.ID, orgB.ID})
	})
	// NOTE: openAdminTestPool takes the package mutex and its unlock is
	// registered as a t.Cleanup — a test body must NOT call it a second
	// time (the pool comes from the fixture).
	return scimFixture{store: store, pool: pool, orgA: orgA.ID, orgB: orgB.ID, creatorID: creatorID}
}

// TestScimTokenLifecycle_Integration: mint → resolve (constant-time confirm)
// → touch → revoke; revocation is org-scoped and a revoked token stays
// findable but flagged (the auth middleware refuses it).
func TestScimTokenLifecycle_Integration(t *testing.T) {
	fx := newScimFixture(t)
	ctx := context.Background()

	token, raw, err := fx.store.CreateScimToken(ctx, fx.orgA, "okta-prod", fx.creatorID)
	require.NoError(t, err)
	assert.NotEmpty(t, token.ID)
	assert.Equal(t, fx.orgA, token.OrgID)
	assert.Equal(t, "okta-prod", token.Label)
	assert.Nil(t, token.RevokedAt)
	require.NotEmpty(t, raw)
	assert.Regexp(t, `^scim_[0-9a-f]{64}$`, raw, "raw token shape: scim_ + 64 hex")

	// Resolve by hash + constant-time confirmation.
	found, err := fx.store.FindScimTokenByHash(ctx, ScimTokenHash(raw))
	require.NoError(t, err)
	assert.Equal(t, token.ID, found.ID)
	assert.True(t, ScimTokenMatches(raw, found.TokenHash))
	assert.False(t, ScimTokenMatches(raw+"x", found.TokenHash))

	// Listings never carry the hash.
	list, err := fx.store.ListScimTokens(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, token.ID, list[0].ID)
	assert.Empty(t, list[0].TokenHash)
	assert.False(t, list[0].HasHash)

	// Touch (throttled upstream — here just the write).
	require.NoError(t, fx.store.TouchScimToken(ctx, fx.orgA, token.ID))
	touched, err := fx.store.ListScimTokens(ctx, fx.orgA)
	require.NoError(t, err)
	require.Len(t, touched, 1)
	require.NotNil(t, touched[0].LastUsedAt)

	// Revocation is org-scoped: org B cannot revoke org A's token.
	require.ErrorIs(t, fx.store.RevokeScimToken(ctx, fx.orgB, token.ID), ErrNotFound)
	require.NoError(t, fx.store.RevokeScimToken(ctx, fx.orgA, token.ID))

	found, err = fx.store.FindScimTokenByHash(ctx, ScimTokenHash(raw))
	require.NoError(t, err, "a revoked token stays resolvable (the middleware refuses it)")
	assert.NotNil(t, found.RevokedAt)
	assert.True(t, found.Revoked())

	// Unknown hash → ErrNotFound.
	_, err = fx.store.FindScimTokenByHash(ctx, ScimTokenHash(raw+"tampered"))
	require.ErrorIs(t, err, ErrNotFound)
}

// TestScimTokenNoPlaintextAtRest_Integration: the dump-grep criterion — no
// scim_tokens column ever contains the raw token material; only 64-hex
// sha256 digests are stored.
func TestScimTokenNoPlaintextAtRest_Integration(t *testing.T) {
	fx := newScimFixture(t)
	pool := fx.pool
	ctx := context.Background()

	_, raw, err := fx.store.CreateScimToken(ctx, fx.orgA, "dump-grep", fx.creatorID)
	require.NoError(t, err)

	rows, err := pool.Query(ctx, `SELECT token_hash FROM scim_tokens`)
	require.NoError(t, err)
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var h string
		require.NoError(t, rows.Scan(&h))
		hashes = append(hashes, h)
	}
	require.NoError(t, rows.Err())
	require.NotEmpty(t, hashes)
	hexRe := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, h := range hashes {
		assert.Regexp(t, hexRe, h, "at rest only sha256 hex may exist")
		assert.NotContains(t, h, raw, "raw token material must never reach the table")
	}
}

// TestScimProvisionIdempotent_Integration: the same userName or externalId
// resolves to the EXISTING identity (no duplicate admin users), and the
// created user holds the provisioning role membership in the token org.
func TestScimProvisionIdempotent_Integration(t *testing.T) {
	fx := newScimFixture(t)
	ctx := context.Background()
	suffix := time.Now().UnixNano()

	created, wasCreated, err := fx.store.ProvisionScimUser(ctx, fx.orgA, ScimUserParams{
		UserName:   fmt.Sprintf("scim-it-%d@example.com", suffix),
		ExternalID: "00u-okta-1",
		GivenName:  "Ada", FamilyName: "Lovelace",
		Active: true, Role: RoleReader,
	})
	require.NoError(t, err)
	require.True(t, wasCreated)
	assert.Equal(t, fx.orgA, created.OrgID)
	assert.Equal(t, "Ada Lovelace", created.DisplayName)

	// Same userName → existing.
	again, wasCreated, err := fx.store.ProvisionScimUser(ctx, fx.orgA, ScimUserParams{
		UserName: created.UserName, ExternalID: "00u-okta-1", Active: true, Role: RoleReader,
	})
	require.NoError(t, err)
	assert.False(t, wasCreated)
	assert.Equal(t, created.ID, again.ID)

	// Same externalId, different userName → still the existing identity.
	resync, wasCreated, err := fx.store.ProvisionScimUser(ctx, fx.orgA, ScimUserParams{
		UserName:   fmt.Sprintf("scim-it-%d-renamed@example.com", suffix),
		ExternalID: "00u-okta-1", Active: true, Role: RoleReader,
	})
	require.NoError(t, err)
	assert.False(t, wasCreated)
	assert.Equal(t, created.ID, resync.ID)

	// Membership in the token org with the provisioning role.
	var role string
	pool := fx.pool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT role FROM admin_org_memberships WHERE user_id::text = $1 AND org_id::text = $2`,
		created.AdminUserID, fx.orgA).Scan(&role))
	assert.Equal(t, string(RoleReader), role)

	// A SCIM-created user has an EMPTY password hash (password login is
	// impossible; SSO is the path).
	var passwordHash string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT password_hash FROM admin_users WHERE id::text = $1`, created.AdminUserID).Scan(&passwordHash))
	assert.Empty(t, passwordHash)

	// Exactly one identity + one admin user exist for the stream (the
	// fixture's creator account is excluded from the count).
	var identities, users int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM scim_identities WHERE org_id::text = $1`, fx.orgA).Scan(&identities))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_users WHERE email LIKE 'scim-it-%' AND email NOT LIKE 'scim-it-creator-%'`).Scan(&users))
	assert.Equal(t, 1, identities)
	assert.Equal(t, 1, users)
}

// TestScimOrgIsolation_Integration: the no-RLS posture — every read/write
// carries the org predicate, so a cross-org scim_user_id is invisible (404
// semantics: ErrNotFound) and never gains a membership.
func TestScimOrgIsolation_Integration(t *testing.T) {
	fx := newScimFixture(t)
	ctx := context.Background()
	pool := fx.pool
	suffix := time.Now().UnixNano()

	userA, _, err := fx.store.ProvisionScimUser(ctx, fx.orgA, ScimUserParams{
		UserName: fmt.Sprintf("scim-it-a-%d@example.com", suffix), ExternalID: "ext-a",
		Active: true, Role: RoleReader,
	})
	require.NoError(t, err)
	userB, _, err := fx.store.ProvisionScimUser(ctx, fx.orgB, ScimUserParams{
		UserName: fmt.Sprintf("scim-it-b-%d@example.com", suffix), ExternalID: "ext-b",
		Active: true, Role: RoleReader,
	})
	require.NoError(t, err)

	// Lists are org-scoped.
	listA, err := fx.store.ListScimUsers(ctx, fx.orgA)
	require.NoError(t, err)
	for _, u := range listA {
		assert.Equal(t, fx.orgA, u.OrgID)
		assert.NotEqual(t, userB.ID, u.ID)
	}

	// Cross-org reads → ErrNotFound.
	_, err = fx.store.GetScimUser(ctx, fx.orgA, userB.ID)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = fx.store.GetScimUser(ctx, fx.orgB, userA.ID)
	require.ErrorIs(t, err, ErrNotFound)

	// Cross-org sync/deactivate → ErrNotFound (no leak, no mutation).
	_, err = fx.store.SyncScimUser(ctx, fx.orgA, userB.ID, ScimUserParams{Active: false})
	require.ErrorIs(t, err, ErrNotFound)
	require.ErrorIs(t, fx.store.DeactivateScimUser(ctx, fx.orgA, userB.ID), ErrNotFound)

	// Cross-org group membership → ErrNotFound; org B's user gains nothing.
	require.ErrorIs(t, fx.store.SetScimMemberRole(ctx, fx.orgA, userB.ID, RoleOrgAdmin), ErrNotFound)
	var memberships int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_org_memberships WHERE user_id::text = $1`, userB.AdminUserID).Scan(&memberships))
	assert.Equal(t, 1, memberships, "org B's user keeps only its original org membership")

	// Cross-org token scoping is covered by TestScimTokenLifecycle.
}

// TestScimGroups_Integration: group→membership semantics — role upsert,
// role-scoped member listing, role-wide removal (DELETE /Groups).
func TestScimGroups_Integration(t *testing.T) {
	fx := newScimFixture(t)
	ctx := context.Background()
	pool := fx.pool
	suffix := time.Now().UnixNano()

	u1, _, err := fx.store.ProvisionScimUser(ctx, fx.orgA, ScimUserParams{
		UserName: fmt.Sprintf("scim-it-g1-%d@example.com", suffix), Active: true, Role: RoleReader,
	})
	require.NoError(t, err)
	u2, _, err := fx.store.ProvisionScimUser(ctx, fx.orgA, ScimUserParams{
		UserName: fmt.Sprintf("scim-it-g2-%d@example.com", suffix), Active: true, Role: RoleReader,
	})
	require.NoError(t, err)
	// One user in the FOREIGN org (its membership must survive org A's
	// group removal untouched).
	uB, _, err := fx.store.ProvisionScimUser(ctx, fx.orgB, ScimUserParams{
		UserName: fmt.Sprintf("scim-it-gb-%d@example.com", suffix), Active: true, Role: RoleReader,
	})
	require.NoError(t, err)

	// Add both to the operator group.
	require.NoError(t, fx.store.SetScimMemberRole(ctx, fx.orgA, u1.ID, RoleOperator))
	require.NoError(t, fx.store.SetScimMemberRole(ctx, fx.orgA, u2.ID, RoleOperator))

	members, err := fx.store.ListScimRoleMembers(ctx, fx.orgA, RoleOperator)
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, m := range members {
		ids[m.Value] = true
	}
	assert.True(t, ids[u1.ID] && ids[u2.ID], "both members visible in the role group")

	// Foreign org sees no members of "its" operator group from A's users.
	membersB, err := fx.store.ListScimRoleMembers(ctx, fx.orgB, RoleOperator)
	require.NoError(t, err)
	assert.Empty(t, membersB)

	// DELETE /Groups/operator: strips the role from ALL members (2). A
	// membership is ONE row per (user, org) whose role the group join
	// replaced, so after the removal these users hold NO membership in the
	// org (the same semantic the admin UI has when changing a role).
	removed, err := fx.store.RemoveScimRoleMembers(ctx, fx.orgA, RoleOperator)
	require.NoError(t, err)
	assert.Equal(t, int64(2), removed)

	var leftInOrg int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_org_memberships WHERE org_id::text = $1`,
		fx.orgA).Scan(&leftInOrg))
	assert.Equal(t, 0, leftInOrg, "removed members hold no membership afterwards")

	// Org B's memberships are untouched by org A's group removal.
	var leftInB int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_org_memberships WHERE org_id::text = $1 AND user_id::text = $2`,
		fx.orgB, uB.AdminUserID).Scan(&leftInB))
	assert.Equal(t, 1, leftInB, "a foreign org's memberships are untouched")
}

// deactivated member (SCIM DELETE /Users semantic) leaves the role group's
// member list while the membership row itself survives — reactivation
// restores the listing, so an IdP never sees stale members.
func TestScimRoleMembers_ExcludeDeactivated_Integration(t *testing.T) {
	fx := newScimFixture(t)
	ctx := context.Background()
	suffix := time.Now().UnixNano()

	gone, _, err := fx.store.ProvisionScimUser(ctx, fx.orgA, ScimUserParams{
		UserName: fmt.Sprintf("scim-it-dg1-%d@example.com", suffix), Active: true, Role: RoleReader,
	})
	require.NoError(t, err)
	stays, _, err := fx.store.ProvisionScimUser(ctx, fx.orgA, ScimUserParams{
		UserName: fmt.Sprintf("scim-it-dg2-%d@example.com", suffix), Active: true, Role: RoleReader,
	})
	require.NoError(t, err)

	memberIDs := func() map[string]bool {
		members, err := fx.store.ListScimRoleMembers(ctx, fx.orgA, RoleReader)
		require.NoError(t, err)
		ids := map[string]bool{}
		for _, m := range members {
			ids[m.Value] = true
		}
		return ids
	}
	require.True(t, memberIDs()[gone.ID] && memberIDs()[stays.ID], "both members visible before deactivation")

	// SCIM DELETE semantic: deactivate. The member list must drop the user
	// even though the membership row is untouched.
	require.NoError(t, fx.store.DeactivateScimUser(ctx, fx.orgA, gone.ID))
	ids := memberIDs()
	assert.False(t, ids[gone.ID], "deactivated member must leave the group list")
	assert.True(t, ids[stays.ID], "active member stays listed")

	// The membership row survived (reactivation restores the listing).
	var membershipAlive int
	require.NoError(t, fx.pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_org_memberships WHERE org_id::text = $1 AND user_id::text = $2`,
		fx.orgA, gone.AdminUserID).Scan(&membershipAlive))
	assert.Equal(t, 1, membershipAlive, "deactivation must not strip the membership row")

	_, err = fx.store.SyncScimUser(ctx, fx.orgA, gone.ID, ScimUserParams{
		UserName: gone.UserName, Active: true,
	})
	require.NoError(t, err)
	assert.True(t, memberIDs()[gone.ID], "reactivated member reappears in the group list")
}

// TestScimRemoveMemberRole_Integration: PATCH /Groups/{id} remove semantics
// mistyped orgID/scimUserID as OrgRole, which compiled but left the store
// unable to satisfy handlers.ScimStore): one membership removed, unknown
// identity → ErrNotFound, invalid role → validation error.
func TestScimRemoveMemberRole_Integration(t *testing.T) {
	fx := newScimFixture(t)
	ctx := context.Background()
	suffix := time.Now().UnixNano()

	u, _, err := fx.store.ProvisionScimUser(ctx, fx.orgA, ScimUserParams{
		UserName: fmt.Sprintf("scim-it-rm-%d@example.com", suffix), Active: true, Role: RoleReader,
	})
	require.NoError(t, err)
	require.NoError(t, fx.store.SetScimMemberRole(ctx, fx.orgA, u.ID, RoleOperator))

	// Remove the membership added above.
	require.NoError(t, fx.store.RemoveScimMemberRole(ctx, fx.orgA, u.ID, RoleOperator))
	members, err := fx.store.ListScimRoleMembers(ctx, fx.orgA, RoleOperator)
	require.NoError(t, err)
	assert.Empty(t, members, "the removed member must leave the role group")

	// Idempotent: removing again is fine (no membership left to delete).
	require.NoError(t, fx.store.RemoveScimMemberRole(ctx, fx.orgA, u.ID, RoleOperator))

	// Unknown identity (foreign-org user) → ErrNotFound.
	require.ErrorIs(t, fx.store.RemoveScimMemberRole(ctx, fx.orgA, "00000000-0000-0000-0000-000000000001", RoleOperator), ErrNotFound)

	// An invalid role is a validation error, never a silent no-op delete.
	require.Error(t, fx.store.RemoveScimMemberRole(ctx, fx.orgA, u.ID, OrgRole("intern")))
	require.Error(t, fx.store.RemoveScimMemberRole(ctx, fx.orgA, u.ID, OrgRole("")))
}

// TestScimSyncDeactivate_Integration: a deactivating sync flips BOTH the
// identity and the admin account (with the session watermark), while
// name-only syncs never touch the account flags.
func TestScimSyncDeactivate_Integration(t *testing.T) {
	fx := newScimFixture(t)
	ctx := context.Background()
	pool := fx.pool
	suffix := time.Now().UnixNano()

	user, _, err := fx.store.ProvisionScimUser(ctx, fx.orgA, ScimUserParams{
		UserName: fmt.Sprintf("scim-it-d-%d@example.com", suffix), GivenName: "Grace",
		FamilyName: "Hopper", Active: true, Role: RoleReader,
	})
	require.NoError(t, err)

	// Name-only sync keeps the user active and does NOT stamp the watermark.
	synced, err := fx.store.SyncScimUser(ctx, fx.orgA, user.ID, ScimUserParams{
		UserName: user.UserName, GivenName: "Grace", FamilyName: "Brewster", Active: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "Grace Brewster", synced.DisplayName)
	var active bool
	var watermark *time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT active, sessions_changed_at FROM admin_users WHERE id::text = $1`,
		user.AdminUserID).Scan(&active, &watermark))
	assert.True(t, active)
	assert.Nil(t, watermark, "a non-deactivating sync must not invalidate sessions")

	// Deactivating sync: identity + account flip, watermark stamped.
	_, err = fx.store.SyncScimUser(ctx, fx.orgA, user.ID, ScimUserParams{
		UserName: user.UserName, Active: false,
	})
	require.NoError(t, err)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT active, sessions_changed_at FROM admin_users WHERE id::text = $1`,
		user.AdminUserID).Scan(&active, &watermark))
	assert.False(t, active)
	require.NotNil(t, watermark, "deactivation must invalidate live sessions")
	firstWatermark := *watermark

	// Retrying the same deactivation is idempotent: an already inactive
	// account must not receive a new session invalidation watermark.
	_, err = fx.store.SyncScimUser(ctx, fx.orgA, user.ID, ScimUserParams{
		UserName: user.UserName, Active: false,
	})
	require.NoError(t, err)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT sessions_changed_at FROM admin_users WHERE id::text = $1`, user.AdminUserID).Scan(&watermark))
	require.NotNil(t, watermark)
	assert.Equal(t, firstWatermark, *watermark, "repeated inactive sync must preserve attribution watermark")

	// SCIM DELETE semantics: deactivation, never deletion.
	require.NoError(t, fx.store.DeactivateScimUser(ctx, fx.orgA, user.ID))
	got, err := fx.store.GetScimUser(ctx, fx.orgA, user.ID)
	require.NoError(t, err, "a deactivated user still resolves (NOT deleted)")
	assert.False(t, got.Active)
	listed, err := fx.store.ListScimUsers(ctx, fx.orgA)
	require.NoError(t, err)
	for _, listedUser := range listed {
		assert.NotEqual(t, user.ID, listedUser.ID, "deactivated identities must be excluded from SCIM lists")
	}
}

// TestScimNoRLSPosture_Integration: pins the DOCUMENTED isolation decision —
// scim_tokens / scim_identities deliberately carry NO RLS (the bearer-auth
// lookup resolves the org FROM the token hash, which an app.current_org-gated
// RLS policy would hide). If this test fails, someone enabled RLS on these
// tables without reworking the auth path — revisit migration 0012's header
// and pkg/adminstore/scim.go before proceeding.
func TestScimNoRLSPosture_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	ctx := context.Background()
	for _, table := range []string{"scim_tokens", "scim_identities"} {
		var relRowSecurity, relForceRowSecurity bool
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1`, table).
			Scan(&relRowSecurity, &relForceRowSecurity))
		assert.False(t, relRowSecurity, "%s: RLS must stay off (documented OP-13 decision)", table)
		assert.False(t, relForceRowSecurity, "%s: forced RLS must stay off", table)
	}
}
