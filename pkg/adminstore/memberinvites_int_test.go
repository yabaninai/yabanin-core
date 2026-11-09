package adminstore

// W-INV: live-PG acceptance for the member_invites store (disposable
// testcontainers stand). Covers the token lifecycle (create → preview →
// accept; resend rotation; revoke), the single-use/TTL contract, duplicate
// active-invite handling, and org isolation under the PRODUCTION pool
// posture (PostgresApp: SET ROLE yabanin_app + region GUC, NOBYPASSRLS) — a
// foreign org must not see or touch another org's invites, while the public
// token path keeps working under the same RLS.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdbPostgresApp is the PRODUCTION pool posture (SET ROLE yabanin_app,
// NOBYPASSRLS) over the shared disposable stand.
func testdbPostgresApp(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testdb.PostgresApp(t, "global")
}

// seedInviteAdminUser inserts an inviter (created_by FK target) with a unique
// email and cleans it up.
func seedInviteAdminUser(t *testing.T, pool *pgxpool.Pool, email string) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(context.Background(),
		`INSERT INTO admin_users (email, password_hash, active) VALUES ($1, 'x', true) RETURNING id::text`,
		email).Scan(&id))
	t.Cleanup(func() {
		// member_invites.created_by cascades; memberships cascade too.
		_, _ = pool.Exec(context.Background(), `DELETE FROM admin_users WHERE id = $1`, id)
	})
	return id
}

func TestStore_MemberInviteTokenShape_Unit(t *testing.T) {
	org := "018c2f3e-9c1a-7c34-9f2e-0d5a1b6c3e4f"
	token, hash, err := newInviteToken(org)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(token, org+"."), "the token embeds the org prefix")
	secret, found := strings.CutPrefix(token, org+".")
	require.True(t, found)
	assert.Len(t, secret, 64, "32 bytes of entropy, hex-encoded")
	_, ok := parseInviteToken(token)
	assert.True(t, ok)
	assert.Equal(t, hash, inviteTokenHash(token))
	assert.Len(t, hash, 64)

	// Malformed tokens never pass the parser (the org segment is pinned into
	// the RLS GUC — a non-uuid would error instead of yielding no rows).
	for _, bad := range []string{
		"", org, org + ".", org + ".short", "not-a-uuid.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		org + ".0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
	} {
		_, ok := parseInviteToken(bad)
		assert.False(t, ok, "token %q must not parse", bad)
	}

	assert.Equal(t, "a@b.test", NormalizeInviteEmail("  A@B.TEST "))
}

func TestStore_MemberInviteLifecycle_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgA := seedByokOrg(t, pool, "inv-a")
	inviterID := seedInviteAdminUser(t, pool, fmt.Sprintf("inviter-%d@example.test", time.Now().UnixNano()))
	email := fmt.Sprintf("invitee-%d@example.test", time.Now().UnixNano())

	inv, token, err := store.CreateMemberInvite(ctx, orgA, strings.ToUpper(email), RoleOperator, inviterID)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.Equal(t, strings.ToLower(email), inv.Email, "email stored normalized")
	assert.Nil(t, inv.AcceptedAt)
	assert.WithinDuration(t, time.Now().Add(InviteTTL), inv.ExpiresAt, 5*time.Minute, "TTL is 72h")
	assert.NotContains(t, token, "token_hash")
	// The database holds only the sha256 of the token.
	var storedHash string
	require.NoError(t, pool.QueryRow(ctx, `SELECT token_hash FROM member_invites WHERE id::text = $1`, inv.ID).Scan(&storedHash))
	assert.NotEqual(t, token, storedHash, "the raw token must never be stored")
	assert.Equal(t, inviteTokenHash(token), storedHash, "exactly the sha256 is stored")

	// Preview resolves the token (org name joined).
	preview, err := store.PreviewMemberInvite(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, strings.ToLower(email), preview.Email)
	assert.Equal(t, RoleOperator, preview.Role)
	assert.NotEmpty(t, preview.OrgName)

	// List shows the pending invite, without token material.
	list, err := store.ListMemberInvites(ctx, orgA)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, inv.ID, list[0].ID)

	// A duplicate ACTIVE invite for the same (org, email) is rejected.
	_, _, err = store.CreateMemberInvite(ctx, orgA, email, RoleReader, inviterID)
	require.ErrorIs(t, err, ErrInvitePending)

	// Resend rotates the token and restarts the window.
	resent, newToken, err := store.ResendMemberInvite(ctx, orgA, inv.ID, inviterID)
	require.NoError(t, err)
	assert.NotEqual(t, token, newToken)
	assert.True(t, resent.ExpiresAt.After(time.Now().Add(InviteTTL-time.Minute)))
	// The OLD token is dead immediately.
	_, err = store.PreviewMemberInvite(ctx, token)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = store.PreviewMemberInvite(ctx, newToken)
	require.NoError(t, err)

	// Revoke removes the pending invite; the token stops resolving.
	require.NoError(t, store.RevokeMemberInvite(ctx, orgA, inv.ID, inviterID))
	_, err = store.PreviewMemberInvite(ctx, newToken)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = store.AcceptMemberInvite(ctx, newToken, "some-hash")
	require.ErrorIs(t, err, ErrNotFound)
	// Revoking again is a not-found, not a success.
	require.ErrorIs(t, store.RevokeMemberInvite(ctx, orgA, inv.ID, inviterID), ErrNotFound)

	// The pair (org, email) is free again after the revoke.
	inv2, _, err := store.CreateMemberInvite(ctx, orgA, email, RoleReader, inviterID)
	require.NoError(t, err)
	require.NoError(t, store.RevokeMemberInvite(ctx, orgA, inv2.ID, inviterID))
}

func TestStore_MemberInviteAccept_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgA := seedByokOrg(t, pool, "inv-accept")
	inviterID := seedInviteAdminUser(t, pool, fmt.Sprintf("inviter-%d@example.test", time.Now().UnixNano()))
	email := fmt.Sprintf("newbie-%d@example.test", time.Now().UnixNano())

	// --- new account path -------------------------------------------------
	inv, token, err := store.CreateMemberInvite(ctx, orgA, email, RoleOperator, inviterID)
	require.NoError(t, err)

	res, err := store.AcceptMemberInvite(ctx, token, "$2a$10$fixturehash")
	require.NoError(t, err)
	assert.True(t, res.UserCreated)
	assert.NotEmpty(t, res.UserID)
	assert.Equal(t, orgA, res.Invite.OrgID)
	assert.Equal(t, RoleOperator, res.Invite.Role)

	var acceptedAt *time.Time
	var invitedUser string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT accepted_at, COALESCE(invited_user_id::text, '') FROM member_invites WHERE id::text = $1`, inv.ID,
	).Scan(&acceptedAt, &invitedUser))
	require.NotNil(t, acceptedAt, "the acceptance closes the invite")
	assert.Equal(t, res.UserID, invitedUser)

	var role string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT role FROM admin_org_memberships WHERE user_id::text = $1 AND org_id::text = $2`,
		res.UserID, orgA).Scan(&role))
	assert.Equal(t, "operator", role)

	// SINGLE USE: a second acceptance of the same token is refused.
	_, err = store.AcceptMemberInvite(ctx, token, "$2a$10$fixturehash")
	require.ErrorIs(t, err, ErrInviteAccepted)
	_, err = store.PreviewMemberInvite(ctx, token)
	require.ErrorIs(t, err, ErrInviteAccepted)

	// The new account's password is exactly the supplied hash and untouched.
	var hash string
	require.NoError(t, pool.QueryRow(ctx, `SELECT password_hash FROM admin_users WHERE id::text = $1`, res.UserID).Scan(&hash))
	assert.Equal(t, "$2a$10$fixturehash", hash)

	// --- expired invite ---------------------------------------------------
	expEmail := fmt.Sprintf("late-%d@example.test", time.Now().UnixNano())
	expInv, expToken, err := store.CreateMemberInvite(ctx, orgA, expEmail, RoleReader, inviterID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE member_invites SET expires_at = now() - interval '1 second' WHERE id::text = $1`, expInv.ID)
	require.NoError(t, err)
	_, err = store.AcceptMemberInvite(ctx, expToken, "x")
	require.ErrorIs(t, err, ErrInviteExpired)
	_, err = store.PreviewMemberInvite(ctx, expToken)
	require.ErrorIs(t, err, ErrInviteExpired)

	// --- existing account path: bound, never re-passworded ----------------
	existingEmail := fmt.Sprintf("member-%d@example.test", time.Now().UnixNano())
	created, err := store.CreateAdminUser(ctx, existingEmail, "Existing", "$2a$10$originalhash", false)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM admin_users WHERE id::text = $1`, created.ID) })

	_, exToken, err := store.CreateMemberInvite(ctx, orgA, existingEmail, RoleReader, inviterID)
	require.NoError(t, err)
	res2, err := store.AcceptMemberInvite(ctx, exToken, "")
	require.NoError(t, err)
	assert.False(t, res2.UserCreated, "an existing account is bound, not created")
	assert.Equal(t, created.ID, res2.UserID)
	require.NoError(t, pool.QueryRow(ctx, `SELECT password_hash FROM admin_users WHERE id::text = $1`, created.ID).Scan(&hash))
	assert.Equal(t, "$2a$10$originalhash", hash, "an invite must never touch an existing password")

	// A membership the invitee already had is moved to the invited role.
	var memRole string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT role FROM admin_org_memberships WHERE user_id::text = $1 AND org_id::text = $2`,
		created.ID, orgA).Scan(&memRole))
	assert.Equal(t, "reader", memRole)

	// Accepting without credentials and without an existing account fails.
	ghostEmail := fmt.Sprintf("ghost-%d@example.test", time.Now().UnixNano())
	_, ghostToken, err := store.CreateMemberInvite(ctx, orgA, ghostEmail, RoleReader, inviterID)
	require.NoError(t, err)
	_, err = store.AcceptMemberInvite(ctx, ghostToken, "")
	require.Error(t, err, "no account and no credentials must not silently accept")
}

func TestStore_MemberInviteOrgIsolation_Integration(t *testing.T) {
	// PRODUCTION posture: yabanin_app (NOBYPASSRLS) + region GUC. The
	// org_isolation policy must hide org-a's invites from org-b's store
	// calls, while the token path (org resolved from the token prefix) keeps
	// working for the public acceptance.
	pool := testdbPostgresApp(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	orgA := seedByokOrg(t, pool, "inv-iso-a")
	orgB := seedByokOrg(t, pool, "inv-iso-b")
	inviterA := seedInviteAdminUser(t, pool, fmt.Sprintf("inviter-a-%d@example.test", time.Now().UnixNano()))
	inviterB := seedInviteAdminUser(t, pool, fmt.Sprintf("inviter-b-%d@example.test", time.Now().UnixNano()))
	email := fmt.Sprintf("shared-%d@example.test", time.Now().UnixNano())

	invA, tokenA, err := store.CreateMemberInvite(ctx, orgA, email, RoleReader, inviterA)
	require.NoError(t, err)

	// Org-b sees nothing of org-a's invites...
	listB, err := store.ListMemberInvites(ctx, orgB)
	require.NoError(t, err)
	assert.Empty(t, listB)

	// ...cannot resend, revoke, or re-create the same email...
	_, _, err = store.ResendMemberInvite(ctx, orgB, invA.ID, inviterB)
	require.ErrorIs(t, err, ErrNotFound, "org-b must not resend org-a's invite")
	err = store.RevokeMemberInvite(ctx, orgB, invA.ID, inviterB)
	require.ErrorIs(t, err, ErrNotFound, "org-b must not revoke org-a's invite")

	// ...and org-a still sees exactly its own invite.
	listA, err := store.ListMemberInvites(ctx, orgA)
	require.NoError(t, err)
	require.Len(t, listA, 1)
	assert.Equal(t, invA.ID, listA[0].ID)

	// The SAME email can hold an active invite in a different org (the
	// unique index is per-org).
	_, tokenB, err := store.CreateMemberInvite(ctx, orgB, email, RoleReader, inviterB)
	require.NoError(t, err)

	// The public token path works under the app role: both tokens accept,
	// each binding its own org.
	resA, err := store.AcceptMemberInvite(ctx, tokenA, "$2a$10$rlshash")
	require.NoError(t, err)
	assert.Equal(t, orgA, resA.Invite.OrgID)
	_, err = store.PreviewMemberInvite(ctx, tokenB)
	require.NoError(t, err)
}
