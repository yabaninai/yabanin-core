package adminstore

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestOrgOnboarding_AppRoleIsolation(t *testing.T) {
	pool := openAdminTestPool(t)
	ctx := t.Context()
	admin := New(pool, slog.New(slog.DiscardHandler), nil)
	orgs := make([]string, 0, 2)
	for range 2 {
		name := "onboarding-" + uuid.NewString()
		org, err := admin.CreateOrganization(ctx, name, name)
		require.NoError(t, err)
		orgs = append(orgs, org.ID)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = pool.Exec(cleanup, "DELETE FROM organizations WHERE id::text = ANY($1)", orgs)
	})
	orgA, orgB := orgs[0], orgs[1]
	_, err := pool.Exec(ctx, "INSERT INTO org_onboarding (org_id, completed, skipped) VALUES ($1, true, false)", orgA)
	require.NoError(t, err)

	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(cleanup, "RESET ROLE")
		_, _ = conn.Exec(cleanup, "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	})
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SELECT set_config('app.current_org', '', false)")
	require.NoError(t, err)
	var user string
	var superuser, bypass, enabled, forced bool
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&user, &superuser, &bypass))
	require.Equal(t, "yabanin_app", user)
	require.False(t, superuser)
	require.False(t, bypass)
	require.NoError(t, conn.QueryRow(ctx, "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'org_onboarding'::regclass").Scan(&enabled, &forced))
	require.True(t, enabled)
	require.True(t, forced)
	store := newForTest(rlsConnAdapter{conn.Conn()}, slog.New(slog.DiscardHandler), nil)

	t.Run("unscoped reads and writes remain denied", func(t *testing.T) {
		var count int
		require.NoError(t, conn.QueryRow(ctx, "SELECT count(*) FROM org_onboarding").Scan(&count))
		require.Zero(t, count)
		_, err := conn.Exec(ctx, "INSERT INTO org_onboarding (org_id, completed, skipped) VALUES ($1, false, true)", orgB)
		var denied *pgconn.PgError
		require.ErrorAs(t, err, &denied)
		require.Equal(t, "42501", denied.Code)
	})

	// The store must scope each transaction, even on a connection previously
	// used for another organization, and restore that session's original scope.
	_, err = conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgB)
	require.NoError(t, err)
	checkScope := func(t *testing.T) {
		t.Helper()
		var scope string
		require.NoError(t, conn.QueryRow(ctx, "SELECT current_setting('app.current_org', true)").Scan(&scope))
		require.Equal(t, orgB, scope)
	}
	t.Run("read persisted state in the requested organization", func(t *testing.T) {
		state, err := store.GetOrgOnboarding(ctx, orgA)
		require.NoError(t, err)
		require.Equal(t, &OrgOnboarding{OrgID: orgA, Completed: true}, state)
		checkScope(t)
	})
	t.Run("write skip and read it back", func(t *testing.T) {
		t.Cleanup(func() {
			_, restoreErr := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgB)
			require.NoError(t, restoreErr)
		})
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', '', false)")
		require.NoError(t, err)
		require.NoError(t, store.UpsertOrgOnboarding(ctx, orgB, false, true))
		require.NoError(t, store.UpsertOrgOnboarding(ctx, orgB, false, true))
		state, err := store.GetOrgOnboarding(ctx, orgB)
		require.NoError(t, err)
		require.Equal(t, &OrgOnboarding{OrgID: orgB, Skipped: true}, state)
		var scope string
		require.NoError(t, conn.QueryRow(ctx, "SELECT current_setting('app.current_org', true)").Scan(&scope))
		require.Empty(t, scope)
		_, err = conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgB)
		require.NoError(t, err)
	})
	t.Run("failed updates preserve state and scope", func(t *testing.T) {
		require.Error(t, store.UpsertOrgOnboarding(ctx, orgA, false, true))
		checkScope(t)
		state, err := store.GetOrgOnboarding(ctx, orgA)
		require.NoError(t, err)
		require.Equal(t, &OrgOnboarding{OrgID: orgA, Completed: true}, state)
		require.Error(t, store.UpsertOrgOnboarding(ctx, orgA, false, false))
		require.Error(t, store.UpsertOrgOnboarding(ctx, orgA, true, true))
		checkScope(t)
	})
	t.Run("foreign keys and absent progress retain their contracts", func(t *testing.T) {
		missing := uuid.NewString()
		state, err := store.GetOrgOnboarding(ctx, missing)
		require.NoError(t, err)
		require.Equal(t, &OrgOnboarding{OrgID: missing}, state)
		require.ErrorIs(t, store.UpsertOrgOnboarding(ctx, missing, true, false), ErrNotFound)
		checkScope(t)
	})
	t.Run("another scope cannot see or alter the completed row", func(t *testing.T) {
		var count int
		require.NoError(t, conn.QueryRow(ctx, "SELECT count(*) FROM org_onboarding WHERE org_id=$1", orgA).Scan(&count))
		require.Zero(t, count)
		tag, err := conn.Exec(ctx, "UPDATE org_onboarding SET completed=false WHERE org_id=$1", orgA)
		require.NoError(t, err)
		require.Zero(t, tag.RowsAffected())
	})
}
