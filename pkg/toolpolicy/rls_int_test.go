package toolpolicy

// 0002_tool_policies_org_isolation). Under the application posture
// (SET ROLE yabanin_app, NOBYPASSRLS — the mcpcreds_int_test.go parity) a
// foreign org's rows are invisible and cross-tenant writes are rejected;
// an unbound session sees nothing at all (fail closed). The production
// store path keeps working because every operation pins the
// app.current_org GUC transaction-locally (Store.withOrgTx).

import (
	"context"
	"testing"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestToolPolicies_RLS_OrgIsolation_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	appStore := NewStore(testdb.PostgresApp(t, "test"))
	ctx := context.Background()

	// Seed two orgs and one policy row each (as the container superuser —
	// the migration path, which bypasses RLS by design).
	var orgA, orgB string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ('r035-rls-a', 'r035-rls-a') RETURNING id::text`).Scan(&orgA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ('r035-rls-b', 'r035-rls-b') RETURNING id::text`).Scan(&orgB))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tool_policies WHERE org_id::text = ANY($1)`, []string{orgA, orgB})
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id::text = ANY($1)`, []string{orgA, orgB})
	})
	store := NewStore(pool)
	_, err := store.Create(ctx, CreateParams{OrgID: orgA, Name: "rls-a-deny", Subject: "*",
		Server: "github", Tool: "delete_issue", Action: "deny", Enabled: true})
	require.NoError(t, err, "store (tx-pinned GUC) must insert under the RLS policy")
	_, err = store.Create(ctx, CreateParams{OrgID: orgB, Name: "rls-b-allow", Subject: "*",
		Tool: "*", Action: "allow", Enabled: true})
	require.NoError(t, err)

	t.Run("raw yabanin_app session bound to orgA", func(t *testing.T) {
		conn := rlsAppRoleConn(t, ctx, pool)
		_, err := conn.Exec(ctx, "SELECT set_config('app.current_org', $1, false)", orgA)
		require.NoError(t, err)
		var seen int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT count(*) FROM tool_policies WHERE org_id = $1::uuid`, orgB).Scan(&seen))
		assert.Zero(t, seen, "a bound session must not see the foreign org's rows")
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT count(*) FROM tool_policies WHERE org_id = $1::uuid`, orgA).Scan(&seen))
		assert.Equal(t, 1, seen, "the bound org's rows are visible")

		// Cross-org INSERT violates the WITH CHECK arm.
		_, err = conn.Exec(ctx, `
			INSERT INTO tool_policies (org_id, name, subject, tool, action)
			VALUES ($1::uuid, 'rls-injected', '*', '*', 'allow')`, orgB)
		require.Error(t, err, "cross-org insert must be rejected by the org_isolation policy")
	})

	t.Run("raw yabanin_app session unbound", func(t *testing.T) {
		conn := rlsAppRoleConn(t, ctx, pool)
		var seen int
		require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM tool_policies`).Scan(&seen))
		assert.Zero(t, seen, "an unbound session must see no policy rows at all (fail closed)")
	})

	t.Run("store path stays org-scoped under the app role", func(t *testing.T) {
		// The production pool posture (SET ROLE yabanin_app on every
		// connection): the store's tx-pinned GUC keeps every operation
		// working and org-scoped — an org's engine loader sees exactly its
		// own rows.
		pols, err := appStore.ListEnabled(ctx, orgA)
		require.NoError(t, err)
		require.Len(t, pols, 1, "orgA's loader sees its own row")
		assert.Equal(t, "rls-a-deny", pols[0].Name)
		assert.Equal(t, "github", pols[0].Server)

		pols, err = appStore.ListEnabled(ctx, orgB)
		require.NoError(t, err)
		require.Len(t, pols, 1)
		assert.Equal(t, "rls-b-allow", pols[0].Name)

		// Admin CRUD round-trip through the RLS-bound posture.
		got, err := appStore.Get(ctx, orgA, "rls-a-deny")
		require.NoError(t, err)
		assert.Equal(t, "deny", got.Action)
		disabled := false
		_, err = appStore.Update(ctx, orgA, "rls-a-deny", UpdateParams{Enabled: &disabled})
		require.NoError(t, err)
		pols, err = appStore.ListEnabled(ctx, orgA)
		require.NoError(t, err)
		assert.Empty(t, pols, "disabled rows are excluded from the loader")
		require.NoError(t, appStore.Delete(ctx, orgA, "rls-a-deny"))
		_, err = appStore.Get(ctx, orgA, "rls-a-deny")
		require.ErrorIs(t, err, ErrNotFound)
	})
}

// rlsAppRoleConn downgrades one pooled connection to the application role
// (the production posture) and returns it with a cleanup that resets the
// session. The app.current_org GUC stays UNBOUND — callers bind their own.
func rlsAppRoleConn(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *pgxpool.Conn {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "RESET ROLE")
		_, _ = conn.Exec(ctx, "SELECT set_config('app.current_org', '', false)")
		conn.Release()
	})
	_, err = conn.Exec(ctx, "RESET ROLE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET row_security = on")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "yabanin_app must exist (testdb bootstrap mirrors the deploy layer)")
	var currentUser string
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser))
	require.Equal(t, "yabanin_app", currentUser, "RLS assertions are void unless the session is downgraded")
	return conn
}
