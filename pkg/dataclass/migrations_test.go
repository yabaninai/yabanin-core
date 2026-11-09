package dataclass

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

// TestMigration0025UpDownUpCycle pins the 0025 pair the same way the 0021
// and 0022 deliveries pinned their own: the production set applies
// through head 25 (testdb bootstrap), the 0025 down drops ONLY the
// taxonomy table (verified against the catalog, not a SELECT that would
// error), the 0025 up re-creates it with the exact column vocabulary and
// the house org_isolation RLS posture, a live row lands and survives the
// re-up empty-recreate rule (down data is not restored), and a second
// down→up converges to the same shape. Pattern: pkg/inventory
// TestMigration0022UpDownUpCycle, itself the pkg/secevents 0021
// precedent.
func TestMigration0025UpDownUpCycle(t *testing.T) {
	pool := testdb.Postgres(t) // full production set incl. 0025_dataclass_taxonomies
	ctx := context.Background()
	up, down := migrationFiles(t)

	require.True(t, tableExists(t, pool, "dataclass_taxonomies"),
		"head-25 stand must carry the taxonomy table")

	// Vocabulary and RLS posture as shipped.
	require.Equal(t, []string{"org_id", "version", "labels", "updated_at", "updated_by"},
		tableColumns(t, pool, "dataclass_taxonomies"),
		"column set and order must match the store's expectations")
	require.True(t, rlsEnabled(t, pool, "dataclass_taxonomies"), "RLS must be enabled")
	require.Equal(t, []string{"org_isolation"}, tablePolicies(t, pool, "dataclass_taxonomies"),
		"exactly the house org_isolation policy (the 0001 pattern)")

	// Down: only the taxonomy table goes.
	_, err := pool.Exec(ctx, string(down))
	require.NoError(t, err, "0025 down must apply cleanly")
	require.False(t, tableExists(t, pool, "dataclass_taxonomies"), "0025 down must drop the table")
	// Down: only the taxonomy table goes. (testdb applies migrations/*.up.sql
	// directly — no golang-migrate bookkeeping table exists in this stand.)
	for _, survivor := range []string{"organizations", "tool_policies"} {
		require.True(t, tableExists(t, pool, survivor),
			"the down must not touch unrelated tables (%s)", survivor)
	}

	// Up again: the table is back, a live row lands, defaults hold.
	_, err = pool.Exec(ctx, string(up))
	require.NoError(t, err, "0025 up must re-apply cleanly")
	require.True(t, tableExists(t, pool, "dataclass_taxonomies"))

	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('dc-cycle', 'dc-cycle') RETURNING id::text`).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id::text = $1`, orgID)
	})
	var version int64
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO dataclass_taxonomies (org_id, labels, updated_by)
		VALUES ($1::uuid, '[{"key":"a"}]'::jsonb, 'cycle-test')
		RETURNING version`, orgID).Scan(&version))
	require.Equal(t, int64(1), version, "version defaults to 1 (bigint NOT NULL DEFAULT 1)")

	// Second down→up converges; the recreate starts empty (house rule:
	// down migrations never restore data).
	_, err = pool.Exec(ctx, string(down))
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(up))
	require.NoError(t, err)
	require.True(t, tableExists(t, pool, "dataclass_taxonomies"))
	var rows int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM dataclass_taxonomies`).Scan(&rows))
	require.Zero(t, rows, "the recreate starts empty — down data is not restored")
}

// migrationFiles reads the root-tree 0025 pair (walk up to go.mod).
func migrationFiles(t *testing.T) (up, down string) {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "migrations")
	var err error
	upB, err := os.ReadFile(filepath.Join(dir, "0025_dataclass_taxonomies.up.sql")) //nolint:gosec // G304: repo-relative migration fixture
	require.NoError(t, err, "the 0025 up pair must exist in migrations/")
	downB, err := os.ReadFile(filepath.Join(dir, "0025_dataclass_taxonomies.down.sql")) //nolint:gosec // G304: repo-relative migration fixture
	require.NoError(t, err, "the 0025 down pair must exist in migrations/")
	return string(upB), string(downB)
}

func tableExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var exists bool
	require.NoError(t, pool.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = $1)`, name).Scan(&exists))
	return exists
}

func tableColumns(t *testing.T, pool *pgxpool.Pool, name string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
		ORDER BY ordinal_position`, name)
	require.NoError(t, err)
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		require.NoError(t, rows.Scan(&c))
		cols = append(cols, c)
	}
	require.NoError(t, rows.Err())
	return cols
}

func rlsEnabled(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var enabled bool
	require.NoError(t, pool.QueryRow(context.Background(), `
		SELECT relrowsecurity FROM pg_class
		WHERE relname = $1 AND relnamespace = 'public'::regnamespace`, name).Scan(&enabled))
	return enabled
}

func tablePolicies(t *testing.T, pool *pgxpool.Pool, name string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT policyname FROM pg_policies
		WHERE schemaname = 'public' AND tablename = $1
		ORDER BY policyname`, name)
	require.NoError(t, err)
	defer rows.Close()
	var pols []string
	for rows.Next() {
		var p string
		require.NoError(t, rows.Scan(&p))
		pols = append(pols, p)
	}
	require.NoError(t, rows.Err())
	return pols
}
