package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/require"
)

// TestMigration0022UpDownUpCycle pins the 0022 pair the same way the 0021
// delivery pinned its own: the production set applies through head 22
// (testdb bootstrap), the 0022 down drops the registry (verified against
// the catalog, not a SELECT that would error), the 0022 up re-creates it
// and the closed-vocabulary checks are live (bad kind rejected, valid row
// lands), a second down→up converges to the same shape. Pattern: 0021
// (e01p03v C4 evidence, TestRun_UpDownUpCycle corpus).
func TestMigration0022UpDownUpCycle(t *testing.T) {
	pool := testdb.Postgres(t) // full production set incl. 0022_inventory_assets
	ctx := context.Background()
	up, down := migrationFiles(t)

	require.True(t, tableExists(t, ctx, pool, "inventory_assets"), "head-22 stand must carry the registry table")

	// Down: the registry is gone.
	_, err := pool.Exec(ctx, string(down))
	require.NoError(t, err, "0022 down must apply cleanly")
	require.False(t, tableExists(t, ctx, pool, "inventory_assets"), "0022 down must drop the table")

	// Up again: the registry is back with live vocabulary checks.
	_, err = pool.Exec(ctx, string(up))
	require.NoError(t, err, "0022 up must re-apply cleanly")
	require.True(t, tableExists(t, ctx, pool, "inventory_assets"))

	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	_, err = pool.Exec(ctx,
		`INSERT INTO inventory_assets (org_id, asset_key, kind, payload, source, confidence, first_seen, last_seen)
		 VALUES ('org-1', 'mcp_server:fs', 'mcp_server', '{"name":"fs"}', 'mcp_registry', 'high', $1, $1)`, at)
	require.NoError(t, err, "a valid row must land")

	_, err = pool.Exec(ctx,
		`INSERT INTO inventory_assets (org_id, asset_key, kind, payload, source, confidence, first_seen, last_seen)
		 VALUES ('org-1', 'x', 'vendor', '{}', 'mcp_registry', 'high', $1, $1)`, at)
	require.Error(t, err, "chk_inventory_assets_kind must reject an unknown kind")

	_, err = pool.Exec(ctx,
		`INSERT INTO inventory_assets (org_id, asset_key, kind, payload, source, confidence, first_seen, last_seen)
		 VALUES ('org-1', 'x', 'tool', '{}', 'mcp_registry', 'certain', $1, $1)`, at)
	require.Error(t, err, "chk_inventory_assets_confidence must reject an unknown confidence")

	// Tombstone shape coupling: tombstone without tombstoned_at is invalid.
	_, err = pool.Exec(ctx,
		`UPDATE inventory_assets SET tombstone = true WHERE asset_key = 'mcp_server:fs'`)
	require.Error(t, err, "chk_inventory_assets_tombstone must couple tombstone to tombstoned_at")

	// Second down→up converges (the cycle is repeatable).
	_, err = pool.Exec(ctx, string(down))
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(up))
	require.NoError(t, err)
	require.True(t, tableExists(t, ctx, pool, "inventory_assets"))
}

// TestMigration0022MirrorsEnsureSchema pins the two DDL homes against
// drift: the EnsureSchema bootstrap must be a no-op over the migrated
// table and must never disturb data. Pattern: TestMigration0021MirrorsDurableSchema.
func TestMigration0022MirrorsEnsureSchema(t *testing.T) {
	pool := testdb.Postgres(t) // one stand: migration home applied by bootstrap
	ctx := context.Background()
	s := NewStore(pool)

	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	_, err := pool.Exec(ctx,
		`INSERT INTO inventory_assets (org_id, asset_key, kind, payload, source, confidence, first_seen, last_seen)
		 VALUES ('org-mirror', 'model:gpt-x', 'model', '{"m":1}', 'mcp_registry', 'high', $1, $1)`, at)
	require.NoError(t, err)

	require.NoError(t, s.EnsureSchema(ctx), "EnsureSchema is idempotent over migration 0022")
	require.NoError(t, s.EnsureSchema(ctx), "a second run stays a no-op")

	var n int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM inventory_assets WHERE org_id = 'org-mirror'").Scan(&n))
	require.Equal(t, 1, n, "bootstrap re-run must not disturb data")
}

func tableExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	// to_regclass answers NULL for missing relations instead of erroring.
	var exists bool
	err := pool.QueryRow(ctx, `SELECT to_regclass($1::text) IS NOT NULL`, "public."+name).Scan(&exists)
	require.NoError(t, err)
	return exists
}

func migrationFiles(t *testing.T) (up, down []byte) {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		dir = filepath.Dir(dir)
	}
	up, err = os.ReadFile(filepath.Join(dir, "migrations", "0022_inventory_assets.up.sql")) //nolint:gosec // G304: repo-relative migration fixture
	require.NoError(t, err)
	down, err = os.ReadFile(filepath.Join(dir, "migrations", "0022_inventory_assets.down.sql")) //nolint:gosec // G304: repo-relative migration fixture
	require.NoError(t, err)
	return up, down
}
