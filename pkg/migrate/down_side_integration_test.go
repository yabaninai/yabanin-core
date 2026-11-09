//go:build integration

package migrate

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// TestRun_DownLeavesDeletedDataDeleted is the live (real-Postgres) arm of the
// packet's negative scenario: a down migration never restores deleted data.
// The observable result — a probe row seeded into a table owned by an
// incremental migration disappears across down → re-up and comes back in no
// form, while the structure does:
//
//  1. full upgrade to the embedded head (version 27, pinned like
//     TestRun_CleanInstallSeedRegression);
//  2. seed a probe row into guard_pack_state (introduced by 0013, a plain
//     single-row table with no FK or RLS dimension);
//  3. downgrade to version 12 — the 0013 down drops the table, the probe
//     row is gone;
//  4. re-upgrade — the structure returns;
//  5. the probe row does NOT: the table exists and is empty, proving the
//     down is a structural reverse and nothing in the migration set
//     promises data restoration.
//
// The static half of the guard (no data-restoring statement classes in any
// down file) is TestDownMigrationsNeverRestoreData; this test proves the
// runtime behavior those classes forbid. If the embedded head moves past 15,
// step 1 fails loudly and the probe versions must be re-pinned in the same
// change that grows the set (same posture as the README head pin).
func TestRun_DownLeavesDeletedDataDeleted(t *testing.T) {
	if dups := duplicateUpVersions(); len(dups) > 0 {
		t.Skipf("skipping: embedded migrations have duplicate version(s) %s — fix the numbering first", dups)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	container, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err, "docker/testcontainers must be available for the down-side negative scenario")
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)
	parts := strings.Split(port.Port(), "/")
	connStr := fmt.Sprintf("postgres://postgres:postgres@%s:%s/yabanin?sslmode=disable", host, parts[0])

	waitPool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(func() { waitPool.Close() })
	waitForDBReady(t, ctx, waitPool)

	// 1) Upgrade to the embedded head.
	up1, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "initial upgrade should apply the full schema")
	require.Equal(t, int64(27), up1.Version,
		"embedded head moved: re-pin the probe versions (0013 table, down target 12) in the same change")

	// 2) Seed the probe row the scenario will require to stay deleted.
	p, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	defer p.Close()
	_, err = p.Exec(ctx,
		`INSERT INTO guard_pack_state (id, active_version) VALUES (1, 'probe-deleted-data-stays-deleted')`)
	require.NoError(t, err, "seeding the probe row into guard_pack_state must succeed")
	requireRowCount(t, ctx, p, "guard_pack_state", 1, "after seeding")

	// 3) Downgrade to 12: the 0013 down drops the probe table; the set below
	// the target must survive and the set above must be gone — down removes
	// exactly what it says (no overshoot past the requested version).
	down1, err := Down(ctx, connStr, "sg", 12)
	require.NoError(t, err, "downgrade to version 12 should succeed")
	require.Equal(t, int64(12), down1.Version, "version should be 12 after the downgrade")
	requireTableMissing(t, ctx, p, "guard_pack_state",
		"the 0013 down must drop the table (structural reverse)")
	// The 0012 tables must survive a downgrade to 12 — reverting stops at the
	// requested version, it does not bulldoze past it.
	requireTableExists(t, connStr, "sso_group_role_rules")

	// 4) Re-upgrade: the structure returns.
	up2, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "re-upgrade should succeed")
	require.Equal(t, up1.Version, up2.Version, "re-upgrade should return to the same head version")
	requireTableExists(t, connStr, "guard_pack_state")

	// 5) The observable negative result: the probe row is not restored.
	requireRowCount(t, ctx, p, "guard_pack_state", 0,
		"deleted data must stay deleted across down → re-up: no migration may restore it")
}

// requireRowCount asserts the exact number of rows in a table.
func requireRowCount(t *testing.T, ctx context.Context, p *pgxpool.Pool, table string, want int, msg string) {
	t.Helper()
	var n int
	err := p.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM public.%s`, table)).Scan(&n)
	require.NoError(t, err)
	require.Equal(t, want, n, "%s: %s row count", table, msg)
}

// requireTableMissing asserts the named table does not exist in the public
// schema.
func requireTableMissing(t *testing.T, ctx context.Context, p *pgxpool.Pool, table, msg string) {
	t.Helper()
	var n int
	err := p.QueryRow(ctx,
		`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name=$1`,
		table).Scan(&n)
	require.NoError(t, err)
	require.Equal(t, 0, n, "%s: %s", table, msg)
}
