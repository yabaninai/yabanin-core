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

// TestRun_UpDownUpCycle is the database half of the S04 migration audit: it
// proves the embedded migrations are not only forward-applicable but that a
// full upgrade → downgrade → upgrade cycle on a disposable database ends back
// at the top version with the schema intact.
//
// It is gated on Docker (testcontainers), mirroring
// TestRun_AppliesFullSchemaOnFreshDB, and skips (with a clear reason) while the
// embedded set has a duplicate version number. When Docker is unavailable it
// fails at container start; the no-database half of the audit
// (migrations_audit_test.go) always runs in the normal gate.
func TestRun_UpDownUpCycle(t *testing.T) {
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
	require.NoError(t, err, "docker/testcontainers must be available for the up/down/up audit")
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

	// 1) Upgrade: full schema applied.
	up1, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "initial upgrade should apply the full schema")
	require.Greater(t, up1.Applied, 0, "expected migrations to apply on a fresh DB")
	require.Greater(t, up1.Version, int64(0), "version should be set after upgrade")

	// A core table exists after upgrade.
	requireTableExists(t, connStr, "organizations")

	// 2) Downgrade: run every down migration back to version 0.
	downTo, err := Down(ctx, connStr, "sg", 0)
	require.NoError(t, err, "downgrade to version 0 should succeed (all downs valid)")
	require.Equal(t, int64(0), downTo.Version, "version should be 0 after full downgrade")

	// 3) Upgrade again: back to the top, idempotent with the first upgrade.
	up2, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "re-upgrade after downgrade should succeed")
	require.Equal(t, up1.Version, up2.Version, "re-upgrade should return to the same top version")
	require.Greater(t, up2.Version, int64(0))

	// The schema is intact after the cycle.
	requireTableExists(t, connStr, "organizations")
}

// requireTableExists asserts the named table exists in the public schema.
func requireTableExists(t *testing.T, connStr, table string) {
	t.Helper()
	p, err := pgxpool.New(context.Background(), connStr)
	require.NoError(t, err)
	defer p.Close()
	var n int
	err = p.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name=$1`,
		table).Scan(&n)
	require.NoError(t, err)
	require.Equal(t, 1, n, "table %s should exist", table)
}
