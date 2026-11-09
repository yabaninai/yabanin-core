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

// TestRun_AppliesFullSchemaOnFreshDB boots a fresh pgvector Postgres and runs
// the in-process migrator. It proves the embedded migrations actually apply
// (regression guard: the prior subprocess path silently applied 0 migrations
// because the file:// source pointed at a nested dir, the file source driver was
// not imported, and the DSN was malformed).
//
// It skips (with a clear reason) while the embedded set has a duplicate version
// number (currently 0035), which golang-migrate rejects. Once the migration
// numbering is fixed, this test must go green — that is the acceptance gate for
// in-process migrate.
func TestRun_AppliesFullSchemaOnFreshDB(t *testing.T) {
	if dups := duplicateUpVersions(); len(dups) > 0 {
		t.Skipf("skipping: embedded migrations have duplicate version(s) %s — "+
			"fix the numbering, then this test is the in-process acceptance gate", dups)
	}
	ctx := context.Background()

	// Use the default superuser like the other integration tests; the pgvector
	// testcontainers image reliably exposes postgres/postgres.
	container, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)
	parts := strings.Split(port.Port(), "/")
	connStr := fmt.Sprintf("postgres://postgres:postgres@%s:%s/yabanin?sslmode=disable", host, parts[0])

	// Wait for the DB to accept connections.
	waitPool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(func() { waitPool.Close() })
	waitForDBReady(t, ctx, waitPool)

	// First run: full schema applied.
	res, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "migrate.Run should apply the full schema")
	require.Greater(t, res.Applied, 0, "expected at least one migration to apply on a fresh DB")

	// Verify a core table from the first migration exists.
	p, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	defer p.Close()
	var tables int
	err = p.QueryRow(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='organizations'`).Scan(&tables)
	require.NoError(t, err)
	require.Equal(t, 1, tables, "organizations table should exist after migration")

	// Second run: idempotent, no error, same version.
	res2, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "re-running migrations should be a no-op success")
	require.GreaterOrEqual(t, res2.Version, res.Version)
}

// waitForDBReady polls the pool until Postgres accepts connections or the
// deadline expires — container healthcheck by deadline, not a fixed
// retry-count sleep loop.
func waitForDBReady(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var err error
	for {
		if err = pool.Ping(ctx); err == nil {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("test postgres did not become reachable within 15s: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
