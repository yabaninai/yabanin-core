//go:build integration

package migrate

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// disposable pgvector container (same stand style as
// TestRun_AppliesFullSchemaOnFreshDB). The steps form one ordered narrative
// against a single fresh database, mirroring what an operator hits on a
// clean install and on a pre-squash stand:
//
//  1. seed before migrate on a clean DB fails with the diagnosable
//     "relation does not exist" (SQLSTATE 42P01) and nothing half-applies;
//  2. migrate applies exactly the embedded set (the current head version);
//  3. after the deploy-layer role bootstrap, the least-privileged app role
//     (NOBYPASSRLS, app.region bound) can perform the seed inserts — the
//     "RLS seed bootstrap incompatible with a clean DB" failure mode is
//     disproven for the shipped baseline;
//  4. a repeated migrate is a no-op success;
//  5. a dirty schema_migrations fails loudly on every attempt (no auto-heal)
//     and recovers only by explicit operator resolution;
//  6. a pre-squash stand recorded at an unknown version (absent from the
//     embedded set — forged into a reserved gap slot) fails loudly without
//     touching data, and recovers via the explicit version stamp — never
//     auto-healed.
func TestRun_FailureBoundariesOnFreshDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	container, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err, "docker/testcontainers must be available for the failure-boundary stand")
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)
	parts := strings.Split(port.Port(), "/")
	connStr := fmt.Sprintf("postgres://postgres:postgres@%s:%s/yabanin?sslmode=disable", host, parts[0])

	ownerPool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(func() { ownerPool.Close() })
	waitForDBReady(t, ctx, ownerPool)

	// --- 1) Seed before migrate: clean DB has no schema yet. The seed must
	// fail with a diagnosable missing-relation error, not half-apply.
	premature, err := pgx.Connect(ctx, connStr)
	require.NoError(t, err)
	_, err = premature.Exec(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('Premature', 'premature')`)
	require.Error(t, err, "seed insert without a migrated schema must fail")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "42P01", pgErr.Code, "expected undefined_table, got: %s", err.Error())
	require.Contains(t, err.Error(), "organizations")
	require.NoError(t, premature.Close(ctx))
	var orgRows int
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='organizations'`).Scan(&orgRows))
	require.Equal(t, 0, orgRows, "failed seed must not leave partial state")

	// --- 2) Baseline apply on the clean DB: the embedded set applies, the
	// head version is recorded (Applied counts the single-row
	// schema_migrations record, Version is the head).
	up, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "fresh-DB baseline apply must succeed")
	require.Equal(t, 1, up.Applied)
	require.Equal(t, int64(27), up.Version)

	// --- 3) Role bootstrap (deploy layer, mirrors
	// deploy/quickstart/bootstrap-app-role.sql) + seed insert as the
	// least-privileged app role: no RLS on seeded tables must hold at runtime.
	_, err = ownerPool.Exec(ctx, `
		DO $$ BEGIN
			IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'yabanin_app') THEN
				CREATE ROLE yabanin_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
			END IF;
		END $$;
		GRANT USAGE ON SCHEMA public TO yabanin_app;
		GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO yabanin_app;
		GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO yabanin_app;`)
	require.NoError(t, err, "app-role bootstrap must succeed on the migrated baseline")

	appConn, err := pgx.Connect(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = appConn.Close(context.Background()) })
	_, err = appConn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "SET ROLE to the non-owner app role must succeed")
	_, err = appConn.Exec(ctx, "SELECT set_config('app.region', 'sg', false)")
	require.NoError(t, err)
	var seededOrg string
	require.NoError(t, appConn.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('Boundary Org', 'boundary-org') RETURNING id::text`).Scan(&seededOrg),
		"seed insert as the app role must succeed on a clean-migrated DB (seeded tables are not RLS-locked)")
	require.NotEmpty(t, seededOrg)

	// --- 4) Repeat operation: a second migrate is a no-op success.
	repeat, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "re-running migrate must be a no-op success")
	require.Equal(t, int64(27), repeat.Version)

	// --- 5) Interruption: dirty schema_migrations (crashed mid-migration).
	_, err = ownerPool.Exec(ctx, `UPDATE schema_migrations SET dirty = true`)
	require.NoError(t, err)
	_, err = Run(ctx, connStr, "sg")
	require.Error(t, err, "migrate must fail loudly on a dirty database")
	require.Contains(t, err.Error(), "Dirty database version 27")
	var dirty bool
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT dirty FROM schema_migrations`).Scan(&dirty))
	require.True(t, dirty, "a failed attempt must not auto-heal the dirty flag")
	_, err = Run(ctx, connStr, "sg")
	require.Error(t, err, "a second attempt must fail identically (no partial success)")
	require.Contains(t, err.Error(), "Dirty database version 27")
	// Recovery is explicit: the operator resolves the state, not the tool.
	_, err = ownerPool.Exec(ctx, `UPDATE schema_migrations SET dirty = false`)
	require.NoError(t, err)
	recovered, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "after explicit resolution migrate succeeds again")
	require.Equal(t, int64(27), recovered.Version)

	// --- 6) Pre-squash stand: recorded version 23 is absent from the
	// embedded set (head is 27; 0023 is the permanently-unused released
	// slot; 0023 alone is a reserved gap; 0022 is present via e02p01a,
	// 0024 via e03p01b and 0025 via e04p01a).
	// Up and Down
	// must fail loudly without touching data, and only an explicit operator
	// stamp resolves it.
	_, err = ownerPool.Exec(ctx, `
		CREATE TABLE canary_r059_boundary (v int NOT NULL);
		INSERT INTO canary_r059_boundary (v) VALUES (42);
		UPDATE schema_migrations SET version = 23, dirty = false;`)
	require.NoError(t, err)
	_, err = Run(ctx, connStr, "sg")
	require.Error(t, err, "migrate must refuse an unknown recorded version (pre-squash stand)")
	require.Contains(t, err.Error(), "no migration found for version 23")
	_, err = Down(ctx, connStr, "sg", 0)
	require.Error(t, err, "down must refuse the same unknown version")
	require.Contains(t, err.Error(), "no migration found for version 23")
	var canary int
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT v FROM canary_r059_boundary`).Scan(&canary))
	require.Equal(t, 42, canary, "failed up/down on an unknown version must not touch data")
	// Explicit operator resolution: stamp the head version the stand's
	// schema actually converged to (the forged-23 record was the only lie;
	// the schema is at the head) — a no-op success, never auto-healed.
	_, err = ownerPool.Exec(ctx, `UPDATE schema_migrations SET version = 27`)
	require.NoError(t, err)
	stamped, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "after the explicit stamp the stand is a no-op success")
	require.Equal(t, int64(27), stamped.Version)
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT v FROM canary_r059_boundary`).Scan(&canary))
	require.Equal(t, 42, canary, "stamping + no-op migrate must leave data untouched")
}
