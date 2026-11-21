//go:build integration

package migrate

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// Fresh install vs supported upgrade — live schema parity. Two disposable
// pgvector stands go through the shipped seams only:
//
//  1. fresh install: migrate.Run applies the whole embedded set
//     and records the pinned head;
//  2. stamp-1 upgrade cohort (stands created between the 2026-10-12 squash
//     and the 2026-10-20 re-add of the incrementals): exactly the 0001_init
//     pair is applied by the same golang-migrate machinery, schema_migrations
//     holds the operator-visible (1, false), and a subsequent migrate.Run
//     applies all shipped incrementals on top;
//
// then pg_dump --schema-only of both stands must be byte-identical (after
// guard-token normalization): both cohorts apply the same embedded files
// (sync test) through the same runner, so any observable schema difference
// would have to originate inside that set. A sensitivity arm mutates one stand
// afterwards and proves the
// comparison actually notices a schema difference, so an empty or vacuous
// equality can never pass silently. Down migrations make no data-restoration
// promise anywhere on this path (structural reverses only; 0001_init.down is
// an honest full reset).
//
// Docker is a hard prerequisite: the stands are not skipped.

// stamp1CohortApply reproduces the stamp-1 cohort on a fresh stand: exactly
// the 0001_init baseline pair is applied through the same invocation the
// shipped runner uses (file:// source over extracted embedded bytes, the same
// configured pgx session), so schema_migrations is created by golang-migrate itself
// and records (1, false) — the real 2026-10-12..20 cohort state, not a
// hand-made replica of its bookkeeping table.
func stamp1CohortApply(t *testing.T, ctx context.Context, pgURI string) {
	t.Helper()
	tmpDir := t.TempDir()
	for _, name := range []string{"0001_init.up.sql", "0001_init.down.sql"} {
		data, err := migrationsFS.ReadFile("migrations/" + name)
		require.NoError(t, err, "embedded baseline pair must be readable")
		// 0600: read only by the migrator in this same process/user.
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, name), data, 0600))
	}
	pool, err := Connect(ctx, pgURI, "test")
	require.NoError(t, err)
	defer pool.Close()
	session, err := openMigrationSession(ctx, pool, "file://"+tmpDir)
	require.NoError(t, err, "the stamp-1 subset source must build")
	operationErr := session.m.Up()
	closeErr := session.close(operationErr)
	require.NoError(t, closeErr, "applying and closing exactly the baseline must succeed")
}

// schemaOnlyDump runs pg_dump --schema-only inside the stand's own container
// (the postgres image ships the matching pg_dump for the exact server
// version) and returns the dump bytes. Writing to a file inside the container
// keeps the compared bytes free of stdout/stderr stream multiplexing.
func schemaOnlyDump(t *testing.T, ctx context.Context, container *testpostgres.PostgresContainer) []byte {
	t.Helper()
	const dumpPath = "/tmp/parity_schema_only.sql"
	code, _, err := container.Exec(ctx, []string{"sh", "-c",
		"pg_dump --schema-only 'postgres://postgres:postgres@127.0.0.1:5432/yabanin?sslmode=disable' > " + dumpPath})
	require.NoError(t, err, "pg_dump exec must run")
	require.Equal(t, 0, code, "pg_dump --schema-only must exit 0")
	reader, err := container.CopyFileFromContainer(ctx, dumpPath)
	require.NoError(t, err, "the schema dump must be copyable out of the stand")
	dump, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	return dump
}

// dumpGuardRe matches the per-run psql guard meta-commands this pg_dump emits
// as CVE-2025-8714 hardening: "\restrict <random-token>" at the top and
// "\unrestrict <random-token>" at the end. The token is fresh for every dump
// invocation (verified: two dumps of the same database differ only there) and
// carries no schema information, so exactly these lines are dropped from both
// dumps before the byte comparison; every other byte must match.
var dumpGuardRe = regexp.MustCompile(`(?m)^\\(?:un)?restrict .*\n?`)

// normalizeDumpGuards strips the per-run guard meta-commands from a dump.
func normalizeDumpGuards(dump []byte) []byte {
	return []byte(dumpGuardRe.ReplaceAllString(string(dump), ""))
}

// TestRun_FreshAndStamp1CohortsConvergeToIdenticalSchema — the card
// acceptance as a live check: fresh install and the stamp-1 supported
// upgrade converge to one and the same schema.
func TestRun_FreshAndStamp1CohortsConvergeToIdenticalSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	// Stand 1 — fresh install: the whole embedded set applies in one Run.
	freshDSN, _, freshStand := spinBaselineStand(t, ctx)
	upFresh, err := Run(ctx, freshDSN, "sg")
	require.NoError(t, err, "fresh-DB apply of the full embedded set must succeed")
	require.Equal(t, 1, upFresh.Applied)
	require.Equal(t, int64(jointScenario.headVersion), upFresh.Version)

	// Stand 2 — stamp-1 upgrade cohort: baseline only first, so
	// schema_migrations records exactly (1, false) as created by
	// golang-migrate, then Run applies the remaining embedded migrations.
	stampDSN, stampPool, stampStand := spinBaselineStand(t, ctx)
	stamp1CohortApply(t, ctx, stampDSN)
	var version int64
	var dirty bool
	require.NoError(t, stampPool.QueryRow(ctx,
		`SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty))
	require.Equal(t, int64(1), version, "the cohort stand must be recorded at stamp version 1")
	require.False(t, dirty)
	upStamp, err := Run(ctx, stampDSN, "sg")
	require.NoError(t, err, "the stamp-1 cohort must upgrade over the shared incrementals")
	require.Equal(t, int64(jointScenario.headVersion), upStamp.Version, "the upgraded cohort must converge to the pinned head")
	require.Equal(t, 1, upStamp.Applied)

	// Parity: schema-only dumps must be byte-identical (modulo the per-run
	// guard tokens, which carry no schema information).
	freshDump := normalizeDumpGuards(schemaOnlyDump(t, ctx, freshStand))
	stampDump := normalizeDumpGuards(schemaOnlyDump(t, ctx, stampStand))
	require.Contains(t, string(freshDump), "CREATE TABLE public.organizations",
		"the dump must carry the real schema, not an empty DB (non-vacuity guard)")
	require.Equal(t, string(freshDump), string(stampDump),
		"fresh install and the stamp-1 supported upgrade must yield the identical schema")

	// Sensitivity arm: the comparison must be able to fail. Mutate one stand
	// (both are disposable) and require the dumps to diverge — the parity
	// assertion above is a live check, not a vacuous equality.
	_, err = stampPool.Exec(ctx,
		`COMMENT ON TABLE public.organizations IS 'parity sensitivity probe'`)
	require.NoError(t, err)
	mutatedDump := normalizeDumpGuards(schemaOnlyDump(t, ctx, stampStand))
	require.Contains(t, string(mutatedDump), "parity sensitivity probe")
	require.NotEqual(t, string(freshDump), string(mutatedDump),
		"the byte comparison must notice a schema difference (sensitivity proof)")
}
