//go:build integration

package migrate

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Recovery narrative on real stands: interruption, retry, resume, and
// operator-assisted recovery of the schema-ownership seams, each staged the
// honest way — the states a real interrupted deployment produces, created by
// the driver itself rather than hand-made bookkeeping edits:
//
//  1. an apply interrupted between versions (schema at a subset boundary,
//     clean bookkeeping) resumes through the shipped runner to the embedded
//     head with the pre-interruption probe data intact, the incremental
//     structures completed, and nothing duplicated across the retry;
//  2. a migration that fails mid-apply leaves the driver's own dirty record
//     (version marked before execution, never cleaned after failure); the
//     shipped runner refuses loudly on it, and after the operator clears the
//     dirty position (the `migrate force` recovery, against the true schema
//     position) the resume completes without re-running committed steps;
//  3. a revert that fails mid-down leaves the same honest dirty record at
//     the partially reverted position; the force-then-retry recovery lands
//     exactly on the requested target, and the re-upgrade brings the
//     dropped structure back empty.
//
// The single-row bookkeeping contract pinned by the boundary corpus
// (exactly one schema_migrations row at every versioned position) is asserted
// at every step. Docker is a hard prerequisite: the stands are not skipped.
// If the embedded head moves past 15, the version probes must be re-pinned
// in the same change.

// extractEmbeddedSubset writes the embedded migration pairs through the named
// version (inclusive) into a fresh temp directory — the same file:// source
// shape the shipped runner builds — and returns the source URL. Reserved-absent
// versions (the reservedGaps set in mirror_numbering_test.go — 0018/0019 carry
// no files) contribute nothing; the pair-count assertion is therefore per
// PRESENT version, not per version number.
func extractEmbeddedSubset(t *testing.T, through int) string {
	t.Helper()
	tmpDir := t.TempDir()
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	require.NoError(t, err, "the embedded migration set must be readable")
	versions := map[int]bool{}
	written := 0
	present := 0
	for _, e := range entries {
		m := migrationFileNameRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		ver, convErr := strconv.Atoi(m[1])
		require.NoError(t, convErr, "migration version must be numeric: %s", e.Name())
		if ver > through {
			continue
		}
		data, err := migrationsFS.ReadFile("migrations/" + e.Name())
		require.NoError(t, err, "embedded pair %s must be readable", e.Name())
		// 0600: read only by the migrator in this same process/user.
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, e.Name()), data, 0600))
		versions[ver] = true
		written++
		if strings.HasSuffix(e.Name(), ".up.sql") {
			present++
		}
	}
	require.Equal(t, 2*present, written,
		"the subset through %d must carry exactly an up/down pair per PRESENT version (reserved gaps carry none)", through)
	return "file://" + tmpDir
}

// corruptEmbeddedSubsetFile builds the subset through the named version but
// replaces one file's body with a leading statement the server rejects
// before any real statement of that file runs — so the failed step leaves no
// partial changes, the same recoverable position a real interrupted apply
// rolls back to. The pair is still shipped (the file source requires both
// directions), only its body is poisoned.
func corruptEmbeddedSubsetFile(t *testing.T, through int, fileName string) string {
	t.Helper()
	sourceURL := extractEmbeddedSubset(t, through)
	body, err := migrationsFS.ReadFile("migrations/" + fileName)
	require.NoError(t, err, "the poisoned pair must exist in the embedded set")
	poisoned := append([]byte("THIS STATEMENT MUST FAIL;\n"), body...)
	require.NoError(t, os.WriteFile(
		filepath.Join(strings.TrimPrefix(sourceURL, "file://"), fileName), poisoned, 0600))
	return sourceURL
}

// subsetMigrator opens a golang-migrate migrator over a subset source and the
// stand DSN — the same invocation the shipped runner uses, so every state it
// produces (including failures) is one the real deployment path can produce.
func subsetMigrator(t *testing.T, ctx context.Context, pgURI, sourceURL string) *migrate.Migrate {
	t.Helper()
	pool, err := Connect(ctx, pgURI, "test")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	session, err := openMigrationSession(ctx, pool, sourceURL)
	require.NoError(t, err, "the subset source must build")
	t.Cleanup(func() { _ = session.close(nil) })
	m := session.m
	return m
}

// requireBookkeeping asserts the exact schema_migrations row — the driver
// keeps the table single-row at every versioned position.
func requireBookkeeping(t *testing.T, ctx context.Context, pool *pgxpool.Pool, wantVersion int64, wantDirty bool, msgAndArgs ...interface{}) {
	t.Helper()
	var version int64
	var dirty bool
	require.NoError(t, pool.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations").Scan(&version, &dirty),
		"the bookkeeping row must exist and be single")
	require.Equal(t, wantVersion, version, append([]interface{}{"bookkeeping version"}, msgAndArgs...)...)
	require.Equal(t, wantDirty, dirty, append([]interface{}{"bookkeeping dirty flag"}, msgAndArgs...)...)
}

// TestRun_ResumesInterruptedApplyWithoutDuplicatesOrLosses — the apply
// interrupted between versions: schema at the subset boundary, clean
// bookkeeping, probe data in a baseline table — then the shipped runner
// resumes to the embedded head and a retry is a no-op. No probe row is
// duplicated or lost anywhere on the path.
func TestRun_ResumesInterruptedApplyWithoutDuplicatesOrLosses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	dsn, pool, _ := spinBaselineStand(t, ctx)

	// Interruption: the apply stops after the subset through version 5 —
	// exactly the on-disk state of a deployment killed between versions.
	subset := subsetMigrator(t, ctx, dsn, extractEmbeddedSubset(t, 5))
	require.NoError(t, subset.Up(), "applying the subset through version 5 must succeed")
	requireBookkeeping(t, ctx, pool, 5, false)

	// Probe data written while the deployment was mid-flight.
	_, err := pool.Exec(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('Recovery Org', 'recovery-org')`)
	require.NoError(t, err, "seeding the recovery probe row must succeed")
	requireRowCount(t, ctx, pool, "organizations", 1, "before the resume")

	// Resume: the shipped runner takes the stand from 5 to the head in one
	// call, over the interrupted position.
	res, err := Run(ctx, dsn, "sg")
	require.NoError(t, err, "the resume must complete the interrupted apply")
	require.Equal(t, int64(27), res.Version,
		"embedded head moved: re-pin the recovery probes in the same change")
	require.Equal(t, 1, res.Applied, "the single-row bookkeeping contract must hold after the resume")

	// No losses: the probe row survived; the incremental structures the
	// interrupted run had not reached are completed.
	requireRowCount(t, ctx, pool, "organizations", 1,
		"the probe row must survive the resume untouched")
	requireTableExists(t, dsn, "guard_pack_state")
	requireTableExists(t, dsn, "principal_delegations")

	// Retry: a second Run is a no-op, the probe row is not duplicated, and
	// the bookkeeping row stays exactly one.
	retry, err := Run(ctx, dsn, "sg")
	require.NoError(t, err, "the retry must be an idempotent no-op")
	require.Equal(t, int64(27), retry.Version)
	require.Equal(t, 1, retry.Applied)
	requireRowCount(t, ctx, pool, "organizations", 1,
		"the retry must not duplicate the probe row")
	requireBookkeeping(t, ctx, pool, 27, false)
}

// TestRun_RecoversAfterRealFailedMigration — a migration that fails mid-apply
// (a poisoned 0006 the server rejects before its first real statement): the
// driver records version 6 dirty and never cleans it. The shipped runner
// refuses loudly, the operator clears the dirty position with the force
// recovery against the true schema position (5), and the resume completes
// without re-running any committed step or losing the probe data.
func TestRun_RecoversAfterRealFailedMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	dsn, pool, _ := spinBaselineStand(t, ctx)

	// The honest crash: golang-migrate marks the version dirty before running
	// the file and leaves it dirty when the file fails.
	poisoned := subsetMigrator(t, ctx, dsn,
		corruptEmbeddedSubsetFile(t, 6, "0006_batch_files.up.sql"))
	require.Error(t, poisoned.Up(), "the poisoned 0006 must fail the apply mid-run")
	requireBookkeeping(t, ctx, pool, 6, true,
		"the failed apply must leave the driver's own dirty record")

	// The crashed apply must not have executed any statement of the poisoned
	// file: the 0006 structures are absent (the failed file rolled back whole).
	requireTableMissing(t, ctx, pool, "batch_files",
		"the rejected migration file must leave no partial structures")

	// Probe data written while the deployment was broken.
	_, err := pool.Exec(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('Broken Apply Org', 'broken-apply-org')`)
	require.NoError(t, err)
	requireRowCount(t, ctx, pool, "organizations", 1, "before the recovery")

	// The shipped runner refuses loudly on the dirty record: no auto-heal.
	_, err = Run(ctx, dsn, "sg")
	require.Error(t, err, "the runner must refuse a dirty database")
	require.Contains(t, err.Error(), "Dirty database version 6",
		"the refusal must name the dirty position")
	requireBookkeeping(t, ctx, pool, 6, true,
		"the refusal must not auto-heal the dirty record")

	// Operator recovery: force the bookkeeping back to the true schema
	// position (the `migrate force 5` step), then resume through the shipped
	// runner.
	full := subsetMigrator(t, ctx, dsn, extractEmbeddedSubset(t, 27))
	require.NoError(t, full.Force(5), "the force recovery must clear the dirty position")
	requireBookkeeping(t, ctx, pool, 5, false)

	res, err := Run(ctx, dsn, "sg")
	require.NoError(t, err, "the resume must complete from the recovered position")
	require.Equal(t, int64(27), res.Version)

	// No duplicates, no losses: exactly one bookkeeping row, the probe row
	// intact, the previously failing step now completed properly.
	requireBookkeeping(t, ctx, pool, 27, false)
	requireRowCount(t, ctx, pool, "organizations", 1,
		"the probe row must survive the recovery untouched")
	requireTableExists(t, dsn, "batch_files")
}

// TestDown_ResumesInterruptedRevert — a revert that fails mid-down (a
// poisoned 0013 down file): versions 16, 15 and 14 have reverted, 13 is
// marked dirty with its structure untouched. The runner refuses, the operator
// forces the true position and retries, the revert lands exactly on the
// requested target, and the re-upgrade completes the cycle with the dropped
// structure back empty.
func TestDown_ResumesInterruptedRevert(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	dsn, pool, _ := spinBaselineStand(t, ctx)

	up, err := Run(ctx, dsn, "sg")
	require.NoError(t, err)
	require.Equal(t, int64(27), up.Version)
	_, err = pool.Exec(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('Revert Org', 'revert-org')`)
	require.NoError(t, err)
	requireRowCount(t, ctx, pool, "organizations", 1, "before the interrupted revert")

	// The honest mid-revert crash: the applied number line is 27, 26, 25, 24,
	// 22, 21, 20, 19, 18, 17, 16, 15, 14 (the embedded set carries the reserved
	// gap 0023 as a no-file version — 0024 is present via e03p01b and 0025
	// via e04p01a — so the revert walks the applied
	// versions, not the plain number line) — the poisoned 0013
	// down fails and leaves the driver's dirty record on the failed step's
	// target position (the driver marks the target dirty before running the
	// file). The source carries every pair (the revert needs the
	// 0014/0015/0016/0017/0018/0019/0020/0021/0022, 0024, 0025, 0026 and
	// 0027 down files) —
	// only the 0013 down body is poisoned. The true schema position stays
	// 13: its down never completed a statement.
	poisoned := subsetMigrator(t, ctx, dsn,
		corruptEmbeddedSubsetFile(t, 27, "0013_guard_pack_state.down.sql"))
	require.Error(t, poisoned.Migrate(uint(12)),
		"the poisoned 0013 down must fail the revert at 13")
	requireBookkeeping(t, ctx, pool, 12, true,
		"the failed revert must leave the driver's dirty record on the failed step's target position")
	requireTableMissing(t, ctx, pool, "principal_delegations",
		"version 14 must have reverted before the failure")
	requireTableExists(t, dsn, "guard_pack_state")
	requireTableExists(t, dsn, "batch_files")

	// The shipped runner refuses loudly on the dirty record.
	_, err = Run(ctx, dsn, "sg")
	require.Error(t, err, "the runner must refuse a dirty database mid-revert")
	require.Contains(t, err.Error(), "Dirty database version 12")

	// Operator recovery: force the true position (13 — its down never
	// completed), then retry the revert to the exact target with the real
	// files.
	full := subsetMigrator(t, ctx, dsn, extractEmbeddedSubset(t, 27))
	require.NoError(t, full.Force(13), "the force recovery must clear the dirty position")
	require.NoError(t, full.Migrate(uint(12)), "the retried revert must land on the target")
	requireBookkeeping(t, ctx, pool, 12, false)
	requireTableMissing(t, ctx, pool, "guard_pack_state",
		"the retried revert must complete the drop")
	requireTableExists(t, dsn, "batch_files")

	// The cycle completes: re-upgrade to the head, structure back empty, probe
	// data intact, bookkeeping single-row.
	res, err := Run(ctx, dsn, "sg")
	require.NoError(t, err)
	require.Equal(t, int64(27), res.Version)
	requireBookkeeping(t, ctx, pool, 27, false)
	requireRowCount(t, ctx, pool, "guard_pack_state", 0,
		"the re-created structure starts empty: deleted data is not restored")
	requireRowCount(t, ctx, pool, "organizations", 1,
		"the probe row must survive the whole interrupted cycle untouched")
}
