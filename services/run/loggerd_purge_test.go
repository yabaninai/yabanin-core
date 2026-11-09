package run

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W-LOGG purge contract: the hourly retention delete runs in bounded
// batches (one long DELETE on a big backlog used to hold a transaction for
// the whole purge) and the loop observes shutdown (select on ctx.Done()).

const (
	purgeTestOrg = "aaaa0000-0000-4000-8000-00000000a11c"
	// purgeTestDays is the retention window every test in this file purges
	// with; the setup sweep must use the SAME window so the cutoffs cannot
	// drift apart.
	purgeTestDays = 10
)

func seedPurgeRows(t *testing.T, pool *pgxpool.Pool, n int) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO organizations (id, name, slug) VALUES ($1, 'purge-test-org', 'purge-test')
		ON CONFLICT (id) DO NOTHING`, purgeTestOrg)
	require.NoError(t, err)
	// The Postgres stand is shared per test binary: rows seeded by a previous
	// pass (e.g. the cancelled-purge fixture, which by design SURVIVES its
	// purge) would otherwise be swept up by the next purge and inflate the
	// exact deleted-row assertions under -count>1. Expired rows come only
	// from this file — every other suite writes fresh rows — so sweeping
	// everything past the cutoff makes the state deterministic without
	// touching live data.
	_, err = pool.Exec(context.Background(),
		`DELETE FROM request_logs WHERE created_at < now() - make_interval(days => $1)`, purgeTestDays)
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(), `
		INSERT INTO request_logs (org_id, model_requested, model_used, status_code, duration_ms, created_at)
		SELECT $1, 'purge-test', '', 0, 0, now() - interval '30 days'
		FROM generate_series(1, $2)`, purgeTestOrg, n)
	require.NoError(t, err)
}

func purgeRowCount(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM request_logs WHERE org_id=$1 AND model_requested='purge-test'`, purgeTestOrg).Scan(&n))
	return n
}

// A backlog larger than one batch drains fully: 6000 rows with a 5000-row
// batch bound must delete across at least two statements.
func TestPurgeExpiredRequestLogs_DrainsBacklogInBatches(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	seedPurgeRows(t, pool, 6000)
	require.Equal(t, int64(6000), purgeRowCount(t, pool))

	deleted, err := purgeExpiredRequestLogs(context.Background(), pool, 5000, purgeTestDays)
	require.NoError(t, err)
	assert.Equal(t, int64(6000), deleted, "the whole backlog drains across batches")
	assert.Zero(t, purgeRowCount(t, pool))
}

// A single batch smaller than the bound finishes in one statement.
func TestPurgeExpiredRequestLogs_SingleBatch(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	seedPurgeRows(t, pool, 3)

	deleted, err := purgeExpiredRequestLogs(context.Background(), pool, 5000, purgeTestDays)
	require.NoError(t, err)
	assert.Equal(t, int64(3), deleted)
	assert.Zero(t, purgeRowCount(t, pool))
}

// Shutdown wins over the backlog: a cancelled context stops the loop early
// and reports the interruption without deleting anything.
func TestPurgeExpiredRequestLogs_StopsOnCancelledContext(t *testing.T) {
	pool := testdb.PostgresRegion(t, "e2e")
	seedPurgeRows(t, pool, 5)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deleted, err := purgeExpiredRequestLogs(ctx, pool, 5000, purgeTestDays)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, deleted, "a cancelled purge deletes nothing")
	assert.Equal(t, int64(5), purgeRowCount(t, pool), "rows survive an interrupted purge")
}
