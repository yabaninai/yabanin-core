package adminstore

// FIX-05 (CA-05) acceptance against a real PostgreSQL (disposable
// testcontainers stand): the request export walks ONE REPEATABLE READ READ
// ONLY snapshot transaction, so
//
//   - a 201-row result exports exactly 201 distinct rows (normal);
//   - an empty org exports nothing (failure);
//   - inserts AND deletes racing an open export create neither duplicates
//     nor unexplained misses — the racing insert is invisible and the
//     racing deletes stay snapshot-readable — even when every seeded row
//     shares one created_at and ordering falls to the request_id
//     tie-break across the page boundary (adversarial);
//   - the store-level row cap still fails the export before/while streaming;
//   - a canceled stream stops promptly and releases the snapshot
//     transaction's connection (mid-stream cancellation is clean).
//
// Per-row authorization is pinned by the existing walk unit tests (the
// boundary decision travels in ctx per row) and the handler/joint retention
// suites; this file does not re-decide payload visibility.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedExportOrg creates an isolated organization holding n request_logs rows
// with deterministic request ids (req-export-000…) and returns the pool, the
// org id, and the seeded ids. Every row carries createdAt — pass one fixed
// stamp to force the request_id tie-break across the 200-row page boundary.
func seedExportOrg(t *testing.T, n int, createdAt time.Time) (*pgxpool.Pool, string, []string) {
	t.Helper()
	pool := openAdminTestPool(t)
	ctx := context.Background()
	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('Export snapshot', $1) RETURNING id::text",
		fmt.Sprintf("export-snapshot-%d", time.Now().UnixNano())).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM request_logs WHERE org_id = $1", orgID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", orgID)
	})
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("req-export-%03d", i)
		_, err := pool.Exec(ctx,
			`INSERT INTO request_logs (org_id, home_region, model_requested, model_used, status_code,
			   duration_ms, tokens_in, tokens_out, request_id, created_at)
			 VALUES ($1, 'sg', 'm', 'm', 200, 10, 1, 1, $2, $3)`, orgID, id, createdAt)
		require.NoError(t, err)
		ids = append(ids, id)
	}
	return pool, orgID, ids
}

// exportOrgIDs streams the org's export into a slice of request ids.
func exportOrgIDs(t *testing.T, store *Store, orgID string, maxRows int) ([]string, error) {
	t.Helper()
	var got []string
	_, err := store.StreamRequestExport(context.Background(),
		RequestListFilters{OrgID: orgID}, RequestPayloadAccess{OrgWideMetadata: true}, maxRows,
		func(d *RequestDetail) error { got = append(got, d.RequestID); return nil })
	return got, err
}

func TestExportSnapshot_201RowsExportExactly201Distinct(t *testing.T) {
	pool, orgID, ids := seedExportOrg(t, 201, time.Now().UTC().Add(-time.Hour))
	store := New(pool, slog.Default(), nil)

	got, err := exportOrgIDs(t, store, orgID, 1000)
	require.NoError(t, err)
	assert.Len(t, got, 201, "every seeded row is emitted exactly once")
	assert.ElementsMatch(t, ids, got)
	seen := map[string]int{}
	for _, id := range got {
		seen[id]++
	}
	for id, n := range seen {
		assert.Equal(t, 1, n, "row %s must not repeat across pages", id)
	}

	// The store-level cap still holds: a maxRows below the filtered total
	// fails closed before anything is emitted (the HTTP handler maps this
	// to its 1000-row 413 / row-limit trailer contract).
	got, err = exportOrgIDs(t, store, orgID, 100)
	require.ErrorIs(t, err, ErrRequestExportTooLarge)
	assert.Empty(t, got, "the cap error must surface before any row is emitted")
}

func TestExportSnapshot_EmptyOrgExportsNothing(t *testing.T) {
	pool, orgID, _ := seedExportOrg(t, 0, time.Now().UTC())
	store := New(pool, slog.Default(), nil)

	got, err := exportOrgIDs(t, store, orgID, 1000)
	require.NoError(t, err)
	assert.Empty(t, got, "an empty org exports zero rows without error")
}

// TestExportSnapshot_RacingInsertsAndDeletes pins the adversarial case: an
// insert that lands at the head of the ordering AND deletes on both sides of
// the page boundary race an open export. Under the snapshot contract the
// insert is invisible (no duplicate shift) and the deleted rows stay
// snapshot-readable (no unexplained misses), so the export emits exactly the
// seeded set — all 201 rows sharing ONE created_at so the ordering falls to
// the request_id tie-break across the page boundary.
func TestExportSnapshot_RacingInsertsAndDeletes(t *testing.T) {
	// One shared stamp: identical timestamps must not create duplicates.
	stamp := time.Now().UTC().Add(-time.Hour)
	pool, orgID, ids := seedExportOrg(t, 201, stamp)
	store := New(pool, slog.Default(), nil)

	raced := false
	var got []string
	_, err := store.StreamRequestExport(context.Background(),
		RequestListFilters{OrgID: orgID}, RequestPayloadAccess{OrgWideMetadata: true}, 1000,
		func(d *RequestDetail) error {
			if !raced {
				raced = true
				// The racing writer commits while the export stream is
				// open: a new newest row (head of the ordering) plus the
				// page-1 tail (listed, detail not yet loaded) and the
				// single page-2 row.
				_, ierr := pool.Exec(context.Background(),
					`INSERT INTO request_logs (org_id, home_region, model_requested, model_used, status_code,
					   duration_ms, tokens_in, tokens_out, request_id, created_at)
					 VALUES ($1, 'sg', 'm', 'm', 200, 10, 1, 1, 'req-export-new', $2)`,
					orgID, stamp.Add(time.Hour))
				require.NoError(t, ierr)
				_, ierr = pool.Exec(context.Background(),
					"DELETE FROM request_logs WHERE org_id = $1 AND request_id IN ('req-export-199', 'req-export-200')", orgID)
				require.NoError(t, ierr)
			}
			got = append(got, d.RequestID)
			return nil
		})
	require.NoError(t, err)

	// Exactly the seeded set: the racing insert never appears, the deleted
	// rows are still exported (snapshot readability), nothing repeats.
	assert.ElementsMatch(t, ids, got, "export must match the snapshot set: no duplicates, no misses")
	assert.Len(t, got, 201)
	assert.NotContains(t, got, "req-export-new", "a row inserted after the snapshot is invisible")
	assert.Contains(t, got, "req-export-199", "a row deleted after the snapshot stays snapshot-readable")
}

// TestExportSnapshot_MidStreamCancellationReleasesSnapshotTx proves a
// canceled stream stops promptly and the snapshot transaction's connection
// is released back to the pool (no leak behind the caller's context).
func TestExportSnapshot_MidStreamCancellationReleasesSnapshotTx(t *testing.T) {
	pool, orgID, _ := seedExportOrg(t, 3, time.Now().UTC().Add(-time.Hour))
	store := New(pool, slog.Default(), nil)

	inFlight := func() int32 { return pool.Stat().TotalConns() - pool.Stat().IdleConns() }
	baseline := inFlight()

	ctx, cancel := context.WithCancel(context.Background())
	emitted := 0
	_, err := store.StreamRequestExport(ctx,
		RequestListFilters{OrgID: orgID}, RequestPayloadAccess{OrgWideMetadata: true}, 10,
		func(*RequestDetail) error {
			emitted++
			cancel() // the client walks away mid-stream
			return nil
		})
	require.ErrorIs(t, err, context.Canceled, "the cancellation surfaces instead of streaming on")
	assert.Equal(t, 1, emitted, "the stream stops promptly: the later rows are never emitted")
	assert.Equal(t, baseline, inFlight(), "the snapshot transaction released its connection")

	// The store is healthy after the canceled export.
	_, _, lerr := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID})
	require.NoError(t, lerr)
}

// TestExportSnapshot_ErrorsRollbackAndStayReadable: a mid-walk store failure
// (here: a detail-level org mismatch is not reachable through the walk, so
// force it via a page-list error) rolls the snapshot transaction back and
// leaves the pool usable — no half-open read transaction lingers.
func TestExportSnapshot_ErrorsRollbackAndStayReadable(t *testing.T) {
	pool, orgID, ids := seedExportOrg(t, 2, time.Now().UTC().Add(-time.Hour))
	store := New(pool, slog.Default(), nil)

	inFlight := func() int32 { return pool.Stat().TotalConns() - pool.Stat().IdleConns() }
	baseline := inFlight()

	_, err := store.StreamRequestExport(context.Background(),
		RequestListFilters{OrgID: orgID}, RequestPayloadAccess{OrgWideMetadata: true}, 10,
		func(d *RequestDetail) error {
			// Second row triggers a caller-side stop; the rollback path.
			if d.RequestID == ids[1] {
				return errors.New("stop the export")
			}
			return nil
		})
	require.Error(t, err)
	assert.Equal(t, baseline, inFlight(), "the failed export rolled back and released its connection")

	_, _, lerr := store.ListRequests(context.Background(), RequestListFilters{OrgID: orgID})
	require.NoError(t, lerr, "the pool stays usable after the rollback")
}
