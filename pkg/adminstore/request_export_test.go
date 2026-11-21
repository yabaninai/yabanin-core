package adminstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeExportList pages a fixed row set with 200 rows per page, mirroring the
// store page size the export walk relies on.
func fakeExportList(rows []RequestListRow, calls *int) requestExportPage {
	return func(_ context.Context, f RequestListFilters) ([]RequestListRow, int, error) {
		*calls++
		start := (f.Page - 1) * fakeExportPageSize
		if start >= len(rows) {
			return []RequestListRow{}, len(rows), nil
		}
		end := start + fakeExportPageSize
		if end > len(rows) {
			end = len(rows)
		}
		return rows[start:end], len(rows), nil
	}
}

// fakeExportDetail serves details by immutable row key, mirroring the
// exact-row detail address the export walk uses.
func fakeExportDetail(rows map[int64]*RequestDetail) requestExportDetail {
	return func(_ context.Context, orgID string, rowKey int64) (*RequestDetail, error) {
		if d, ok := rows[rowKey]; ok && d.OrgID == orgID {
			return d, nil
		}
		return nil, ErrNotFound
	}
}

func TestStreamRequestExportRejectsInvalidOptions(t *testing.T) {
	list := fakeExportList(nil, new(int))
	detail := fakeExportDetail(map[int64]*RequestDetail{})
	emit := func(*RequestDetail) error { return nil }
	if _, err := streamRequestExport(context.Background(), list, detail, RequestListFilters{}, RequestPayloadAccess{}, 0, emit); err == nil {
		t.Fatal("maxRows < 1 must be rejected")
	}
	if _, err := streamRequestExport(context.Background(), list, detail, RequestListFilters{}, RequestPayloadAccess{}, 10, nil); err == nil {
		t.Fatal("nil emit must be rejected")
	}
	if _, err := streamRequestExport(context.Background(), nil, detail, RequestListFilters{}, RequestPayloadAccess{}, 10, emit); err == nil {
		t.Fatal("nil page fetcher must be rejected")
	}
	if _, err := (&Store{}).StreamRequestExport(context.Background(), RequestListFilters{}, RequestPayloadAccess{}, 10, emit); err == nil {
		t.Fatal("a store without a database must fail closed")
	}
	var missing *Store
	if _, err := missing.StreamRequestExport(context.Background(), RequestListFilters{}, RequestPayloadAccess{}, 10, emit); err == nil {
		t.Fatal("a nil store must fail closed")
	}
}

func TestStreamRequestExportFailsClosedOnMidExportListError(t *testing.T) {
	rows := make([]RequestListRow, 0, 201)
	for i := 0; i < 201; i++ {
		rows = append(rows, RequestListRow{RowKey: int64(i + 1), RequestID: fmt.Sprintf("req-%03d", i), OrgID: "org-1"})
	}
	calls := 0
	list := func(_ context.Context, f RequestListFilters) ([]RequestListRow, int, error) {
		calls++
		if f.Page == 1 {
			return rows, len(rows), nil
		}
		return nil, len(rows), errors.New("page 2 read failed")
	}
	_, err := streamRequestExport(context.Background(), list, fakeExportDetail(nil), RequestListFilters{OrgID: "org-1"}, RequestPayloadAccess{}, 1000, func(*RequestDetail) error { return nil })
	if err == nil || err.Error() != "page 2 read failed" {
		t.Fatalf("err = %v, want the mid-export page failure to surface", err)
	}
	if calls != 3 {
		// One total-count fetch plus one fetch per page (201 rows → 2 pages).
		t.Fatalf("calls=%d, want count + two page fetches", calls)
	}
}

func TestStreamRequestExportFailsClosedOnListError(t *testing.T) {
	calls := 0
	listErr := errors.New("list failed")
	list := func(context.Context, RequestListFilters) ([]RequestListRow, int, error) {
		calls++
		return nil, 0, listErr
	}
	emitted := 0
	_, err := streamRequestExport(context.Background(), list, fakeExportDetail(nil), RequestListFilters{}, RequestPayloadAccess{}, 10, func(*RequestDetail) error { emitted++; return nil })
	if !errors.Is(err, listErr) {
		t.Fatalf("list error = %v, want %v", err, listErr)
	}
	if calls != 1 || emitted != 0 {
		t.Fatalf("calls=%d emitted=%d, want the walk to stop before emitting", calls, emitted)
	}
}

func TestStreamRequestExportRejectsUnboundedResult(t *testing.T) {
	calls := 0
	list := func(context.Context, RequestListFilters) ([]RequestListRow, int, error) {
		calls++
		return nil, 11, nil
	}
	_, err := streamRequestExport(context.Background(), list, fakeExportDetail(nil), RequestListFilters{}, RequestPayloadAccess{}, 10, func(*RequestDetail) error { return nil })
	if !errors.Is(err, ErrRequestExportTooLarge) {
		t.Fatalf("err = %v, want ErrRequestExportTooLarge", err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d, want the cap check before paging", calls)
	}
}

// TestStreamRequestExportCapsEmittedRowsAtMaxRows is the FIX-05 regression
// for the emitted cap (CA-05, second finding): a drifting page source that
// grows mid-walk must never push the ACTUAL emitted count past maxRows. The
// walk fails loudly with ErrRequestExportTooLarge once a (maxRows+1)-th
// candidate row appears. (This is NOT an HTTP 1000-cap bypass proof: the
// handler pre-checks the total before streaming; this pins the helper cap.)
func TestStreamRequestExportCapsEmittedRowsAtMaxRows(t *testing.T) {
	calls := 0
	list := func(_ context.Context, f RequestListFilters) ([]RequestListRow, int, error) {
		calls++
		if calls == 1 {
			// The count fetch reports 1 row, so the pre-check passes.
			return nil, 1, nil
		}
		// The page then serves 2 rows, as a concurrent insert would.
		return []RequestListRow{{RowKey: 1, RequestID: "old"}, {RowKey: 2, RequestID: "new"}}, 2, nil
	}
	detail := func(_ context.Context, _ string, _ int64) (*RequestDetail, error) { return &RequestDetail{}, nil }
	emitted := 0
	_, err := streamRequestExport(context.Background(), list, detail, RequestListFilters{}, RequestPayloadAccess{}, 1, func(*RequestDetail) error { emitted++; return nil })
	if !errors.Is(err, ErrRequestExportTooLarge) {
		t.Fatalf("err = %v, want ErrRequestExportTooLarge past the emitted cap", err)
	}
	if emitted != 1 {
		t.Fatalf("emitted=%d, want exactly maxRows=1 emitted before the cap error", emitted)
	}
}

// TestStreamRequestExportNeverReemitsDriftedRows is the FIX-05 regression
// for the OFFSET duplicate (CA-05): a page source whose first row is newly
// inserted between page fetches shifts every OFFSET window, so the previous
// 200th row re-appears at the head of page 2. The walk must never emit a
// request ID twice even then (the snapshot transaction keeps the real store
// from drifting at all; this guards the walk against any backend that does).
func TestStreamRequestExportNeverReemitsDriftedRows(t *testing.T) {
	rows := make([]RequestListRow, 201)
	for i := range rows {
		// Stable identity: the key belongs to the row's request id, never
		// to its position in the window.
		rows[i] = RequestListRow{RowKey: int64(i + 1), RequestID: fmt.Sprintf("req-%03d", i)}
	}
	calls := 0
	list := driftingExportList(&rows, &calls)
	seen := map[string]int{}
	detail := func(_ context.Context, _ string, rowKey int64) (*RequestDetail, error) {
		seen[driftRowID(rowKey)]++
		return &RequestDetail{}, nil
	}
	_, err := streamRequestExport(context.Background(), list, detail, RequestListFilters{}, RequestPayloadAccess{}, 1000, func(*RequestDetail) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for id, n := range seen {
		if n > 1 {
			t.Fatalf("request %s emitted %d times after the concurrent insert", id, n)
		}
	}
	// No physical row may repeat. The drifted-in "new" row sits inside the
	// already-consumed first OFFSET window, so the walk's guarantee here is
	// exactly "no duplicates": every originally-visible row appears exactly
	// once. Making the drifted row visible (or invisible) is the snapshot
	// transaction's contract, proven on real Postgres in
	// TestExportSnapshot_RacingInsertsAndDeletes.
	if len(seen) != 201 || seen["req-199"] != 1 || seen["req-200"] != 1 || seen["new"] != 0 {
		t.Fatalf("walked %d distinct rows (req-199=%d req-200=%d new=%d), want the 201 original rows exactly once each", len(seen), seen["req-199"], seen["req-200"], seen["new"])
	}
}

// driftingExportList pages over *rows but inserts a new head row between
// page 1 and page 2, shifting every OFFSET window like a racing writer would.
func driftingExportList(rows *[]RequestListRow, calls *int) requestExportPage {
	return func(_ context.Context, f RequestListFilters) ([]RequestListRow, int, error) {
		*calls++
		if *calls == 1 {
			return nil, len(*rows), nil
		}
		if *calls == 3 {
			// The racing insert lands between page 1 and page 2.
			*rows = append([]RequestListRow{{RowKey: 1000, RequestID: "new"}}, *rows...)
		}
		start := (f.Page - 1) * fakeExportPageSize
		end := start + fakeExportPageSize
		if end > len(*rows) {
			end = len(*rows)
		}
		out := make([]RequestListRow, end-start)
		copy(out, (*rows)[start:end])
		return out, len(*rows), nil
	}
}

// driftRowID maps the drift test's stable row keys back to their request
// ids for assertion purposes (1..201 = req-000..req-200, 1000 = "new").
func driftRowID(rowKey int64) string {
	if rowKey == 1000 {
		return "new"
	}
	return fmt.Sprintf("req-%03d", rowKey-1)
}

// fakeExportPageSize mirrors the store page size fakeExportList relies on.
const fakeExportPageSize = 200

// TestStreamRequestExportRequiresSnapshotPool pins the store-backed fail
// closed path: a mock-db store (no pool) cannot open the export snapshot
// transaction, so the export must refuse instead of paging without one.
func TestStreamRequestExportRequiresSnapshotPool(t *testing.T) {
	store := newForTest(&mockDB{}, newTestLogger(), nil)
	_, err := store.StreamRequestExport(context.Background(), RequestListFilters{}, RequestPayloadAccess{}, 10, func(*RequestDetail) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("err = %v, want the missing-snapshot-pool failure", err)
	}
}

func TestStreamRequestExportPagesSkipsMissingAndStopsOnEmitError(t *testing.T) {
	rows := make([]RequestListRow, 0, 401)
	for i := 0; i < 401; i++ {
		rows = append(rows, RequestListRow{RowKey: int64(i + 1), RequestID: fmt.Sprintf("req-%03d", i), OrgID: "org-1"})
	}
	calls := 0
	list := fakeExportList(rows, &calls)
	details := map[int64]*RequestDetail{}
	for i := range rows {
		details[rows[i].RowKey] = &RequestDetail{RequestID: rows[i].RequestID, OrgID: "org-1"}
	}
	delete(details, 1) // vanished mid-export: skipped, not fatal

	var emitted []string
	detailCalls := 0
	detail := grantCheckingDetail(t, fakeExportDetail(details), &detailCalls)
	total, err := streamRequestExport(context.Background(), list, detail, RequestListFilters{OrgID: "org-1"}, RequestPayloadAccess{Grant: true}, 1000, collectingEmit(&emitted, 2))
	if err == nil || err.Error() != "stop the stream" {
		t.Fatalf("err = %v, want the emit error to stop the walk", err)
	}
	if total != 401 {
		t.Fatalf("total = %d, want 401", total)
	}
	if len(emitted) != 2 {
		t.Fatalf("emitted %d rows, want exactly the two before the stop", len(emitted))
	}
	if calls != 2 || detailCalls != 4 {
		// req-000 (missing) is skipped, req-001/002 are emitted, req-003's
		// detail is loaded before its emit rejects and stops the walk.
		t.Fatalf("calls=%d detailCalls=%d, want two pages and four detail loads", calls, detailCalls)
	}
}

// grantCheckingDetail wraps a detail source and fails the test when a call
// arrives without the grant boundary decision in ctx.
func grantCheckingDetail(t *testing.T, next requestExportDetail, calls *int) requestExportDetail {
	t.Helper()
	return func(ctx context.Context, orgID string, rowKey int64) (*RequestDetail, error) {
		*calls++
		if access, ok := RequestPayloadAccessFromContext(ctx); !ok || !access.Grant {
			t.Errorf("detail for row %d must receive the boundary decision in ctx, got %+v", rowKey, access)
		}
		return next(ctx, orgID, rowKey)
	}
}

// collectingEmit records each emitted request id and rejects once stopAt rows
// were already collected, so tests can observe where the walk actually stops.
func collectingEmit(emitted *[]string, stopAt int) func(*RequestDetail) error {
	return func(d *RequestDetail) error {
		if len(*emitted) == stopAt {
			return errors.New("stop the stream")
		}
		*emitted = append(*emitted, d.RequestID)
		return nil
	}
}

func TestStreamRequestExportSurfacesDetailErrorsAndSkipsNotFound(t *testing.T) {
	rows := []RequestListRow{{RowKey: 1, RequestID: "req-a", OrgID: "org-1"}, {RowKey: 2, RequestID: "req-b", OrgID: "org-1"}}
	calls := 0
	detailErr := errors.New("detail scan failed")
	detail := func(_ context.Context, _ string, rowKey int64) (*RequestDetail, error) {
		if rowKey == 1 {
			return nil, ErrNotFound
		}
		return nil, detailErr
	}
	_, err := streamRequestExport(context.Background(), fakeExportList(rows, &calls), detail, RequestListFilters{OrgID: "org-1"}, RequestPayloadAccess{}, 10, func(*RequestDetail) error { return nil })
	if !errors.Is(err, detailErr) {
		t.Fatalf("err = %v, want %v (NotFound must skip, real errors must surface)", err, detailErr)
	}
}

func TestStreamRequestExportCompletesAndCarriesAccessIntoEveryRow(t *testing.T) {
	rows := []RequestListRow{{RowKey: 1, RequestID: "req-a", OrgID: "org-1"}, {RowKey: 2, RequestID: "req-b", OrgID: "org-1"}}
	calls := 0
	details := map[int64]*RequestDetail{
		1: {RequestID: "req-a", OrgID: "org-1"},
		2: {RequestID: "req-b", OrgID: "org-1"},
	}
	access := RequestPayloadAccess{UserID: "subject-a", Grant: true, Originals: true}
	var seen []RequestPayloadAccess
	detail := func(ctx context.Context, orgID string, rowKey int64) (*RequestDetail, error) {
		a, ok := RequestPayloadAccessFromContext(ctx)
		if !ok || a != access {
			t.Errorf("detail for row %d must carry the boundary decision, got %+v ok=%t", rowKey, a, ok)
		}
		seen = append(seen, a)
		return fakeExportDetail(details)(ctx, orgID, rowKey)
	}
	var emitted []string
	total, err := streamRequestExport(context.Background(), fakeExportList(rows, &calls), detail, RequestListFilters{OrgID: "org-1"}, access, 10, func(d *RequestDetail) error {
		emitted = append(emitted, d.RequestID)
		return nil
	})
	if err != nil {
		t.Fatalf("complete walk must not fail: %v", err)
	}
	if total != 2 || len(emitted) != 2 || emitted[0] != "req-a" || emitted[1] != "req-b" {
		t.Fatalf("total=%d emitted=%v, want both rows in result order", total, emitted)
	}
	if len(seen) != 2 {
		t.Fatalf("detail calls=%d, want one per row", len(seen))
	}
}

func TestSearchRequestArchiveDelegatesToValidatedHotList(t *testing.T) {
	if _, _, err := (&Store{}).SearchRequestArchive(context.Background(), RequestListFilters{}); err == nil {
		t.Fatal("archive search without a database must fail closed")
	}
}

// TestStreamRequestExportEmitsEveryRowSharingACorrelation is the core
// exact-row identity regression (0028 contract): two legitimate invocations
// may share the client-supplied request id, bill independently and log as
// two physical request_logs rows. The walk must emit BOTH rows, load each
// detail by its own row key (never by the shared correlation), and preserve
// each row's own usage in the emitted records.
func TestStreamRequestExportEmitsEveryRowSharingACorrelation(t *testing.T) {
	rows := []RequestListRow{
		{RowKey: 11, RequestID: "same-correlation", OrgID: "org-1"},
		{RowKey: 22, RequestID: "same-correlation", OrgID: "org-1"},
	}
	calls := 0
	list := fakeExportList(rows, &calls)
	details := map[int64]*RequestDetail{
		11: {RequestID: "same-correlation", OrgID: "org-1", TokensIn: 7},
		22: {RequestID: "same-correlation", OrgID: "org-1", TokensIn: 19},
	}
	var loadedKeys []int64
	detail := func(ctx context.Context, orgID string, rowKey int64) (*RequestDetail, error) {
		loadedKeys = append(loadedKeys, rowKey)
		return fakeExportDetail(details)(ctx, orgID, rowKey)
	}
	var tokens []int64
	total, err := streamRequestExport(context.Background(), list, detail,
		RequestListFilters{OrgID: "org-1"}, RequestPayloadAccess{OrgWideMetadata: true}, 10,
		func(d *RequestDetail) error { tokens = append(tokens, d.TokensIn); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(tokens) != 2 {
		t.Fatalf("total=%d emitted=%d, want both physical rows exported", total, len(tokens))
	}
	if tokens[0] != 7 || tokens[1] != 19 {
		t.Fatalf("tokens=%v, want each row's own usage (7 then 19)", tokens)
	}
	if len(loadedKeys) != 2 || loadedKeys[0] != 11 || loadedKeys[1] != 22 {
		t.Fatalf("detail loads addressed keys %v, want each physical row key once (11, 22)", loadedKeys)
	}
}

// TestStreamRequestExportDedupesRepeatedPhysicalRow pins the drift control on
// the exact identity: a page source that re-serves the SAME physical row
// (same row key) across pages must not emit it twice — regardless of its
// request id.
func TestStreamRequestExportDedupesRepeatedPhysicalRow(t *testing.T) {
	calls := 0
	list := func(_ context.Context, f RequestListFilters) ([]RequestListRow, int, error) {
		calls++
		// Page 1: rows 1..200. Page 2: the drifted source re-serves row 200
		// (key 200) before the new tail row 201.
		if f.Page == 1 {
			rows := make([]RequestListRow, 200)
			for i := range rows {
				rows[i] = RequestListRow{RowKey: int64(i + 1), RequestID: fmt.Sprintf("req-%03d", i)}
			}
			return rows, 201, nil
		}
		return []RequestListRow{{RowKey: 200, RequestID: "req-199"}, {RowKey: 201, RequestID: "req-200"}}, 201, nil
	}
	emitted := 0
	detail := func(_ context.Context, _ string, _ int64) (*RequestDetail, error) {
		return &RequestDetail{}, nil
	}
	_, err := streamRequestExport(context.Background(), list, detail, RequestListFilters{}, RequestPayloadAccess{}, 1000, func(*RequestDetail) error {
		emitted++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if emitted != 201 {
		t.Fatalf("emitted=%d, want 201: the repeated physical row must be deduped, the tail row kept", emitted)
	}
}

// TestStreamRequestExportIdenticalTimestampsAcrossPageBoundary walks 201 rows
// that share created_at AND the request id, so only the immutable row key
// distinguishes them — the ordering contract the list's final rl.id tiebreak
// provides. Across the 200/201 page boundary no row may be lost or doubled.
// (The SQL-level tiebreak itself is proven on real Postgres by
// TestExportIdenticalKeysPageBoundary_RowKeyTiebreak.)
func TestStreamRequestExportIdenticalTimestampsAcrossPageBoundary(t *testing.T) {
	stamp := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	rows := make([]RequestListRow, 0, 201)
	for i := 0; i < 201; i++ {
		rows = append(rows, RequestListRow{RowKey: int64(i + 1), RequestID: "same-correlation", OrgID: "org-1", CreatedAt: stamp})
	}
	calls := 0
	list := fakeExportList(rows, &calls)
	seen := map[int64]int{}
	detail := func(_ context.Context, _ string, rowKey int64) (*RequestDetail, error) {
		seen[rowKey]++
		return &RequestDetail{}, nil
	}
	total, err := streamRequestExport(context.Background(), list, detail,
		RequestListFilters{OrgID: "org-1"}, RequestPayloadAccess{OrgWideMetadata: true}, 1000,
		func(*RequestDetail) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if total != 201 || len(seen) != 201 {
		t.Fatalf("total=%d distinct=%d, want all 201 identical-key rows across the page boundary", total, len(seen))
	}
	for key, n := range seen {
		if n != 1 {
			t.Fatalf("row key %d walked %d times, want exactly once", key, n)
		}
	}
}
