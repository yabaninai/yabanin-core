package adminstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ErrRequestExportTooLarge reports that an export would exceed its hard row cap.
var ErrRequestExportTooLarge = errors.New("request export exceeds row limit")

// exportPageSize is the page size the export walk uses (the store list cap).
const exportPageSize = 200

// SearchRequestArchive is the archive query contract. Until N10 creates an
// archive zone, it intentionally searches the hot request_logs table using
// the same validated filters and payload authorization predicates.
func (s *Store) SearchRequestArchive(ctx context.Context, filters RequestListFilters) ([]RequestListRow, int, error) {
	return s.ListRequests(ctx, filters)
}

// requestExportPage fetches one validated page of request rows.
type requestExportPage func(context.Context, RequestListFilters) ([]RequestListRow, int, error)

// requestExportDetail loads one authorized request detail by its immutable
// request_logs row key (org + id), so every emitted record is the exact
// physical row the list page selected.
type requestExportDetail func(context.Context, string, int64) (*RequestDetail, error)

// exportQueryRunner is the read surface the export runs on. It is satisfied
// both by the pool adapter (pgxdb) and by pgx.Tx, so the whole walk — count,
// pages, and every detail — can execute inside one snapshot transaction.
type exportQueryRunner interface {
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

// StreamRequestExport walks the bounded request result in pages and emits each
// authorized detail independently. Every read — the count, each page, and
// each detail — runs inside ONE REPEATABLE READ READ ONLY transaction, so the
// export reflects a single point-in-time snapshot: all rows committed before
// the snapshot are exported exactly once, and rows inserted or deleted after
// the snapshot are invisible to every page and detail read. The snapshot
// therefore rules out both OFFSET-shift duplicates (a first row inserted
// between pages) and unexplained misses (a listed row deleted before its
// detail load): MVCC keeps snapshot-visible rows readable even when a
// concurrent writer deletes them, so the delete neither aborts the export
// nor skips the row.
//
// The payload boundary decision travels in ctx per row, so the detail loader
// re-applies it row by row. Callback errors stop the stream promptly. The
// snapshot transaction is rolled back on every error path (including context
// cancellation) and never holds writes. Resource shape: the walk holds one
// pool connection for the stream's duration — bounded by maxRows, the byte
// cap the HTTP caller enforces per line, and the caller's context.
func (s *Store) StreamRequestExport(ctx context.Context, filters RequestListFilters, access RequestPayloadAccess, maxRows int, emit func(*RequestDetail) error) (int, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("database not available")
	}
	if s.pool == nil {
		return 0, fmt.Errorf("request export snapshot requires a database pool")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, fmt.Errorf("begin request export snapshot: %w", err)
	}
	// Rollback is the error path (the explicit Commit below runs on success);
	// WithoutCancel so a canceled stream still releases its connection.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	total, err := streamRequestExport(ctx,
		func(ctx context.Context, f RequestListFilters) ([]RequestListRow, int, error) {
			return listRequestsOn(ctx, tx, f)
		},
		func(ctx context.Context, orgID string, rowKey int64) (*RequestDetail, error) {
			return getRequestDetailOnKey(ctx, tx, orgID, rowKey)
		},
		filters, access, maxRows, emit)
	if err != nil {
		return total, err
	}
	if err := tx.Commit(ctx); err != nil {
		return total, fmt.Errorf("commit request export snapshot: %w", err)
	}
	return total, nil
}

// streamRequestExport is the storage-independent export walk, so the paging,
// cap, and boundary semantics stay unit-testable without a live database.
//
// Row identity is EXACT: the client-supplied request id is a correlation
// field only (0028) — two legitimate invocations may share it, each billing
// and logging as its own request_logs row — so the walk addresses every
// detail by the immutable row key the list selected and emits each physical
// row independently.
//
// The list fetcher is expected to serve a stable snapshot (the store-backed
// path pins one with a REPEATABLE READ transaction). On top of that contract
// the walk adds two backend-independent guarantees. First, a physical row is
// never emitted twice, even if a non-snapshot page source drifts under it —
// detail loads address rows by (org, row key), so a repeated key could only
// ever produce identical detail content. Second, the ACTUAL emitted count
// never exceeds maxRows: seeing a (maxRows+1)-th candidate row fails the
// export with ErrRequestExportTooLarge instead of emitting past the cap.
// validateExportOptions rejects the degenerate walk configurations before
// any page or detail read happens.
func validateExportOptions(maxRows int, emit func(*RequestDetail) error, list requestExportPage, detail requestExportDetail) error {
	if maxRows < 1 || emit == nil || list == nil || detail == nil {
		return fmt.Errorf("invalid request export options")
	}
	return nil
}

// emitExportRow loads one row's detail by its immutable row key and emits it.
// A row whose detail vanished (ErrNotFound) is skipped, not fatal: the walk
// continues with the next row. The boundary decision travels in ctx so the
// loader re-applies it for this row.
func emitExportRow(ctx context.Context, detail requestExportDetail, orgID string, row RequestListRow, access RequestPayloadAccess, emit func(*RequestDetail) error) error {
	detailCtx := WithRequestPayloadAccess(ctx, access)
	d, err := detail(detailCtx, orgID, row.RowKey)
	if IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return emit(d)
}

func streamRequestExport(ctx context.Context, list requestExportPage, detail requestExportDetail, filters RequestListFilters, access RequestPayloadAccess, maxRows int, emit func(*RequestDetail) error) (int, error) {
	if err := validateExportOptions(maxRows, emit, list, detail); err != nil {
		return 0, err
	}
	filters.Page = 1
	filters.PageSize = exportPageSize
	_, total, err := list(ctx, filters)
	if err != nil {
		return 0, err
	}
	if total > maxRows {
		return total, ErrRequestExportTooLarge
	}
	emitted := 0
	seen := make(map[int64]struct{}, total)
	for page := 1; page <= (total+exportPageSize-1)/exportPageSize; page++ {
		filters.Page = page
		rows, _, err := list(ctx, filters)
		if err != nil {
			return total, err
		}
		for _, row := range rows {
			if emitted == maxRows {
				// The page source holds more exportable rows than the cap
				// allows: fail loudly instead of emitting past maxRows.
				return total, ErrRequestExportTooLarge
			}
			if _, dup := seen[row.RowKey]; dup {
				continue
			}
			seen[row.RowKey] = struct{}{}
			if err := emitExportRow(ctx, detail, filters.OrgID, row, access, emit); err != nil {
				return total, err
			}
			emitted++
		}
	}
	return total, nil
}
