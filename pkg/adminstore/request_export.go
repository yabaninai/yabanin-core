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

// requestExportDetail loads one authorized request detail.
type requestExportDetail func(context.Context, string, string) (*RequestDetail, error)

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
		func(ctx context.Context, orgID, requestID string) (*RequestDetail, error) {
			return getRequestDetailOn(ctx, tx, orgID, requestID)
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
// The list fetcher is expected to serve a stable snapshot (the store-backed
// path pins one with a REPEATABLE READ transaction). On top of that contract
// the walk adds two backend-independent guarantees. First, a request ID is
// never emitted twice, even if a non-snapshot page source drifts under it —
// safe because detail loads address rows by (org, request_id), so a repeated
// ID could only ever produce identical detail content. Second, the ACTUAL
// emitted count never exceeds maxRows: seeing a (maxRows+1)-th candidate row
// fails the export with ErrRequestExportTooLarge instead of emitting past
// the cap.
func streamRequestExport(ctx context.Context, list requestExportPage, detail requestExportDetail, filters RequestListFilters, access RequestPayloadAccess, maxRows int, emit func(*RequestDetail) error) (int, error) {
	if maxRows < 1 || emit == nil || list == nil || detail == nil {
		return 0, fmt.Errorf("invalid request export options")
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
	seen := make(map[string]struct{}, total)
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
			if _, dup := seen[row.RequestID]; dup {
				continue
			}
			seen[row.RequestID] = struct{}{}
			detailCtx := WithRequestPayloadAccess(ctx, access)
			d, err := detail(detailCtx, filters.OrgID, row.RequestID)
			if IsNotFound(err) {
				continue
			}
			if err != nil {
				return total, err
			}
			if err := emit(d); err != nil {
				return total, err
			}
			emitted++
		}
	}
	return total, nil
}
