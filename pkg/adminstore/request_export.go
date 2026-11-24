package adminstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ErrRequestExportTooLarge reports that an export would exceed its hard row cap.
var ErrRequestExportTooLarge = errors.New("request export exceeds row limit")

// ErrOriginalRetentionDisabled reports that an originals-scoped disclosure
// was refused because the org's effective original-text retention is off at
// the disclosure snapshot — not merely stale-off at an earlier authorization
// check. It is a fail-closed boundary: no row, and no originals field of any
// row, is emitted.
var ErrOriginalRetentionDisabled = errors.New("request export originals: org retention disabled")

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
// When access.Originals allows original-text disclosure, the effective org
// retention decision is evaluated as the first read of that same snapshot:
// retention disabled in-flight after authorization fails the stream with
// ErrOriginalRetentionDisabled before any row is read.
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
	// Retention at disclosure (ordering contract): when this export can
	// disclose original text, the effective retention decision is the FIRST
	// read of the snapshot transaction, so it and every row the walk
	// discloses share one point-in-time. An authorize-time decision alone is
	// only a preflight — retention disabled in-flight between authorization
	// and disclosure must not let retained originals flow under a stale
	// allow. No data read happens before this check, so any failure here
	// discloses nothing.
	if access.Originals {
		setting, settingErr := getOrgOriginalRetentionOn(ctx, tx, filters.OrgID)
		if settingErr != nil {
			return 0, fmt.Errorf("request export retention: %w", settingErr)
		}
		if !setting.Effective {
			return 0, ErrOriginalRetentionDisabled
		}
	}
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

// validateExportOptions rejects the degenerate walk configurations before
// any page or detail read happens.
func validateExportOptions(maxRows int, emit func(*RequestDetail) error, list requestExportPage, detail requestExportDetail) error {
	if maxRows < 1 || emit == nil || list == nil || detail == nil {
		return fmt.Errorf("invalid request export options")
	}
	return nil
}

func processExportCandidate(ctx context.Context, detail requestExportDetail, orgID string, row RequestListRow, access RequestPayloadAccess, maxRows int, seen map[int64]struct{}, emitted *int, emit func(*RequestDetail) error) error {
	if *emitted == maxRows {
		// Refuse before another detail read once the visible-row cap is
		// reached; detail lookup can expose payload data.
		return ErrRequestExportTooLarge
	}
	if _, dup := seen[row.RowKey]; dup {
		return nil
	}
	seen[row.RowKey] = struct{}{}
	d, err := detail(WithRequestPayloadAccess(ctx, access), orgID, row.RowKey)
	if IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := emit(d); err != nil {
		return err
	}
	*emitted++
	return nil
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
// never exceeds maxRows: after maxRows successful emits, seeing another
// candidate fails with ErrRequestExportTooLarge before another detail read.
// Missing details do not count as exported rows and do not consume the cap
// when a non-snapshot page source drifts.
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
			if err := processExportCandidate(ctx, detail, filters.OrgID, row, access, maxRows, seen, &emitted, emit); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}
