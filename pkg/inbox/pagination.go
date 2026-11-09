// Keyset pagination for the unified security inbox (E06-P01 W05-C02).
//
// Paging is keyset-cursor, not OFFSET: the position is the (last_seen,
// incident_id) pair of the last served row — the exact total order the
// list/search surface emits and the 0027 index
// security_inbox_org_last_seen_id_idx serves. OFFSET paging shifts under
// concurrent inserts (page 2 re-serves or skips rows when a new incident
// lands at the head); a keyset walk is immune: every row already ordered
// BEFORE the cursor stays before it, whatever is inserted afterwards.
//
// The house page-size law is pkg/adminstore/pagination.go's NewPageFilter:
// defaults 50, max 100, sub-1 values normalize to the default — clamped,
// never rejected (the store-side twin of that law; the HTTP surface
// already speaks those semantics). SearchPage applies the same clamp
// itself so a raw struct cannot smuggle an unbounded fetch.
//
// SearchPage composes with W05-C01 filters (SearchFilters) unchanged:
// the cursor predicate is appended to the filter predicates, so a paged,
// filtered walk is stable in BOTH dimensions.
package inbox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DefaultPageSize is the page size used when none is requested (the
// house law, pkg/adminstore DefaultPageSize).
const DefaultPageSize = 50

// MaxPageSize is the upper bound for a page (the house law,
// pkg/adminstore MaxPageSize).
const MaxPageSize = 100

// ErrInvalidPageRequest reports a malformed page request (a cursor that
// does not identify a real position).
var ErrInvalidPageRequest = errors.New("inbox: pagination: invalid page request")

// PageCursor is the keyset position: the (last_seen, id) of the last
// served row. Opaque to callers that treat it as a token; meaningful to
// the store as the strict continuation point in the (last_seen DESC,
// id ASC) order.
type PageCursor struct {
	LastSeen   time.Time
	IncidentID uuid.UUID
}

// PageRequest asks for one page: PageSize rows strictly AFTER Cursor
// (nil Cursor = the first page).
type PageRequest struct {
	PageSize int
	Cursor   *PageCursor
}

// NewPageRequest constructs a PageRequest with the house clamp:
// pageSize < 1 → DefaultPageSize, > MaxPageSize → MaxPageSize. The cursor
// passes through untouched (its shape is validated where it is used).
func NewPageRequest(pageSize int, cursor *PageCursor) PageRequest {
	if pageSize < 1 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	return PageRequest{PageSize: pageSize, Cursor: cursor}
}

// validate enforces the cursor contract: a cursor must identify a real
// position — a zero IncidentID or zero LastSeen is a truncated/foreign
// token, and silently serving from it would duplicate the first page.
func (r PageRequest) validate() error {
	if r.Cursor == nil {
		return nil
	}
	if r.Cursor.IncidentID == uuid.Nil {
		return fmt.Errorf("%w: cursor incident id is the zero uuid", ErrInvalidPageRequest)
	}
	if r.Cursor.LastSeen.IsZero() {
		return fmt.Errorf("%w: cursor last_seen is the zero time", ErrInvalidPageRequest)
	}
	return nil
}

// PageResult is one served page. NextCursor is nil on the last page; a
// non-nil NextCursor is the continuation token (the position of the last
// row of THIS page). Rows is never nil — an empty page is an empty slice
// (the "200 []" contract).
type PageResult struct {
	Rows       []Incident
	NextCursor *PageCursor
}

// SearchPage returns one page of the org's incidents matching the
// filters, in the keyset order (last_seen DESC, id ASC), strictly after
// the cursor when one is given. It reads with the store's reader law
// (pin + explicit org predicate in one transaction) and refuses — before
// any statement — a missing org (ErrStoreOrgRequired), invalid filters
// (ErrInvalidSearchFilters) and a malformed cursor
// (ErrInvalidPageRequest). PageSize is clamped by the house law.
func (s *Store) SearchPage(ctx context.Context, orgID uuid.UUID, f SearchFilters, req PageRequest) (PageResult, error) {
	if orgID == uuid.Nil {
		return PageResult{}, ErrStoreOrgRequired
	}
	if err := f.validate(); err != nil {
		return PageResult{}, err
	}
	if err := req.validate(); err != nil {
		return PageResult{}, err
	}
	size := req.PageSize
	if size < 1 {
		size = DefaultPageSize
	}
	if size > MaxPageSize {
		size = MaxPageSize
	}

	sql := searchSelectPrefix
	clauses, args, next := searchConditions(f, 2)
	for _, c := range clauses {
		sql += " AND " + c
	}
	if req.Cursor != nil {
		args = append(args, req.Cursor.LastSeen, req.Cursor.IncidentID)
		sql += fmt.Sprintf(" AND (last_seen < $%d OR (last_seen = $%d AND id > $%d))", next, next, next+1)
	}
	sql += searchOrder + fmt.Sprintf("\nLIMIT %d", size+1) // +1: the has-more probe row

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return PageResult{}, fmt.Errorf("inbox: pagination: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	// Reader law: pin + explicit predicate in one transaction.
	if _, err := tx.Exec(ctx, readerPinSQL, orgID.String()); err != nil {
		return PageResult{}, fmt.Errorf("inbox: pagination: pin: %w", err)
	}
	rows, err := tx.Query(ctx, sql, append([]any{orgID}, args...)...)
	if err != nil {
		return PageResult{}, fmt.Errorf("inbox: pagination: query: %w", err)
	}
	incs, err := scanIncidents(rows)
	rows.Close()
	if err != nil {
		return PageResult{}, err
	}
	if err := rows.Err(); err != nil {
		return PageResult{}, fmt.Errorf("inbox: pagination: rows: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return PageResult{}, fmt.Errorf("inbox: pagination: commit: %w", err)
	}

	page := PageResult{Rows: incs}
	if len(incs) > size {
		last := incs[size-1]
		page.Rows = incs[:size]
		page.NextCursor = &PageCursor{LastSeen: last.LastSeen, IncidentID: last.ID}
	}
	if page.Rows == nil {
		page.Rows = []Incident{} // never nil (the "200 []" contract)
	}
	return page, nil
}
