package feedback

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// List defaults (card W-FEED): the owner feedback page serves 50 rows like the
// other admin lists; 200 is the ceiling so one request cannot dump the table.
const (
	ListDefaultPageSize = 50
	ListMaxPageSize     = 200
)

// ListFilter narrows the owner feedback listing. Empty OrgID/Action mean "no
// filter"; Action must be one of ValidActions (the handler rejects others).
// Page is 1-based.
type ListFilter struct {
	OrgID    string
	Action   string
	Page     int
	PageSize int
}

// Norm clamps the pagination bounds and returns the filter unchanged otherwise.
func (f ListFilter) Norm() ListFilter {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 {
		f.PageSize = ListDefaultPageSize
	}
	if f.PageSize > ListMaxPageSize {
		f.PageSize = ListMaxPageSize
	}
	return f
}

// Valid reports whether the Action filter (when set) is a known action.
func (f ListFilter) Valid() bool {
	if f.Action == "" {
		return true
	}
	for _, a := range ValidActions() {
		if a == f.Action {
			return true
		}
	}
	return false
}

// Entry is one classifier_feedback row as the owner page sees it.
type Entry struct {
	ID            int64     `json:"id"`
	OrgID         string    `json:"org_id"`
	RequestID     string    `json:"request_id"`
	PromptHash    string    `json:"prompt_hash"`
	OriginalClass string    `json:"original_class"`
	Action        string    `json:"action"`
	CreatedAt     time.Time `json:"created_at"`
}

// ListPage is one page of feedback entries plus the unfiltered-with-filters
// total, so the UI can paginate without a second probe.
type ListPage struct {
	Entries  []Entry `json:"feedback"`
	Total    int64   `json:"total"`
	Page     int     `json:"page"`
	PageSize int     `json:"page_size"`
}

// Lister reads classifier_feedback for the root-only owner page. It is a
// separate type from Collector/Exporter so the admin surface cannot reach the
// write path.
type Lister struct {
	pool *pgxpool.Pool
}

// NewLister creates a Lister over the given pool (nil pool = unwired; routes
// answer 503).
func NewLister(pool *pgxpool.Pool) *Lister {
	return &Lister{pool: pool}
}

// ListFeedback returns one page of classifier_feedback ordered newest first,
// scoped by the explicit org/action filters. The root-only page is the only
// consumer; org scoping rests on the filter parameter (classifier_feedback
// carries no RLS — see the card W-FEED handoff).
func (l *Lister) ListFeedback(ctx context.Context, filter ListFilter) (ListPage, error) {
	filter = filter.Norm()
	out := ListPage{Entries: []Entry{}, Page: filter.Page, PageSize: filter.PageSize}
	if l == nil || l.pool == nil {
		return out, fmt.Errorf("feedback list is not configured")
	}
	if !filter.Valid() {
		return out, fmt.Errorf("invalid action filter: %s", filter.Action)
	}

	where, args := listWhere(filter)
	var total int64
	if err := l.pool.QueryRow(ctx,
		"SELECT count(*) FROM classifier_feedback"+where, args...).Scan(&total); err != nil {
		return out, fmt.Errorf("feedback list count: %w", err)
	}
	out.Total = total

	args = append(args, filter.PageSize, (filter.Page-1)*filter.PageSize)
	rows, err := l.pool.Query(ctx, `
		SELECT id::bigint, org_id::text, request_id, prompt_hash, original_class, action, created_at
		  FROM classifier_feedback`+where+`
		 ORDER BY created_at DESC, id DESC
		 LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return out, fmt.Errorf("feedback list: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.OrgID, &e.RequestID, &e.PromptHash, &e.OriginalClass, &e.Action, &e.CreatedAt); err != nil {
			return out, fmt.Errorf("feedback list scan: %w", err)
		}
		out.Entries = append(out.Entries, e)
	}
	return out, rows.Err()
}

// listWhere builds the parameterized WHERE clause for the optional org/action
// filters. Values are always bound, never interpolated.
func listWhere(filter ListFilter) (string, []any) {
	where := ""
	var args []any
	if filter.OrgID != "" {
		args = append(args, filter.OrgID)
		where += fmt.Sprintf(" WHERE org_id = $%d::text", len(args))
	}
	if filter.Action != "" {
		op := "WHERE"
		if where != "" {
			op = " AND"
		}
		args = append(args, filter.Action)
		where += op + fmt.Sprintf(" action = $%d::text", len(args))
	}
	return where, args
}

// CSVColumns is the export header; WriteCSV emits rows in the same order.
var CSVColumns = []string{"id", "org_id", "request_id", "prompt_hash", "original_class", "action", "created_at"}

// WriteCSV encodes entries as RFC 4180 CSV (header row included) into w.
// created_at is RFC3339 so spreadsheets and scripts parse it unambiguously.
func WriteCSV(w io.Writer, entries []Entry) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVColumns); err != nil {
		return fmt.Errorf("feedback csv header: %w", err)
	}
	for _, e := range entries {
		if err := cw.Write([]string{
			fmt.Sprint(e.ID),
			e.OrgID,
			e.RequestID,
			e.PromptHash,
			e.OriginalClass,
			e.Action,
			e.CreatedAt.UTC().Format(time.RFC3339),
		}); err != nil {
			return fmt.Errorf("feedback csv row: %w", err)
		}
	}
	cw.Flush()
	return cw.Error()
}
