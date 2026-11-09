// Scoped search for the unified security inbox (E06-P01 W05-C01).
//
// Search is a READ and follows the store's reader law exactly (store.go
// List/Get): the org is mandatory and refused before any statement, the
// pin and the select run in ONE transaction, and the explicit org_id
// predicate stays as defense-in-depth on top of the org_isolation policy.
// The handler surface (W03-C02 query params) does NOT change here — this
// card is the store capability the pattern of request_archive_search.go:18
// asked for: an interface method that fails closed, never a SQL string
// escaped at the call site.
//
// Filter semantics (v1, fixed by the card):
//
//   - severity/status: exact match against the 0027 CHECK dictionaries,
//     validated fail-loud HERE (a word outside the dictionary is a caller
//     bug, not an empty result — the same law the W03-C02 handler applies
//     at its boundary);
//   - assignee: tri-state, the OperatorPatch shape — AssigneeSet=false
//     means "don't filter", AssigneeSet with uuid.Nil means "unassigned",
//     AssigneeSet with a member id means that member only;
//   - from/to: a closed window on last_seen (activity time, the same
//     clock the list order is keyed on); from > to is refused, not
//     silently empty;
//   - group_key: exact match, bounded by the model's MaxGroupKeyLen;
//   - summary query: a bounded LITERAL substring match (ILIKE '%…%'
//     with \ % _ escaped) — not a pattern language: the caller's % and _
//     have no special meaning, so injected wildcards or SQL cannot widen
//     the match. tsvector is deliberately out of scope for v1:
//     summaries are short single sentences folded by the projection, the
//     page is bounded, and an FTS index/maintenance dependency is not
//     owned by this packet (revisit only with evidence it pays for
//     itself).
//
// Multiple filters AND together. An empty filter set is the org-scoped
// list in the W05-C02 keyset order (last_seen DESC, id ASC) — search
// never returns "all orgs" and never errors on an empty result.
package inbox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// MaxSummaryQueryLen bounds the summary substring query. It is a guard
// against unbounded pattern construction, not a product limit: summaries
// themselves are short.
const MaxSummaryQueryLen = 128

// ErrInvalidSearchFilters reports a filter set the store refuses before
// any statement is issued (dictionary violation, oversized input, or an
// inverted time window).
var ErrInvalidSearchFilters = errors.New("inbox: search: invalid filters")

// SearchFilters is one org's scoped search. The zero value filters
// nothing (the full org inbox, keyset order).
type SearchFilters struct {
	// Severity, when non-empty, must be in the severity dictionary
	// (low|medium|high).
	Severity string
	// Status, when non-empty, must be in the status dictionary
	// (new|acknowledged|in_progress|resolved|dismissed).
	Status string
	// Assignee/AssigneeSet are the OperatorPatch tri-state: false =
	// don't filter; true + uuid.Nil = unassigned; true + member id =
	// that member.
	Assignee    uuid.UUID
	AssigneeSet bool
	// From/To bound last_seen inclusively ([from, to]). From > to is
	// refused as invalid, not served as empty.
	From, To *time.Time
	// GroupKey, when non-empty, is an exact match bounded by
	// MaxGroupKeyLen.
	GroupKey string
	// SummaryQuery, when non-empty, is a literal substring (ILIKE,
	// wildcards escaped), bounded by MaxSummaryQueryLen.
	SummaryQuery string
}

// validate enforces the filter contract before any statement runs.
func (f SearchFilters) validate() error {
	if f.Severity != "" {
		switch f.Severity {
		case SeverityLow, SeverityMedium, SeverityHigh:
		default:
			return fmt.Errorf("%w: severity %q not in the low|medium|high dictionary", ErrInvalidSearchFilters, f.Severity)
		}
	}
	if f.Status != "" {
		switch f.Status {
		case StatusNew, StatusAcknowledged, StatusInProgress, StatusResolved, StatusDismissed:
		default:
			return fmt.Errorf("%w: status %q not in the state-machine dictionary", ErrInvalidSearchFilters, f.Status)
		}
	}
	if f.GroupKey != "" && len(f.GroupKey) > MaxGroupKeyLen {
		return fmt.Errorf("%w: group key longer than %d chars", ErrInvalidSearchFilters, MaxGroupKeyLen)
	}
	if len(f.SummaryQuery) > MaxSummaryQueryLen {
		return fmt.Errorf("%w: summary query longer than %d chars", ErrInvalidSearchFilters, MaxSummaryQueryLen)
	}
	if f.From != nil && f.To != nil && f.From.After(*f.To) {
		return fmt.Errorf("%w: from (%s) after to (%s)", ErrInvalidSearchFilters, f.From.Format(time.RFC3339), f.To.Format(time.RFC3339))
	}
	return nil
}

// searchSelectPrefix is the shared read surface for search and keyset
// pagination (W05-C02): the full column list (storeListSQL's shape), the
// mandatory org predicate as $1, and — appended by the callers — the
// total order last_seen DESC, id ASC that the 0027 index
// security_inbox_org_last_seen_id_idx serves.
const searchSelectPrefix = `
SELECT id, org_id, group_key, summary, severity, confidence, status,
  assignee, first_seen, last_seen, event_count, first_event_id,
  last_event_id, evidence, created_at, updated_at
FROM security_inbox
WHERE org_id = $1`

// searchOrder is the stable total order shared by List, Search and
// SearchPage (last_seen DESC, id ASC — the keyset order).
const searchOrder = `
ORDER BY last_seen DESC, id`

// searchConditions appends the filter predicates to searchSelectPrefix.
// next is the placeholder index of the FIRST parameter the conditions may
// bind ($1 is always org_id); the returned index is one past the last
// bound. Clause order is fixed (severity, status, assignee, window,
// group_key, summary) so identical filters always produce identical SQL.
func searchConditions(f SearchFilters, next int) (clauses []string, args []any, nextAfter int) {
	if f.Severity != "" {
		args = append(args, f.Severity)
		clauses = append(clauses, fmt.Sprintf("severity = $%d", next))
		next++
	}
	if f.Status != "" {
		args = append(args, f.Status)
		clauses = append(clauses, fmt.Sprintf("status = $%d", next))
		next++
	}
	if f.AssigneeSet {
		if f.Assignee == uuid.Nil {
			clauses = append(clauses, "assignee IS NULL")
		} else {
			args = append(args, f.Assignee)
			clauses = append(clauses, fmt.Sprintf("assignee = $%d", next))
			next++
		}
	}
	if f.From != nil {
		args = append(args, *f.From)
		clauses = append(clauses, fmt.Sprintf("last_seen >= $%d", next))
		next++
	}
	if f.To != nil {
		args = append(args, *f.To)
		clauses = append(clauses, fmt.Sprintf("last_seen <= $%d", next))
		next++
	}
	if f.GroupKey != "" {
		args = append(args, f.GroupKey)
		clauses = append(clauses, fmt.Sprintf("group_key = $%d", next))
		next++
	}
	if f.SummaryQuery != "" {
		args = append(args, "%"+escapeLike(f.SummaryQuery)+"%")
		clauses = append(clauses, fmt.Sprintf("summary ILIKE $%d", next))
		next++
	}
	return clauses, args, next
}

// escapeLike neutralises LIKE/ILIKE wildcards so the summary query stays
// a literal substring. The default escape character for LIKE/ILIKE is the
// backslash; escaping the backslash itself first keeps the mapping total.
func escapeLike(s string) string {
	r := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '%', '_':
			r = append(r, '\\', s[i])
		default:
			r = append(r, s[i])
		}
	}
	return string(r)
}

// searchQuery assembles the search statement for one filter set.
func searchQuery(f SearchFilters) (string, []any) {
	clauses, args, _ := searchConditions(f, 2)
	sql := searchSelectPrefix
	for _, c := range clauses {
		sql += " AND " + c
	}
	sql += searchOrder
	return sql, append([]any{nil /* org_id placeholder, set by the caller */}, args...)
}

// Search returns the org's incidents matching the filters, in the keyset
// order (last_seen DESC, id ASC). An empty match is an empty slice,
// never an error (the W01-C03 "200 []" contract). Invalid filters are
// refused with ErrInvalidSearchFilters before any statement runs; a
// missing org is refused with ErrStoreOrgRequired before any statement
// runs — both ahead of Begin, like every store refusal.
func (s *Store) Search(ctx context.Context, orgID uuid.UUID, f SearchFilters) ([]Incident, error) {
	if orgID == uuid.Nil {
		return nil, ErrStoreOrgRequired
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	sql, args := searchQuery(f)
	args[0] = orgID

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("inbox: search: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	// Reader law: pin + explicit predicate in one transaction.
	if _, err := tx.Exec(ctx, readerPinSQL, orgID.String()); err != nil {
		return nil, fmt.Errorf("inbox: search: pin: %w", err)
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("inbox: search: query: %w", err)
	}
	incs, err := scanIncidents(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inbox: search: rows: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("inbox: search: commit: %w", err)
	}
	return incs, nil
}
