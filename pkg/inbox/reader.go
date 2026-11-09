// Package inbox is the unified security inbox (E06-P01): the read side of
// the durable security-event store (secevents_documents, migration 0021).
//
// Trigger ② single owner (E01-P04 W04-readpath-decision.md §5–6): migration
// 0026 (RLS org_isolation), the writer pin (pkg/secevents durableInsertSQL)
// and this first production reader landed as ONE change — XF-1 ("no
// production reader exists") is closed by this package, not by a future
// card.
//
// The org derivation law (W04 §5.3, the read-side twin of XF-2): the org is
// taken from the authenticated context (WithOrg), NEVER from a client-
// supplied parameter — a caller-chosen org would make the reader a confused
// deputy even under RLS. The law is enforced twice here: the Go boundary
// refuses to run without a bound org (ErrOrgRequired), and the SQL pins
// app.current_org transaction-locally so the org_isolation policy scopes
// every row.
package inbox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// ReaderDB is the read surface the reader needs: a Begin-capable connection
// surface for the pin+select pair. It is satisfied directly by *pgxpool.Pool
// and *pgx.Tx (the production connection surfaces) without a wrapper — a Tx
// wraps the pair in a savepoint, a Pool runs it as one short transaction.
type ReaderDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// ctxKeyOrg is the context key type for the authenticated org. Unexported:
// WithOrg is the only way to bind an org, so the value can never be set
// from a client-supplied parameter by accident.
type ctxKeyOrg struct{}

// WithOrg binds the authenticated org into ctx. Callers derive the org from
// the authenticated session/org scope (the same derivation the admin
// handlers use), never from a request parameter.
func WithOrg(ctx context.Context, org string) context.Context {
	return context.WithValue(ctx, ctxKeyOrg{}, org)
}

// ErrOrgRequired is returned when the org context is absent OR empty. An
// empty org is not a valid "no scope": per the E01-P04 W05 verdict the
// boundary must REFUSE an empty org parameter — the policy layer alone
// does not (an empty GUC must not degrade into a wildcard read).
var ErrOrgRequired = errors.New("inbox: reader: authenticated org context required (empty or missing org refused)")

// orgFromContext enforces the derivation law at the Go boundary.
func orgFromContext(ctx context.Context) (string, error) {
	org, _ := ctx.Value(ctxKeyOrg{}).(string)
	if org == "" {
		return "", ErrOrgRequired
	}
	return org, nil
}

// readerPinSQL binds app.current_org transaction-locally (is_local = true —
// the withOrgTx semantics proven in durable_read_isolation_int_test.go):
// the binding lives exactly until the surrounding transaction ends, so a
// pooled connection can never carry org A into org B's next transaction.
const readerPinSQL = `SELECT set_config('app.current_org', $1, true)`

// readerSelectSQL is the read: the explicit org predicate is the
// defense-in-depth layer ON TOP of the org_isolation policy (contract §1.5
// interim law — it stays after 0026). The order is a deterministic total
// order (occurred_at, event_id) so downstream folds/replays are stable
// under timestamp ties; presentation order is a consumer concern.
const readerSelectSQL = `SELECT org_id, event_id, schema_version, event_type, occurred_at, document
FROM secevents_documents
WHERE org_id = $1
ORDER BY occurred_at, event_id`

// Reader reads an org's durable security events. Safe for concurrent use.
type Reader struct {
	db ReaderDB
}

// NewReader returns a Reader over db.
func NewReader(db ReaderDB) *Reader {
	return &Reader{db: db}
}

// Events returns the bound org's events in (occurred_at, event_id) order.
// The org comes from ctx (WithOrg); it is never a method argument, and a
// missing or empty binding fails closed with ErrOrgRequired before any
// query is issued.
//
// The pin and the select run in ONE transaction (the W04 §5.2 law, the
// writer's exact shape). Same-statement CTE pinning is NOT used: on PG14+
// any set_config of a custom GUC leaves the session placeholder as ” (and
// for a SELECT the join order is a planner freedom on top of that), while
// transaction statement ordering is the guarantee both the writer and this
// reader rely on — and the reason ReaderDB needs Begin.
//
// Every row is decoded and checked for org-homes agreement (row org ==
// document org == bound org, the W04-C02 REAL pin enforced here in the
// production reader). A divergent row is a security event in itself: the
// whole feed is refused, never partially served and never silently skipped.
// Pagination is intentionally out of scope (E06-P05 W02).
func (r *Reader) Events(ctx context.Context) ([]secevents.Event, error) {
	org, err := orgFromContext(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("inbox: reader: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	if _, err := tx.Exec(ctx, readerPinSQL, org); err != nil {
		return nil, fmt.Errorf("inbox: reader: pin org: %w", err)
	}
	rows, err := tx.Query(ctx, readerSelectSQL, org)
	if err != nil {
		return nil, fmt.Errorf("inbox: reader: query org %s: %w", org, err)
	}
	var events []secevents.Event
	for rows.Next() {
		var (
			orgID         string
			eventID       string
			schemaVersion int
			eventType     string
			occurredAt    time.Time
			document      []byte
		)
		if err := rows.Scan(&orgID, &eventID, &schemaVersion, &eventType, &occurredAt, &document); err != nil {
			rows.Close()
			return nil, fmt.Errorf("inbox: reader: scan %s/%s: %w", org, eventID, err)
		}
		ev, _, err := secevents.Decode(document)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("inbox: reader: decode %s/%s: %w", orgID, eventID, err)
		}
		if orgID != org || ev.OrgID != org {
			rows.Close()
			return nil, fmt.Errorf("inbox: reader: org mismatch on event %s/%s: row org %q, document org %q, bound org %q",
				orgID, eventID, orgID, ev.OrgID, org)
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("inbox: reader: rows: %w", err)
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("inbox: reader: commit: %w", err)
	}
	return events, nil
}
