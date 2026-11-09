package adminstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/reireirei/yabanin/pkg/auditlog"
)

// ENT-03 + AF-10: audit write-path wiring.
//
// The admin mutation path persists tamper-evident rows through the shared
// auditlog.AppendInTx protocol: both append implementations (this store over
// pgx and pkg/auditlog.Writer over database/sql) serialize on the same
// transaction-scoped advisory lock — which is correct including the empty
// table, where a FOR UPDATE on MAX(seq) has no row to lock and two
// concurrent first appends would fork the chain. The head is read after the
// lock, so every row chains onto the actually committed predecessor.
//
// AF-10: the full sanitized before/after snapshots and the operator reason
// are stored on the row and read back for the API; the hash payload version
// is explicit (auditlog.HashVersionFor): rows with snapshot/reason data are
// hash_version 2, plain rows stay v1 — new data never silently extends the
// legacy formula.

// AuditLogEntryRecord is one audit entry to persist (AF-10). Before/After
// must already be sanitized by the caller; empty string = absent snapshot.
type AuditLogEntryRecord struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Details   string    `json:"details,omitempty"`
	AdminID   string    `json:"admin_id,omitempty"`
	AdminName string    `json:"admin_name,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Before    string    `json:"before,omitempty"`
	After     string    `json:"after,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// AuditLogEntry is one persisted audit entry as read back from the DB — the
// so Before/After are raw JSON snapshots (json.RawMessage) exactly as
// sanitized at write time. Empty snapshot = absent.
type AuditLogEntry struct {
	ID        string          `json:"id"`
	Action    string          `json:"action"`
	Resource  string          `json:"resource"`
	Details   string          `json:"details,omitempty"`
	AdminID   string          `json:"admin_id"`
	AdminName string          `json:"admin_name"`
	IPAddress string          `json:"ip_address"`
	Timestamp time.Time       `json:"timestamp"`
	Before    json.RawMessage `json:"before,omitempty"`
	After     json.RawMessage `json:"after,omitempty"`
	Reason    string          `json:"reason,omitempty"`
}

// AuditLogQuery is the journal read contract: allowlisted sort column,
// direction, and page window. Page/PageSize mirror the handler's query
// parameters (1-based page; PageSize capped by the caller).
type AuditLogQuery struct {
	Sort     string // "" = insertion (seq) order
	Desc     bool
	Page     int
	PageSize int
}

// auditSortColumns maps the allowlisted sort columns to SQL expressions.
// Handler-local literals only: request values select from this fixed map and
// never enter the query string themselves.
var auditSortColumns = map[string]string{
	"id":         "id",
	"action":     "action",
	"resource":   "resource",
	"admin_id":   "admin_id",
	"admin_name": "admin_name",
	"ip_address": "ip_address",
	"timestamp":  "created_at",
}

// pgxAppendTx adapts the store's auditTx to the shared auditlog.AppendTx
// protocol. pgx only talks to PostgreSQL, so the advisory lock is supported.
type pgxAppendTx struct{ tx auditTx }

func (t pgxAppendTx) QueryRow(ctx context.Context, query string, args ...any) auditlog.Row {
	return t.tx.QueryRow(ctx, query, args...)
}

func (t pgxAppendTx) Exec(ctx context.Context, query string, args ...any) error {
	_, err := t.tx.Exec(ctx, query, args...)
	return err
}

func (t pgxAppendTx) AdvisoryLock() bool { return true }

// computeAuditHash is kept for the existing tests: the shared RowHash is the
// canonical implementation (identical formula).
func computeAuditHash(prevHash, payload string) string {
	return auditlog.RowHash(prevHash, payload)
}

// auditPayload is the legacy v1 payload builder (kept for tests).
func auditPayload(action, resource, details, adminID, ip string) string {
	return auditlog.PayloadV1(action, resource, details, adminID, ip)
}

// InsertAuditLog inserts a tamper-evident audit row without snapshots/reason
// (hash_version 1, byte-identical to the pre-AF-10 formula). Returns nil
// (no-op) when the database is not available (the "audit disabled" case).
func (s *Store) InsertAuditLog(ctx context.Context, id, action, resource, details, adminID, adminName, ipAddr string) error {
	return s.InsertAuditLogEntry(ctx, AuditLogEntryRecord{
		ID: id, Action: action, Resource: resource, Details: details,
		AdminID: adminID, AdminName: adminName, IPAddress: ipAddr,
	})
}

// InsertAuditLogEntry persists the full sanitized entry (snapshots/reason
// included) as a hash-chained row through the shared append protocol. The
// write is synchronous: callers get durable success or an error — a store
// failure never looks like a persisted audit.
func (s *Store) InsertAuditLogEntry(ctx context.Context, rec AuditLogEntryRecord) error {
	if s.db == nil {
		return nil
	}
	tx, err := s.db.BeginAuditTx(ctx)
	if err != nil {
		return fmt.Errorf("begin audit tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := auditlog.AppendInTx(ctx, pgxAppendTx{tx}, auditlog.Entry{
		ID:        rec.ID,
		Action:    rec.Action,
		Resource:  rec.Resource,
		Details:   rec.Details,
		AdminID:   rec.AdminID,
		AdminName: rec.AdminName,
		IP:        rec.IPAddress,
		Before:    rec.Before,
		After:     rec.After,
		Reason:    rec.Reason,
		CreatedAt: rec.CreatedAt,
	}); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit audit row: %w", err)
	}
	return nil
}

// auditEntryScan is the shared column list for journal reads. Snapshots are
// COALESCEd to ” so NULL legacy rows scan as absent.
const auditEntryScan = `id, action, resource, details, admin_id, admin_name, ip_address,
		created_at, COALESCE(before_snapshot, ''), COALESCE(after_snapshot, ''), COALESCE(reason, '')`

func scanAuditEntry(row pgx.Row) (*AuditLogEntry, error) {
	var e AuditLogEntry
	// Snapshots are scanned as strings (the columns are COALESCEd text) and
	// re-typed as raw JSON — the wire format handlers have always served.
	var before, after string
	err := row.Scan(&e.ID, &e.Action, &e.Resource, &e.Details, &e.AdminID, &e.AdminName,
		&e.IPAddress, &e.Timestamp, &before, &after, &e.Reason)
	if err != nil {
		return nil, err
	}
	e.Before, e.After = json.RawMessage(before), json.RawMessage(after)
	return &e, nil
}

// ListAuditLogEntries reads the persisted journal: allowlisted sort column
// with a unique seq tie-breaker (stable pagination), 1-based page window,
// the full row count, and the number of entries still pending in the durable
// outbox. The returned entries carry the full sanitized before/after/reason.
func (s *Store) ListAuditLogEntries(ctx context.Context, q AuditLogQuery) ([]AuditLogEntry, int64, int64, error) {
	if s.db == nil {
		return nil, 0, 0, nil
	}

	col, ok := auditSortColumns[q.Sort]
	if !ok && q.Sort != "" {
		return nil, 0, 0, fmt.Errorf("unsupported audit sort column %q", q.Sort)
	}
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize < 1 {
		q.PageSize = 50
	}

	order := " ASC"
	if q.Desc {
		order = " DESC"
	}
	tie := " ASC"
	if q.Desc {
		tie = " DESC"
	}
	orderBy := "seq" + tie
	if q.Sort != "" {
		orderBy = col + order + ", seq" + tie
	}

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM admin_audit_logs`).Scan(&total); err != nil {
		return nil, 0, 0, fmt.Errorf("count audit rows: %w", err)
	}

	var pending int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM admin_audit_outbox`).Scan(&pending); err != nil {
		return nil, 0, 0, fmt.Errorf("count pending audit rows: %w", err)
	}

	rows, err := s.db.Query(ctx,
		`SELECT `+auditEntryScan+` FROM admin_audit_logs
		 ORDER BY `+orderBy+`
		 LIMIT $1 OFFSET $2`,
		q.PageSize, (q.Page-1)*q.PageSize)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("query audit rows: %w", err)
	}
	defer rows.Close()

	entries := make([]AuditLogEntry, 0, q.PageSize)
	for rows.Next() {
		e, err := scanAuditEntry(rows)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("scan audit row: %w", err)
		}
		entries = append(entries, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, fmt.Errorf("iterate audit rows: %w", err)
	}

	return entries, total, pending, nil
}

// EnqueueAuditOutbox durably records the intent to deliver an audit entry.
// Idempotent per entry id. This is the AF-10 fallback when the direct append
// failed: the intent survives a process restart and the drain loop delivers
// it later.
func (s *Store) EnqueueAuditOutbox(ctx context.Context, rec AuditLogEntryRecord) error {
	if s.db == nil {
		return nil
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal audit outbox payload: %w", err)
	}
	_, err = s.db.Exec(ctx,
		`INSERT INTO admin_audit_outbox (id, payload) VALUES ($1, $2)
		 ON CONFLICT (id) DO NOTHING`,
		rec.ID, payload)
	if err != nil {
		return fmt.Errorf("insert audit outbox row: %w", err)
	}
	return nil
}

// DrainAuditOutbox delivers up to limit due outbox entries into the
// hash-chained journal (one transaction per entry: the shared append
// protocol already serializes on the advisory lock, so drains from several
// admin instances cannot fork the chain). Delivered rows are deleted;
// failed rows get their attempt counter and next-attempt backoff bumped.
// Returns the number of delivered entries.
func (s *Store) DrainAuditOutbox(ctx context.Context, limit int) (int, error) {
	if s.db == nil {
		return 0, nil
	}
	if limit < 1 {
		limit = 50
	}

	rows, err := s.db.Query(ctx,
		`SELECT id, payload FROM admin_audit_outbox
		 WHERE next_attempt_at <= now() ORDER BY created_at, id LIMIT $1`, limit)
	if err != nil {
		return 0, fmt.Errorf("query audit outbox: %w", err)
	}
	type due struct {
		id      string
		payload []byte
	}
	var batch []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.payload); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan audit outbox row: %w", err)
		}
		batch = append(batch, d)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate audit outbox: %w", err)
	}
	rows.Close()

	delivered := 0
	for _, d := range batch {
		var rec AuditLogEntryRecord
		if err := json.Unmarshal(d.payload, &rec); err != nil {
			// A permanently undecodable payload can never succeed: mark it
			// failed with the error so operators can see it, and move on.
			_ = s.failOutboxRow(ctx, d.id, err)
			continue
		}
		if err := s.InsertAuditLogEntry(ctx, rec); err != nil {
			if isJournalDuplicateErr(err) {
				// Strict dedup rule (N10-P04-T04): the journal already
				// durably contains this entry id. That can only mean a
				// previous drain attempt committed the append but crashed
				// before the outbox row was deleted, or a concurrent admin
				// instance delivered the same due row first. The delivery
				// SUCCEEDED — the replay must converge, not fail the row
				// into an eternal hourly retry loop on a constraint the
				// entry can never satisfy again.
				if _, delErr := s.db.Exec(ctx, `DELETE FROM admin_audit_outbox WHERE id = $1`, d.id); delErr != nil {
					return delivered, fmt.Errorf("delete deduped audit outbox row: %w", delErr)
				}
				delivered++
				continue
			}
			_ = s.failOutboxRow(ctx, d.id, err)
			continue
		}
		if _, err := s.db.Exec(ctx, `DELETE FROM admin_audit_outbox WHERE id = $1`, d.id); err != nil {
			return delivered, fmt.Errorf("delete delivered audit outbox row: %w", err)
		}
		delivered++
	}
	return delivered, nil
}

// isJournalDuplicateErr reports whether err is the PostgreSQL unique
// violation on the journal's primary key (admin_audit_logs_pkey). Only that
// exact constraint counts as "already delivered": any other violation is a
// real failure and keeps the strict fail-closed path (the outbox row is
// never dropped on an unrecognized error).
func isJournalDuplicateErr(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505" && pgErr.ConstraintName == "admin_audit_logs_pkey"
}

// failOutboxRow records a failed delivery attempt with capped exponential
// backoff. Returns the underlying error for logging.
func (s *Store) failOutboxRow(ctx context.Context, id string, cause error) error {
	_, err := s.db.Exec(ctx,
		`UPDATE admin_audit_outbox
		 SET attempts = attempts + 1,
		     last_error = $2,
		     next_attempt_at = now() + least(power(2, attempts + 1), 3600) * interval '1 second'
		 WHERE id = $1`,
		id, cause.Error())
	if err != nil {
		return errors.Join(cause, fmt.Errorf("update audit outbox failure state: %w", err))
	}
	return cause
}
