package auditlog

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Hash payload versions (AF-10, explicit compatibility rule).
//
//	v1 (legacy): payload = action|resource|details|admin_id|ip_address
//	v2:          payload = action|resource|details|admin_id|ip_address +
//	                     before_snapshot|after_snapshot|reason
//
// The chaining formula is identical in both versions: row_hash =
// sha256(prev_hash + "|" + payload), prev_hash = "" for the first row. Rows
// without any snapshot/reason data are written as v1, so an application
// rollback to a pre-AF-10 binary still verifies them; rows carrying the new
// data are v2 and are only verified by version-aware verifiers (fail-closed
// on unknown versions).
const (
	// HashVersionV1 is the legacy payload formula (pre-0019 rows).
	HashVersionV1 = 1
	// HashVersionV2 extends the payload with the snapshot/reason data.
	HashVersionV2 = 2
)

// appendLockSQL serializes concurrent appends inside one transaction.
//
// The previous protocol (SELECT ... FOR UPDATE on the last row) does NOT
// serialize the empty-table case — there is no row to lock, so two
// concurrent first appends both read prev_hash="" and fork the chain — and
// on a non-empty table a waiting transaction re-reads the OLD head after the
// lock is released (the winner inserted a new row rather than updating the
// locked one), producing the same fork. A transaction-scoped advisory lock
// covers both cases: it needs no row and every later head read happens after
// the previous appender committed (READ COMMITTED, the default).
const appendLockSQL = `SELECT pg_advisory_xact_lock(hashtext(current_database() || ':admin_audit_logs:append'))`

// insertSQL is the shared append statement. seq comes from the column
// default; created_at is always written explicitly so the stored timestamp
// equals the one returned to callers.
const insertSQL = `
		INSERT INTO admin_audit_logs
			(id, action, resource, details, admin_id, admin_name, ip_address,
			 prev_hash, row_hash, hash_version, before_snapshot, after_snapshot, reason, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

// Entry is one audit row to append through the shared protocol. Before,
// After and Reason are scrubbed by the writer before hashing and persistence.
// Recognized credential values are replaced with [REDACTED]; other text is
// retained. Callers must not rely on this boundary to sanitize other fields.
type Entry struct {
	ID        string
	Action    string
	Resource  string
	Details   string
	AdminID   string
	AdminName string
	IP        string
	Before    string // sanitized JSON snapshot text; "" = absent
	After     string // sanitized JSON snapshot text; "" = absent
	Reason    string
	// CreatedAt stamps the row; the zero value resolves to time.Now().UTC().
	CreatedAt time.Time
}

// Row is the minimal single-result scan surface shared by pgx.Row and
// database/sql rows.
type Row interface {
	Scan(dest ...any) error
}

// AppendTx is the minimal transaction surface the shared append protocol
// needs, satisfied by tiny adapters over pgx.Tx (adminstore) and
// database/sql.Tx (this package).
type AppendTx interface {
	QueryRow(ctx context.Context, query string, args ...any) Row
	Exec(ctx context.Context, query string, args ...any) error
	// AdvisoryLock reports whether the backend supports transaction-scoped
	// advisory locks (PostgreSQL). Backends without them (embedded
	// single-process databases) serialize through the in-process append
	// mutex instead.
	AdvisoryLock() bool
}

// sqlAppendTx adapts a database/sql transaction to AppendTx.
type sqlAppendTx struct {
	tx       *sql.Tx
	advisory bool
}

func (t sqlAppendTx) QueryRow(ctx context.Context, query string, args ...any) Row {
	return t.tx.QueryRowContext(ctx, query, args...)
}

func (t sqlAppendTx) Exec(ctx context.Context, query string, args ...any) error {
	_, err := t.tx.ExecContext(ctx, query, args...)
	return err
}

func (t sqlAppendTx) AdvisoryLock() bool { return t.advisory }

// HashVersionFor is the explicit version rule: new data (snapshots/reason)
// never enters the legacy v1 formula — rows carrying it are v2.
func HashVersionFor(before, after, reason string) int {
	if before == "" && after == "" && reason == "" {
		return HashVersionV1
	}
	return HashVersionV2
}

// PayloadV1 is the legacy hash payload (admin_name deliberately excluded).
func PayloadV1(action, resource, details, adminID, ip string) string {
	return action + "|" + resource + "|" + details + "|" + adminID + "|" + ip
}

// PayloadV2 extends the legacy payload with the AF-10 snapshot/reason data.
func PayloadV2(v1Payload, before, after, reason string) string {
	return v1Payload + "|" + before + "|" + after + "|" + reason
}

// RowHash chains a payload onto prevHash ("" for the first row). Shared by
// both payload versions.
func RowHash(prevHash, payload string) string {
	h := sha256.Sum256([]byte(prevHash + "|" + payload))
	return hex.EncodeToString(h[:])
}

// appendMu serializes appends on backends without advisory locks (embedded
// databases such as SQLite). PostgreSQL always takes the advisory-lock path;
// the mutex is a single-process fallback, not a cross-instance guarantee.
var appendMu sync.Mutex

// AppendInTx is the shared, correct lock/head protocol for both append
// implementations (pkg/auditlog.Writer over database/sql and
// pkg/adminstore.Store over pgx): it serializes on a transaction-scoped
// advisory lock (correct including the empty table), reads the head AFTER
// the lock, computes the versioned hash and inserts the row. The caller owns
// Begin/Commit/Rollback.
func AppendInTx(ctx context.Context, tx AppendTx, e Entry) error {
	e.Before = scrubAuditSecrets(e.Before)
	e.After = scrubAuditSecrets(e.After)
	e.Reason = scrubAuditSecrets(e.Reason)
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}

	// Serialize appends. PostgreSQL takes a transaction-scoped advisory lock
	// (correct including the empty table); backends without advisory locks
	// fall back to the in-process mutex (single-process embedded DBs).
	if tx.AdvisoryLock() {
		if err := tx.Exec(ctx, appendLockSQL); err != nil {
			return fmt.Errorf("audit append lock: %w", err)
		}
	} else {
		appendMu.Lock()
		defer appendMu.Unlock()
	}

	// Head read happens after serialization, so it observes every committed
	// (and same-transaction) predecessor. No rows → first link (prev "").
	var prevHash string
	err := tx.QueryRow(ctx,
		`SELECT row_hash FROM admin_audit_logs ORDER BY seq DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("get last audit hash: %w", err)
	}

	v1 := PayloadV1(e.Action, e.Resource, e.Details, e.AdminID, e.IP)
	version := HashVersionFor(e.Before, e.After, e.Reason)
	var rowHash string
	if version == HashVersionV2 {
		rowHash = RowHash(prevHash, PayloadV2(v1, e.Before, e.After, e.Reason))
	} else {
		rowHash = RowHash(prevHash, v1)
	}

	if err := tx.Exec(ctx, insertSQL,
		e.ID, e.Action, e.Resource, e.Details, e.AdminID, e.AdminName, e.IP,
		prevHash, rowHash, version, e.Before, e.After, e.Reason, e.CreatedAt); err != nil {
		return fmt.Errorf("insert audit row: %w", err)
	}
	return nil
}

// Writer appends tamper-evident audit rows over a database/sql connection
// using the shared AppendInTx protocol.
type Writer struct {
	db *sql.DB
	// advisory caches whether the backend is PostgreSQL (answers version();
	// embedded backends like SQLite have no such function and serialize on
	// the in-process mutex instead). Probed once per writer.
	advisoryOnce sync.Once
	advisory     bool
}

// NewWriter creates a new audit log writer bound to the given database.
func NewWriter(db *sql.DB) *Writer { return &Writer{db: db} }

// isPostgres probes the backend once: PostgreSQL answers version(), embedded
// backends (SQLite) do not.
func (w *Writer) isPostgres(ctx context.Context) bool {
	w.advisoryOnce.Do(func() {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var version string
		w.advisory = w.db.QueryRowContext(probeCtx, `SELECT version()`).Scan(&version) == nil
	})
	return w.advisory
}

// Append inserts a simple audit row (no snapshots/reason → hash_version 1,
// byte-identical to the pre-AF-10 formula).
func (w *Writer) Append(ctx context.Context, action, resource, details, adminID, adminName, ip string) error {
	return w.AppendEntry(ctx, Entry{
		ID:        uuid.New().String(),
		Action:    action,
		Resource:  resource,
		Details:   details,
		AdminID:   adminID,
		AdminName: adminName,
		IP:        ip,
	})
}

// AppendEntry inserts a full audit row (snapshots/reason included) through
// the shared lock/head protocol.
func (w *Writer) AppendEntry(ctx context.Context, e Entry) error {
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := AppendInTx(ctx, sqlAppendTx{tx: tx, advisory: w.isPostgres(ctx)}, e); err != nil {
		return err
	}
	return tx.Commit()
}
