package auditlog

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// Verifier checks the entire hash-chain of audit log rows. Returns the first
// broken seq (0 = chain intact). An error is returned only for DB-level failures.
type Verifier struct {
	db *sql.DB
}

// NewVerifier creates a new verifier bound to the given database.
func NewVerifier(db *sql.DB) *Verifier { return &Verifier{db: db} }

// Verify walks all rows in seq order, recomputing each row's hash with the
// formula its hash_version selects (v1 legacy payload; v2 payload extended
// with the snapshot/reason data) and comparing against the stored row_hash.
// Unknown versions fail closed: the row is reported broken, never skipped.
// Returns the first broken seq (0 = intact).
func (v *Verifier) Verify(ctx context.Context) (int64, error) {
	rows, err := v.db.QueryContext(ctx,
		`SELECT seq, prev_hash, row_hash, hash_version, action, resource, details,
		        admin_id, ip_address, COALESCE(before_snapshot, ''), COALESCE(after_snapshot, ''), reason
		 FROM admin_audit_logs ORDER BY seq ASC`)
	if err != nil {
		return 0, fmt.Errorf("query audit rows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	expectedPrev := ""
	for rows.Next() {
		var seq int64
		var prevHash, rowHash, action, resource, details, adminID, ip string
		var version int
		var before, after, reason string
		if err := rows.Scan(&seq, &prevHash, &rowHash, &version, &action, &resource, &details,
			&adminID, &ip, &before, &after, &reason); err != nil {
			return seq, fmt.Errorf("scan row %d: %w", seq, err)
		}

		if prevHash != expectedPrev {
			return seq, fmt.Errorf("chain broken at seq %d: prev_hash mismatch (expected %s, got %s)",
				seq, expectedPrev, prevHash)
		}

		v1 := PayloadV1(action, resource, details, adminID, ip)
		var expected string
		switch version {
		case HashVersionV1:
			expected = RowHash(expectedPrev, v1)
		case HashVersionV2:
			expected = RowHash(expectedPrev, PayloadV2(v1, before, after, reason))
		default:
			return seq, fmt.Errorf("chain broken at seq %d: unknown hash_version %d (fail-closed)", seq, version)
		}
		if rowHash != expected {
			return seq, fmt.Errorf("chain broken at seq %d: row_hash mismatch (tampered)", seq)
		}

		expectedPrev = rowHash
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("row iteration error: %w", err)
	}

	return 0, nil // chain intact
}

// BackfillChain computes hash-chain links for all existing rows (one-time
// migration). Legacy rows are backfilled with the v1 formula and stamped
// hash_version 1. Must be called before Verify can succeed on pre-chain data.
func (w *Writer) BackfillChain(ctx context.Context) error {
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx,
		`SELECT seq, action, resource, details, admin_id, ip_address
		 FROM admin_audit_logs ORDER BY seq ASC`)
	if err != nil {
		return fmt.Errorf("query for backfill: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Buffer every row BEFORE writing: the pgx (database/sql) driver
	// rejects a second statement while the rows stream is open on the
	// same connection ("driver: bad connection"), so the update loop
	// must run after the stream is closed.
	type backfillRow struct {
		seq                       int64
		action, resource, details string
		adminID, ip               string
	}
	var pending []backfillRow
	for rows.Next() {
		var r backfillRow
		if err := rows.Scan(&r.seq, &r.action, &r.resource, &r.details, &r.adminID, &r.ip); err != nil {
			return fmt.Errorf("scan backfill row: %w", err)
		}
		pending = append(pending, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("backfill iteration error: %w", err)
	}

	expectedPrev := ""
	for _, r := range pending {
		rowHash := RowHash(expectedPrev, PayloadV1(r.action, r.resource, r.details, r.adminID, r.ip))

		if _, err := tx.ExecContext(ctx,
			`UPDATE admin_audit_logs SET row_hash = $1, prev_hash = $2, hash_version = $3 WHERE seq = $4`,
			rowHash, expectedPrev, HashVersionV1, r.seq); err != nil {
			return fmt.Errorf("update hash for seq %d: %w", r.seq, err)
		}

		expectedPrev = rowHash
	}

	return tx.Commit()
}

// SeedDemoData inserts a small set of demo audit rows for testing verify.
func (w *Writer) SeedDemoData(ctx context.Context) error {
	demo := []Entry{
		{Action: "LOGIN", Resource: "admin", Details: "user logged in", AdminID: "root-1", IP: "10.0.0.1"},
		{Action: "CREATE_ORG", Resource: "org", Details: "created org=acme", AdminID: "root-1", IP: "10.0.0.1"},
		{Action: "ROUTE_MODEL", Resource: "model", Details: "routed openai-gpt-4o", AdminID: "admin-2", IP: "10.0.0.2"},
	}
	for i := range demo {
		demo[i].ID = uuid.New().String()
		if err := w.AppendEntry(ctx, demo[i]); err != nil {
			return err
		}
	}
	return nil
}
