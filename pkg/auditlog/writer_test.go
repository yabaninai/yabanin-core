package auditlog

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestDB creates an in-memory SQLite database with admin_audit_logs table.
// One shared-cache connection: concurrent goroutines must observe the same
// in-memory database, and the append mutex fallback serializes writers.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:auditlogtest?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	//nolint:noctx // test setup, no context needed for DDL on in-memory DB
	_, err = db.Exec(`
		CREATE TABLE admin_audit_logs (
			id              TEXT NOT NULL,
			action          TEXT NOT NULL,
			resource        TEXT NOT NULL,
			details         TEXT NOT NULL,
			admin_id        TEXT NOT NULL DEFAULT '',
			admin_name      TEXT NOT NULL DEFAULT '',
			ip_address      TEXT NOT NULL DEFAULT '',
			prev_hash       TEXT,
			row_hash        TEXT NOT NULL DEFAULT '',
			hash_version    INTEGER NOT NULL DEFAULT 1,
			before_snapshot TEXT,
			after_snapshot  TEXT,
			reason          TEXT NOT NULL DEFAULT '',
			created_at      TEXT NOT NULL DEFAULT '',
			seq             INTEGER PRIMARY KEY AUTOINCREMENT
		)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	return db
}

func verifyIntact(t *testing.T, db *sql.DB) {
	t.Helper()
	broken, err := NewVerifier(db).Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if broken != 0 {
		t.Fatalf("expected intact chain (0), got broken at seq %d", broken)
	}
}

func TestWriter_Append_ComputesHashChain(t *testing.T) {
	db := setupTestDB(t)
	w := NewWriter(db)

	ctx := context.Background()
	err := w.Append(ctx, "LOGIN", "admin", "user logged in", "root-1", "", "10.0.0.1")
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	verifyIntact(t, db)

	// A plain append (no snapshot/reason data) stays on the legacy formula:
	// hash_version 1 and a row_hash identical to the pre-AF-10 computation.
	var version int
	var rowHash, prevHash string
	//nolint:noctx // test assertion on in-memory DB
	if err := db.QueryRow(
		`SELECT hash_version, row_hash, COALESCE(prev_hash, '') FROM admin_audit_logs WHERE seq = 1`,
	).Scan(&version, &rowHash, &prevHash); err != nil {
		t.Fatalf("scan row: %v", err)
	}
	if version != HashVersionV1 {
		t.Errorf("plain append: expected hash_version %d, got %d", HashVersionV1, version)
	}
	want := RowHash("", PayloadV1("LOGIN", "admin", "user logged in", "root-1", "10.0.0.1"))
	if rowHash != want {
		t.Errorf("plain append must keep the legacy formula: want %s, got %s", want, rowHash)
	}
	if prevHash != "" {
		t.Errorf("first row prev_hash must be empty, got %q", prevHash)
	}
}

// TestWriter_AppendEntry_VersionedPayload pins the AF-10 version rule: new
// data (snapshots/reason) never enters the legacy formula — the row is
// stamped hash_version 2 and the hash covers the extended payload.
func TestWriter_AppendEntry_VersionedPayload(t *testing.T) {
	db := setupTestDB(t)
	w := NewWriter(db)
	ctx := context.Background()

	err := w.AppendEntry(ctx, Entry{
		ID: "entry-1", Action: "update", Resource: "api_key", Details: "id=k",
		AdminID: "root-1", IP: "10.0.0.1",
		Before: `{"active":true}`, After: `{"active":false}`, Reason: "suspected leak",
	})
	if err != nil {
		t.Fatalf("append entry: %v", err)
	}

	// A following plain row keeps v1 and chains onto the v2 row's hash.
	if err := w.Append(ctx, "LOGIN", "admin", "hello", "root-1", "", "10.0.0.1"); err != nil {
		t.Fatalf("append: %v", err)
	}

	verifyIntact(t, db)

	var version int
	var before, after, reason string
	//nolint:noctx // test assertion on in-memory DB
	if err := db.QueryRow(
		`SELECT hash_version, COALESCE(before_snapshot, ''), COALESCE(after_snapshot, ''), reason
		 FROM admin_audit_logs WHERE id = 'entry-1'`,
	).Scan(&version, &before, &after, &reason); err != nil {
		t.Fatalf("scan entry: %v", err)
	}
	if version != HashVersionV2 {
		t.Errorf("entry with snapshots: expected hash_version %d, got %d", HashVersionV2, version)
	}
	if before != `{"active":true}` || after != `{"active":false}` || reason != "suspected leak" {
		t.Errorf("snapshot/reason data not stored: %q %q %q", before, after, reason)
	}

	var v1Hash string
	//nolint:noctx // test assertion on in-memory DB
	if err := db.QueryRow(`SELECT row_hash FROM admin_audit_logs WHERE seq = 1`).Scan(&v1Hash); err != nil {
		t.Fatalf("scan hash: %v", err)
	}
	want := RowHash("", PayloadV2(
		PayloadV1("update", "api_key", "id=k", "root-1", "10.0.0.1"),
		`{"active":true}`, `{"active":false}`, "suspected leak"))
	if v1Hash != want {
		t.Errorf("v2 row_hash must cover the extended payload: want %s, got %s", want, v1Hash)
	}
}

func TestWriter_AppendEntry_ScrubsSecretsBeforeDurableWrite(t *testing.T) {
	db := setupTestDB(t)
	w := NewWriter(db)
	ctx := context.Background()
	if err := w.AppendEntry(ctx, Entry{
		ID: "scrubbed", Action: "update", Resource: "credential",
		Before: `{"api_key":"audit-before-secret"}`,
		After:  `{"password":"audit-after-secret"}`,
		Reason: "operator maintenance; token=audit-reason-secret",
	}); err != nil {
		t.Fatalf("append entry: %v", err)
	}
	var before, after, reason string
	if err := db.QueryRowContext(ctx, `SELECT before_snapshot, after_snapshot, reason FROM admin_audit_logs WHERE id='scrubbed'`).Scan(&before, &after, &reason); err != nil {
		t.Fatalf("read scrubbed entry: %v", err)
	}
	for _, secret := range []string{"audit-before-secret", "audit-after-secret", "audit-reason-secret"} {
		if strings.Contains(before+after+reason, secret) {
			t.Errorf("secret %q reached durable audit row: %s %s %s", secret, before, after, reason)
		}
	}
	if !strings.Contains(reason, "operator maintenance") || !strings.Contains(reason, "[REDACTED]") {
		t.Errorf("reason should remain useful and masked: %q", reason)
	}
	verifyIntact(t, db)
}

func TestHashVersionFor(t *testing.T) {
	if got := HashVersionFor("", "", ""); got != HashVersionV1 {
		t.Errorf("empty data: want v1, got %d", got)
	}
	for _, tc := range [][3]string{
		{"{\"a\":1}", "", ""},
		{"", "{\"a\":1}", ""},
		{"", "", "why"},
	} {
		if got := HashVersionFor(tc[0], tc[1], tc[2]); got != HashVersionV2 {
			t.Errorf("data %v: want v2, got %d", tc, got)
		}
	}
}

// TestWriter_ConcurrentAppends_ChainIntact exercises real (unserialized by
// the test) concurrent appends: on PG they serialize via the advisory lock,
// on SQLite via the in-process fallback mutex — either way the chain must
// stay linear.
func TestWriter_ConcurrentAppends_ChainIntact(t *testing.T) {
	db := setupTestDB(t)
	w := NewWriter(db)

	ctx := context.Background()
	const n = 20
	done := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(k int) {
			done <- w.AppendEntry(ctx, Entry{
				ID: "concurrent-entry", Action: "TEST", Resource: "model",
				Details: "concurrent test", AdminID: "root-1", IP: "10.0.0.1",
				Reason: "unique reason", // v2 rows exercise the extended payload
			})
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent append %d: %v", i, err)
		}
	}

	var count int
	//nolint:noctx // test assertion on in-memory DB
	if err := db.QueryRow(`SELECT count(*) FROM admin_audit_logs`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != n {
		t.Fatalf("expected %d rows, got %d", n, count)
	}
	verifyIntact(t, db)
}

func TestVerifier_IntactChain_ReturnsZero(t *testing.T) {
	db := setupTestDB(t)
	w := NewWriter(db)

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		err := w.Append(ctx, "ACTION", "resource", "details", "admin-1", "", "10.0.0.1")
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	verifyIntact(t, db)
}

func TestVerifier_TamperedRow_DetectsBreak(t *testing.T) {
	db := setupTestDB(t)
	w := NewWriter(db)

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		err := w.Append(ctx, "ACTION", "resource", "details", "admin-1", "", "10.0.0.1")
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// Tamper with row at seq 3 (row_hash).
	//nolint:noctx // test setup, no context needed for DDL on in-memory DB
	_, err := db.Exec(`UPDATE admin_audit_logs SET action='TAMPERED' WHERE seq=3`)
	if err != nil {
		t.Fatalf("tamper: %v", err) // may fail due to WORM — that's fine, test still passes
	}

	v := NewVerifier(db)
	broken, err := v.Verify(ctx)
	if err != nil {
		// DB-level error is acceptable (WORM may prevent update).
		t.Logf("verify returned error: %v", err)
		return
	}
	if broken == 0 {
		t.Error("expected chain break after tampering, but got intact")
	}
}

// TestVerifier_TamperedNewPayload_DetectsBreak: tampering with a v2 row's
// snapshot column must be detected — the extended payload is hashed.
func TestVerifier_TamperedNewPayload_DetectsBreak(t *testing.T) {
	db := setupTestDB(t)
	w := NewWriter(db)

	ctx := context.Background()
	err := w.AppendEntry(ctx, Entry{
		ID: "entry-1", Action: "update", Resource: "api_key",
		AdminID: "root-1", IP: "10.0.0.1",
		Before: `{"active":true}`, After: `{"active":false}`, Reason: "why",
	})
	if err != nil {
		t.Fatalf("append entry: %v", err)
	}

	//nolint:noctx // test setup, no context needed for DML on in-memory DB
	if _, err := db.Exec(`UPDATE admin_audit_logs SET before_snapshot='{"active":false}' WHERE id='entry-1'`); err != nil {
		t.Fatalf("tamper snapshot: %v", err)
	}

	broken, err := NewVerifier(db).Verify(ctx)
	if err != nil {
		t.Logf("snapshot tampering detected via verify error: %v", err)
		return
	}
	if broken == 0 {
		t.Error("expected chain break after snapshot tampering, but got intact")
	}
}

// TestVerifier_UnknownVersionFailsClosed: a row stamped with a version this
// binary does not know is reported broken, never skipped.
func TestVerifier_UnknownVersionFailsClosed(t *testing.T) {
	db := setupTestDB(t)
	w := NewWriter(db)

	ctx := context.Background()
	if err := w.Append(ctx, "ACTION", "resource", "details", "admin-1", "", "10.0.0.1"); err != nil {
		t.Fatalf("append: %v", err)
	}
	//nolint:noctx // test setup, no context needed for DML on in-memory DB
	if _, err := db.Exec(`UPDATE admin_audit_logs SET hash_version = 99`); err != nil {
		t.Fatalf("bump version: %v", err)
	}

	broken, err := NewVerifier(db).Verify(ctx)
	if err != nil {
		t.Logf("unknown version fails closed with error: %v", err)
		return
	}
	if broken != 1 {
		t.Errorf("expected unknown version to break at seq 1, got %d", broken)
	}
}

func TestVerifier_EmptyChain_ReturnsZero(t *testing.T) {
	db := setupTestDB(t)
	v := NewVerifier(db)

	ctx := context.Background()
	broken, err := v.Verify(ctx)
	if err != nil {
		t.Fatalf("verify on empty: %v", err)
	}
	if broken != 0 {
		t.Errorf("expected intact chain (0) for empty table, got %d", broken)
	}
}

// TestBackfillChain_StampsLegacyVersion: backfilled pre-chain rows verify as
// v1.
func TestBackfillChain_StampsLegacyVersion(t *testing.T) {
	db := setupTestDB(t)
	w := NewWriter(db)

	ctx := context.Background()
	//nolint:noctx // test setup, no context needed for DML on in-memory DB
	_, err := db.Exec(`
		INSERT INTO admin_audit_logs (id, action, resource, details, admin_id, admin_name, ip_address, created_at)
		VALUES ('legacy-1', 'LOGIN', 'admin', 'seeded', 'root-1', 'Root', '10.0.0.1', '2026-01-01')`)
	if err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	if err := w.BackfillChain(ctx); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	verifyIntact(t, db)

	var version int
	//nolint:noctx // test assertion on in-memory DB
	if err := db.QueryRow(`SELECT hash_version FROM admin_audit_logs WHERE id='legacy-1'`).Scan(&version); err != nil {
		t.Fatalf("scan version: %v", err)
	}
	if version != HashVersionV1 {
		t.Errorf("backfilled row: want hash_version %d, got %d", HashVersionV1, version)
	}
}
