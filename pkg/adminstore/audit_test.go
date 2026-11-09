package adminstore

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENT-03 + AF-10: audit write-path — hash-chain row_hash/prev_hash through
// the shared auditlog.AppendInTx protocol (advisory-lock serialization,
// versioned payload, snapshot/reason columns).

// fakeAuditTx is the minimal auditTx double: it returns a seeded last-row hash
// (or ErrNoRows for the first row) and captures the INSERT args (the advisory
// lock Exec carries no args and is ignored).
type fakeAuditTx struct {
	lastHash   *string // nil → ErrNoRows (first row)
	committed  bool
	rolledBack bool
	inserted   []interface{}
}

func (t *fakeAuditTx) QueryRow(_ context.Context, _ string, _ ...interface{}) pgx.Row {
	if t.lastHash == nil {
		return &mockPGXRow{err: pgx.ErrNoRows}
	}
	return &mockPGXRow{data: [][]interface{}{{*t.lastHash}}}
}
func (t *fakeAuditTx) Query(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
	return nil, pgx.ErrNoRows
}
func (t *fakeAuditTx) Exec(_ context.Context, _ string, args ...interface{}) (pgconn.CommandTag, error) {
	if len(args) > 0 {
		t.inserted = args
	}
	return pgconn.NewCommandTag("INSERT 1"), nil
}
func (t *fakeAuditTx) Commit(context.Context) error   { t.committed = true; return nil }
func (t *fakeAuditTx) Rollback(context.Context) error { t.rolledBack = true; return nil }

func TestComputeAuditHash_ChainsAndMatchesWriterFormula(t *testing.T) {
	// The shared formula: sha256(prev_hash + "|" + payload).
	// An empty prev (first row) and a chained prev must differ and be
	// deterministic.
	first := computeAuditHash("", "create|org|d|u1|1.2.3.4")
	chained := computeAuditHash(first, "update|org|d|u1|1.2.3.4")
	assert.NotEqual(t, first, chained)
	// Re-computing is deterministic.
	assert.Equal(t, first, computeAuditHash("", "create|org|d|u1|1.2.3.4"))
	assert.Len(t, first, 64) // hex sha256
}

func TestInsertAuditLog_FirstRow(t *testing.T) {
	fake := &fakeAuditTx{} // no prior row
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return fake, nil }}
	s := newForTest(db, newTestLogger(), nil)

	err := s.InsertAuditLog(context.Background(), "id-1", "create", "org", "details", "u1", "alice", "1.2.3.4")
	require.NoError(t, err)
	assert.True(t, fake.committed, "audit tx must be committed")
	require.Len(t, fake.inserted, 14)
	// args: id, action, resource, details, admin_id, admin_name, ip,
	//       prev_hash, row_hash, hash_version, before, after, reason, created_at
	assert.Equal(t, "id-1", fake.inserted[0])
	assert.Empty(t, fake.inserted[7], "first row prev_hash is empty")
	wantHash := computeAuditHash("", auditPayload("create", "org", "details", "u1", "1.2.3.4"))
	assert.Equal(t, wantHash, fake.inserted[8], "row_hash must chain from the empty prev")
	// A plain entry (no snapshots/reason) keeps the legacy hash version.
	assert.Equal(t, 1, fake.inserted[9], "plain row stays hash_version 1")
	assert.Empty(t, fake.inserted[10])
	assert.Empty(t, fake.inserted[11])
	assert.Empty(t, fake.inserted[12])
	assert.False(t, fake.inserted[13].(time.Time).IsZero(), "created_at is stamped")
}

func TestInsertAuditLog_ChainedRow(t *testing.T) {
	prev := "previous-row-hash"
	fake := &fakeAuditTx{lastHash: &prev}
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return fake, nil }}
	s := newForTest(db, newTestLogger(), nil)

	err := s.InsertAuditLog(context.Background(), "id-2", "update", "org", "d", "u1", "alice", "1.2.3.4")
	require.NoError(t, err)
	require.Len(t, fake.inserted, 14)
	assert.Equal(t, prev, fake.inserted[7], "prev_hash carries the last row's hash")
	wantHash := computeAuditHash(prev, auditPayload("update", "org", "d", "u1", "1.2.3.4"))
	assert.Equal(t, wantHash, fake.inserted[8])
}

func TestInsertAuditLogEntry_FullRecord_HasVersionedPayload(t *testing.T) {
	prev := "previous-row-hash"
	fake := &fakeAuditTx{lastHash: &prev}
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return fake, nil }}
	s := newForTest(db, newTestLogger(), nil)

	ts := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	err := s.InsertAuditLogEntry(context.Background(), AuditLogEntryRecord{
		ID: "id-3", Action: "update", Resource: "api_key", Details: "id=k",
		AdminID: "u1", AdminName: "alice", IPAddress: "1.2.3.4",
		CreatedAt: ts,
		Before:    `{"active":true}`, After: `{"active":false}`, Reason: "leak",
	})
	require.NoError(t, err)
	require.Len(t, fake.inserted, 14)
	assert.Equal(t, 2, fake.inserted[9], "row with snapshot/reason data is hash_version 2")
	assert.Equal(t, `{"active":true}`, fake.inserted[10])
	assert.Equal(t, `{"active":false}`, fake.inserted[11])
	assert.Equal(t, "leak", fake.inserted[12])
	assert.Equal(t, ts, fake.inserted[13], "created_at is written explicitly")
	wantHash := computeAuditHash(prev, "update|api_key|id=k|u1|1.2.3.4|"+
		`{"active":true}`+"|"+`{"active":false}`+"|leak")
	assert.Equal(t, wantHash, fake.inserted[8], "v2 hash covers the extended payload")
}

func TestInsertAuditLog_NilDBNoop(t *testing.T) {
	s := newForTest(nil, newTestLogger(), nil)
	// No DB → no-op, no error (the "audit disabled" case).
	require.NoError(t, s.InsertAuditLog(context.Background(), "id", "a", "r", "d", "u", "n", "ip"))
}

func TestInsertAuditLog_BeginError(t *testing.T) {
	db := &mockDB{beginAuditTxFn: func(context.Context) (auditTx, error) { return nil, assert.AnError }}
	s := newForTest(db, newTestLogger(), nil)
	err := s.InsertAuditLog(context.Background(), "id", "a", "r", "d", "u", "n", "ip")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "begin audit tx")
}

func TestListAuditLogEntries_NilDBNoop(t *testing.T) {
	s := newForTest(nil, newTestLogger(), nil)
	items, total, pending, err := s.ListAuditLogEntries(context.Background(), AuditLogQuery{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.Empty(t, items)
	assert.Zero(t, total)
	assert.Zero(t, pending)
}

func TestListAuditLogEntries_RejectsUnknownSortColumn(t *testing.T) {
	db := &mockDB{}
	s := newForTest(db, newTestLogger(), nil)
	_, _, _, err := s.ListAuditLogEntries(context.Background(),
		AuditLogQuery{Sort: "action; DROP TABLE admin_audit_logs", Page: 1, PageSize: 10})
	require.Error(t, err, "non-allowlisted sort column must be rejected, never interpolated")
}
