package lineage

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDB is a scriptable dbtx double: it records Exec calls and serves
// canned QueryRow / Query results.
type fakeDB struct {
	mu sync.Mutex

	execs []execCall

	// execFn, when set, overrides the default success return.
	execFn func(sql string, args []any) (pgconn.CommandTag, error)

	// queryRowFn serves lastRecordHash lookups (and anything else QueryRow).
	queryRowFn func(sql string, args []any) pgx.Row

	// queryFn serves the pending-rows claim query.
	queryFn func(sql string, args []any) (pgx.Rows, error)
}

type execCall struct {
	sql  string
	args []any
}

func (f *fakeDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.mu.Lock()
	f.execs = append(f.execs, execCall{sql: sql, args: args})
	f.mu.Unlock()
	if f.execFn != nil {
		return f.execFn(sql, args)
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (f *fakeDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	if f.queryRowFn != nil {
		return f.queryRowFn(sql, args)
	}
	return &fakeRow{err: pgx.ErrNoRows}
}

func (f *fakeDB) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	if f.queryFn != nil {
		return f.queryFn(sql, args)
	}
	return &fakeRows{}, nil
}

func (f *fakeDB) execCalls() []execCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]execCall, len(f.execs))
	copy(out, f.execs)
	return out
}

// fakeRow is a pgx.Row with canned values.
type fakeRow struct {
	vals []any
	err  error
}

func (r *fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, d := range dest {
		if i >= len(r.vals) {
			break
		}
		switch v := d.(type) {
		case *string:
			*v = r.vals[i].(string)
		default:
			return errors.New("fakeRow: unsupported dest type")
		}
	}
	return nil
}

// fakeRows is a pgx.Rows over canned rows. Every row must have the same shape
// as the RelayPass claim query: 13 columns (id first, raw last).
type fakeRows struct {
	rows [][]any
	idx  int
	err  error
}

func (r *fakeRows) Next() bool { return r.idx < len(r.rows) }
func (r *fakeRows) Scan(dest ...any) error {
	if r.idx >= len(r.rows) {
		return errors.New("fakeRows: no row")
	}
	row := r.rows[r.idx]
	r.idx++
	for i, d := range dest {
		if i >= len(row) {
			break
		}
		switch v := d.(type) {
		case *int64:
			*v = row[i].(int64)
		case *string:
			*v = row[i].(string)
		case *[]byte:
			*v = row[i].([]byte)
		case *any:
			*v = row[i]
		default:
			return errors.New("fakeRows: unsupported dest type")
		}
	}
	return nil
}
func (r *fakeRows) Err() error                                   { return r.err }
func (r *fakeRows) Close()                                       {}
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Conn() *pgx.Conn                              { return nil }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Values() ([]any, error)                       { return nil, nil }

func testAttestation(reqID string) Attestation {
	return Attestation{
		RequestID:        reqID,
		OrgID:            "org-1",
		ModelUsed:        "gpt-4o-mini",
		InferenceRegion:  "US",
		ModelOrigin:      "US",
		LogStorageRegion: "SG",
		ProviderEntity:   "US",
		Timestamp:        time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
}

func TestOutbox_Enqueue(t *testing.T) {
	db := &fakeDB{}
	ob := NewOutbox(db, slog.Default())
	att := testAttestation("req-1")

	require.NoError(t, ob.Enqueue(context.Background(), att, "sig-b64", "org:org-1:v1"))

	calls := db.execCalls()
	require.Len(t, calls, 1)
	assert.Contains(t, calls[0].sql, "INSERT INTO lineage_outbox")
	assert.Contains(t, calls[0].sql, "ON CONFLICT (request_id) DO NOTHING")
	// args: request_id, org_id, model_used, inference_region, model_origin,
	// log_storage_region, provider_entity, region_evidence, hash, sig, key, raw
	require.Len(t, calls[0].args, 12)
	assert.Equal(t, "req-1", calls[0].args[0])
	assert.Equal(t, "org:org-1:v1", calls[0].args[10])
}

func TestOutbox_Enqueue_DBError(t *testing.T) {
	db := &fakeDB{execFn: func(string, []any) (pgconn.CommandTag, error) {
		return pgconn.NewCommandTag(""), errors.New("db down")
	}}
	ob := NewOutbox(db, slog.Default())
	err := ob.Enqueue(context.Background(), testAttestation("req-1"), "sig", "k")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "enqueue lineage outbox")
}

func TestOutbox_RelayPass_ChainLinks(t *testing.T) {
	att := testAttestation("req-2")
	raw, err := json.Marshal(att)
	require.NoError(t, err)
	hash, err := att.Hash()
	require.NoError(t, err)

	db := &fakeDB{
		// lastRecordHash returns an existing chain head.
		queryRowFn: func(sql string, args []any) pgx.Row {
			if strings.Contains(sql, "record_hash") {
				return &fakeRow{vals: []any{"prev-hash-hex"}}
			}
			return &fakeRow{err: pgx.ErrNoRows}
		},
		queryFn: func(sql string, args []any) (pgx.Rows, error) {
			if strings.Contains(sql, "lineage_outbox") {
				return &fakeRows{rows: [][]any{{
					int64(1), "req-2", "org-1", "gpt-4o-mini", "US", "US", "SG", "US", "US",
					hash, "sig-b64", "org:org-1:v1", raw,
				}}}, nil
			}
			return &fakeRows{}, nil
		},
	}
	ob := NewOutbox(db, slog.Default())

	n, err := ob.RelayPass(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	calls := db.execCalls()
	require.Len(t, calls, 2) // relay insert + mark relayed
	ins := calls[0]
	assert.Contains(t, ins.sql, "INSERT INTO request_lineage")
	assert.Contains(t, ins.sql, "ON CONFLICT (request_id) DO NOTHING")
	require.Len(t, ins.args, 14)
	assert.Equal(t, "req-2", ins.args[0])
	assert.Equal(t, "sig-b64", ins.args[9])
	// record_hash = sha256(prev + "|" + canonical), prev_hash = head.
	wantRec := rowHash("prev-hash-hex", canonicalRecord(att, hash, "sig-b64", "org:org-1:v1"))
	assert.Equal(t, wantRec, ins.args[12])
	assert.Equal(t, "prev-hash-hex", ins.args[13])
	assert.Contains(t, calls[1].sql, "UPDATE lineage_outbox SET relayed_at")
}

func TestOutbox_RelayPass_MalformedRawSkipped(t *testing.T) {
	db := &fakeDB{
		queryFn: func(sql string, args []any) (pgx.Rows, error) {
			return &fakeRows{rows: [][]any{{
				int64(1), "req-bad", "org-1", "m", "US", "US", "SG", "US", "US",
				"hash", nil, nil, []byte("{not-json"),
			}}}, nil
		},
	}
	ob := NewOutbox(db, slog.Default())
	n, err := ob.RelayPass(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	// The malformed row is marked relayed so it cannot wedge the pipeline.
	calls := db.execCalls()
	require.Len(t, calls, 1)
	assert.Contains(t, calls[0].sql, "UPDATE lineage_outbox SET relayed_at")
}

func TestOutbox_RelayPass_InsertErrorLeavesPending(t *testing.T) {
	att := testAttestation("req-3")
	raw, err := json.Marshal(att)
	require.NoError(t, err)
	hash, err := att.Hash()
	require.NoError(t, err)

	inserts := 0
	db := &fakeDB{
		execFn: func(sql string, args []any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "INSERT INTO request_lineage") {
				inserts++
				return pgconn.NewCommandTag(""), errors.New("insert failed")
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
		queryFn: func(sql string, args []any) (pgx.Rows, error) {
			return &fakeRows{rows: [][]any{{
				int64(1), "req-3", "org-1", "gpt-4o-mini", "US", "US", "SG", "US", "US",
				hash, nil, nil, raw,
			}}}, nil
		},
	}
	ob := NewOutbox(db, slog.Default())
	n, err := ob.RelayPass(context.Background())
	require.NoError(t, err) // per-row failure does not fail the pass
	assert.Equal(t, 0, n)
	assert.Equal(t, 1, inserts)
	// No mark-relayed: the row stays pending for the next pass.
	for _, c := range db.execCalls() {
		assert.NotContains(t, c.sql, "UPDATE lineage_outbox")
	}
}

func TestOutbox_RelayPass_BoundedLimit(t *testing.T) {
	var gotLimit any
	db := &fakeDB{
		queryFn: func(sql string, args []any) (pgx.Rows, error) {
			if strings.Contains(sql, "lineage_outbox") {
				gotLimit = args[len(args)-1]
			}
			return &fakeRows{}, nil
		},
	}
	ob := NewOutbox(db, slog.Default())
	_, err := ob.RelayPass(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 500, gotLimit, "claim must be bounded to maxRel")
}

func TestOutbox_RelayPass_ConcurrentGuard(t *testing.T) {
	ob := NewOutbox(&fakeDB{}, slog.Default())
	require.True(t, ob.mu.tryLock())
	defer ob.mu.unlock()
	_, err := ob.RelayPass(context.Background())
	assert.ErrorIs(t, err, ErrRelayInProgress)
}

func TestOutbox_RelayPass_Empty(t *testing.T) {
	ob := NewOutbox(&fakeDB{}, slog.Default())
	n, err := ob.RelayPass(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestRelayLoop_FinalDrainOnCancel(t *testing.T) {
	att := testAttestation("req-4")
	raw, err := json.Marshal(att)
	require.NoError(t, err)
	hash, err := att.Hash()
	require.NoError(t, err)

	db := &fakeDB{
		queryFn: func(sql string, args []any) (pgx.Rows, error) {
			return &fakeRows{rows: [][]any{{
				int64(7), "req-4", "org-1", "gpt-4o-mini", "US", "US", "SG", "US", "US",
				hash, nil, nil, raw,
			}}}, nil
		},
	}
	ob := NewOutbox(db, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ob.RelayLoop(ctx, 50*time.Millisecond)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RelayLoop did not exit after cancel")
	}
	// The final drain relayed the pending row.
	found := false
	for _, c := range db.execCalls() {
		if strings.Contains(c.sql, "INSERT INTO request_lineage") {
			found = true
			assert.Equal(t, "req-4", c.args[0])
		}
	}
	assert.True(t, found, "final drain must relay pending rows")
}

func TestAsyncLedger_AppendDurable(t *testing.T) {
	db := &fakeDB{}
	ob := NewOutbox(db, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	al := newAsyncLedgerWithOutbox(ob, slog.Default(), ctx)
	defer al.Close(2 * time.Second)

	require.NoError(t, al.Append(context.Background(), testAttestation("req-5"), "sig", "k"))
	calls := db.execCalls()
	require.Len(t, calls, 1)
	assert.Contains(t, calls[0].sql, "INSERT INTO lineage_outbox")
}

func TestAsyncLedger_AppendErrorPropagates(t *testing.T) {
	db := &fakeDB{execFn: func(string, []any) (pgconn.CommandTag, error) {
		return pgconn.NewCommandTag(""), errors.New("db down")
	}}
	ob := NewOutbox(db, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	al := newAsyncLedgerWithOutbox(ob, slog.Default(), ctx)
	defer al.Close(2 * time.Second)

	err := al.Append(context.Background(), testAttestation("req-6"), "sig", "k")
	require.Error(t, err, "evidence must never be silently dropped on DB failure")
}

func TestAsyncLedger_CloseStops(t *testing.T) {
	al := newAsyncLedgerWithOutbox(NewOutbox(&fakeDB{}, slog.Default()), slog.Default(), context.Background())
	al.Close(2 * time.Second)
	// Double-close must be safe.
	al.Close(2 * time.Second)
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *fakeRows) TypeMap() *pgtype.Map { return nil }
