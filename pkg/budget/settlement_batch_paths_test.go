package budget

// Routing control for the §5.5 batch executor's decision blocks
// (settlement_batch.go). One scenario-configurable fake re-drives every
// error and schema-domain branch of SettleOrgBatch and its helpers as
// pure unit work — no PostgreSQL, no docker, no randomness. Each test
// asserts the observable contract of the branch it reaches: the error
// text of the exact failing site, the durable dispositions, and whether
// the fake ever reached the commit site.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/require"
)

// pathFakeDB steers one SQL site per field; a zero-value field leaves its
// site succeeding with a sane default. The zero value therefore describes
// a fully successful batch, and each test switches on exactly the failure
// or row shape the branch under test needs.
type pathFakeDB struct {
	beginErr error // Begin failure: the batch aborts before any tx work

	syncCommitErr error // `SET LOCAL synchronous_commit` failure
	advisoryErr   error // pg_advisory_xact_lock failure

	fencingErr  error            // fencing SELECT failure
	fencingRows *pathFencingRows // fencing SELECT rows (nil = empty result)

	probeErr        error // schema-probe Scan failure
	probeGrace      int   // probe count for org_credits.grace_floor_cents
	probeInvocation int   // probe count for credit_transactions.invocation_id

	walletErr  error // wallet SELECT failure (not ErrNoRows)
	walletVals []any // wallet row values; nil = no wallet row (ErrNoRows)

	usageErr  error // idempotency SELECT failure (not ErrNoRows)
	usageVals []any // usage row values; nil = no prior usage row (ErrNoRows)

	insertErr       error  // usage-ledger INSERT failure
	insertTag       string // usage-ledger INSERT command tag ("" = "INSERT 0 1")
	updateWalletErr error  // `UPDATE org_credits SET balance_cents` failure
	markErr         error  // terminal-state `UPDATE settlement_jobs` failure

	begins  int
	commits int
}

func (d *pathFakeDB) Begin(context.Context) (pgx.Tx, error) {
	d.begins++
	if d.beginErr != nil {
		return nil, d.beginErr
	}
	return &pathFakeTx{parent: d}, nil
}

// pathFakeTx routes the batch's statements by SQL substring. Unrouted
// QueryRow/Query shapes fail loudly — a test silently exercising the
// wrong statement would assert against the wrong branch.
type pathFakeTx struct {
	pgx.Tx // nil-embedded: only the statements the batch exercises are routed
	parent *pathFakeDB
}

func (t *pathFakeTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	d := t.parent
	switch {
	case strings.Contains(sql, "synchronous_commit"):
		return pgconn.CommandTag{}, d.syncCommitErr
	case strings.Contains(sql, "pg_advisory_xact_lock"):
		return pgconn.CommandTag{}, d.advisoryErr
	case strings.Contains(sql, "INSERT INTO credit_transactions"):
		if d.insertErr != nil {
			return pgconn.CommandTag{}, d.insertErr
		}
		tag := d.insertTag
		if tag == "" {
			tag = "INSERT 0 1"
		}
		return pgconn.NewCommandTag(tag), nil
	case strings.Contains(sql, "UPDATE org_credits") && strings.Contains(sql, "balance_cents"):
		return pgconn.CommandTag{}, d.updateWalletErr
	case strings.Contains(sql, "UPDATE settlement_jobs"):
		return pgconn.CommandTag{}, d.markErr
	default:
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}
}

func (t *pathFakeTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	d := t.parent
	switch {
	case strings.Contains(sql, "information_schema.columns"):
		if d.probeErr != nil {
			return pathErrRow{err: d.probeErr}
		}
		return pathRow{vals: []any{d.probeGrace, d.probeInvocation}}
	case strings.Contains(sql, "FROM org_credits"):
		if d.walletErr != nil {
			return pathErrRow{err: d.walletErr}
		}
		if d.walletVals == nil {
			return pathErrRow{err: pgx.ErrNoRows}
		}
		return pathRow{vals: d.walletVals}
	case strings.Contains(sql, "FROM credit_transactions"):
		if d.usageErr != nil {
			return pathErrRow{err: d.usageErr}
		}
		if d.usageVals == nil {
			return pathErrRow{err: pgx.ErrNoRows}
		}
		return pathRow{vals: d.usageVals}
	default:
		return pathErrRow{err: fmt.Errorf("pathFakeTx: unrouted QueryRow: %s", pathFirstLine(sql))}
	}
}

func (t *pathFakeTx) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	d := t.parent
	if strings.Contains(sql, "FROM settlement_jobs") {
		if d.fencingErr != nil {
			return nil, d.fencingErr
		}
		if d.fencingRows == nil {
			return &pathFencingRows{}, nil
		}
		return d.fencingRows, nil
	}
	return nil, fmt.Errorf("pathFakeTx: unrouted Query: %s", pathFirstLine(sql))
}

func (t *pathFakeTx) Commit(context.Context) error {
	t.parent.commits++
	return nil
}

func (t *pathFakeTx) Rollback(context.Context) error { return nil }

// pathRow scans fixed values into the dest shapes the batch uses
// (*int, *int64, *string, **int64). A shape mismatch is a fake bug and
// fails loudly instead of feeding the branch wrong-typed zeros.
type pathRow struct{ vals []any }

func (r pathRow) Scan(dest ...any) error {
	if len(dest) != len(r.vals) {
		return fmt.Errorf("pathRow: %d dests but %d values", len(dest), len(r.vals))
	}
	for i, d := range dest {
		switch d := d.(type) {
		case *int:
			v, ok := r.vals[i].(int)
			if !ok {
				return fmt.Errorf("pathRow: dest %d wants int, got %T", i, r.vals[i])
			}
			*d = v
		case *int64:
			v, ok := r.vals[i].(int64)
			if !ok {
				return fmt.Errorf("pathRow: dest %d wants int64, got %T", i, r.vals[i])
			}
			*d = v
		case *string:
			v, ok := r.vals[i].(string)
			if !ok {
				return fmt.Errorf("pathRow: dest %d wants string, got %T", i, r.vals[i])
			}
			*d = v
		case **int64:
			p, ok := r.vals[i].(*int64)
			if !ok {
				return fmt.Errorf("pathRow: dest %d wants *int64, got %T", i, r.vals[i])
			}
			*d = p
		default:
			return fmt.Errorf("pathRow: unsupported dest %T", dest[i])
		}
	}
	return nil
}

// pathErrRow always fails Scan with its error.
type pathErrRow struct{ err error }

func (r pathErrRow) Scan(...any) error { return r.err }

// pathFencingRow is one settlement_jobs row projected by the fencing read.
type pathFencingRow struct {
	id       int64
	attempts int32
}

// pathFencingRows replays the fencing SELECT result. scanErr fails every
// Scan; err is surfaced by Err() after iteration — the two distinct
// driver-failure shapes the fencing verifier must tell apart.
type pathFencingRows struct {
	pgx.Rows // nil-embedded: the batch uses only Next/Scan/Err/Close
	rows     []pathFencingRow
	scanErr  error
	err      error
	i        int
}

func (r *pathFencingRows) Next() bool {
	r.i++
	return r.i <= len(r.rows)
}

func (r *pathFencingRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	if r.i < 1 || r.i > len(r.rows) || len(dest) != 2 {
		return fmt.Errorf("pathFencingRows: Scan misuse (i=%d dests=%d)", r.i, len(dest))
	}
	*(dest[0].(*int64)) = r.rows[r.i-1].id
	*(dest[1].(*int32)) = r.rows[r.i-1].attempts
	return nil
}

func (r *pathFencingRows) Err() error { return r.err }
func (r *pathFencingRows) Close()     {}

// pathFakeAgentSpender is the BatchAgentSpender whose execution fails —
// the agent-spend error the batch must propagate uncommitted.
type pathFakeAgentSpender struct{ err error }

func (s pathFakeAgentSpender) RecordAgentSpendExact(context.Context, SpendExecutor, string, money.MicroUSD, int64, int64) error {
	return s.err
}

func pathFirstLine(sql string) string {
	if i := strings.IndexByte(sql, '\n'); i >= 0 {
		return sql[:i]
	}
	return sql
}

func pathInt64Ptr(v int64) *int64 { return &v }

// pathOneResaleEntry is the minimal wallet-scope batch for error-path
// tests: one chargeable resale entry, no fencing token.
func pathOneResaleEntry() []SettleEntry {
	return []SettleEntry{{JobID: 1, Kind: SettleKindResale, RequestID: "req-1", Amount: 1000}}
}

// pathTokenEntries mixes one fenced job with one legacy zero-token job:
// the fencing verifier must select and check only the fenced one.
func pathTokenEntries() []SettleEntry {
	return []SettleEntry{
		{JobID: 11, FencingToken: 3, Kind: SettleKindResale, RequestID: "req-11", Amount: 1000},
		{JobID: 12, FencingToken: 0, Kind: SettleKindResale, RequestID: "req-12", Amount: 1000},
	}
}

func TestSettleOrgBatch_RejectsEmptyOrgBeforeBegin(t *testing.T) {
	db := &pathFakeDB{beginErr: errors.New("begin must never be reached")}
	_, err := SettleOrgBatch(context.Background(), db, "", 0, pathOneResaleEntry(), BatchSpenders{})
	require.ErrorContains(t, err, "empty org id")
	require.Zero(t, db.begins, "validation must refuse the input before Begin")
}

func TestValidateSettlementBatch_RejectsNilDB(t *testing.T) {
	err := validateSettlementBatch(nil, "org-2", nil)
	require.ErrorContains(t, err, "nil db")
}

func TestSettleOrgBatch_BeginErrorAborts(t *testing.T) {
	db := &pathFakeDB{beginErr: errors.New("pool unavailable")}
	dispositions, err := SettleOrgBatch(context.Background(), db, "org-3", 0, pathOneResaleEntry(), BatchSpenders{})
	require.ErrorContains(t, err, "settlement batch begin tx")
	require.ErrorContains(t, err, "pool unavailable")
	require.Nil(t, dispositions)
	require.Zero(t, db.commits)
}

func TestSettleOrgBatch_LockErrorsAbortUncommitted(t *testing.T) {
	t.Run("synchronous_commit", func(t *testing.T) {
		db := &pathFakeDB{syncCommitErr: errors.New("set local rejected")}
		_, err := SettleOrgBatch(context.Background(), db, "org-4", 0, pathOneResaleEntry(), BatchSpenders{})
		require.ErrorContains(t, err, "settlement batch synchronous commit")
		require.Zero(t, db.commits)
	})
	t.Run("advisory_lock", func(t *testing.T) {
		db := &pathFakeDB{advisoryErr: errors.New("lock function failed")}
		_, err := SettleOrgBatch(context.Background(), db, "org-5", 0, pathOneResaleEntry(), BatchSpenders{})
		require.ErrorContains(t, err, "settlement batch advisory lock")
		require.Zero(t, db.commits)
	})
}

func TestSettleOrgBatch_FencingFailuresAbortUncommitted(t *testing.T) {
	t.Run("fencing_read_error", func(t *testing.T) {
		db := &pathFakeDB{fencingErr: errors.New("fencing select failed")}
		_, err := SettleOrgBatch(context.Background(), db, "org-fencing", 0, pathTokenEntries(), BatchSpenders{})
		require.ErrorContains(t, err, "settlement batch fencing read")
		require.Zero(t, db.commits)
	})
	t.Run("stale_token", func(t *testing.T) {
		db := &pathFakeDB{fencingRows: &pathFencingRows{rows: []pathFencingRow{{id: 11, attempts: 4}}}}
		_, err := SettleOrgBatch(context.Background(), db, "org-fencing", 0, pathTokenEntries(), BatchSpenders{})
		require.ErrorIs(t, err, ErrStaleSettlementToken)
		require.ErrorContains(t, err, "claim=3 current=4")
		require.Zero(t, db.commits)
	})
	t.Run("job_no_longer_processing", func(t *testing.T) {
		// The fencing SELECT returns zero rows: the claimed job left
		// 'processing' under this token (recovered or re-claimed).
		db := &pathFakeDB{}
		_, err := SettleOrgBatch(context.Background(), db, "org-fencing", 0, pathTokenEntries(), BatchSpenders{})
		require.ErrorIs(t, err, ErrStaleSettlementToken)
		require.ErrorContains(t, err, "no longer 'processing'")
		require.Zero(t, db.commits)
	})
	t.Run("fencing_scan_error", func(t *testing.T) {
		db := &pathFakeDB{fencingRows: &pathFencingRows{
			rows:    []pathFencingRow{{id: 11, attempts: 3}},
			scanErr: errors.New("scan decode failed"),
		}}
		_, err := SettleOrgBatch(context.Background(), db, "org-fencing", 0, pathTokenEntries(), BatchSpenders{})
		require.ErrorContains(t, err, "settlement batch fencing scan")
		require.Zero(t, db.commits)
	})
	t.Run("rows_iterate_error", func(t *testing.T) {
		db := &pathFakeDB{fencingRows: &pathFencingRows{err: errors.New("driver stream broke")}}
		_, err := SettleOrgBatch(context.Background(), db, "org-fencing", 0, pathTokenEntries(), BatchSpenders{})
		require.ErrorContains(t, err, "settlement batch fencing rows")
		require.Zero(t, db.commits)
	})
}

// A fencing read whose single row still carries the claimed token must
// pass and let the batch settle normally — the control proving the
// failure shapes above are the only fences raised.
func TestSettleOrgBatch_MatchingFencingCompletes(t *testing.T) {
	db := &pathFakeDB{
		probeGrace:      0,
		probeInvocation: 1,
		fencingRows:     &pathFencingRows{rows: []pathFencingRow{{id: 21, attempts: 7}}},
		walletVals:      []any{int64(1000), int64(0)},
	}
	entries := []SettleEntry{{
		JobID: 21, FencingToken: 7, Kind: SettleKindResale,
		InvocationID: "inv-21", RequestID: "req-21", Amount: 50_000,
	}}
	dispositions, err := SettleOrgBatch(context.Background(), db, "org-21", 0, entries, BatchSpenders{})
	require.NoError(t, err)
	got := dispositions[21]
	require.True(t, got.Settled, "a token-matching job must settle")
	require.True(t, got.Applied)
	require.Equal(t, 1, db.commits, "the batch must reach the commit site")
}

func TestSettleOrgBatch_SchemaProbeErrorAborts(t *testing.T) {
	db := &pathFakeDB{probeErr: errors.New("catalog unavailable")}
	_, err := SettleOrgBatch(context.Background(), db, "org-10", 0, pathOneResaleEntry(), BatchSpenders{})
	require.ErrorContains(t, err, "settlement batch schema probe")
	require.Zero(t, db.commits)
}

// grace_floor_cents absent: the two-column wallet read runs and the
// global grace floor governs the charge.
func TestSettleOrgBatch_TwoColumnWalletReadAppliesCharge(t *testing.T) {
	db := &pathFakeDB{probeGrace: 0, probeInvocation: 1, walletVals: []any{int64(500), int64(0)}}
	entries := []SettleEntry{{JobID: 31, Kind: SettleKindResale, RequestID: "req-31", Amount: 150_000}}
	dispositions, err := SettleOrgBatch(context.Background(), db, "org-31", -100, entries, BatchSpenders{})
	require.NoError(t, err)
	got := dispositions[31]
	require.True(t, got.Settled)
	require.True(t, got.Applied)
	require.Equal(t, 1, db.commits)
}

func TestSettleOrgBatch_WalletReadErrorAborts(t *testing.T) {
	db := &pathFakeDB{
		probeGrace: 1, probeInvocation: 1,
		walletErr: errors.New("wallet read broke"),
	}
	_, err := SettleOrgBatch(context.Background(), db, "org-12", 0, pathOneResaleEntry(), BatchSpenders{})
	require.ErrorContains(t, err, "settlement batch wallet read")
	require.Zero(t, db.commits)
}

// An explicit org grace floor overrides the global fallback, and a
// poison entry (no request identity) parks without spending it.
func TestSettleOrgBatch_GraceOverrideParksPoison(t *testing.T) {
	db := &pathFakeDB{
		probeGrace: 1, probeInvocation: 1,
		walletVals: []any{int64(500), int64(0), pathInt64Ptr(-5)},
	}
	entries := []SettleEntry{{JobID: 41, Kind: SettleKindResale, RequestID: "", Amount: 1000}}
	dispositions, err := SettleOrgBatch(context.Background(), db, "org-41", -100, entries, BatchSpenders{})
	require.NoError(t, err)
	require.Equal(t, ReasonPoisonPayload, dispositions[41].Reason)
	require.False(t, dispositions[41].Settled)
	require.Equal(t, 1, db.commits, "the parked disposition must still be committed durably")
}

func TestSettleOrgBatch_UsageReadErrorAborts(t *testing.T) {
	db := &pathFakeDB{
		probeGrace: 0, probeInvocation: 1,
		walletVals: []any{int64(1000), int64(0)},
		usageErr:   errors.New("idempotency read broke"),
	}
	_, err := SettleOrgBatch(context.Background(), db, "org-14", 0, pathOneResaleEntry(), BatchSpenders{})
	require.ErrorContains(t, err, "settlement batch idempotency read")
	require.Zero(t, db.commits)
}

// A charge that would land the wallet below its floor parks the job as
// insufficient_credits without touching the wallet state.
func TestSettleOrgBatch_InsufficientCreditsParksUnapplied(t *testing.T) {
	db := &pathFakeDB{probeGrace: 0, probeInvocation: 0, walletVals: []any{int64(0), int64(0)}}
	entries := []SettleEntry{{JobID: 51, Kind: SettleKindResale, RequestID: "req-51", Amount: 100_000}}
	dispositions, err := SettleOrgBatch(context.Background(), db, "org-51", 0, entries, BatchSpenders{})
	require.NoError(t, err)
	require.Equal(t, ReasonInsufficientCredits, dispositions[51].Reason)
	require.False(t, dispositions[51].Settled)
	require.False(t, dispositions[51].Applied)
	require.Equal(t, 1, db.commits)
}

// An invocation-bearing entry on a ledger without the invocation column
// is refused loudly — never downgraded to the legacy identity domain.
func TestSettleOrgBatch_InvocationRefusedOnLegacyLedger(t *testing.T) {
	db := &pathFakeDB{
		probeGrace: 1, probeInvocation: 0,
		walletVals: []any{int64(1000), int64(0), (*int64)(nil)},
	}
	entries := []SettleEntry{{
		JobID: 61, Kind: SettleKindResale,
		RequestID: "req-61", InvocationID: "inv-61", Amount: 1000,
	}}
	_, err := SettleOrgBatch(context.Background(), db, "org-61", 0, entries, BatchSpenders{})
	require.ErrorContains(t, err, "refusing the legacy domain")
	require.Zero(t, db.commits)
}

// The invocation identity domain end to end: minted-uuid idempotency
// read, invocation-arbiter ledger insert, committed settle.
func TestSettleOrgBatch_InvocationDomainSettles(t *testing.T) {
	db := &pathFakeDB{probeGrace: 0, probeInvocation: 1, walletVals: []any{int64(1000), int64(0)}}
	entries := []SettleEntry{{
		JobID: 71, Kind: SettleKindResale,
		RequestID: "req-71", InvocationID: "inv-71", Amount: 50_000,
	}}
	dispositions, err := SettleOrgBatch(context.Background(), db, "org-71", 0, entries, BatchSpenders{})
	require.NoError(t, err)
	got := dispositions[71]
	require.True(t, got.Settled)
	require.True(t, got.Applied)
	require.Equal(t, 1, db.commits)
}

// Legacy (request-id) identity on both schema generations: the
// NULL-invocation lookup and each ledger insert statement complete.
func TestSettleOrgBatch_LegacyIdentityDomainsSettle(t *testing.T) {
	t.Run("legacy_on_0028_ledger", func(t *testing.T) {
		db := &pathFakeDB{
			probeGrace: 1, probeInvocation: 1,
			walletVals: []any{int64(1000), int64(0), (*int64)(nil)},
		}
		entries := []SettleEntry{{JobID: 81, Kind: SettleKindResale, RequestID: "req-81", Amount: 50_000}}
		dispositions, err := SettleOrgBatch(context.Background(), db, "org-81", 0, entries, BatchSpenders{})
		require.NoError(t, err)
		require.True(t, dispositions[81].Settled)
		require.True(t, dispositions[81].Applied)
		require.Equal(t, 1, db.commits)
	})
	t.Run("pre_0028_ledger", func(t *testing.T) {
		db := &pathFakeDB{probeGrace: 0, probeInvocation: 0, walletVals: []any{int64(1000), int64(0)}}
		entries := []SettleEntry{{JobID: 82, Kind: SettleKindResale, RequestID: "req-82", Amount: 50_000}}
		dispositions, err := SettleOrgBatch(context.Background(), db, "org-82", 0, entries, BatchSpenders{})
		require.NoError(t, err)
		require.True(t, dispositions[82].Settled)
		require.True(t, dispositions[82].Applied)
		require.Equal(t, 1, db.commits)
	})
}

func TestSettleOrgBatch_LedgerInsertFailuresAbort(t *testing.T) {
	invocationEntry := func() []SettleEntry {
		return []SettleEntry{{
			JobID: 71, Kind: SettleKindResale,
			RequestID: "req-71", InvocationID: "inv-71", Amount: 50_000,
		}}
	}
	t.Run("insert_exec_error", func(t *testing.T) {
		db := &pathFakeDB{
			probeGrace: 0, probeInvocation: 1,
			walletVals: []any{int64(1000), int64(0)},
			insertErr:  errors.New("insert broke"),
		}
		_, err := SettleOrgBatch(context.Background(), db, "org-20", 0, invocationEntry(), BatchSpenders{})
		require.ErrorContains(t, err, "settlement batch ledger insert")
		require.Zero(t, db.commits)
	})
	t.Run("insert_swallowed_conflict", func(t *testing.T) {
		// A zero-row insert would silently drop a charge; the batch must
		// fail loudly even though the statement itself succeeded.
		db := &pathFakeDB{
			probeGrace: 0, probeInvocation: 1,
			walletVals: []any{int64(1000), int64(0)},
			insertTag:  "INSERT 0 0",
		}
		_, err := SettleOrgBatch(context.Background(), db, "org-21x", 0, invocationEntry(), BatchSpenders{})
		require.ErrorContains(t, err, "vanished mid-transaction")
		require.Zero(t, db.commits)
	})
}

// A committed usage row owned by a foreign org is an identity conflict:
// the entry parks durably, no money moves.
func TestSettleOrgBatch_IdentityConflictParks(t *testing.T) {
	db := &pathFakeDB{
		probeGrace: 0, probeInvocation: 1,
		walletVals: []any{int64(1000), int64(0)},
		usageVals:  []any{"other-org"},
	}
	entries := []SettleEntry{{JobID: 91, Kind: SettleKindResale, RequestID: "req-91", Amount: 1000}}
	dispositions, err := SettleOrgBatch(context.Background(), db, "org-91", 0, entries, BatchSpenders{})
	require.NoError(t, err)
	require.Equal(t, ReasonIdentityConflict, dispositions[91].Reason)
	require.False(t, dispositions[91].Settled)
	require.Equal(t, 1, db.commits)
}

func TestSettleOrgBatch_WalletUpdateErrorAborts(t *testing.T) {
	db := &pathFakeDB{
		probeGrace: 0, probeInvocation: 1,
		walletVals:      []any{int64(1000), int64(0)},
		updateWalletErr: errors.New("update broke"),
	}
	_, err := SettleOrgBatch(context.Background(), db, "org-22", 0, pathOneResaleEntry(), BatchSpenders{})
	require.ErrorContains(t, err, "settlement batch wallet update")
	require.Zero(t, db.commits)
}

// A spend-scope-only batch skips the wallet phase entirely and the
// agent-spend error surfaces before anything commits.
func TestSettleOrgBatch_AgentSpenderErrorAborts(t *testing.T) {
	db := &pathFakeDB{}
	entries := []SettleEntry{{
		JobID: 101, Kind: SettleKindAgent, RequestID: "req-101", Amount: 1000,
		Payload: []byte(`{"agent_id":"11111111-1111-1111-1111-111111111111","tokens_in":10,"tokens_out":20}`),
	}}
	spenders := BatchSpenders{Agent: pathFakeAgentSpender{err: errors.New("spender broke")}}
	_, err := SettleOrgBatch(context.Background(), db, "org-101", 0, entries, spenders)
	require.ErrorContains(t, err, "spender broke")
	require.Zero(t, db.commits)
}

// Terminal-state write failure: the whole batch must report the error
// and leave nothing committed.
func TestSettleOrgBatch_MarkSettledErrorAborts(t *testing.T) {
	db := &pathFakeDB{probeGrace: 0, probeInvocation: 1, markErr: errors.New("mark broke")}
	_, err := SettleOrgBatch(context.Background(), db, "org-102", 0, pathOneResaleEntry(), BatchSpenders{})
	require.ErrorContains(t, err, "settlement batch attention mark")
	require.Zero(t, db.commits)
}

// The ledger-insert guard against an invocation identity reaching a
// pre-0028 statement is unreachable through SettleOrgBatch (the
// idempotency read refuses that state first); the unit call pins the
// guard so no future path can silently bill under the shared identity.
func TestInsertWalletLedgerRow_RefusesInvocationOnLegacyLedger(t *testing.T) {
	db := &pathFakeDB{}
	err := insertWalletLedgerRow(context.Background(), &pathFakeTx{parent: db}, "org-103",
		SettleEntry{JobID: 103, Kind: SettleKindResale, RequestID: "req-103", InvocationID: "inv-103", Amount: 1000},
		100, 1, batchSchema{})
	require.ErrorContains(t, err, "refusing the legacy domain")
	require.Zero(t, db.commits)
}
