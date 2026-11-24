package budget

// Deterministic classification control for the §5.5 batch commit branch.
// A mixed group (one chargeable job, one parked as debt) whose commit
// outcome is unknown must never re-execute: the worker keys that decision
// on ErrCommitUncertain, and this control pins exactly which commit-stage
// errors carry that marker. Pure unit — a fake BatchDB drives
// SettleOrgBatch to the commit site with no PostgreSQL.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// commitFakeDB routes SettleOrgBatch deterministically: the schema probe
// reports both modern columns, the wallet read reports no wallet row
// (every entry parks — dispositions exist, nothing durable claimed), and
// Commit returns the injected error.
type commitFakeDB struct {
	commitErr error
	commits   int
}

func (d *commitFakeDB) Begin(ctx context.Context) (pgx.Tx, error) {
	return &commitFakeTx{parent: d}, nil
}

type commitFakeTx struct {
	pgx.Tx // nil-embedded: only the statements the batch exercises are routed
	parent *commitFakeDB
}

func (t *commitFakeTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (t *commitFakeTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "information_schema.columns") {
		// Schema probe: both grace_floor_cents and invocation_id present.
		return commitRow{vals: []any{1, 1}}
	}
	// Wallet read: no wallet row → every resale entry parks as no-wallet.
	return commitErrRow{err: pgx.ErrNoRows}
}

func (t *commitFakeTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	// Unreachable with zero fencing tokens, but keep the tx honest.
	return nil, errors.New("commitFakeTx: unexpected Query")
}

func (t *commitFakeTx) Commit(ctx context.Context) error {
	t.parent.commits++
	return t.parent.commitErr
}

func (t *commitFakeTx) Rollback(ctx context.Context) error { return nil }

// commitRow scans fixed scalar values (the probe row).
type commitRow struct{ vals []any }

func (r commitRow) Scan(dest ...any) error {
	if len(dest) != len(r.vals) {
		return fmt.Errorf("commitRow: dest count %d != vals %d", len(dest), len(r.vals))
	}
	for i := range dest {
		d, ok := dest[i].(*int)
		if !ok {
			return fmt.Errorf("commitRow: unsupported dest %T", dest[i])
		}
		v, ok := r.vals[i].(int)
		if !ok {
			return fmt.Errorf("commitRow: unsupported val %T", r.vals[i])
		}
		*d = v
	}
	return nil
}

// commitErrRow always fails with its error.
type commitErrRow struct{ err error }

func (r commitErrRow) Scan(dest ...any) error { return r.err }

// commitClassEntries is the mixed-group shape: two resale jobs — in the
// real system one would settle and one park; here both park on the
// no-wallet read, which leaves the same durable disposition map the
// commit protects.
func commitClassEntries() []SettleEntry {
	return []SettleEntry{
		{JobID: 1, Kind: SettleKindResale, Amount: 10000, RequestID: "cls-req-1"},
		{JobID: 2, Kind: SettleKindResale, Amount: 10000, RequestID: "cls-req-2"},
	}
}

// settleToCommit runs the batch against the fake and returns the
// classification verdict. The dispositions prove the batch reached the
// commit site; a verdict that passed vacuously on an early error would
// mislead the worker's no-replay contract.
func settleToCommit(t *testing.T, commitErr error) (map[int64]BatchDisposition, int, error) {
	t.Helper()
	db := &commitFakeDB{commitErr: commitErr}
	dispositions, err := SettleOrgBatch(context.Background(), db, "commit-class-org", -100, commitClassEntries(), BatchSpenders{})
	return dispositions, db.commits, err
}

func TestSettlementBatchCommitClassification(t *testing.T) {
	// Control: a clean commit reaches the site and returns dispositions —
	// every classification verdict below is proven non-vacuous by the
	// commits counter and the "settlement batch commit" error text.
	dispositions, commits, err := settleToCommit(t, nil)
	require.NoError(t, err)
	require.Equal(t, 1, commits, "the fake must reach the commit site")
	require.Len(t, dispositions, 2)

	// SQLSTATE 08007 transaction_resolution_unknown: the server answered
	// with an explicit outcome-unknown class — uncertain, never replay.
	_, _, err = settleToCommit(t, &pgconn.PgError{Code: "08007", Message: "connection failure during commit"})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCommitUncertain, "08007 is outcome-unknown, not a proven rollback")
	require.NotErrorIs(t, err, pgx.ErrTxCommitRollback)
	require.Contains(t, err.Error(), "settlement batch commit", "the error must come from the commit site, not an earlier stage")

	// SQLSTATE 40003 statement_completion_unknown: same verdict.
	_, _, err = settleToCommit(t, &pgconn.PgError{Code: "40003", Message: "statement completion unknown"})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCommitUncertain, "40003 is outcome-unknown, not a proven rollback")
	require.NotErrorIs(t, err, pgx.ErrTxCommitRollback)

	// A server-evaluated commit rejection (deferred constraint at COMMIT)
	// is ALSO uncertain under the default-uncertain rule: lease recovery
	// decides, never an immediate replay.
	_, _, err = settleToCommit(t, &pgconn.PgError{Code: "23503", Message: "foreign key violation on commit"})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCommitUncertain)

	// Transport loss: no outcome at all — uncertain.
	_, _, err = settleToCommit(t, errors.New("write tcp: broken pipe"))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCommitUncertain)

	// Definite rollback: pgx.ErrTxCommitRollback is returned only when the
	// COMMIT command executed and rolled the transaction back — the one
	// provably-safe case, which keeps the ordinary fallback contract.
	_, _, err = settleToCommit(t, pgx.ErrTxCommitRollback)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrCommitUncertain, "a proven rollback keeps the fallback contract")
	require.Contains(t, err.Error(), "settlement batch commit")
}
