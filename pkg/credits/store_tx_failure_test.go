package credits

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/money"
)

type creditTxStep struct {
	method      string
	contains    string
	notContains string
	args        []any
	values      []any
	err         error
}

type scriptedCreditTx struct {
	pgx.Tx
	t     *testing.T
	steps []creditTxStep
	next  int
}

func (tx *scriptedCreditTx) step(method, query string, args []any) creditTxStep {
	tx.t.Helper()
	if tx.next == len(tx.steps) {
		tx.t.Fatalf("unexpected %s: %s %#v", method, query, args)
	}
	step := tx.steps[tx.next]
	tx.next++
	if step.method != method || !strings.Contains(query, step.contains) ||
		step.notContains != "" && strings.Contains(query, step.notContains) || !reflect.DeepEqual(args, step.args) {
		tx.t.Fatalf("step %d = %s %q %#v, want %s containing %q with %#v",
			tx.next, method, query, args, step.method, step.contains, step.args)
	}
	return step
}

func (tx *scriptedCreditTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	step := tx.step("query", query, args)
	return scriptedCreditRow{values: step.values, err: step.err}
}

func (tx *scriptedCreditTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	step := tx.step("exec", query, args)
	return pgconn.CommandTag{}, step.err
}

func (tx *scriptedCreditTx) Commit(context.Context) error {
	return tx.step("commit", "", nil).err
}

func (tx *scriptedCreditTx) Rollback(context.Context) error {
	return tx.step("rollback", "", nil).err
}

func (tx *scriptedCreditTx) requireDone() {
	tx.t.Helper()
	if tx.next != len(tx.steps) {
		tx.t.Fatalf("consumed %d of %d scripted transaction steps", tx.next, len(tx.steps))
	}
}

type scriptedCreditRow struct {
	values []any
	err    error
}

type deductAlreadyCase struct {
	name        string
	invocation  string
	hasInvCol   bool
	values      []any
	rowErr      error
	wantApplied bool
	wantErr     error
	query       string
	notQuery    string
}

type insertUsageCase struct {
	name, invocation string
	hasInvCol        bool
	query            string
	notQuery         string
	lastArg          any
	wantErr          error
}

func (row scriptedCreditRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) != len(row.values) {
		return fmt.Errorf("scan got %d destinations for %d values", len(dest), len(row.values))
	}
	for i, value := range row.values {
		switch target := dest[i].(type) {
		case *bool:
			*target = value.(bool)
		case *int64:
			*target = value.(int64)
		case *string:
			*target = value.(string)
		default:
			return fmt.Errorf("unsupported scripted scan target %T", dest[i])
		}
	}
	return nil
}

func TestApplyMicroChargeRejectsBeforeWalletUpdate(t *testing.T) {
	query := "WITH wallet AS ("
	queryFailure := errors.New("wallet query failed")
	for _, tc := range []struct {
		name   string
		values []any
		err    error
		want   error
	}{
		{name: "missing wallet", err: pgx.ErrNoRows, want: ErrNoWallet},
		{name: "query failure", err: queryFailure, want: queryFailure},
		{name: "grace floor", values: []any{int64(-101), int64(1), int64(1), false}, want: ErrInsufficientCredits},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &scriptedCreditTx{t: t, steps: []creditTxStep{{
				method: "query", contains: query,
				args: []any{"org-credit", int64(1), int64(-100)}, values: tc.values, err: tc.err,
			}}}
			store := NewStore(nil, nil)
			_, _, _, err := store.applyMicroCharge(context.Background(), tx, "org-credit", money.MicroUSD(1))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want wrapped %v", err, tc.want)
			}
			tx.requireDone()
		})
	}
}

func TestApplyMicroChargeUpdatesOnlyAfterAllowedSnapshot(t *testing.T) {
	query := "WITH wallet AS ("
	update := "UPDATE org_credits SET balance_cents = $2"
	updateFailure := errors.New("wallet update failed")
	for _, tc := range []struct {
		name      string
		updateErr error
		wantErr   bool
	}{
		{name: "accepted", wantErr: false},
		{name: "update failure", updateErr: updateFailure, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			steps := []creditTxStep{
				{method: "query", contains: query, args: []any{"org-credit", int64(250000), int64(-100)}, values: []any{int64(75), int64(0), int64(25), true}},
				{method: "exec", contains: update, args: []any{"org-credit", int64(75), int64(0)}, err: tc.updateErr},
			}
			tx := &scriptedCreditTx{t: t, steps: steps}
			balance, remainder, charge, err := NewStore(nil, nil).applyMicroCharge(context.Background(), tx, "org-credit", money.MicroUSD(250000))
			if tc.wantErr {
				if !errors.Is(err, tc.updateErr) {
					t.Fatalf("update error %v, want wrapped update failure", err)
				}
			} else if err != nil || balance != 75 || remainder != 0 || charge != 25 {
				t.Fatalf("accepted snapshot = (%d,%d,%d,%v), want (75,0,25,nil)", balance, remainder, charge, err)
			}
			tx.requireDone()
		})
	}
}

func TestDeductMicroTxPreservesRollbackAndCommitOrdering(t *testing.T) {
	const (
		org        = "org-credit"
		request    = "request-credit"
		invocation = "00000000-0000-4000-8000-000000000001"
		amount     = money.MicroUSD(250000)
	)
	steps := []creditTxStep{
		{method: "exec", contains: "pg_advisory_xact_lock", args: []any{org}},
		{method: "query", contains: "WHERE invocation_id = $1", args: []any{invocation}, err: pgx.ErrNoRows},
		{method: "query", contains: "WITH wallet AS (", args: []any{org, int64(amount), int64(-100)}, values: []any{int64(75), int64(0), int64(25), true}},
		{method: "exec", contains: "UPDATE org_credits SET balance_cents = $2", args: []any{org, int64(75), int64(0)}},
		{method: "exec", contains: "INSERT INTO credit_transactions", args: []any{org, int64(-25), int64(75), sql.NullString{String: request, Valid: true}, "{}", int64(-amount), invocation}},
		{method: "commit"},
	}
	tx := &scriptedCreditTx{t: t, steps: steps}
	store := NewStore(nil, nil)
	store.cache[org] = &cachedBalance{walletCents: 100}
	if err := store.deductMicroTx(context.Background(), tx, org, amount, request, invocation, nil, true); err != nil {
		t.Fatalf("deduct transaction: %v", err)
	}
	tx.requireDone()
	if _, cached := store.cache[org]; cached {
		t.Fatal("committed deduction must invalidate the display cache")
	}
}

func TestDeductMicroTxRollsBackFailuresWithoutInsertingLedger(t *testing.T) {
	const (
		org        = "org-credit"
		request    = "request-credit"
		invocation = "00000000-0000-4000-8000-000000000001"
		amount     = money.MicroUSD(250000)
	)
	lockFailure := errors.New("lock failed")
	identityLookupFailure := errors.New("identity lookup failed")
	ledgerFailure := errors.New("ledger insert failed")
	for _, tc := range []struct {
		name     string
		metadata map[string]interface{}
		steps    []creditTxStep
		want     error
		wantType bool
	}{
		{
			name: "advisory lock",
			steps: []creditTxStep{
				{method: "exec", contains: "pg_advisory_xact_lock", args: []any{org}, err: lockFailure},
				{method: "rollback"},
			},
			want: lockFailure,
		},
		{
			name: "idempotency query",
			steps: []creditTxStep{
				{method: "exec", contains: "pg_advisory_xact_lock", args: []any{org}},
				{method: "query", contains: "WHERE invocation_id = $1", args: []any{invocation}, err: identityLookupFailure},
				{method: "rollback"},
			},
			want: identityLookupFailure,
		},
		{
			name: "missing wallet",
			steps: []creditTxStep{
				{method: "exec", contains: "pg_advisory_xact_lock", args: []any{org}},
				{method: "query", contains: "WHERE invocation_id = $1", args: []any{invocation}, err: pgx.ErrNoRows},
				{method: "query", contains: "WITH wallet AS (", args: []any{org, int64(amount), int64(-100)}, err: pgx.ErrNoRows},
				{method: "rollback"},
			},
			want: ErrNoWallet,
		},
		{
			name: "grace floor",
			steps: []creditTxStep{
				{method: "exec", contains: "pg_advisory_xact_lock", args: []any{org}},
				{method: "query", contains: "WHERE invocation_id = $1", args: []any{invocation}, err: pgx.ErrNoRows},
				{method: "query", contains: "WITH wallet AS (", args: []any{org, int64(amount), int64(-100)}, values: []any{int64(-101), int64(0), int64(25), false}},
				{method: "rollback"},
			},
			want: ErrInsufficientCredits,
		},
		{
			name:     "metadata marshal",
			metadata: map[string]interface{}{"unsupported": make(chan int)},
			steps: []creditTxStep{
				{method: "exec", contains: "pg_advisory_xact_lock", args: []any{org}},
				{method: "query", contains: "WHERE invocation_id = $1", args: []any{invocation}, err: pgx.ErrNoRows},
				{method: "query", contains: "WITH wallet AS (", args: []any{org, int64(amount), int64(-100)}, values: []any{int64(75), int64(0), int64(25), true}},
				{method: "exec", contains: "UPDATE org_credits SET balance_cents = $2", args: []any{org, int64(75), int64(0)}},
				{method: "rollback"},
			},
			wantType: true,
		},
		{
			name:     "ledger insert",
			metadata: map[string]interface{}{"model": "m"},
			steps: []creditTxStep{
				{method: "exec", contains: "pg_advisory_xact_lock", args: []any{org}},
				{method: "query", contains: "WHERE invocation_id = $1", args: []any{invocation}, err: pgx.ErrNoRows},
				{method: "query", contains: "WITH wallet AS (", args: []any{org, int64(amount), int64(-100)}, values: []any{int64(75), int64(0), int64(25), true}},
				{method: "exec", contains: "UPDATE org_credits SET balance_cents = $2", args: []any{org, int64(75), int64(0)}},
				{method: "exec", contains: "INSERT INTO credit_transactions", args: []any{org, int64(-25), int64(75), sql.NullString{String: request, Valid: true}, `{"model":"m"}`, int64(-amount), invocation}, err: ledgerFailure},
				{method: "rollback"},
			},
			want: ledgerFailure,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &scriptedCreditTx{t: t, steps: tc.steps}
			err := NewStore(nil, nil).deductMicroTx(context.Background(), tx, org, amount, request, invocation, tc.metadata, true)
			if tc.wantType {
				var typeErr *json.UnsupportedTypeError
				if !errors.As(err, &typeErr) {
					t.Fatalf("error %v, want wrapped unsupported-type error", err)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want wrapped %v", err, tc.want)
			}
			tx.requireDone()
		})
	}
}

func TestDeductMicroTxDuplicateAndCommitFailureEffects(t *testing.T) {
	const (
		org        = "org-credit"
		request    = "request-credit"
		invocation = "00000000-0000-4000-8000-000000000001"
		amount     = money.MicroUSD(250000)
	)
	commitFailure := errors.New("commit outcome uncertain")
	for _, tc := range []struct {
		name  string
		steps []creditTxStep
		want  error
	}{
		{
			name: "duplicate invocation rolls back without wallet write",
			steps: []creditTxStep{
				{method: "exec", contains: "pg_advisory_xact_lock", args: []any{org}},
				{method: "query", contains: "WHERE invocation_id = $1", args: []any{invocation}, values: []any{org, int64(-amount)}},
				{method: "rollback"},
			},
		},
		{
			name: "commit error does not evict display cache",
			steps: []creditTxStep{
				{method: "exec", contains: "pg_advisory_xact_lock", args: []any{org}},
				{method: "query", contains: "WHERE invocation_id = $1", args: []any{invocation}, err: pgx.ErrNoRows},
				{method: "query", contains: "WITH wallet AS (", args: []any{org, int64(amount), int64(-100)}, values: []any{int64(75), int64(0), int64(25), true}},
				{method: "exec", contains: "UPDATE org_credits SET balance_cents = $2", args: []any{org, int64(75), int64(0)}},
				{method: "exec", contains: "INSERT INTO credit_transactions", args: []any{org, int64(-25), int64(75), sql.NullString{String: request, Valid: true}, "{}", int64(-amount), invocation}},
				{method: "commit", err: commitFailure},
			},
			want: commitFailure,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &scriptedCreditTx{t: t, steps: tc.steps}
			store := NewStore(nil, nil)
			store.cache[org] = &cachedBalance{walletCents: 100}
			err := store.deductMicroTx(context.Background(), tx, org, amount, request, invocation, nil, true)
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want wrapped %v", err, tc.want)
			}
			if tc.want == nil && err != nil {
				t.Fatalf("duplicate must be an idempotent success, got %v", err)
			}
			if _, cached := store.cache[org]; !cached {
				t.Fatal("uncommitted or duplicate attempt must not evict display cache")
			}
			tx.requireDone()
		})
	}
}

func TestDeductAlreadyAppliedRequiresExactIdentity(t *testing.T) {
	const (
		org        = "org-credit"
		request    = "request-credit"
		invocation = "00000000-0000-4000-8000-000000000001"
		amount     = money.MicroUSD(250000)
	)
	lookupFailure := errors.New("lookup unavailable")
	for _, tc := range []deductAlreadyCase{
		{name: "exact invocation", invocation: invocation, hasInvCol: true, values: []any{org, int64(-amount)}, wantApplied: true, query: "WHERE invocation_id = $1 AND type = 'usage'"},
		{name: "wrong tenant", invocation: invocation, hasInvCol: true, values: []any{"other-org", int64(-amount)}, wantErr: ErrChargeIdentityConflict, query: "WHERE invocation_id = $1 AND type = 'usage'"},
		{name: "wrong amount", invocation: invocation, hasInvCol: true, values: []any{org, int64(-amount + 1)}, wantErr: ErrChargeIdentityConflict, query: "WHERE invocation_id = $1 AND type = 'usage'"},
		{name: "lookup error", invocation: invocation, hasInvCol: true, rowErr: lookupFailure, wantErr: lookupFailure, query: "WHERE invocation_id = $1 AND type = 'usage'"},
		{name: "legacy invocation schema", hasInvCol: true, values: []any{int64(7)}, wantApplied: true, query: "AND invocation_id IS NULL"},
		{name: "legacy old schema", values: []any{int64(7)}, wantApplied: true, query: "WHERE org_id = $1 AND request_id = $2 AND type = 'usage'", notQuery: "invocation_id"},
		{name: "missing legacy row", hasInvCol: true, rowErr: pgx.ErrNoRows, query: "AND invocation_id IS NULL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []any{org, request}
			if tc.invocation != "" {
				args = []any{tc.invocation}
			}
			tx := &scriptedCreditTx{t: t, steps: []creditTxStep{{
				method: "query", contains: tc.query, notContains: tc.notQuery,
				args: args, values: tc.values, err: tc.rowErr,
			}}}
			applied, err := NewStore(nil, nil).deductAlreadyApplied(context.Background(), tx, org, amount, request, tc.invocation, tc.hasInvCol)
			assertDeductAlreadyResult(t, applied, err, tc)
			tx.requireDone()
		})
	}
}

func assertDeductAlreadyResult(t *testing.T, applied bool, err error, tc deductAlreadyCase) {
	t.Helper()
	if tc.wantErr == nil {
		if err != nil || applied != tc.wantApplied {
			t.Fatalf("result applied=%t err=%v, want applied=%t", applied, err, tc.wantApplied)
		}
		return
	}
	if !errors.Is(err, tc.wantErr) || applied {
		t.Fatalf("result applied=%t err=%v, want wrapped %v", applied, err, tc.wantErr)
	}
}

func TestInsertUsageTransactionSchemaShapesAndFailure(t *testing.T) {
	const org, request, invocation = "org-credit", "request-credit", "00000000-0000-4000-8000-000000000001"
	ledgerFailure := errors.New("ledger rejected row")
	for _, tc := range []insertUsageCase{
		{name: "pre-0028 schema", notQuery: "invocation_id", lastArg: int64(-250000)},
		{name: "0028 legacy domain", hasInvCol: true, query: "invocation_id)", lastArg: nil},
		{name: "invocation domain", invocation: invocation, hasInvCol: true, query: "invocation_id)", lastArg: invocation},
		{name: "insert failure", hasInvCol: true, query: "invocation_id)", lastArg: nil, wantErr: ledgerFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step := insertUsageExpectedStep(tc, org, request)
			tx := &scriptedCreditTx{t: t, steps: []creditTxStep{step}}
			err := NewStore(nil, nil).insertUsageTransaction(context.Background(), tx, org, request, tc.invocation, 25, 75, money.MicroUSD(250000), []byte(`{"model":"m"}`), tc.hasInvCol)
			assertInsertUsageResult(t, err, tc.wantErr)
			tx.requireDone()
		})
	}
}

func insertUsageExpectedStep(tc insertUsageCase, org, request string) creditTxStep {
	args := []any{org, int64(-25), int64(75), sql.NullString{String: request, Valid: true}, `{"model":"m"}`, int64(-250000)}
	if tc.hasInvCol || tc.invocation != "" {
		args = append(args, tc.lastArg)
	}
	step := creditTxStep{method: "exec", contains: "INSERT INTO credit_transactions", notContains: tc.notQuery, args: args}
	if tc.query != "" {
		step.contains = tc.query
	}
	step.err = tc.wantErr
	return step
}

func assertInsertUsageResult(t *testing.T, err, wantErr error) {
	t.Helper()
	if wantErr != nil && !errors.Is(err, wantErr) {
		t.Fatalf("insert error %v, want wrapped %v", err, wantErr)
	}
	if wantErr == nil && err != nil {
		t.Fatalf("insert: %v", err)
	}
}

func TestRollbackDeductLogsFailureWithoutReplacingOriginal(t *testing.T) {
	var logs bytes.Buffer
	store := NewStore(nil, slog.New(slog.NewTextHandler(&logs, nil)))
	rollbackErr := errors.New("rollback failed")
	tx := &scriptedCreditTx{t: t, steps: []creditTxStep{{method: "rollback", err: rollbackErr}}}
	store.rollbackDeduct(context.Background(), tx)
	tx.requireDone()
	if !strings.Contains(logs.String(), "deduct rollback failed") || !strings.Contains(logs.String(), rollbackErr.Error()) {
		t.Fatalf("rollback error must be logged: %s", logs.String())
	}
}
