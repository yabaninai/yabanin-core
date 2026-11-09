package consumer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRows is a minimal pgx.Rows stub for the backlog/claim queries.
// Non-overridden interface methods are never called by the worker.
type fakeRows struct {
	pgx.Rows // nil-embedded: only the overridden methods are exercised

	vals [][]any
	i    int
}

func (r *fakeRows) Next() bool { r.i++; return r.i <= len(r.vals) }

func (r *fakeRows) Scan(dest ...any) error {
	row := r.vals[r.i-1]
	for j, d := range dest {
		if j >= len(row) {
			continue
		}
		switch v := d.(type) {
		case *string:
			*v = row[j].(string)
		case *int64:
			*v = row[j].(int64)
		case *int:
			*v = row[j].(int)
		case *[]byte:
			*v = row[j].([]byte)
		}
	}
	return nil
}

func (r *fakeRows) Err() error                    { return nil }
func (r *fakeRows) Close()                        {}
func (r *fakeRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }

// ---- Fakes for the settlement worker's DB surface ----

type execRecord struct {
	query string
	args  []any
}

// fakeSettlementDB records Exec calls and can fail queries by substring.
type fakeSettlementDB struct {
	mu       sync.Mutex
	execs    []execRecord
	failNext map[string]int // query substring -> remaining failures
	failErr  error
	tagRows  int64 // RowsAffected reported for successful execs (default 1)
}

func (f *fakeSettlementDB) fail(query string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for sub, n := range f.failNext {
		if strings.Contains(query, sub) && n > 0 {
			f.failNext[sub] = n - 1
			return f.failErr
		}
	}
	return nil
}

func (f *fakeSettlementDB) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if err := f.fail(query); err != nil {
		return pgconn.CommandTag{}, err
	}
	f.mu.Lock()
	f.execs = append(f.execs, execRecord{query, args})
	rows := f.tagRows
	f.mu.Unlock()
	if rows <= 0 {
		rows = 1
	}
	return pgconn.NewCommandTag(fmt.Sprintf("UPDATE %d", rows)), nil
}

func (f *fakeSettlementDB) execsBySubstring(sub string) []execRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []execRecord
	for _, e := range f.execs {
		if strings.Contains(e.query, sub) {
			out = append(out, e)
		}
	}
	return out
}

func (f *fakeSettlementDB) Begin(context.Context) (pgx.Tx, error) { return &fakeSettlementTx{}, nil }
func (f *fakeSettlementDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return &fakeRow{vals: []any{int64(0)}}
}
func (f *fakeSettlementDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return &fakeRows{}, nil
}

// fakeSettlementTx is the transactional slice (agent-spend path). Only
// Exec/QueryRow/Commit/Rollback are exercised by the worker; the embedded
// nil pg.Tx covers the rest of the interface.
type fakeSettlementTx struct {
	pgx.Tx // nil-embedded: only the overridden methods are exercised

	mu         sync.Mutex
	execs      []execRecord
	failNext   map[string]int                    // query substring -> remaining injected failures
	zeroRows   map[string]int                    // query substring -> remaining zero-rows-affected tags (§7.1.3 underflow)
	queryRowFn func(query string) ([]any, error) // canned QueryRow answers (allowance FOR SHARE, usage replay guard)
	committed  bool
	rolled     bool
}

func (t *fakeSettlementTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for sub, n := range t.failNext {
		if strings.Contains(query, sub) && n > 0 {
			t.failNext[sub] = n - 1
			return pgconn.CommandTag{}, fmt.Errorf("injected failure for %q", sub)
		}
	}
	tag := "INSERT 0 1"
	for sub, n := range t.zeroRows {
		if strings.Contains(query, sub) && n > 0 {
			t.zeroRows[sub] = n - 1
			tag = "UPDATE 0"
			break
		}
	}
	t.execs = append(t.execs, execRecord{query, args})
	return pgconn.NewCommandTag(tag), nil
}

func (t *fakeSettlementTx) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	t.mu.Lock()
	fn := t.queryRowFn
	t.mu.Unlock()
	if fn != nil {
		vals, err := fn(query)
		return &fakeTxRow{vals: vals, err: err}
	}
	return &fakeTxRow{err: fmt.Errorf("fakeSettlementTx: unexpected QueryRow: %s", query)}
}

func (t *fakeSettlementTx) Commit(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.committed = true
	return nil
}

func (t *fakeSettlementTx) Rollback(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rolled = true
	return nil
}

func (t *fakeSettlementTx) execsByQuerySubstring(sub string) []execRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []execRecord
	for _, e := range t.execs {
		if strings.Contains(e.query, sub) {
			out = append(out, e)
		}
	}
	return out
}

// fakeTxRow answers one canned QueryRow inside fakeSettlementTx.
type fakeTxRow struct {
	vals []any
	err  error
}

func (r *fakeTxRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, d := range dest {
		if i < len(r.vals) {
			switch v := d.(type) {
			case *string:
				*v = r.vals[i].(string)
			}
		}
	}
	return nil
}

func newUnitWorker(db SettlementDB) *SettlementWorker {
	return NewSettlementWorker(db, nil, nil, silentLogger()).WithConfig(SettlementConfig{
		BackoffBase: time.Millisecond,
		BackoffMax:  5 * time.Millisecond,
	})
}

// ---- classifyFailure matrix: transient ≠ terminal ----

func TestClassifyFailure_Matrix(t *testing.T) {
	w := newUnitWorker(&fakeSettlementDB{})

	generic := errors.New("connection reset by peer")
	uniqueViolation := &pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint"}

	tests := []struct {
		name     string
		err      error
		attempts int
		want     string
		wantWhy  string
	}{
		{"no charge target", ErrNoChargeTarget, 1, "requires_attention", "charge_target_not_configured"},
		{"poison payload", fmt.Errorf("%w: decode: bad json", ErrPoisonJob), 1, "requires_attention", "poison_payload"},
		{"no wallet", credits.ErrNoWallet, 1, "requires_attention", "no_wallet"},
		{"insufficient after incurred cost", credits.ErrInsufficientCredits, 1, "requires_attention", "insufficient_credits"},
		{"wrapped insufficient", fmt.Errorf("deduct balance check: %w", credits.ErrInsufficientCredits), 1, "requires_attention", "insufficient_credits"},
		{"identity conflict (unique violation)", uniqueViolation, 1, "requires_attention", "request_identity_conflict"},
		{"transient under budget", generic, 1, "retry", "transient_error"},
		{"transient at last attempt", generic, 12, "requires_attention", "retry_budget_exhausted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, why := w.classifyFailure(tt.err, tt.attempts)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantWhy, why)
		})
	}
}

// A transient error must never look like a terminal success: the job goes to
// retry with a bounded future next_attempt_at, never to settled.
func TestExecuteJob_TransientErrorIsRetryNotSuccess(t *testing.T) {
	db := &fakeSettlementDB{failNext: map[string]int{}}
	w := NewSettlementWorker(db, credits.NewStore(nil, silentLogger()), nil, silentLogger()).
		WithConfig(SettlementConfig{BackoffBase: time.Millisecond, BackoffMax: 5 * time.Millisecond})
	// resale execution fails at the store level (nil DB).
	job := &settlementJob{ID: 7, OrgID: "org", RequestID: "req", ChargeKind: ChargeKindResaleDeduction,
		AmountMicro: money.MustFromCents(5), Payload: []byte(`{}`), Attempts: 1, NextBackoff: 2 * time.Millisecond}

	w.executeJob(context.Background(), job)

	retries := db.execsBySubstring("status = 'retry'")
	require.Len(t, retries, 1, "transient failure must schedule a retry")
	settles := db.execsBySubstring("status = 'settled'")
	assert.Empty(t, settles, "a failed execution must never be marked settled")
}

// A poison payload can never succeed: it must not busy-loop forever — it
// goes straight to requires_attention as a diagnostic.
func TestExecuteJob_PoisonPayloadRequiresAttention(t *testing.T) {
	db := &fakeSettlementDB{}
	w := NewSettlementWorker(db, credits.NewStore(nil, silentLogger()), nil, silentLogger()).
		WithConfig(SettlementConfig{BackoffBase: time.Millisecond, BackoffMax: 5 * time.Millisecond})
	job := &settlementJob{ID: 9, OrgID: "org", RequestID: "req", ChargeKind: ChargeKindResaleDeduction,
		AmountMicro: money.MustFromCents(5), Payload: []byte("not-json"), Attempts: 1}

	w.executeJob(context.Background(), job)

	require.Len(t, db.execsBySubstring("status = 'requires_attention'"), 1)
	assert.Empty(t, db.execsBySubstring("status = 'retry'"), "poison must not burn the retry budget")
}

// An unknown charge kind is a schema-contract violation: diagnostic, not an
// infinite retry loop.
func TestExecuteJob_UnknownChargeKindRequiresAttention(t *testing.T) {
	db := &fakeSettlementDB{}
	w := newUnitWorker(db)
	job := &settlementJob{ID: 11, ChargeKind: "mystery_kind", Attempts: 1}

	w.executeJob(context.Background(), job)

	require.Len(t, db.execsBySubstring("status = 'requires_attention'"), 1)
	assert.Empty(t, db.execsBySubstring("status = 'retry'"))
}

// The agent-spend execution commits the spend and the settle mark in ONE
// transaction under the per-org advisory lock (§5.3 canonical order); the
// settle mark carries the reconcile payload key exactly when the §5.3
// retries.
func TestExecuteAgentSpend_SpendAndSettleShareOneTransaction(t *testing.T) {
	tx := &fakeSettlementTx{}
	spender := &recordingExactSpender{}
	w := NewSettlementWorker(&stubBeginDB{tx: tx}, nil, spender, silentLogger())

	job := &settlementJob{ID: 13, OrgID: "org", RequestID: "req", ChargeKind: ChargeKindAgentSpend,
		AmountMicro: money.MicroUSD(12300), Payload: []byte(`{"agent_id":"agent-uuid","tokens_in":10,"tokens_out":5}`)}
	require.NoError(t, w.execute(context.Background(), job))

	require.Len(t, tx.execs, 3, "advisory lock + spend + settle mark inside one tx")
	assert.Contains(t, tx.execs[0].query, "pg_advisory_xact_lock")
	assert.Equal(t, "org", tx.execs[0].args[0])
	assert.Contains(t, tx.execs[1].query, "INSERT INTO agent_spend_daily")
	assert.Contains(t, tx.execs[2].query, "status = 'settled'")
	assert.Nil(t, tx.execs[2].args[1], "legacy payload without a linkage: no reserve key written")
	assert.True(t, tx.committed)
	require.Len(t, spender.calls, 1)
	assert.Equal(t, int64(12300), spender.calls[0].micro, "exact micro amount, no cent rounding")

	// Spend failure: rollback, error surfaces for classification.
	failing := &fakeSettlementTx{failNext: map[string]int{"agent_spend_daily": 1}}
	wf := NewSettlementWorker(&stubBeginDB{tx: failing}, nil, spender, silentLogger())
	require.Error(t, wf.execute(context.Background(), job))
	assert.True(t, failing.rolledBack())
	assert.False(t, failing.committed)
}

// A reserve-linked agent-spend job applies the §5.3 Settle step 2 in the
// scope-row reserve drops by min(actual, bound) and the reconcile payload
// key lands with status='settled' — the batch executor's semantics on the
// per-job/fallback path.
func TestExecuteAgentSpend_ReserveLinkedSettleReleasesReserve(t *testing.T) {
	tx := &fakeSettlementTx{queryRowFn: func(query string) ([]any, error) {
		if strings.Contains(query, "FROM budget_allowances") {
			return []any{"agent_day", "agent-uuid", "2026-10-02", "active"}, nil
		}
		return nil, fmt.Errorf("unexpected QueryRow: %s", query)
	}}
	spender := &recordingExactSpender{}
	w := NewSettlementWorker(&stubBeginDB{tx: tx}, nil, spender, silentLogger())

	// actual 15000 > bound 12000 → the settle amount is the bound.
	job := &settlementJob{ID: 14, OrgID: "org", RequestID: "req", ChargeKind: ChargeKindAgentSpend,
		AmountMicro: money.MicroUSD(15000),
		Payload:     []byte(`{"agent_id":"agent-uuid","tokens_in":10,"tokens_out":5,"allowance_id":77,"bound_micro_usd":12000}`)}
	require.NoError(t, w.execute(context.Background(), job))

	decrements := tx.execsByQuerySubstring("agent_spend_daily SET reserved_micro_usd")
	require.Len(t, decrements, 1, "scope-row reserve decrement inside the settle tx")
	assert.Equal(t, int64(12000), decrements[0].args[len(decrements[0].args)-1],
		"min(actual, bound) leaves the scope row, underflow is an explicit error")
	marks := tx.execsByQuerySubstring("status = 'settled'")
	require.Len(t, marks, 1)
	assert.Contains(t, marks[0].query, budget.ReconcileSettleKey)
	assert.Equal(t, int64(12000), marks[0].args[1], "reconcile key recorded exactly when the reserve moved")
	assert.True(t, tx.committed, "spend + decrement + settle mark are one atomic unit")
}

// A released allowance (late settle after reconcile, §5.3) settles
// ledger-only: the reserve is not decremented twice and no key is written.
func TestExecuteAgentSpend_ReleasedAllowanceIsLedgerOnly(t *testing.T) {
	tx := &fakeSettlementTx{queryRowFn: func(query string) ([]any, error) {
		if strings.Contains(query, "FROM budget_allowances") {
			return []any{"agent_day", "agent-uuid", "2026-10-02", budget.AllowanceReleased}, nil
		}
		return nil, fmt.Errorf("unexpected QueryRow: %s", query)
	}}
	spender := &recordingExactSpender{}
	w := NewSettlementWorker(&stubBeginDB{tx: tx}, nil, spender, silentLogger())

	job := &settlementJob{ID: 16, OrgID: "org", RequestID: "req", ChargeKind: ChargeKindAgentSpend,
		AmountMicro: money.MicroUSD(12000),
		Payload:     []byte(`{"agent_id":"agent-uuid","allowance_id":77,"bound_micro_usd":12000}`)}
	require.NoError(t, w.execute(context.Background(), job))

	assert.Empty(t, tx.execsByQuerySubstring("reserved_micro_usd = reserved_micro_usd -"),
		"released allowance: the reserve already went back with the reconcile")
	marks := tx.execsByQuerySubstring("status = 'settled'")
	require.Len(t, marks, 1)
	assert.Nil(t, marks[0].args[1], "no reconcile key without a reserve decrement")
}

// A reserve decrement that would drive the scope row underflow (§7.1.3
// drift) fails the whole settlement: rollback, no settle mark, the job
// retries — the fail-safe freeze direction, never a silent clamp.
func TestExecuteAgentSpend_ReserveUnderflowRollsBack(t *testing.T) {
	tx := &fakeSettlementTx{
		queryRowFn: func(query string) ([]any, error) {
			if strings.Contains(query, "FROM budget_allowances") {
				return []any{"agent_day", "agent-uuid", "2026-10-02", "active"}, nil
			}
			return nil, fmt.Errorf("unexpected QueryRow: %s", query)
		},
		zeroRows: map[string]int{"reserved_micro_usd = reserved_micro_usd -": 1},
	}
	spender := &recordingExactSpender{}
	w := NewSettlementWorker(&stubBeginDB{tx: tx}, nil, spender, silentLogger())

	job := &settlementJob{ID: 18, OrgID: "org", RequestID: "req", ChargeKind: ChargeKindAgentSpend,
		AmountMicro: money.MicroUSD(12000),
		Payload:     []byte(`{"agent_id":"agent-uuid","allowance_id":77,"bound_micro_usd":12000}`)}
	require.ErrorIs(t, w.execute(context.Background(), job), budget.ErrReservedUnderflow)
	assert.True(t, tx.rolledBack())
	assert.False(t, tx.committed)
	assert.Empty(t, tx.execsByQuerySubstring("status = 'settled'"))
}

// ONE transaction — the exactly-once guard for team budget accounting; a
// spend failure rolls both back and retries. The transaction runs under the
// per-org advisory lock and the settle mark carries the reconcile payload
func TestExecuteTeamSpend_SpendAndSettleShareOneTransaction(t *testing.T) {
	tx := &fakeSettlementTx{}
	w := NewSettlementWorker(&stubBeginDB{tx: tx}, nil, nil, silentLogger())

	job := &settlementJob{ID: 15, OrgID: "org", RequestID: "req", ChargeKind: ChargeKindTeamSpend,
		AmountMicro: money.MicroUSD(12_345), Payload: []byte(`{"team_id":"team-uuid","period":"2026-10"}`)}
	require.NoError(t, w.execute(context.Background(), job))

	require.Len(t, tx.execs, 3, "advisory lock + spend + settle mark inside one tx")
	assert.Contains(t, tx.execs[0].query, "pg_advisory_xact_lock")
	assert.Contains(t, tx.execs[1].query, "INSERT INTO team_spend_monthly")
	require.Len(t, tx.execs[1].args, 3)
	assert.Equal(t, "team-uuid", tx.execs[1].args[0])
	assert.Equal(t, "2026-10", tx.execs[1].args[1], "the request-time period from the payload, never re-derived")
	assert.Equal(t, int64(12_345), tx.execs[1].args[2], "exact micro amount, no cent rounding")
	assert.Contains(t, tx.execs[2].query, "status = 'settled'")
	assert.Nil(t, tx.execs[2].args[1], "legacy payload without a linkage: no reserve key written")
	assert.True(t, tx.committed)

	// Spend failure: rollback, error surfaces for classification.
	failing := &fakeSettlementTx{failNext: map[string]int{"team_spend_monthly": 1}}
	wf := NewSettlementWorker(&stubBeginDB{tx: failing}, nil, nil, silentLogger())
	require.Error(t, wf.execute(context.Background(), job))
	assert.True(t, failing.rolledBack())
	assert.False(t, failing.committed)
}

// A reserve-linked team-spend job releases the team-month reserve in the
// amount min(actual, bound) leaves the scope row and lands under the
// reconcile payload key atomically with status='settled'.
func TestExecuteTeamSpend_ReserveLinkedSettleReleasesReserve(t *testing.T) {
	tx := &fakeSettlementTx{queryRowFn: func(query string) ([]any, error) {
		if strings.Contains(query, "FROM budget_allowances") {
			return []any{"team_month", "team-uuid", "2026-10", "active"}, nil
		}
		return nil, fmt.Errorf("unexpected QueryRow: %s", query)
	}}
	w := NewSettlementWorker(&stubBeginDB{tx: tx}, nil, nil, silentLogger())

	job := &settlementJob{ID: 19, OrgID: "org", RequestID: "req", ChargeKind: ChargeKindTeamSpend,
		AmountMicro: money.MicroUSD(9_000),
		Payload:     []byte(`{"team_id":"team-uuid","period":"2026-10","allowance_id":42,"bound_micro_usd":12000}`)}
	require.NoError(t, w.execute(context.Background(), job))

	decrements := tx.execsByQuerySubstring("team_spend_monthly SET reserved_micro_usd")
	require.Len(t, decrements, 1)
	assert.Equal(t, int64(9_000), decrements[0].args[len(decrements[0].args)-1], "actual < bound → the actual amount")
	marks := tx.execsByQuerySubstring("status = 'settled'")
	require.Len(t, marks, 1)
	assert.Contains(t, marks[0].query, budget.ReconcileSettleKey)
	assert.Equal(t, int64(9_000), marks[0].args[1])
	assert.True(t, tx.committed)
}

// The resale settle (singletons and per-job fallback — the common one-intent
// path) releases the wallet reserve and writes the reconcile payload key in
func TestSettle_ResaleReleasesReserveWithReconcileKey(t *testing.T) {
	tx := &fakeSettlementTx{queryRowFn: func(query string) ([]any, error) {
		if strings.Contains(query, "FROM budget_allowances") {
			return []any{"wallet", "org", "", "active"}, nil
		}
		return nil, fmt.Errorf("unexpected QueryRow: %s", query)
	}}
	w := NewSettlementWorker(&stubBeginDB{tx: tx}, nil, nil, silentLogger())

	job := &settlementJob{ID: 21, OrgID: "org", RequestID: "req", ChargeKind: ChargeKindResaleDeduction,
		AmountMicro: money.MicroUSD(12000),
		Payload:     []byte(`{"model":"gpt-4","allowance_id":7,"bound_micro_usd":12000}`)}
	w.settle(context.Background(), job)

	decrements := tx.execsByQuerySubstring("org_credits SET reserved_micro_usd")
	require.Len(t, decrements, 1, "wallet reserve released inside the settle tx")
	assert.Equal(t, int64(12000), decrements[0].args[len(decrements[0].args)-1])
	marks := tx.execsByQuerySubstring("status = 'settled'")
	require.Len(t, marks, 1)
	assert.Contains(t, marks[0].query, budget.ReconcileSettleKey)
	assert.Equal(t, int64(12000), marks[0].args[1], "the key is atomic with status='settled'")
	assert.True(t, tx.committed)
}

// The replay guard: a re-claimed job whose payload still carries the
// reconcile key (its committed settle released the reserve; the mark was
// externally lost — the pre-batch crash window) settles as an idempotent
// no-op: no second decrement, the key stays.
func TestSettle_ResaleReplayIsNoOpWithoutDecrement(t *testing.T) {
	tx := &fakeSettlementTx{}
	w := NewSettlementWorker(&stubBeginDB{tx: tx}, nil, nil, silentLogger())

	job := &settlementJob{ID: 22, OrgID: "org", RequestID: "req", ChargeKind: ChargeKindResaleDeduction,
		AmountMicro: money.MicroUSD(12000),
		Payload:     []byte(`{"model":"gpt-4","allowance_id":7,"bound_micro_usd":12000,"settle_decrement_micro_usd":12000}`)}
	w.settle(context.Background(), job)

	assert.Empty(t, tx.execsByQuerySubstring("reserved_micro_usd = reserved_micro_usd -"),
		"replay must not decrement the reserve a second time")
	marks := tx.execsByQuerySubstring("status = 'settled'")
	require.Len(t, marks, 1)
	assert.Nil(t, marks[0].args[1], "no new key: the payload keeps the earlier settle's marker")
	assert.True(t, tx.committed)
}

// A batch that fails to even open its transaction (transient DB refusal)
// falls back to the per-job executor (§5.5): both refused jobs re-run
// per-job, each applying the §5.3 reserve decrement and the reconcile key.
func TestTick_BatchFailureFallsBackToPerJobWithReserveRelease(t *testing.T) {
	tx := &fakeSettlementTx{queryRowFn: func(query string) ([]any, error) {
		if strings.Contains(query, "FROM budget_allowances") {
			return []any{"agent_day", "agent-uuid", "2026-10-02", "active"}, nil
		}
		return nil, fmt.Errorf("unexpected QueryRow: %s", query)
	}}
	payload := []byte(`{"agent_id":"agent-uuid","tokens_in":10,"tokens_out":5,"allowance_id":77,"bound_micro_usd":12000}`)
	db := &fallbackBeginDB{
		fakeSettlementDB: &fakeSettlementDB{},
		tx:               tx,
		claimRows: &fakeRows{vals: [][]any{
			{int64(31), "org", "req-a", ChargeKindAgentSpend, int64(12000), int64(120), payload, 1},
			{int64(32), "org", "req-b", ChargeKindAgentSpend, int64(12000), int64(120), payload, 1},
		}},
		failFirstBegin: true,
	}
	spender := &recordingExactSpender{}
	w := NewSettlementWorker(db, nil, spender, silentLogger())

	w.tick(context.Background())

	marks := tx.execsByQuerySubstring("status = 'settled'")
	require.Len(t, marks, 2, "both refused jobs settled through the per-job fallback")
	for i, m := range marks {
		assert.Contains(t, m.query, budget.ReconcileSettleKey)
		assert.Equal(t, int64(12000), m.args[1], "fallback job %d carries the applied decrement", i)
	}
	decrements := tx.execsByQuerySubstring("reserved_micro_usd = reserved_micro_usd -")
	require.Len(t, decrements, 2, "every fallback job released its scope reserve")
	require.Len(t, spender.calls, 2, "both spends applied exactly once")
	assert.True(t, tx.committed)
	assert.False(t, tx.rolledBack())
}

// A team-spend job that can never succeed (undecodable payload, missing team
// or period) is poison: straight to the diagnostic, never a retry loop.
func TestExecuteTeamSpend_PoisonPayloadsRequireAttention(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"undecodable json", "not-json"},
		{"no team id", `{"period":"2026-10"}`},
		{"no period", `{"team_id":"team-uuid"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &fakeSettlementDB{}
			w := newUnitWorker(db)
			job := &settlementJob{ID: 17, OrgID: "org", RequestID: "req", ChargeKind: ChargeKindTeamSpend,
				AmountMicro: money.MicroUSD(100), Payload: []byte(tt.payload), Attempts: 1}

			err := w.execute(context.Background(), job)
			require.ErrorIs(t, err, ErrPoisonJob)

			w.executeJob(context.Background(), job)
			require.Len(t, db.execsBySubstring("status = 'requires_attention'"), 1)
			assert.Empty(t, db.execsBySubstring("status = 'retry'"))
		})
	}
}

// recordingExactSpender mimics budget.AgentEnforcer.RecordAgentSpendExact:
// the spend upsert goes through the caller's transaction executor.
type recordingExactSpender struct {
	calls []struct {
		agent string
		micro int64
	}
}

func (s *recordingExactSpender) RecordAgentSpendExact(ctx context.Context, db budget.SpendExecutor, agentID string, amount money.MicroUSD, tokensIn, tokensOut int64) error {
	s.calls = append(s.calls, struct {
		agent string
		micro int64
	}{agentID, int64(amount)})
	_, err := db.Exec(ctx,
		`INSERT INTO agent_spend_daily (agent_id, day, cost_cents, cost_micro_usd, tokens_in, tokens_out)
		 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (agent_id, day) DO NOTHING`,
		agentID, "2026-10-02", amount.Cents(), int64(amount), tokensIn, tokensOut)
	return err
}

// stubBeginDB returns a prepared tx from Begin (worker-level test seam).
type stubBeginDB struct{ tx *fakeSettlementTx }

func (s *stubBeginDB) Begin(context.Context) (pgx.Tx, error) { return s.tx, nil }
func (s *stubBeginDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("UPDATE 1"), nil
}
func (s *stubBeginDB) QueryRow(context.Context, string, ...any) pgx.Row { return &fakeRow{} }
func (s *stubBeginDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return &fakeRows{}, nil
}

// fallbackBeginDB drives the §5.5 fallback: Begin refuses the FIRST call
// (the org batch transaction) and serves the shared tx afterwards (the
// per-job executions); the claim query returns the canned batch once.
type fallbackBeginDB struct {
	*fakeSettlementDB
	tx             *fakeSettlementTx
	claimRows      *fakeRows
	beginCalls     int
	failFirstBegin bool
}

func (f *fallbackBeginDB) Begin(context.Context) (pgx.Tx, error) {
	f.beginCalls++
	if f.failFirstBegin && f.beginCalls == 1 {
		return nil, errors.New("injected: batch transaction refused")
	}
	return f.tx, nil
}

func (f *fallbackBeginDB) Query(_ context.Context, query string, _ ...any) (pgx.Rows, error) {
	if strings.Contains(query, "FROM claimed") && f.claimRows != nil {
		rows := f.claimRows
		f.claimRows = nil
		return rows, nil
	}
	return &fakeRows{}, nil
}

func (t *fakeSettlementTx) rolledBack() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rolled
}

// ---- backoff schedule: bounded, jittered, no busy loop ----

func TestSettlementBackoff_BoundedAndShaped(t *testing.T) {
	w := newUnitWorker(&fakeSettlementDB{})

	first := w.backoff(1)
	assert.GreaterOrEqual(t, first, time.Duration(0))
	assert.Less(t, first, time.Millisecond, "attempt 1 window is [0, base)")

	for i := 0; i < 200; i++ {
		capped := w.backoff(1000)
		assert.Less(t, capped, 5*time.Millisecond, "backoff is capped at BackoffMax")
	}
}

// ---- event_inbox retention: bounded passes, fresh rows kept ----

func TestCleanupInbox_BoundedPassesAndCadence(t *testing.T) {
	db := &fakeSettlementDB{tagRows: 10} // DB always reports a full batch deleted
	w := newUnitWorker(db).WithConfig(SettlementConfig{
		InboxCleanupBatch:  10,
		InboxCleanupPasses: 2,
		InboxCleanupEvery:  time.Hour,
		InboxRetention:     24 * time.Hour,
		Interval:           time.Hour,
	})

	now := time.Now()
	w.cleanupNower = func() time.Time { return now }

	// DB always reports a full batch deleted: the pass bound (2×10=20) caps
	// the deletes regardless of how many rows qualify.
	w.cleanupInbox(context.Background())
	deletes := db.execsBySubstring("DELETE FROM event_inbox")
	require.Len(t, deletes, 2, "cleanup stops at InboxCleanupPasses")
	require.Len(t, deletes[0].args, 2)
	assert.InDelta(t, float64(24*3600), deletes[0].args[0], 0.001, "retention window is passed in seconds")
	assert.Equal(t, int64(10), deletes[0].args[1], "per-statement batch bound")

	// Same tick moment: the cadence gate suppresses a second run.
	w.cleanupInbox(context.Background())
	assert.Len(t, db.execsBySubstring("DELETE FROM event_inbox"), 2)

	// A later tick (cadence elapsed) runs again.
	w.cleanupNower = func() time.Time { return now.Add(2 * time.Hour) }
	w.cleanupInbox(context.Background())
	assert.Len(t, db.execsBySubstring("DELETE FROM event_inbox"), 4)
}

// ---- backlog visibility ----

func TestPublishBacklog_SetsGaugesForAllStates(t *testing.T) {
	db := &stubBacklogDB{}
	w := newUnitWorker(db)

	w.publishBacklog(context.Background())

	assert.InDelta(t, float64(3), testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("pending")), 0.001)
	assert.InDelta(t, float64(1), testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("retry")), 0.001)
	assert.InDelta(t, float64(0), testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("processing")), 0.001)
	assert.InDelta(t, float64(2), testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("requires_attention")), 0.001)
}

// stubBacklogDB answers the backlog GROUP BY query with a fixed state mix.
type stubBacklogDB struct {
	fakeSettlementDB
}

func (s *stubBacklogDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return &fakeRows{vals: [][]any{
		{"pending", int64(3)},
		{"requires_attention", int64(2)},
		{"retry", int64(1)},
	}}, nil
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *fakeRows) TypeMap() *pgtype.Map { return nil }
