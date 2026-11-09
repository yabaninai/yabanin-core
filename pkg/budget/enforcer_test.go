package budget

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newBudgetTestLogger returns a logger that discards all output.
func newBudgetTestLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// mockPool implements the subset of pgxpool.Pool used by Enforcer.
type mockPool struct {
	queryRowFn func(ctx context.Context, query string, args ...interface{}) pgx.Row
	execFn     func(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error)
}

func (m *mockPool) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	if m.queryRowFn != nil {
		return m.queryRowFn(ctx, query, args...)
	}
	return &mockRow{err: pgx.ErrNoRows}
}

func (m *mockPool) Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	if m.execFn != nil {
		return m.execFn(ctx, query, args...)
	}
	return pgconn.NewCommandTag("OK"), nil
}

func (m *mockPool) Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	return &mockRows{}, nil
}

// mockRow implements pgx.Row.
type mockRow struct {
	data [][]interface{}
	idx  int
	err  error
}

func (r *mockRow) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	if r.idx >= len(r.data) {
		return errors.New("no row")
	}
	row := r.data[r.idx]
	r.idx++
	for i, v := range dest {
		if i >= len(row) {
			break
		}
		switch d := v.(type) {
		case *float64:
			if n, ok := row[i].(float64); ok {
				*d = n
			} else if n, ok := row[i].(int64); ok {
				*d = float64(n)
			}
		case *int64:
			if n, ok := row[i].(int64); ok {
				*d = n
			} else if n, ok := row[i].(float64); ok {
				*d = int64(n)
			}
		case *bool:
			*d = row[i].(bool)
		case *string:
			*d = row[i].(string)
		case **string:
			// Nullable parent_id columns (AUDIT-P1-03 walk): a nil cell
			// leaves the *string nil; a string cell points at it.
			if n, ok := row[i].(*string); ok {
				*d = n
			} else if n, ok := row[i].(string); ok {
				*d = &n
			}
		}
	}
	return nil
}

// mockRows implements pgx.Rows (not needed for enforcer, but satisfies interface).
type mockRows struct{}

func (r *mockRows) Next() bool                                   { return false }
func (r *mockRows) Err() error                                   { return nil }
func (r *mockRows) Close()                                       {}
func (r *mockRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (r *mockRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *mockRows) Conn() *pgx.Conn                              { return nil }
func (r *mockRows) RawValues() [][]byte                          { return nil }
func (r *mockRows) Values() ([]any, error)                       { return nil, nil }
func (r *mockRows) Scan(dest ...interface{}) error               { return errors.New("scan not supported") }

// newSmartMockPool creates a pool that routes budget vs spend queries correctly.
// budgetQueryFn is called for the team_budgets SELECT; spendQueryFn for the
func newSmartMockPool(budgetQueryFn, spendQueryFn func() pgx.Row) *mockPool {
	return &mockPool{
		queryRowFn: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
			if strings.Contains(query, "team_budgets") {
				f := budgetQueryFn
				if f == nil {
					f = func() pgx.Row { return &mockRow{err: pgx.ErrNoRows} }
				}
				return f()
			}
			f := spendQueryFn
			if f == nil {
				f = func() pgx.Row { return &mockRow{err: pgx.ErrNoRows} }
			}
			return f()
		},
		execFn: func(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("OK"), nil
		},
	}
}

func TestNewEnforcer(t *testing.T) {
	log := newBudgetTestLogger()
	e := NewEnforcer(nil, log)
	require.NotNil(t, e)
	assert.NotNil(t, e.cache)
	assert.Equal(t, 1*time.Minute, e.ttl)
}

func TestCheckBudget_EmptyTeamID(t *testing.T) {
	e := &Enforcer{log: newBudgetTestLogger()}
	err := e.CheckBudget(context.Background(), "")
	require.NoError(t, err)
}

func TestCheckBudget_NilDB(t *testing.T) {
	e := &Enforcer{db: nil, log: newBudgetTestLogger()}
	err := e.CheckBudget(context.Background(), "team-123")
	require.NoError(t, err)
}

func TestCheckBudget_NoBudgetConfigured(t *testing.T) {
	e := NewEnforcer(newSmartMockPool(nil, nil), newBudgetTestLogger())
	err := e.CheckBudget(context.Background(), "team-1")
	assert.ErrorIs(t, err, ErrNoBudget) // deny by default — no budget row configured
}

func TestCheckBudget_HardLimitExceeded(t *testing.T) {
	pool := newSmartMockPool(
		func() pgx.Row { return &mockRow{data: [][]interface{}{{100.0, true}}} },
		func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(150_000_000)}}} }, // $150 exact
	)

	e := NewEnforcer(pool, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBudgetExceeded)
}

func TestCheckBudget_SoftLimitExceeded(t *testing.T) {
	pool := newSmartMockPool(
		func() pgx.Row { return &mockRow{data: [][]interface{}{{100.0, false}}} }, // soft limit
		func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(150_000_000)}}} },
	)

	e := NewEnforcer(pool, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-2")
	require.NoError(t, err) // soft limit → warn but allow
}

func TestCheckBudget_WithinHardLimit(t *testing.T) {
	pool := newSmartMockPool(
		func() pgx.Row { return &mockRow{data: [][]interface{}{{100.0, true}}} },
		func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(50_000_000)}}} }, // $50 exact
	)

	e := NewEnforcer(pool, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-3")
	require.NoError(t, err)
}

func TestCheckBudget_CacheHit(t *testing.T) {
	pool := newSmartMockPool(
		func() pgx.Row { return &mockRow{err: pgx.ErrNoRows} }, // no budget
		nil,
	)

	e := NewEnforcer(pool, newBudgetTestLogger())

	// First call — misses cache, fetches from DB (no budget → ErrNoBudget cached)
	err := e.CheckBudget(context.Background(), "team-4")
	require.ErrorIs(t, err, ErrNoBudget)

	// Second call — should hit negative cache, no DB query, same denial
	err = e.CheckBudget(context.Background(), "team-4")
	require.ErrorIs(t, err, ErrNoBudget)
}

func TestCheckBudget_DBErrorFailClosed(t *testing.T) {
	pool := newSmartMockPool(
		func() pgx.Row { return &mockRow{err: errors.New("connection refused")} },
		nil,
	)

	e := NewEnforcer(pool, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-5")
	assert.ErrorIs(t, err, ErrBudgetUnavailable) // fail-closed on DB error
}

func TestCheckBudget_SpendFetchErrorFailClosed(t *testing.T) {
	pool := newSmartMockPool(
		func() pgx.Row { return &mockRow{data: [][]interface{}{{100.0, true}}} },
		func() pgx.Row { return &mockRow{err: errors.New("spend DB error")} },
	)

	e := NewEnforcer(pool, newBudgetTestLogger())
	err := e.CheckBudget(context.Background(), "team-6")
	assert.ErrorIs(t, err, ErrBudgetUnavailable) // fail-closed on spend fetch error
}

// recordExactSpendArgs captures one RecordTeamSpendExact upsert.
type recordExactSpendArgs struct {
	teamID  string
	period  string
	amount  int64
	queries []string
}

func TestRecordTeamSpendExact_Success(t *testing.T) {
	var captured recordExactSpendArgs
	executor := &mockSpendExecutor{
		execFn: func(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			captured.queries = append(captured.queries, query)
			captured.teamID = args[0].(string)
			captured.period = args[1].(string)
			captured.amount = args[2].(int64)
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}

	err := RecordTeamSpendExact(context.Background(), executor, "team-8", "2026-10", money.MicroUSD(25_500_000))
	require.NoError(t, err)
	assert.Equal(t, "team-8", captured.teamID)
	assert.Equal(t, "2026-10", captured.period, "period is the caller-supplied request-time month (ADR I5)")
	assert.Equal(t, int64(25_500_000), captured.amount, "exact micro amount applied verbatim")
	require.Len(t, captured.queries, 1)
	assert.Contains(t, captured.queries[0], "spend_micro_usd")
}

func TestRecordTeamSpendExact_GuardsSkipWrite(t *testing.T) {
	var execCalls int
	executor := &mockSpendExecutor{
		execFn: func(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			execCalls++
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}

	require.NoError(t, RecordTeamSpendExact(context.Background(), executor, "", "2026-10", money.MicroUSD(1)))
	require.NoError(t, RecordTeamSpendExact(context.Background(), executor, "team-7", "", money.MicroUSD(1)))
	require.NoError(t, RecordTeamSpendExact(context.Background(), nil, "team-7", "2026-10", money.MicroUSD(1)))
	assert.Zero(t, execCalls, "no identity or no executor must not write")
}

func TestRecordTeamSpendExact_NegativeAmountFlooredToZero(t *testing.T) {
	var captured recordExactSpendArgs
	executor := &mockSpendExecutor{
		execFn: func(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			captured.amount = args[2].(int64)
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}

	err := RecordTeamSpendExact(context.Background(), executor, "team-18", "2026-10", money.MicroUSD(-5))
	require.NoError(t, err)
	assert.Equal(t, int64(0), captured.amount)
}

func TestRecordTeamSpendExact_DBError(t *testing.T) {
	executor := &mockSpendExecutor{
		execFn: func(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("disk full")
		},
	}

	err := RecordTeamSpendExact(context.Background(), executor, "team-9", "2026-10", money.MicroUSD(10))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "record exact team spend")
}

// mockSpendExecutor implements budget.SpendExecutor (the transactional write
// surface the exact spend paths run on).
type mockSpendExecutor struct {
	execFn func(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
}

func (m *mockSpendExecutor) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return m.execFn(ctx, query, args...)
}

func TestGetSpendThisMonth_NoRows(t *testing.T) {
	pool := newSmartMockPool(nil, func() pgx.Row { return &mockRow{err: pgx.ErrNoRows} })
	e := NewEnforcer(pool, newBudgetTestLogger())

	spend, err := e.getSpendThisMonthMicro(context.Background(), "team-10")
	require.NoError(t, err)
	assert.Equal(t, int64(0), spend)
}

func TestGetSpendThisMonth_WithSpend(t *testing.T) {
	pool := newSmartMockPool(nil, func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(75_250_000)}}} })
	e := NewEnforcer(pool, newBudgetTestLogger())

	spend, err := e.getSpendThisMonthMicro(context.Background(), "team-11")
	require.NoError(t, err)
	assert.Equal(t, int64(75_250_000), spend, "the exact accumulator is read, not the projection")
}

func TestGetSpendThisMonth_DBError(t *testing.T) {
	pool := newSmartMockPool(nil, func() pgx.Row { return &mockRow{err: errors.New("connection lost")} })
	e := NewEnforcer(pool, newBudgetTestLogger())

	spend, err := e.getSpendThisMonthMicro(context.Background(), "team-12")
	require.Error(t, err)
	assert.Equal(t, int64(0), spend)
}

func TestClearCache(t *testing.T) {
	pool := newSmartMockPool(
		func() pgx.Row { return &mockRow{err: pgx.ErrNoRows} },
		nil,
	)

	e := NewEnforcer(pool, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-13")
	require.ErrorIs(t, err, ErrNoBudget) // no budget row → deny (and cache the absence)
	require.Len(t, e.cache, 1)

	e.ClearCache("team-13")
	assert.Empty(t, e.cache)
}

func TestCheckBudget_BudgetAtExactLimit(t *testing.T) {
	pool := newSmartMockPool(
		func() pgx.Row { return &mockRow{data: [][]interface{}{{100.0, true}}} },
		func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(100_000_000)}}} },
	)

	e := NewEnforcer(pool, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-14")
	require.Error(t, err) // spend (100_000_000µ) >= limit ($100) → hard limit blocks
	assert.ErrorIs(t, err, ErrBudgetExceeded)
}

func TestCheckBudget_BudgetJustBelowLimit(t *testing.T) {
	pool := newSmartMockPool(
		func() pgx.Row { return &mockRow{data: [][]interface{}{{100.0, true}}} },
		func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(100_000_000 - 1)}}} },
	)

	e := NewEnforcer(pool, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-15")
	require.NoError(t, err) // 1µ below the limit → allowed
}

// outcome. A cent-rounded projection would lose the last 4000µ.
func TestCheckBudget_SubCentExactPrecision(t *testing.T) {
	under := newSmartMockPool(
		func() pgx.Row { return &mockRow{data: [][]interface{}{{0.01, true}}} }, // $0.01 = 10_000µ
		func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(9_999)}}} },
	)
	require.NoError(t, NewEnforcer(under, newBudgetTestLogger()).CheckBudget(context.Background(), "team-19"))

	at := newSmartMockPool(
		func() pgx.Row { return &mockRow{data: [][]interface{}{{0.01, true}}} },
		func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(10_000)}}} },
	)
	require.ErrorIs(t,
		NewEnforcer(at, newBudgetTestLogger()).CheckBudget(context.Background(), "team-20"),
		ErrBudgetExceeded)
}

func TestCheckBudget_NegativeSpendAllowed(t *testing.T) {
	pool := newSmartMockPool(
		func() pgx.Row { return &mockRow{data: [][]interface{}{{100.0, true}}} },
		nil,
	)

	e := NewEnforcer(pool, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-16")
	require.NoError(t, err) // no spend record → 0 < 100
}

// blockingRow blocks its Scan until the test releases it — it models a slow
// team_budgets read for one team while another team's check must proceed.
type blockingRow struct {
	started chan struct{}
	release chan struct{}
}

func (r *blockingRow) Scan(dest ...interface{}) error {
	close(r.started)
	<-r.release
	for _, d := range dest {
		switch p := d.(type) {
		case *float64:
			*p = 100.0
		case *int64:
			*p = 100_000
		case *bool:
			*p = true
		}
	}
	return nil
}

// TestCheckBudget_ConcurrentTeamsDoNotSerialize (W-MONEY): the budget read
// runs OUTSIDE the cache lock, so a slow DB read for one team cannot block
// another team's check — the old write-lock-across-the-query serialized
// every tenant behind the slowest budget read.
func TestCheckBudget_ConcurrentTeamsDoNotSerialize(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	e := NewEnforcer(&mockPool{
		queryRowFn: func(_ context.Context, query string, args ...interface{}) pgx.Row {
			teamID, _ := args[0].(string)
			if strings.Contains(query, "team_budgets") {
				if teamID == "team-slow" {
					return &blockingRow{started: started, release: release}
				}
				return &mockRow{data: [][]interface{}{{100.0, true}}}
			}
			return &mockRow{err: pgx.ErrNoRows} // spend: zero for both teams
		},
	}, newBudgetTestLogger())

	slowDone := make(chan error, 1)
	go func() { slowDone <- e.CheckBudget(context.Background(), "team-slow") }()
	<-started // the slow team's budget read is in flight, cache unlocked

	fastDone := make(chan error, 1)
	go func() { fastDone <- e.CheckBudget(context.Background(), "team-fast") }()
	select {
	case err := <-fastDone:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("team-fast's CheckBudget serialized behind team-slow's DB read")
	}

	close(release)
	require.NoError(t, <-slowDone, "the slow team's check completes once its read unblocks")
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *mockRows) TypeMap() *pgtype.Map { return nil }
