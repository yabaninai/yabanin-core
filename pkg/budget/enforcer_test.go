package budget

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	pgtype "github.com/jackc/pgx/v5/pgtype"
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
func (r *mockRows) Scan(dest ...any) error                       { return errors.New("scan not supported") }

// fakeBudgetDB models the committed team_budgets / team_spend_monthly rows
// behind the enforcer's ONE snapshot query: rows maps team → {limit, hard}
// (absent key = no budget row), spend maps team → exact micro-USD. Tests
// flip state BETWEEN calls to model committed admin writes; snapshot reads
// are counted so controls can pin that a check actually re-read the
// authoritative row instead of serving something remembered.
type fakeBudgetDB struct {
	mu    sync.Mutex
	rows  map[string][]interface{}
	spend map[string]int64
	// outage, when set, fails every snapshot read (store-down control).
	outage error
	reads  int
}

func newFakeBudgetDB() *fakeBudgetDB {
	return &fakeBudgetDB{rows: map[string][]interface{}{}, spend: map[string]int64{}}
}

// setBudget models the committed PUT /api/teams/{id}/budget row.
func (f *fakeBudgetDB) setBudget(teamID string, monthlyLimitUSD float64, hard bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[teamID] = []interface{}{monthlyLimitUSD, hard}
}

// deleteBudget models the committed DELETE /api/teams/{id}/budget.
func (f *fakeBudgetDB) deleteBudget(teamID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, teamID)
}

// setSpend models the month's exact micro-USD accumulator.
func (f *fakeBudgetDB) setSpend(teamID string, micro int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spend[teamID] = micro
}

// setOutage models a budget-store outage (every read fails).
func (f *fakeBudgetDB) setOutage(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outage = err
}

func (f *fakeBudgetDB) snapshotReads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

func (f *fakeBudgetDB) QueryRow(_ context.Context, _ string, args ...interface{}) pgx.Row {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.outage != nil {
		return &mockRow{err: f.outage}
	}
	teamID, _ := args[0].(string)
	row, ok := f.rows[teamID]
	if !ok {
		return &mockRow{err: pgx.ErrNoRows}
	}
	return &mockRow{data: [][]interface{}{append(append([]interface{}{}, row...), f.spend[teamID])}}
}

func (f *fakeBudgetDB) Exec(_ context.Context, _ string, _ ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("OK"), nil
}

func TestNewEnforcer(t *testing.T) {
	e := NewEnforcer(newFakeBudgetDB(), newBudgetTestLogger())
	require.NotNil(t, e)
	require.NotNil(t, e.db)
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
	db := newFakeBudgetDB()
	e := NewEnforcer(db, newBudgetTestLogger())
	err := e.CheckBudget(context.Background(), "team-1")
	assert.ErrorIs(t, err, ErrNoBudget) // deny by default — no budget row configured
	assert.Equal(t, 1, db.snapshotReads(), "the denial comes from an authoritative read")
}

func TestCheckBudget_HardLimitExceeded(t *testing.T) {
	db := newFakeBudgetDB()
	db.setBudget("team-1", 100.0, true)
	db.setSpend("team-1", 150_000_000) // $150 exact
	e := NewEnforcer(db, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBudgetExceeded)
}

func TestCheckBudget_SoftLimitExceeded(t *testing.T) {
	db := newFakeBudgetDB()
	db.setBudget("team-2", 100.0, false) // soft limit
	db.setSpend("team-2", 150_000_000)
	e := NewEnforcer(db, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-2")
	require.NoError(t, err) // soft limit → warn but allow
}

func TestCheckBudget_WithinHardLimit(t *testing.T) {
	db := newFakeBudgetDB()
	db.setBudget("team-3", 100.0, true)
	db.setSpend("team-3", 50_000_000) // $50 exact
	e := NewEnforcer(db, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-3")
	require.NoError(t, err)
}

// TestFirstBudgetWriteVisibleToNextCheck is the frozen original-sequence
// control: a team is denied while unconfigured, an authorized budget write
// commits, and the IMMEDIATELY following check on the same team evaluates
// the persisted budget (no TTL wait, no cache of the absence). The read
// count pins that the second check re-read the authoritative row — the
// pre-fix 1-minute negative cache fails this test by serving the remembered
// absence (ErrNoBudget, one snapshot read total).
func TestFirstBudgetWriteVisibleToNextCheck(t *testing.T) {
	db := newFakeBudgetDB()
	e := NewEnforcer(db, newBudgetTestLogger())

	// Original immediate denial: no budget row configured.
	err := e.CheckBudget(context.Background(), "team-4")
	require.ErrorIs(t, err, ErrNoBudget)
	require.Equal(t, 1, db.snapshotReads())

	// The authorized write commits (PUT /api/teams/team-4/budget: $100 hard).
	db.setBudget("team-4", 100.0, true)
	db.setSpend("team-4", 50_000_000)

	// The very next check evaluates the persisted budget.
	err = e.CheckBudget(context.Background(), "team-4")
	require.NoError(t, err, "a committed first budget must be visible to the immediately following request")
	require.Equal(t, 2, db.snapshotReads(), "the allowance comes from a fresh authoritative read")
}

// TestChangedLimitEnforcedByNextCheck is the frozen stale-limit control: a
// lowered limit takes effect on the next check — the previous state (an
// allowed request under $100) must never keep authorizing spend above the
// new $0.50 cap.
func TestChangedLimitEnforcedByNextCheck(t *testing.T) {
	db := newFakeBudgetDB()
	db.setBudget("team-5", 100.0, true)
	db.setSpend("team-5", 50_000_000) // $50 of spend
	e := NewEnforcer(db, newBudgetTestLogger())

	require.NoError(t, e.CheckBudget(context.Background(), "team-5"))

	// The operator lowers the cap below the already-recorded spend.
	db.setBudget("team-5", 0.50, true)

	err := e.CheckBudget(context.Background(), "team-5")
	require.ErrorIs(t, err, ErrBudgetExceeded,
		"the lowered limit binds the next request; a remembered higher limit is never served")
}

// TestDeletedBudgetDeniesNextCheck is the delete half of the stale control:
// removing the row restores the fail-closed denial immediately — the
// previously allowed team must not keep a phantom cap.
func TestDeletedBudgetDeniesNextCheck(t *testing.T) {
	db := newFakeBudgetDB()
	db.setBudget("team-6", 100.0, true)
	db.setSpend("team-6", 50_000_000)
	e := NewEnforcer(db, newBudgetTestLogger())

	require.NoError(t, e.CheckBudget(context.Background(), "team-6"))

	db.deleteBudget("team-6") // DELETE /api/teams/team-6/budget commits

	err := e.CheckBudget(context.Background(), "team-6")
	require.ErrorIs(t, err, ErrNoBudget, "no stale allow after a committed delete")
}

// TestBudgetStoreOutage_DeniesNeverServesLastKnownLimit is the frozen outage
// control: when freshness cannot be established the enforcer denies — the
// last-known $100 limit is never served as proof of the current cap.
func TestBudgetStoreOutage_DeniesNeverServesLastKnownLimit(t *testing.T) {
	db := newFakeBudgetDB()
	db.setBudget("team-7", 100.0, true)
	db.setSpend("team-7", 50_000_000)
	e := NewEnforcer(db, newBudgetTestLogger())

	require.NoError(t, e.CheckBudget(context.Background(), "team-7"), "preconditions: allowed under the live limit")

	db.setOutage(errors.New("connection refused"))

	err := e.CheckBudget(context.Background(), "team-7")
	assert.ErrorIs(t, err, ErrBudgetUnavailable, "an unreadable store is a denial, not a last-known allowance")
}

// TestCheckBudget_DBErrorOnUnbudgetedTeam pins the same fail-closed posture
// for the first read of an unconfigured team.
func TestCheckBudget_DBErrorOnUnbudgetedTeam(t *testing.T) {
	db := newFakeBudgetDB()
	db.setOutage(errors.New("connection refused"))
	e := NewEnforcer(db, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-8")
	assert.ErrorIs(t, err, ErrBudgetUnavailable) // fail-closed on DB error
}

// TestTwoTeamIsolation_BudgetWriteScopedPerTeam: a budget configured for
// team B never authorizes team A, and A's later configuration changes
// nothing for B — each team's denial/allowance rides its own row.
func TestTwoTeamIsolation_BudgetWriteScopedPerTeam(t *testing.T) {
	db := newFakeBudgetDB()
	db.setBudget("team-b", 100.0, true)
	db.setSpend("team-b", 10_000_000)
	e := NewEnforcer(db, newBudgetTestLogger())

	// B configured, A not: B allowed, A denied.
	require.NoError(t, e.CheckBudget(context.Background(), "team-b"))
	require.ErrorIs(t, e.CheckBudget(context.Background(), "team-a"), ErrNoBudget)

	// The write that fixes A (PUT /api/teams/team-a/budget) — B untouched.
	db.setBudget("team-a", 25.0, true)
	require.NoError(t, e.CheckBudget(context.Background(), "team-a"),
		"team A's own write is visible to A immediately")
	require.NoError(t, e.CheckBudget(context.Background(), "team-b"), "team B stays within its own limit")

	// Deleting B's budget denies B while A keeps its allowance.
	db.deleteBudget("team-b")
	require.ErrorIs(t, e.CheckBudget(context.Background(), "team-b"), ErrNoBudget)
	require.NoError(t, e.CheckBudget(context.Background(), "team-a"))
}

func TestCheckBudget_BudgetAtExactLimit(t *testing.T) {
	db := newFakeBudgetDB()
	db.setBudget("team-14", 100.0, true)
	db.setSpend("team-14", 100_000_000)
	e := NewEnforcer(db, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-14")
	require.Error(t, err) // spend (100_000_000µ) >= limit ($100) → hard limit blocks
	assert.ErrorIs(t, err, ErrBudgetExceeded)
}

func TestCheckBudget_BudgetJustBelowLimit(t *testing.T) {
	db := newFakeBudgetDB()
	db.setBudget("team-15", 100.0, true)
	db.setSpend("team-15", 100_000_000-1)
	e := NewEnforcer(db, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-15")
	require.NoError(t, err) // 1µ below the limit → allowed
}

// TestCheckBudget_SubCentExactPrecision: the comparison runs on the exact
// micro-USD accumulator, not a cent-rounded projection. A cent-rounded
// projection would lose the last 4000µ.
func TestCheckBudget_SubCentExactPrecision(t *testing.T) {
	under := newFakeBudgetDB()
	under.setBudget("team-19", 0.01, true) // $0.01 = 10_000µ
	under.setSpend("team-19", 9_999)
	require.NoError(t, NewEnforcer(under, newBudgetTestLogger()).CheckBudget(context.Background(), "team-19"))

	at := newFakeBudgetDB()
	at.setBudget("team-20", 0.01, true)
	at.setSpend("team-20", 10_000)
	require.ErrorIs(t,
		NewEnforcer(at, newBudgetTestLogger()).CheckBudget(context.Background(), "team-20"),
		ErrBudgetExceeded)
}

func TestCheckBudget_NegativeSpendAllowed(t *testing.T) {
	db := newFakeBudgetDB()
	db.setBudget("team-16", 100.0, true) // no spend entry → COALESCE 0
	e := NewEnforcer(db, newBudgetTestLogger())

	err := e.CheckBudget(context.Background(), "team-16")
	require.NoError(t, err) // no spend record → 0 < 100
}

// TestConcurrentChecksDuringBudgetWrite: checks racing a committed write see
// either the old or the new committed state — never an error, never a torn
// row. Barrier-synchronized phases, no sleeps.
func TestConcurrentChecksDuringBudgetWrite(t *testing.T) {
	db := newFakeBudgetDB()
	e := NewEnforcer(db, newBudgetTestLogger())
	const workers = 8

	runPhase := func(begin chan struct{}) []error {
		out := make(chan error, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-begin
				out <- e.CheckBudget(context.Background(), "team-race")
			}()
		}
		close(begin)
		wg.Wait()
		close(out)
		errs := make([]error, 0, workers)
		for err := range out {
			errs = append(errs, err)
		}
		return errs
	}

	// Phase 1: every concurrent check denies (no row).
	for _, err := range runPhase(make(chan struct{})) {
		require.ErrorIs(t, err, ErrNoBudget, "pre-write concurrent phase: uniform denial")
	}

	// The write commits.
	db.setBudget("team-race", 100.0, true)

	// Phase 2: every concurrent check allows.
	for _, err := range runPhase(make(chan struct{})) {
		require.NoError(t, err, "post-write concurrent phase: uniform allowance")
	}
}

// TestConcurrentChecksWhileBudgetToggles: barrier-separated rounds of
// concurrent checks around committed flips — absent, present, absent, ... —
// pin that every round's concurrent checks agree with the COMMITTED state
// (uniform denial / uniform allowance, never a torn row or an error). The
// write happens strictly between rounds, so the polarity assertions are
// deterministic; the checks within a round still execute concurrently.
func TestConcurrentChecksWhileBudgetToggles(t *testing.T) {
	db := newFakeBudgetDB()
	e := NewEnforcer(db, newBudgetTestLogger())

	const readers = 8
	const rounds = 10
	for round := 0; round < rounds; round++ {
		present := round%2 == 1 // round 0 reads the absent state; flips alternate

		begin := make(chan struct{})
		done := make(chan error, readers)
		var wg sync.WaitGroup
		for i := 0; i < readers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-begin
				done <- e.CheckBudget(context.Background(), "team-toggle")
			}()
		}
		close(begin)
		wg.Wait()
		close(done)

		for err := range done {
			if present {
				require.NoError(t, err, "round %d: committed budget present — allowance expected", round)
			} else {
				require.ErrorIs(t, err, ErrNoBudget, "round %d: no committed row — denial expected", round)
			}
		}

		// The committed write lands strictly between rounds (no reader in flight).
		if present {
			db.deleteBudget("team-toggle")
		} else {
			db.setBudget("team-toggle", 100.0, true)
		}
	}

	db.setBudget("team-toggle", 100.0, true)
	require.NoError(t, e.CheckBudget(context.Background(), "team-toggle"), "final committed state: allowed")
}

// TestConcurrentChecksRacingWriter_NeverOutsideCommittedStates: readers spin
// freely while a writer flips the row continuously — each outcome must be a
// committed state (denial or allowance), never ErrBudgetUnavailable or a
// torn row. Polarity counts are scheduler-dependent and deliberately NOT
// asserted here (the deterministic rounds above pin the polarity contract).
func TestConcurrentChecksRacingWriter_NeverOutsideCommittedStates(t *testing.T) {
	db := newFakeBudgetDB()
	e := NewEnforcer(db, newBudgetTestLogger())

	const readers = 4
	const iterations = 200
	begin := make(chan struct{})
	outcomes := make(chan error, readers*iterations)
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-begin
			for j := 0; j < iterations; j++ {
				outcomes <- e.CheckBudget(context.Background(), "team-race-writer")
			}
		}()
	}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		<-begin
		for j := 0; j < 25; j++ {
			db.setBudget("team-race-writer", 100.0, true)
			db.deleteBudget("team-race-writer")
		}
		db.setBudget("team-race-writer", 100.0, true)
	}()
	close(begin)
	wg.Wait()
	<-writerDone
	close(outcomes)

	for err := range outcomes {
		if err != nil && !errors.Is(err, ErrNoBudget) {
			t.Fatalf("outcome outside the committed-state set: %v", err)
		}
	}
	require.NoError(t, e.CheckBudget(context.Background(), "team-race-writer"), "final committed state: allowed")
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

// blockingRow blocks its Scan until the test releases it — it models a slow
// snapshot read for one team while another team's check must proceed. It
// fills the snapshot dests: $100 hard limit, $0.10 exact spend.
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

// TestCheckBudget_ConcurrentTeamsDoNotSerialize (W-MONEY): the snapshot read
// carries no enforcer-level lock, so a slow DB read for one team cannot
// block another team's check — the old write-lock-across-the-query
// serialized every tenant behind the slowest budget read.
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
				return &mockRow{data: [][]interface{}{{100.0, true, int64(0)}}}
			}
			return &mockRow{err: pgx.ErrNoRows}
		},
	}, newBudgetTestLogger())

	slowDone := make(chan error, 1)
	go func() { slowDone <- e.CheckBudget(context.Background(), "team-slow") }()
	<-started // the slow team's snapshot read is in flight

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
