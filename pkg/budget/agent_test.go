package budget

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newAgentMockPool routes budget (agent_budgets) vs spend (agent_spend_daily)
// SELECTs, and records Exec calls (for RecordAgentSpend).
func newAgentMockPool(budgetFn, spendFn func() pgx.Row, execFn func(...interface{}) (pgconn.CommandTag, error)) *agentMock {
	return &agentMock{budgetFn: budgetFn, spendFn: spendFn, execFn: execFn}
}

type agentMock struct {
	budgetFn func() pgx.Row
	spendFn  func() pgx.Row
	// keysFn resolves agent_keys queries (AUDIT-P1-03: parent walk +
	// subtree spend SUM). It is checked FIRST: the subtree query mentions
	// both agent_keys and agent_spend_daily, while getBudget/getSpendToday
	// never mention agent_keys, so the legacy fns are unaffected.
	keysFn func(query string, args ...interface{}) pgx.Row
	// budgetFnArgs / spendFnArgs are arg-aware variants used by the
	// delegation-walk tests where child and ancestor rows differ. When nil
	// the legacy fixed fns are used.
	budgetFnArgs func(args ...interface{}) pgx.Row
	spendFnArgs  func(args ...interface{}) pgx.Row
	execFn       func(...interface{}) (pgconn.CommandTag, error)
}

func (m *agentMock) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	switch {
	case strings.Contains(query, "agent_keys"):
		if m.keysFn != nil {
			return m.keysFn(query, args...)
		}
	case strings.Contains(query, "agent_budgets"):
		if m.budgetFnArgs != nil {
			return m.budgetFnArgs(args...)
		}
		if m.budgetFn != nil {
			return m.budgetFn()
		}
	case strings.Contains(query, "agent_spend_daily"):
		if m.spendFnArgs != nil {
			return m.spendFnArgs(args...)
		}
		if m.spendFn != nil {
			return m.spendFn()
		}
	}
	return &mockRow{err: pgx.ErrNoRows}
}

func (m *agentMock) Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	if m.execFn != nil {
		return m.execFn(args...)
	}
	return pgconn.NewCommandTag("OK"), nil
}

func (m *agentMock) Query(ctx context.Context, query string, args ...interface{}) pgx.Rows {
	return &mockRows{}
}

func fixedNow() time.Time {
	return time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
}

func TestCheckAgentBudget_EmptyAgentID(t *testing.T) {
	e := NewAgentEnforcer(newAgentMockPool(nil, nil, nil), newBudgetTestLogger())
	e.now = fixedNow
	assert.NoError(t, e.CheckAgentBudget(context.Background(), ""))
}

func TestCheckAgentBudget_NilDB(t *testing.T) {
	e := NewAgentEnforcer(nil, newBudgetTestLogger())
	e.now = fixedNow
	assert.NoError(t, e.CheckAgentBudget(context.Background(), "agent-1"))
}

func TestCheckAgentBudget_NoBudgetRow(t *testing.T) {
	e := NewAgentEnforcer(newAgentMockPool(nil, nil, nil), newBudgetTestLogger())
	e.now = fixedNow
	err := e.CheckAgentBudget(context.Background(), "agent-1")
	assert.ErrorIs(t, err, ErrNoAgentBudget)
}

func TestCheckAgentBudget_WithinLimit(t *testing.T) {
	e := NewAgentEnforcer(newAgentMockPool(
		func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(100000)}}} },
		func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(50000)}}} },
		nil,
	), newBudgetTestLogger())
	e.now = fixedNow
	assert.NoError(t, e.CheckAgentBudget(context.Background(), "agent-1"))
}

func TestCheckAgentBudget_Exceeded(t *testing.T) {
	e := NewAgentEnforcer(newAgentMockPool(
		func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(100000)}}} },
		func() pgx.Row { return &mockRow{data: [][]interface{}{{int64(100000)}}} },
		nil,
	), newBudgetTestLogger())
	e.now = fixedNow
	err := e.CheckAgentBudget(context.Background(), "agent-1")
	assert.ErrorIs(t, err, ErrAgentBudgetExceeded)
}

func TestCheckAgentBudget_Unavailable(t *testing.T) {
	dbErr := errors.New("connection refused")
	e := NewAgentEnforcer(newAgentMockPool(
		func() pgx.Row { return &mockRow{err: dbErr} },
		nil, nil,
	), newBudgetTestLogger())
	e.now = fixedNow
	err := e.CheckAgentBudget(context.Background(), "agent-1")
	assert.ErrorIs(t, err, ErrAgentBudgetUnavailable)
}

func TestRecordAgentSpend(t *testing.T) {
	var gotQuery string
	var gotArgs []interface{}
	e := NewAgentEnforcer(newAgentMockPool(nil, nil, func(args ...interface{}) (pgconn.CommandTag, error) {
		gotArgs = args
		return pgconn.NewCommandTag("OK"), nil
	}), newBudgetTestLogger())
	e.now = fixedNow

	require.NoError(t, e.RecordAgentSpend(context.Background(), "agent-1", 1234, 10, 20))

	// Args: agent_id, day, cost_cents, tokens_in, tokens_out.
	require.Len(t, gotArgs, 5)
	assert.Equal(t, "agent-1", gotArgs[0])
	assert.Equal(t, "2026-09-06", gotArgs[1])
	assert.Equal(t, int64(1234), gotArgs[2])
	assert.Equal(t, int64(10), gotArgs[3])
	assert.Equal(t, int64(20), gotArgs[4])
	_ = gotQuery
}

func TestRecordAgentSpend_EmptyOrNegative(t *testing.T) {
	// Empty agent id: no-op (no Exec).
	called := false
	e := NewAgentEnforcer(newAgentMockPool(nil, nil, func(args ...interface{}) (pgconn.CommandTag, error) {
		called = true
		return pgconn.NewCommandTag("OK"), nil
	}), newBudgetTestLogger())
	e.now = fixedNow
	require.NoError(t, e.RecordAgentSpend(context.Background(), "", 100, 1, 1))
	assert.False(t, called)

	// Negative cost is floored to 0, still records.
	called2 := false
	e2 := NewAgentEnforcer(newAgentMockPool(nil, nil, func(args ...interface{}) (pgconn.CommandTag, error) {
		called2 = true
		return pgconn.NewCommandTag("OK"), nil
	}), newBudgetTestLogger())
	e2.now = fixedNow
	require.NoError(t, e2.RecordAgentSpend(context.Background(), "agent-1", -5, 1, 1))
	assert.True(t, called2)
}

// exactSpendRecorder captures the caller's-transaction write made by
// RecordAgentSpendExact (the AF-06 settlement path).
type exactSpendRecorder struct {
	execs    int
	gotQuery string
	gotArgs  []interface{}
	err      error
}

func (r *exactSpendRecorder) Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	r.execs++
	r.gotQuery = query
	r.gotArgs = args
	if r.err != nil {
		return pgconn.CommandTag{}, r.err
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func TestRecordAgentSpendExact_AppliesExactMicro(t *testing.T) {
	e := NewAgentEnforcer(nil, newBudgetTestLogger())
	e.now = fixedNow
	rec := &exactSpendRecorder{}

	// $0.0123 = 12_300 µUSD: the exact amount is applied verbatim; the
	// compatibility cents are derived from it (12_300µ = 1.23¢ -> 1¢,
	// half away from zero), never re-rounded from a float.
	require.NoError(t, e.RecordAgentSpendExact(context.Background(), rec, "agent-1", 12_300, 10, 20))

	require.Equal(t, 1, rec.execs)
	assert.Contains(t, rec.gotQuery, "agent_spend_daily")
	assert.Contains(t, rec.gotQuery, "cost_micro_usd")
	require.Len(t, rec.gotArgs, 6)
	assert.Equal(t, "agent-1", rec.gotArgs[0])
	assert.Equal(t, "2026-09-06", rec.gotArgs[1], "UTC day of the injected clock")
	assert.Equal(t, int64(1), rec.gotArgs[2], "compat cents projection")
	assert.Equal(t, int64(12_300), rec.gotArgs[3], "exact micro amount")
	assert.Equal(t, int64(10), rec.gotArgs[4])
	assert.Equal(t, int64(20), rec.gotArgs[5])
}

func TestRecordAgentSpendExact_Guards(t *testing.T) {
	e := NewAgentEnforcer(nil, newBudgetTestLogger())
	e.now = fixedNow

	// Empty agent id and nil executor: no-op.
	require.NoError(t, e.RecordAgentSpendExact(context.Background(), nil, "agent-1", 100, 1, 1))
	rec := &exactSpendRecorder{}
	require.NoError(t, e.RecordAgentSpendExact(context.Background(), rec, "", 100, 1, 1))
	assert.Zero(t, rec.execs)

	// Negative amount is clamped to a zero-cost record (defensive; intents
	// are non-negative by contract).
	require.NoError(t, e.RecordAgentSpendExact(context.Background(), rec, "agent-1", -7, 1, 1))
	require.Equal(t, 1, rec.execs)
	assert.Equal(t, int64(0), rec.gotArgs[2])
	assert.Equal(t, int64(0), rec.gotArgs[3], "negative amount clamps to a zero-cost record")

	// Executor failure surfaces for the worker's classification.
	fail := &exactSpendRecorder{err: errors.New("tx aborted")}
	assert.Error(t, e.RecordAgentSpendExact(context.Background(), fail, "agent-1", 100, 1, 1))
}

func TestValidTaskID(t *testing.T) {
	cases := map[string]bool{
		"":                       true, // untagged is valid
		"task-1":                 true,
		"Task_1":                 true,
		"a.b-c:d_e":              true,
		strings.Repeat("a", 128): true,
		strings.Repeat("a", 129): false, // too long
		"bad char":               false, // space
		"semi;colon":             false, // ; not allowed
		"slash/here":             false, // / not allowed
		"unicode-тест":           false, // non-ascii
	}
	for in, want := range cases {
		assert.Equalf(t, want, ValidTaskID(in), "ValidTaskID(%q)", in)
	}
}

// TestRecordAgentSpendExactAt_RequestTimeBucketsDay (W-MONEY, ADR I5): the
// day bucket follows the REQUEST's own time — a request served before UTC
// midnight lands in the day it was served in, never in the later settle
// day. A zero request time keeps the settle-time default.
func TestRecordAgentSpendExactAt_RequestTimeBucketsDay(t *testing.T) {
	e := NewAgentEnforcer(nil, newBudgetTestLogger())
	e.now = fixedNow // settle clock pinned to 2026-09-06 12:00 UTC
	rec := &exactSpendRecorder{}

	requestAt := time.Date(2026, 9, 5, 23, 59, 59, int(500*time.Millisecond), time.UTC)
	require.NoError(t, e.RecordAgentSpendExactAt(context.Background(), rec, "agent-1", 12_300, 10, 20, requestAt))
	require.Equal(t, 1, rec.execs)
	assert.Equal(t, "2026-09-05", rec.gotArgs[1], "day bucket is the request's day, not the settle day")

	require.NoError(t, e.RecordAgentSpendExactAt(context.Background(), rec, "agent-1", 12_300, 10, 20, time.Time{}))
	require.Equal(t, 2, rec.execs)
	assert.Equal(t, "2026-09-06", rec.gotArgs[1], "a zero request time falls back to the settle clock")

	// The legacy entry point stays on the settle-time default (unchanged
	// contract for callers that carry no request clock).
	require.NoError(t, e.RecordAgentSpendExact(context.Background(), rec, "agent-1", 12_300, 10, 20))
	require.Equal(t, 3, rec.execs)
	assert.Equal(t, "2026-09-06", rec.gotArgs[1])
}

// TestCheckAgentBudget_ConcurrentAgentsDoNotSerialize (W-MONEY): the agent
// budget read runs OUTSIDE the cache lock — a slow read for one agent must
// not stall another agent's check.
func TestCheckAgentBudget_ConcurrentAgentsDoNotSerialize(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	e := NewAgentEnforcer(&mockPool{
		queryRowFn: func(_ context.Context, query string, args ...interface{}) pgx.Row {
			agentID, _ := args[0].(string)
			if strings.Contains(query, "agent_budgets") {
				if agentID == "agent-slow" {
					return &blockingRow{started: started, release: release}
				}
				return &mockRow{data: [][]interface{}{{int64(100_000)}}}
			}
			return &mockRow{err: pgx.ErrNoRows} // spend: zero
		},
	}, newBudgetTestLogger())
	e.now = fixedNow

	slowDone := make(chan error, 1)
	go func() { slowDone <- e.CheckAgentBudget(context.Background(), "agent-slow") }()
	<-started

	fastDone := make(chan error, 1)
	go func() { fastDone <- e.CheckAgentBudget(context.Background(), "agent-fast") }()
	select {
	case err := <-fastDone:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("agent-fast's check serialized behind agent-slow's DB read")
	}

	close(release)
	require.NoError(t, <-slowDone, "the slow agent's check completes once its read unblocks")
}

// ---------------------------------------------------------------------------
// LoopBudget: N06-P07-T03 — internal model/tool loops share the SAME budget
// story (§5/§6): per-episode hop caps block runaway detectors fail-closed,
// episodes release with their request, and a nil budget disables accounting.
// ---------------------------------------------------------------------------

func newLoopTestBudget(maxHops int, ttl time.Duration) (*LoopBudget, *time.Time) {
	b := NewLoopBudget(maxHops, ttl)
	now := time.Now()
	b.now = func() time.Time { return now }
	return b, &now
}

func TestLoopBudget_AdmitsUpToCapThenBlocks(t *testing.T) {
	b, _ := newLoopTestBudget(3, time.Minute)
	for i := 1; i <= 3; i++ {
		require.NoError(t, b.Admit("req-1"), "hop %d is under the cap", i)
		require.Equal(t, i, b.Hops("req-1"))
	}
	err := b.Admit("req-1")
	require.ErrorIs(t, err, ErrLoopBudgetExceeded)
	// The refused hop must not consume quota.
	require.Equal(t, 3, b.Hops("req-1"))
}

func TestLoopBudget_EpisodesAreIndependent(t *testing.T) {
	b, _ := newLoopTestBudget(1, time.Minute)
	require.NoError(t, b.Admit("req-a"))
	require.ErrorIs(t, b.Admit("req-a"), ErrLoopBudgetExceeded)
	require.NoError(t, b.Admit("req-b"), "another episode starts at zero")
	require.Equal(t, 0, b.Hops("req-unknown"))
}

func TestLoopBudget_ReleaseResetsEpisode(t *testing.T) {
	b, _ := newLoopTestBudget(1, time.Minute)
	require.NoError(t, b.Admit("req-1"))
	require.ErrorIs(t, b.Admit("req-1"), ErrLoopBudgetExceeded)

	b.Release("req-1")
	require.Equal(t, 0, b.Hops("req-1"))
	require.NoError(t, b.Admit("req-1"), "the request ended; its episode is gone")
}

func TestLoopBudget_TTLSweepsIdleEpisodes(t *testing.T) {
	b, now := newLoopTestBudget(1, time.Minute)
	require.NoError(t, b.Admit("req-1"))
	require.ErrorIs(t, b.Admit("req-1"), ErrLoopBudgetExceeded)

	*now = now.Add(2 * DefaultLoopTTL)
	require.NoError(t, b.Admit("req-1"), "an episode idle past the TTL is swept, not throttled forever")
	require.Equal(t, 1, b.Hops("req-1"), "the swept episode restarted at one hop")
}

func TestLoopBudget_DefaultsAndNilSafety(t *testing.T) {
	b := NewLoopBudget(0, 0)
	require.Equal(t, DefaultLoopMaxHops, b.maxHops)
	require.Equal(t, DefaultLoopTTL, b.ttl)

	var nilB *LoopBudget
	require.NoError(t, nilB.Admit("req-1"), "a nil budget disables loop accounting")
	require.Equal(t, 0, nilB.Hops("req-1"))
	require.NotPanics(t, func() { nilB.Release("req-1") })

	// An empty episode is unattributable and always allowed, untracked.
	require.NoError(t, b.Admit(""))
	require.Equal(t, 0, b.Hops(""))
}
