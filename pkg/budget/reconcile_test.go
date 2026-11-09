package budget

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- reconcile worker unit tests (NEXT-18e): config defaults, the pure
// §7.1.3 divergence math and the cadence/batch bounds of the §7.1.5
// retention. The money-accurate behavior is covered by the live-PG
// acceptance tests in reconcile_int_test.go.

func TestReconcileConfig_DefaultsFillEveryZeroField(t *testing.T) {
	cfg := ReconcileConfig{}.withDefaults()
	def := DefaultReconcileConfig()
	assert.Equal(t, def, cfg)

	assert.Equal(t, 5*time.Minute, cfg.Interval)
	assert.Equal(t, ReservationSafetyWindow, cfg.SafetyWindow, "§14/D13 safety window")
	assert.Positive(t, cfg.ReleasedRetention)
	assert.Positive(t, cfg.RetentionBatch)
	assert.Positive(t, cfg.RetentionPasses)
	assert.Positive(t, cfg.ViolationLogLimit)

	// Custom values survive.
	custom := ReconcileConfig{Interval: time.Second}.withDefaults()
	assert.Equal(t, time.Second, custom.Interval)
	assert.Equal(t, def.SafetyWindow, custom.SafetyWindow)
}

func TestMergeDivergence_DetectsEveryDriftShape(t *testing.T) {
	walletKey := scopeRowKey{ScopeWallet, "org-1", ""}
	teamKey := scopeRowKey{ScopeTeamMonth, "team-1", "2026-10"}

	t.Run("consistent state is zero divergence", func(t *testing.T) {
		reserved := map[scopeRowKey]int64{walletKey: 500, teamKey: 700}
		remainders := map[scopeRowKey]int64{walletKey: 500, teamKey: 700}
		out := map[ScopeKind]int64{}
		mergeDivergence(out, reserved, remainders)
		assert.Empty(t, out)
	})

	t.Run("reserved above remainders", func(t *testing.T) {
		out := map[ScopeKind]int64{}
		mergeDivergence(out, map[scopeRowKey]int64{walletKey: 800}, map[scopeRowKey]int64{walletKey: 500})
		assert.Equal(t, map[ScopeKind]int64{ScopeWallet: 300}, out)
	})

	t.Run("reserved below remainders", func(t *testing.T) {
		out := map[ScopeKind]int64{}
		mergeDivergence(out, map[scopeRowKey]int64{walletKey: 500}, map[scopeRowKey]int64{walletKey: 900})
		assert.Equal(t, map[ScopeKind]int64{ScopeWallet: 400}, out,
			"missing reserve money must alert, not hide behind a signed sum")
	})

	t.Run("key present only on one side", func(t *testing.T) {
		out := map[ScopeKind]int64{}
		mergeDivergence(out,
			map[scopeRowKey]int64{walletKey: 100, teamKey: 250},
			map[scopeRowKey]int64{walletKey: 100})
		assert.Equal(t, map[ScopeKind]int64{ScopeTeamMonth: 250}, out)
	})

	t.Run("drift within a kind does not cancel", func(t *testing.T) {
		org2 := scopeRowKey{ScopeWallet, "org-2", ""}
		out := map[ScopeKind]int64{}
		mergeDivergence(out,
			map[scopeRowKey]int64{walletKey: 600, org2: 100},
			map[scopeRowKey]int64{walletKey: 500, org2: 200})
		assert.Equal(t, map[ScopeKind]int64{ScopeWallet: 200}, out,
			"+100 on one row and −100 on another must sum to 200, not 0")
	})
}

// recDB is the reconcile worker's fake reservationDB: queries route by
// substring to canned row sets; exec calls are recorded with their row
// counts.
type recDB struct {
	queryRowFn func(query string) ([]any, error)
	queryFn    func(query string) ([][]any, error)
	execFn     func(query string) (int64, error)

	execs []string
}

func (d *recDB) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("recDB: no tx expected in this test")
}

func (d *recDB) Exec(_ context.Context, query string, _ ...any) (pgconn.CommandTag, error) {
	d.execs = append(d.execs, query)
	if d.execFn != nil {
		n, err := d.execFn(query)
		if err != nil {
			return pgconn.NewCommandTag(""), err
		}
		return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", n)), nil
	}
	return pgconn.NewCommandTag(""), nil
}

func (d *recDB) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	if d.queryFn != nil {
		rows, err := d.queryFn(query)
		if err != nil {
			return nil, err
		}
		if rows != nil {
			return &recRows{rows: rows}, nil
		}
	}
	return &recRows{}, nil
}

func (d *recDB) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	if d.queryRowFn != nil {
		data, err := d.queryRowFn(query)
		return &recRow{data: data, err: err}
	}
	return &recRow{err: errors.New("recDB: unexpected QueryRow")}
}

type recRow struct {
	data []any
	err  error
}

func (r *recRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, d := range dest {
		if i >= len(r.data) {
			break
		}
		switch v := d.(type) {
		case *int64:
			*v = r.data[i].(int64)
		case *float64:
			*v = r.data[i].(float64)
		case *string:
			*v = r.data[i].(string)
		case **int64:
			if n, ok := r.data[i].(int64); ok {
				*v = &n
			}
		}
	}
	return nil
}

type recRows struct {
	rows [][]any
	idx  int
}

func (r *recRows) Next() bool {
	if r.idx < len(r.rows) {
		r.idx++
		return true
	}
	return false
}

func (r *recRows) Scan(dest ...any) error {
	row := r.rows[r.idx-1]
	for i, d := range dest {
		switch v := d.(type) {
		case *string:
			*v = row[i].(string)
		case *int64:
			*v = row[i].(int64)
		}
	}
	return nil
}

func (r *recRows) Err() error { return nil }
func (r *recRows) Close()     {}

func (r *recRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (r *recRows) Conn() *pgx.Conn                              { return nil }
func (r *recRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *recRows) RawValues() [][]byte                          { return nil }
func (r *recRows) Values() ([]any, error)                       { return nil, errors.New("not implemented") }

// recInvariantQueries routes every worker query by a distinctive substring
// and returns empty/zero data — a full healthy, empty deployment.
func recInvariantQueries(t *testing.T, override func(query string) ([][]any, error)) *recDB {
	t.Helper()
	return &recDB{
		queryRowFn: func(query string) ([]any, error) {
			switch {
			case strings.Contains(query, "lease_until < now()"):
				return []any{int64(0)}, nil // stranded (contains settlement_jobs too — first)
			case strings.Contains(query, "COUNT(*)"):
				return []any{int64(0)}, nil // exact §7.1.4 violator total: none
			case strings.Contains(query, "settlement_jobs"):
				return []any{float64(0)}, nil
			case strings.Contains(query, "MIN(balance_cents"):
				return []any{}, nil // NULL min: no wallets
			default:
				return nil, fmt.Errorf("unexpected row query: %.80s", query)
			}
		},
		queryFn: func(query string) ([][]any, error) {
			if override != nil {
				rows, err := override(query)
				if rows != nil || err != nil {
					return rows, err
				}
			}
			switch {
			case strings.Contains(query, "GROUP BY a.scope_kind"),
				strings.Contains(query, "org_id, scope_kind, scope_key"),
				strings.Contains(query, "FROM org_credits"),
				strings.Contains(query, "FROM team_spend_monthly"),
				strings.Contains(query, "FROM agent_spend_daily"),
				strings.Contains(query, "FROM session_spend"),
				strings.Contains(query, "reserved_micro_usd < 0"):
				return [][]any{}, nil
			default:
				return nil, fmt.Errorf("unexpected query: %.80s", query)
			}
		},
	}
}

// TestReconcileTick_RunsEveryStepOnFakes: one tick touches the release
// candidates, both invariant sides, the lag query and (first tick) the
// retention delete — and no step aborts the pass.
func TestReconcileTick_RunsEveryStepOnFakes(t *testing.T) {
	db := recInvariantQueries(t, nil)
	w := NewReconcileWorker(db, newBudgetTestLogger(), DefaultReconcileConfig())
	w.Tick(context.Background())

	require.Len(t, db.execs, 1, "first tick runs the retention (cadence elapsed)")
	assert.Contains(t, db.execs[0], "DELETE FROM budget_allowances")
	assert.Contains(t, db.execs[0], "status = $1", "retention only ever names 'released' rows")
}

// TestReconcileRetention_CadenceAndBatchBounds (§7.1.5, AF-06/16 shape):
// bounded batches, early stop when the window drains, error propagation and
// cadence gating.
func TestReconcileRetention_CadenceAndBatchBounds(t *testing.T) {
	db := &recDB{}
	w := NewReconcileWorker(db, newBudgetTestLogger(), DefaultReconcileConfig())
	w.cfg.RetentionBatch = 2
	w.cfg.RetentionPasses = 3
	w.cfg.RetentionEvery = time.Hour

	now := time.Unix(1_700_000_000, 0)
	w.SetClock(func() time.Time { return now })

	// Every batch reports a full batch → the pass stops after 3 batches.
	db.execFn = func(string) (int64, error) { return 2, nil }
	deleted, err := w.RetentionPass(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(6), deleted, "3 passes × batch 2")
	assert.Len(t, db.execs, 3, "bounded by RetentionPasses even with backlog")

	// Window drains: a partial batch ends the pass early.
	db.execs = nil
	db.execFn = func(string) (int64, error) { return 1, nil }
	deleted, err = w.RetentionPass(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
	assert.Len(t, db.execs, 1, "partial batch means the window drained")

	// Statement error is returned, not swallowed (retentionTick logs it).
	db.execs = nil
	db.execFn = func(string) (int64, error) { return 0, errors.New("boom") }
	_, err = w.RetentionPass(context.Background())
	require.ErrorContains(t, err, "boom")

	// Cadence: a fresh tick runs the retention once, the next (same clock)
	// skips it, and only after RetentionEvery does it run again.
	db.execs = nil
	db.execFn = func(string) (int64, error) { return 0, nil }
	w.retentionTick(context.Background())
	assert.Len(t, db.execs, 1)
	w.retentionTick(context.Background())
	assert.Len(t, db.execs, 1, "cadence not elapsed — skipped")
	now = now.Add(time.Hour)
	w.retentionTick(context.Background())
	assert.Len(t, db.execs, 2, "cadence elapsed — ran again")
}

// TestReconcileCheckInvariants_ReportsDivergenceAndViolations: the fake
// feeds a divergent wallet row, stranded escrow and two violating orgs; the
// report and the gauges must reflect all of them.
func TestReconcileCheckInvariants_ReportsDivergenceAndViolations(t *testing.T) {
	db := recInvariantQueries(t, func(query string) ([][]any, error) {
		switch {
		case strings.Contains(query, "GROUP BY a.scope_kind"):
			return [][]any{{"wallet", "org-1", "", int64(42)}}, nil
		case strings.Contains(query, "reserved_micro_usd < 0"):
			return [][]any{{"org-1", int64(-2_000_000)}, {"org-2", int64(-5)}}, nil
		case strings.Contains(query, "FROM org_credits"):
			return [][]any{{"org-1", "", int64(100)}}, nil
		default:
			return nil, nil
		}
	})
	db.queryRowFn = func(query string) ([]any, error) {
		switch {
		case strings.Contains(query, "lease_until < now()"):
			return []any{int64(9_000_000)}, nil // stranded (contains settlement_jobs too — first)
		case strings.Contains(query, "COUNT(*)"):
			return []any{int64(7)}, nil // 7 orgs violate, the log list stays capped at 2
		case strings.Contains(query, "settlement_jobs"):
			return []any{float64(1800)}, nil
		case strings.Contains(query, "MIN(balance_cents"):
			return []any{int64(-2_000_000)}, nil
		default:
			return nil, fmt.Errorf("unexpected row query: %.80s", query)
		}
	}
	w := NewReconcileWorker(db, newBudgetTestLogger(), DefaultReconcileConfig())

	report, err := w.CheckInvariants(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[ScopeKind]int64{ScopeWallet: 100}, report.ReservedPerScope)
	assert.Equal(t, map[ScopeKind]int64{ScopeWallet: 58}, report.DivergencePerScope,
		"reserved 100 vs remainder 42 → divergence 58")
	assert.Equal(t, int64(9_000_000), report.StrandedMicroUSD)
	assert.Equal(t, int64(-2_000_000), report.WalletHeadroomMin)
	assert.Equal(t, 7, report.WalletViolationCount,
		"the count is the exact total, not the log list's cap")
	assert.Equal(t, []string{"org-1", "org-2"}, report.WalletViolatingOrgs,
		"the logged list stays bounded by ViolationLogLimit")

	require.NoError(t, w.checkInvariants(context.Background()))
	assert.InDelta(t, 58,
		testutil.ToFloat64(metrics.BudgetReservedDivergenceMicroUSD.WithLabelValues("wallet")), 0.001)
	assert.InDelta(t, 100,
		testutil.ToFloat64(metrics.BudgetReservedMicroUSD.WithLabelValues("wallet")), 0.001)
	assert.InDelta(t, 9_000_000, testutil.ToFloat64(metrics.BudgetStrandedMicroUSD), 0.001)
	assert.InDelta(t, -2_000_000, testutil.ToFloat64(metrics.BudgetWalletHeadroomMicroUSD), 0.001)
	assert.Equal(t, 7, int(testutil.ToFloat64(metrics.BudgetWalletInvariantViolations)),
		"gauge carries the exact total")
	require.NoError(t, w.checkSettlementLag(context.Background()))
	assert.InDelta(t, 1800, testutil.ToFloat64(metrics.SettlementLagSeconds), 0.001)
}

// TestReconcileWorkerRun_StopsOnContextCancel: the ticker loop exits cleanly.
func TestReconcileWorkerRun_StopsOnContextCancel(t *testing.T) {
	db := recInvariantQueries(t, nil)
	w := NewReconcileWorker(db, newBudgetTestLogger(), DefaultReconcileConfig())
	w.cfg.Interval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on ctx cancel")
	}
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *recRows) TypeMap() *pgtype.Map { return nil }
