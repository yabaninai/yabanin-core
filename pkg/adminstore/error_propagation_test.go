package adminstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A02: all-or-error in the analytics store. A partial report (missing
// top-model / daily / classifier rows) would misstate the savings figures, so
// Query/Scan/rows.Err must be propagated — no silent `if err == nil` swallowing.

// totalRow scans an aggregate whose first dest is a count — the legacy
// 3-column (count, actual, counterfactual) totals row or the AF-14 combined
// 9-column (total + cache + routing via FILTER) savings aggregate.
type totalRow struct {
	count int
}

func (r *totalRow) Scan(dest ...interface{}) error {
	if len(dest) == 3 || len(dest) == 9 {
		if c, ok := dest[0].(*int); ok {
			*c = r.count
		}
	}
	return nil
}

// erroringRows is a pgx.Rows whose Next succeeds once and whose Scan fails
// (or whose Err is set after the loop).
type erroringRows struct {
	scanErr error
}

func (r *erroringRows) Next() bool { return true }
func (r *erroringRows) Err() error { return nil }
func (r *erroringRows) Close()     {}
func (r *erroringRows) Scan(dest ...interface{}) error {
	return r.scanErr
}
func (r *erroringRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (r *erroringRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *erroringRows) Conn() *pgx.Conn                              { return nil }
func (r *erroringRows) RawValues() [][]byte                          { return nil }
func (r *erroringRows) Values() ([]any, error)                       { return nil, nil }

// --- GetSavingsReport -------------------------------------------------------

func TestGetSavingsReport_TopModelsScanError_Propagates(t *testing.T) {
	// QueryRow answers (in call order): total=5, cache=1, routing=1,
	// pricing-coverage=1. Query: first call (top models) returns erroring
	// rows; nothing after must run (all-or-error).
	var queryCalls int
	db := &mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &totalRow{count: 5}
		},
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			queryCalls++
			switch {
			case containsSubstr(sql, "model_requested"): // top models — must fail
				return &erroringRows{scanErr: errors.New("simulated scan failure")}, nil
			case containsSubstr(sql, "NOT EXISTS"): // pricing coverage — clean
				return &mockPGXRows{data: nil}, nil
			}
			return &mockPGXRows{data: nil}, nil
		},
	}
	s := &Store{db: db}
	_, err := s.GetSavingsReport(context.Background(), "", 7, "")
	require.Error(t, err, "scan error in top-models must fail the whole report")
	assert.Contains(t, err.Error(), "top-models")
}

func TestGetSavingsReport_DailyRowsErr_Propagates(t *testing.T) {
	// Top models: no rows (empty). Daily: one good row then rows.Err() set
	// → must propagate (the error is only visible after the loop).
	var queryCalls int
	db := &mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &totalRow{count: 0}
		},
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			queryCalls++
			switch {
			case containsSubstr(sql, "DATE(created_at)"): // daily — one good row then iterErr
				return &mockPGXRows{
					data: [][]interface{}{{time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), 10, 1.0, 2.0}},
					err:  errors.New("simulated iteration failure"),
				}, nil
			case containsSubstr(sql, "NOT EXISTS"): // pricing coverage
				return &mockPGXRows{data: nil}, nil
			}
			// top models / classifier — clean, empty
			return &mockPGXRows{data: nil}, nil
		},
	}
	s := &Store{db: db}
	_, err := s.GetSavingsReport(context.Background(), "", 7, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "daily rows")
}

func TestGetSavingsReport_SuccessPathStillWorks(t *testing.T) {
	// All sub-queries return clean data → report is produced.
	db := &mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &totalRow{count: 0}
		},
		queryFn: func(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: nil}, nil
		},
	}
	s := &Store{db: db}
	rep, err := s.GetSavingsReport(context.Background(), "", 7, "")
	require.NoError(t, err)
	require.NotNil(t, rep)
	assert.Equal(t, "last_7_days", rep.Period)
	assert.Contains(t, rep.Pricing.PricingAsOf, "sha256:")
}

// --- GetCostAnalytics -------------------------------------------------------

func TestGetCostAnalytics_ByModelScanError_Propagates(t *testing.T) {
	// Total query scans (cost, counterfactual, count) → totalRow handles the
	// 3-dest scan. First Query (by-model, contains tokens_in) returns
	// erroring rows → must fail the report.
	db := &mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &totalRow{count: 0}
		},
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			if sql != "" && containsSubstr(sql, "tokens_in") {
				return &erroringRows{scanErr: errors.New("simulated by-model scan failure")}, nil
			}
			return &mockPGXRows{data: nil}, nil
		},
	}
	s := &Store{db: db}
	_, err := s.GetCostAnalytics(context.Background(), "org-1", time.Now().AddDate(0, 0, -7), time.Now(), "")
	require.Error(t, err, "by-model scan error must fail the whole cost report")
	assert.Contains(t, err.Error(), "by-model")
}

func TestGetCostAnalytics_SuccessPathStillWorks(t *testing.T) {
	db := &mockDB{
		queryRowFn: func(_ context.Context, _ string, _ ...interface{}) pgx.Row {
			return &totalRow{count: 0}
		},
		queryFn: func(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: nil}, nil
		},
	}
	s := &Store{db: db}
	rep, err := s.GetCostAnalytics(context.Background(), "org-1", time.Now().AddDate(0, 0, -7), time.Now(), "")
	require.NoError(t, err)
	require.NotNil(t, rep)
	assert.Contains(t, rep.Pricing.PricingAsOf, "sha256:")
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TypeMap satisfies the pgx.Rows interface (pgx v5.12 added the method);
// the fake synthesizes rows, so no type map is available or needed.
func (r *erroringRows) TypeMap() *pgtype.Map { return nil }
