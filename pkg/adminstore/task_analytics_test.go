package adminstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetTaskAnalytics_Success(t *testing.T) {
	db := &mockDB{
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{
				data: [][]interface{}{
					{"task-1", 10.0, 20.0, int64(5), int64(50)},
					{UntaggedBucket, 3.0, 6.0, int64(1), int64(10)},
				},
			}, nil
		},
	}
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)

	rep, err := s.GetTaskAnalytics(context.Background(), "org-1", from, to, "task", 100)
	require.NoError(t, err)
	require.NotNil(t, rep)
	assert.Equal(t, "org-1", rep.OrgID)
	assert.Equal(t, "task", rep.GroupBy)
	require.Len(t, rep.Groups, 2)
	assert.Equal(t, "task-1", rep.Groups[0].Group)
	assert.InDelta(t, 10.0, rep.Groups[0].CostUSD, 1e-9)
	assert.InDelta(t, 20.0, rep.Groups[0].CounterfactualUSD, 1e-9)
	assert.InDelta(t, 10.0, rep.Groups[0].SavingsUSD, 1e-9) // 20-10
	assert.Equal(t, int64(5), rep.Groups[0].CacheHits)
	assert.Equal(t, int64(50), rep.Groups[0].RequestCount)
	assert.Equal(t, UntaggedBucket, rep.Groups[1].Group)
	assert.InDelta(t, 13.0, rep.TotalCostUSD, 1e-9)
}

func TestGetTaskAnalytics_Empty(t *testing.T) {
	db := &mockDB{
		queryFn: func(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: nil}, nil
		},
	}
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	rep, err := s.GetTaskAnalytics(context.Background(), "org-1", from, from.Add(time.Hour), "session", 10)
	require.NoError(t, err)
	require.NotNil(t, rep)
	assert.Empty(t, rep.Groups)
}

func TestGetTaskAnalytics_InvalidGroupBy(t *testing.T) {
	s := &Store{db: &mockDB{}}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	_, err := s.GetTaskAnalytics(context.Background(), "org-1", from, from.Add(time.Hour), "bogus", 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group_by must be one of")
}

func TestGetTaskAnalytics_LimitCapped(t *testing.T) {
	var gotLimit interface{}
	db := &mockDB{
		queryFn: func(_ context.Context, _ string, args ...interface{}) (pgx.Rows, error) {
			gotLimit = args[len(args)-1] // $4 is the limit
			return &mockPGXRows{data: nil}, nil
		},
	}
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	_, err := s.GetTaskAnalytics(context.Background(), "org-1", from, from.Add(time.Hour), "agent", 10000)
	require.NoError(t, err)
	assert.Equal(t, 500, gotLimit)
}

func TestGetTaskAnalytics_GroupByColumnMapping(t *testing.T) {
	var sawColumn string
	db := &mockDB{
		queryFn: func(_ context.Context, sql string, _ ...interface{}) (pgx.Rows, error) {
			sawColumn = sql
			return &mockPGXRows{data: nil}, nil
		},
	}
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	_, err := s.GetTaskAnalytics(context.Background(), "org-1", from, from.Add(time.Hour), "agent", 10)
	require.NoError(t, err)
	assert.Contains(t, sawColumn, "agent_id")

	_, err = s.GetTaskAnalytics(context.Background(), "org-1", from, from.Add(time.Hour), "user", 10)
	require.NoError(t, err)
	assert.Contains(t, sawColumn, "user_id")
}

func TestGetTaskAnalytics_QueryError(t *testing.T) {
	db := &mockDB{
		queryFn: func(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	s := &Store{db: db}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	_, err := s.GetTaskAnalytics(context.Background(), "org-1", from, from.Add(time.Hour), "task", 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "task analytics query")
}
