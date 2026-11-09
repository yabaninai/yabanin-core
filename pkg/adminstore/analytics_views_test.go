package adminstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestNormalizeAnalyticsViewQuery(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	got, err := NormalizeAnalyticsViewQuery(map[string]string{
		"org_id":      "org-1",
		"from":        "2026-09-01T00:00:00Z",
		"to":          "2026-09-02T00:00:00Z",
		"group_by":    "label:Issue",
		"compare":     "previous",
		"format":      "csv",
		"granularity": "day",
		"top":         "10",
	}, now)
	require.NoError(t, err)
	require.Equal(t, "requests", got["metrics"])
	require.Equal(t, "label:issue", got["group_by"])
	require.Equal(t, "previous", got["compare"])
	require.Equal(t, "csv", got["format"])

	_, err = NormalizeAnalyticsViewQuery(map[string]string{
		"org_id": "org-1", "from": "2026-09-01T00:00:00Z", "to": "2026-09-02T00:00:00Z", "metrics": "nope",
	}, now)
	require.Error(t, err)
}

func viewScanRow() []any {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return []any{"view-1", "org-1", "admin-1", "cost", []byte(`{"org_id":"org-1","metrics":"requests"}`), true, now, now}
}

func TestAnalyticsViewStore(t *testing.T) {
	ctx := t.Context()
	nilStore := newForTest(nil, newTestLogger(), nil)
	_, err := nilStore.ListAnalyticsViews(ctx, "org-1", "admin-1")
	require.Error(t, err)
	_, err = nilStore.CountAnalyticsViews(ctx, "org-1", "admin-1")
	require.Error(t, err)
	_, err = nilStore.CreateAnalyticsView(ctx, AnalyticsView{})
	require.Error(t, err)
	_, err = nilStore.GetAnalyticsView(ctx, "view-1")
	require.Error(t, err)
	require.Error(t, nilStore.UpdateAnalyticsView(ctx, AnalyticsView{}))
	require.Error(t, nilStore.DeleteAnalyticsView(ctx, "view-1"))

	store := newForTest(&mockDB{
		queryFn: func(context.Context, string, ...any) (pgx.Rows, error) {
			return &mockPGXRows{data: [][]any{viewScanRow()}}, nil
		},
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if containsCount(sql) {
				return &mockPGXRow{data: [][]any{{7}}}
			}
			return &mockPGXRow{data: [][]any{viewScanRow()}}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}, newTestLogger(), nil)

	listed, err := store.ListAnalyticsViews(ctx, "org-1", "admin-1")
	require.NoError(t, err)
	require.Equal(t, "cost", listed[0].Name)
	require.Equal(t, "requests", listed[0].Query["metrics"])

	n, err := store.CountAnalyticsViews(ctx, "org-1", "admin-1")
	require.NoError(t, err)
	require.Equal(t, 7, n)

	created, err := store.CreateAnalyticsView(ctx, AnalyticsView{
		OrgID: "org-1", OwnerID: "admin-1", Name: "cost", Query: map[string]string{"metrics": "requests"}, Shared: true,
	})
	require.NoError(t, err)
	require.Equal(t, "view-1", created.ID)

	got, err := store.GetAnalyticsView(ctx, "view-1")
	require.NoError(t, err)
	require.True(t, got.Shared)
	require.NoError(t, store.UpdateAnalyticsView(ctx, created))
	require.NoError(t, store.DeleteAnalyticsView(ctx, "view-1"))

	empty := newForTest(&mockDB{
		queryFn: func(context.Context, string, ...any) (pgx.Rows, error) {
			return &mockPGXRows{}, nil
		},
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			return &mockPGXRow{err: pgx.ErrNoRows}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		},
	}, newTestLogger(), nil)
	listed, err = empty.ListAnalyticsViews(ctx, "org-1", "admin-1")
	require.NoError(t, err)
	require.Empty(t, listed)
	_, err = empty.GetAnalyticsView(ctx, "missing")
	require.ErrorIs(t, err, ErrNotFound)
	require.ErrorIs(t, empty.UpdateAnalyticsView(ctx, AnalyticsView{ID: "missing"}), ErrNotFound)
	require.ErrorIs(t, empty.DeleteAnalyticsView(ctx, "missing"), ErrNotFound)

	broken := newForTest(&mockDB{
		queryFn: func(context.Context, string, ...any) (pgx.Rows, error) {
			return nil, errors.New("db down")
		},
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "count(*)") {
				return &mockPGXRow{err: errors.New("count failed")}
			}
			row := viewScanRow()
			row[4] = []byte(`{`)
			return &mockPGXRow{data: [][]any{row}}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("db down")
		},
	}, newTestLogger(), nil)
	_, err = broken.ListAnalyticsViews(ctx, "org-1", "admin-1")
	require.Error(t, err)
	_, err = broken.CountAnalyticsViews(ctx, "org-1", "admin-1")
	require.Error(t, err)
	_, err = broken.CreateAnalyticsView(ctx, AnalyticsView{Query: map[string]string{"metrics": "requests"}})
	require.Error(t, err)
	_, err = broken.GetAnalyticsView(ctx, "view-1")
	require.Error(t, err)
	require.Error(t, broken.UpdateAnalyticsView(ctx, AnalyticsView{ID: "view-1", Query: map[string]string{"a": "b"}}))
	require.Error(t, broken.DeleteAnalyticsView(ctx, "view-1"))
}

func containsCount(sql string) bool {
	return strings.Contains(sql, "count(*)")
}
