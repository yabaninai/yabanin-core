package consumer

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestHandleRequestComplete_AccountingDefaults(t *testing.T) {
	var args []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, a ...any) (pgconn.CommandTag, error) {
			args = a
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	consumer := New(nil, pool, "events:queue", slog.Default())
	msg := redis.XMessage{Values: map[string]interface{}{
		"model_requested": "m",
		"model_used":      "m",
		"status_code":     "200",
	}}
	require.NoError(t, consumer.handleRequestComplete(context.Background(), msg))
	require.GreaterOrEqual(t, len(args), 5)
	assert.Equal(t, "chat.completions", args[len(args)-10])
	assert.Equal(t, "provider", args[len(args)-9])
	assert.Equal(t, "legacy", args[len(args)-8])
	assert.Nil(t, args[len(args)-7])
	assert.Nil(t, args[len(args)-6])
	assert.Equal(t, []byte("{}"), args[len(args)-5])
	assert.Nil(t, args[len(args)-4])
	// W-LOGG: created_at sits between the builder columns and the
	// attribution columns (event business time).
	assert.IsType(t, time.Time{}, args[len(args)-3])
	assert.Nil(t, args[len(args)-2])
	assert.Nil(t, args[len(args)-1])
}

func TestHandleRequestComplete_AccountingFields(t *testing.T) {
	var args []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, a ...any) (pgconn.CommandTag, error) {
			args = a
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	consumer := New(nil, pool, "events:queue", slog.Default())
	msg := redis.XMessage{Values: map[string]interface{}{
		"model_requested":       "m",
		"model_used":            "m",
		"status_code":           "200",
		"endpoint":              "chat.completions",
		"usage_source":          "estimated",
		"cost_status":           "priced",
		"cache_read_tokens":     "12",
		"cache_creation_tokens": "3",
	}}
	require.NoError(t, consumer.handleRequestComplete(context.Background(), msg))
	require.GreaterOrEqual(t, len(args), 5)
	assert.Equal(t, "chat.completions", args[len(args)-10])
	assert.Equal(t, "estimated", args[len(args)-9])
	assert.Equal(t, "priced", args[len(args)-8])
	assert.Equal(t, int64(12), args[len(args)-7])
	assert.Equal(t, int64(3), args[len(args)-6])
	assert.Equal(t, []byte("{}"), args[len(args)-5])
	assert.Nil(t, args[len(args)-4])
	assert.IsType(t, time.Time{}, args[len(args)-3]) // W-LOGG created_at
	assert.Nil(t, args[len(args)-2])
	assert.Nil(t, args[len(args)-1])
}

func TestHandleRequestComplete_AccountingColumnsRoundTrip(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `ALTER TABLE request_logs ALTER COLUMN home_region SET DEFAULT 'global'`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE request_logs ALTER COLUMN home_region SET DEFAULT current_setting('app.region', true)`)
	})
	consumer := New(nil, NewDBOps(pool), "events:queue", slog.Default())
	old := redis.XMessage{ID: "1-0", Values: map[string]interface{}{
		"model_requested": "legacy-model",
		"model_used":      "legacy-model",
		"status_code":     "200",
		"request_id":      "rm10-old",
	}}
	require.NoError(t, consumer.handleRequestComplete(ctx, old))
	var endpoint, source, status string
	var cacheRead, cacheCreate *int
	err = pool.QueryRow(ctx, `SELECT endpoint, usage_source, cost_status, cache_read_tokens, cache_creation_tokens FROM request_logs WHERE request_id = $1`, "rm10-old").
		Scan(&endpoint, &source, &status, &cacheRead, &cacheCreate)
	require.NoError(t, err)
	assert.Equal(t, "chat.completions", endpoint)
	assert.Equal(t, "provider", source)
	assert.Equal(t, "legacy", status)
	assert.Nil(t, cacheRead)
	assert.Nil(t, cacheCreate)

	fresh := redis.XMessage{ID: "1-1", Values: map[string]interface{}{
		"model_requested":       "new-model",
		"model_used":            "new-model",
		"status_code":           "200",
		"request_id":            "rm10-new",
		"endpoint":              "chat.completions",
		"usage_source":          "estimated",
		"cost_status":           "unknown_price",
		"cache_read_tokens":     "9",
		"cache_creation_tokens": "4",
	}}
	require.NoError(t, consumer.handleRequestComplete(ctx, fresh))
	err = pool.QueryRow(ctx, `SELECT endpoint, usage_source, cost_status, cache_read_tokens, cache_creation_tokens FROM request_logs WHERE request_id = $1`, "rm10-new").
		Scan(&endpoint, &source, &status, &cacheRead, &cacheCreate)
	require.NoError(t, err)
	assert.Equal(t, "estimated", source)
	assert.Equal(t, "unknown_price", status)
	require.NotNil(t, cacheRead)
	require.NotNil(t, cacheCreate)
	assert.Equal(t, 9, *cacheRead)
	assert.Equal(t, 4, *cacheCreate)
}
