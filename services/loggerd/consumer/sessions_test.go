package consumer

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveSessionID_EmptyInputsAreNil(t *testing.T) {
	consumer := New(nil, &mockDB{}, "events:queue", slog.Default())
	tx, err := consumer.dbPool.BeginTx(context.Background())
	require.NoError(t, err)
	assert.Nil(t, consumer.resolveSessionID(context.Background(), tx, testOrgUUID, ""))
	assert.Nil(t, consumer.resolveSessionID(context.Background(), tx, "", "ses_x"))
}

func TestResolveSessionID_InvalidOrgFailsOpenToNil(t *testing.T) {
	queried := false
	db := &mockDB{
		QueryRowFn: func(ctx context.Context, query string, args ...any) pgx.Row {
			queried = true
			return &fakeRow{vals: []any{"x"}}
		},
	}
	consumer := New(nil, db, "events:queue", slog.Default())
	tx, err := db.BeginTx(context.Background())
	require.NoError(t, err)

	out := consumer.resolveSessionID(context.Background(), tx, "org-abc", "ses_x")
	assert.Nil(t, out, "org without a valid uuid can never satisfy sessions_org_id_fkey")
	assert.False(t, queried, "registry must not be consulted for an invalid org")
}

func TestResolveSessionID_UpsertArgsAndFailureFailsOpen(t *testing.T) {
	var mu sync.Mutex
	var sql string
	var qargs []any
	db := &mockDB{
		QueryRowFn: func(ctx context.Context, query string, args ...any) pgx.Row {
			mu.Lock()
			sql = query
			qargs = args
			mu.Unlock()
			return &errorRow{}
		},
	}
	consumer := New(nil, db, "events:queue", slog.Default())
	tx, err := db.BeginTx(context.Background())
	require.NoError(t, err)

	out := consumer.resolveSessionID(context.Background(), tx, testOrgUUID, "ses_f7c8cea03ffeQF8w3WLp7oRA9w")
	assert.Nil(t, out, "upsert failure must not fail the log write")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, qargs, 3)
	assert.Equal(t, goldenOpenCodeSession, qargs[0], "registry id is the deterministic v5 mapping")
	assert.Equal(t, testOrgUUID, qargs[1])
	assert.Equal(t, "ses_f7c8cea03ffeQF8w3WLp7oRA9w", qargs[2], "client_session keeps the raw id")
	assert.Contains(t, sql, "ON CONFLICT (client_session)")
}

func TestResolveSessionID_ValidClientUUIDKeepsValue(t *testing.T) {
	db := &mockDB{}
	consumer := New(nil, db, "events:queue", slog.Default())
	tx, err := db.BeginTx(context.Background())
	require.NoError(t, err)
	out := consumer.resolveSessionID(context.Background(), tx, testOrgUUID, testSessionUUID)
	require.IsType(t, "", out)
	assert.Equal(t, testSessionUUID, out.(string))
}

// TestConsumer_FKViolationMessageStillLogged pins the end-to-end invariant:
// even when the session registry insert fails, the request_logs row is
// written (with a NULL session) instead of the event being dropped to DLQ.
func TestConsumer_FKViolationMessageStillLogged(t *testing.T) {
	var inserted bool
	db := &mockDB{
		QueryRowFn: func(ctx context.Context, query string, args ...any) pgx.Row {
			return &errorRow{}
		},
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			if strings.Contains(q, "INSERT INTO request_logs") {
				inserted = true
				assert.Nil(t, args[0], "unresolvable session falls back to NULL")
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	consumer := New(nil, db, "events:queue", slog.Default())

	msg := redis.XMessage{
		ID: "1-1",
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "ses_orphan",
			"org_id":          testOrgUUID,
			"model_requested": "gpt-4",
			"model_used":      "gpt-4",
			"status_code":     float64(200),
			"duration_ms":     float64(10),
			"method":          "POST",
		},
	}
	require.NoError(t, consumer.handleRequestComplete(context.Background(), msg))
	assert.True(t, inserted, "the request_logs row must be persisted")
}

type errorRow struct{}

func (r *errorRow) Scan(dest ...any) error { return errors.New("sqlstate 23503") }
