package consumer

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
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
	wantID := uuid.NewSHA1(nsRequestLogsUUID, []byte(testOrgUUID + "\x00" + "ses_f7c8cea03ffeQF8w3WLp7oRA9w")).String()
	assert.Equal(t, wantID, qargs[0], "registry id is the org-scoped deterministic v5 mapping")
	assert.Equal(t, testOrgUUID, qargs[1])
	assert.Equal(t, "ses_f7c8cea03ffeQF8w3WLp7oRA9w", qargs[2], "client_session keeps the raw id")
	assert.Contains(t, sql, "ON CONFLICT (org_id, client_session)",
		"the conflict target is org-scoped: sessions RLS is region isolation only, so the query itself must never touch a foreign org's row")
}

// Two orgs delivering the same raw client session must offer distinct
// registry ids (the org-scoped v5 mapping), so the second org's row mints
// under the (org_id, client_session) arbiter instead of colliding on the
// sessions primary key — and the same org always maps deterministically.
func TestSessionRegistryUUIDIsOrgScoped(t *testing.T) {
	orgA := "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
	orgB := "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"
	raw := "ses_f7c8cea03ffeQF8w3WLp7oRA9w"

	idA := sessionRegistryUUID(orgA, raw)
	idB := sessionRegistryUUID(orgB, raw)
	assert.NotEqual(t, idA, idB, "the same raw id maps to distinct registry rows per org")
	assert.Equal(t, idA, sessionRegistryUUID(orgA, raw), "the mapping is deterministic for the same org")

	// A client-supplied valid UUID keeps its exact value (the pre-0032
	// contract); the one cross-org collision on the primary key fails the
	// upsert and resolves to the documented fail-open.
	clientUUID := "3f2b8a4c-9d1e-4f5a-8b7c-6e5d4c3b2a10"
	assert.Equal(t, clientUUID, sessionRegistryUUID(orgA, clientUUID))
	assert.Equal(t, clientUUID, sessionRegistryUUID(orgB, clientUUID))
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
