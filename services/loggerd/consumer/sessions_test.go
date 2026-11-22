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
	out, err := consumer.resolveSessionID(context.Background(), tx, testOrgUUID, "")
	require.NoError(t, err, "statement-free guards must not fail the delivery")
	assert.Nil(t, out)
	out, err = consumer.resolveSessionID(context.Background(), tx, "", "ses_x")
	require.NoError(t, err)
	assert.Nil(t, out)
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

	out, err := consumer.resolveSessionID(context.Background(), tx, "org-abc", "ses_x")
	require.NoError(t, err, "statement-free guards must not fail the delivery")
	assert.Nil(t, out, "org without a valid uuid can never satisfy sessions_org_id_fkey")
	assert.False(t, queried, "registry must not be consulted for an invalid org")
}

func TestResolveSessionID_UpsertArgsAndFailureFailsDelivery(t *testing.T) {
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

	out, err := consumer.resolveSessionID(context.Background(), tx, testOrgUUID, "ses_f7c8cea03ffeQF8w3WLp7oRA9w")
	assert.Nil(t, out)
	require.Error(t, err, "a failed upsert statement aborts the delivery transaction (PostgreSQL 25P02 on the next statement), so swallowing the error would fake a success the commit cannot deliver")
	assert.ErrorContains(t, err, "session registry upsert")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, qargs, 3)
	wantID := uuid.NewSHA1(nsRequestLogsUUID, []byte(testOrgUUID+"\x00"+"ses_f7c8cea03ffeQF8w3WLp7oRA9w")).String()
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

	// A client-supplied valid UUID is org-scoped like any other shape: a
	// verbatim shared id would collide across orgs on the sessions primary
	// key, and that statement error aborts the whole delivery transaction
	// instead of staying contained to one registry row. Same-tenant
	// preexisting rows keep their original ids through the arbiter.
	clientUUID := "3f2b8a4c-9d1e-4f5a-8b7c-6e5d4c3b2a10"
	idAUUID := sessionRegistryUUID(orgA, clientUUID)
	idBUUID := sessionRegistryUUID(orgB, clientUUID)
	assert.Equal(t, uuid.NewSHA1(nsRequestLogsUUID, []byte(orgA+"\x00"+clientUUID)).String(), idAUUID)
	assert.Equal(t, uuid.NewSHA1(nsRequestLogsUUID, []byte(orgB+"\x00"+clientUUID)).String(), idBUUID)
	assert.NotEqual(t, idAUUID, idBUUID, "two orgs sharing one UUID get distinct registry rows")
	assert.NotEqual(t, clientUUID, idAUUID, "the verbatim-value branch is gone")
}

// A valid client UUID offered by a NEW (org, raw) pair maps to the org-
// scoped registry id, not the verbatim value — the verbatim branch is what
// made two orgs sharing one UUID collide on the sessions primary key.
func TestResolveSessionID_ValidClientUUIDIsOrgScoped(t *testing.T) {
	var qargs []any
	db := &mockDB{
		QueryRowFn: func(ctx context.Context, query string, args ...any) pgx.Row {
			qargs = args
			return &fakeRow{vals: []any{args[0]}}
		},
	}
	consumer := New(nil, db, "events:queue", slog.Default())
	tx, err := db.BeginTx(context.Background())
	require.NoError(t, err)

	out, err := consumer.resolveSessionID(context.Background(), tx, testOrgUUID, testSessionUUID)
	require.NoError(t, err)
	require.IsType(t, "", out)
	assert.Equal(t, sessionRegistryUUID(testOrgUUID, testSessionUUID), out.(string))
	require.Len(t, qargs, 3)
	assert.Equal(t, testSessionUUID, qargs[2], "client_session still carries the raw UUID")
}

// TestConsumer_SessionRegistryFailureFailsDelivery pins the fail-closed
// contract: a failed registry upsert statement aborts the delivery
// transaction (PostgreSQL rejects every later statement with 25P02), so the
// delivery must return the error for redelivery instead of pretending the
// request_logs row was written. Guard-path nils (absent session/org) are
// statement-free and still log with a NULL session.
func TestConsumer_SessionRegistryFailureFailsDelivery(t *testing.T) {
	var requestLogInserts int
	db := &mockDB{
		QueryRowFn: func(ctx context.Context, query string, args ...any) pgx.Row {
			return &errorRow{}
		},
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			if strings.Contains(q, "INSERT INTO request_logs") {
				requestLogInserts++
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
	err := consumer.handleRequestComplete(context.Background(), msg)
	require.Error(t, err, "the aborted transaction cannot commit; the delivery must report failure for redelivery")
	assert.ErrorContains(t, err, "session registry upsert")
	assert.Zero(t, requestLogInserts, "no request_logs write follows a poisoned transaction")
}

type errorRow struct{}

func (r *errorRow) Scan(dest ...any) error { return errors.New("sqlstate 23503") }
