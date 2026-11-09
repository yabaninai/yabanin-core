package consumer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRedis struct {
	XAddFn                 func(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd
	XGroupCreateMkStreamFn func(ctx context.Context, stream, group, startID string) *redis.StatusCmd
	XReadGroupFn           func(ctx context.Context, args *redis.XReadGroupArgs) *redis.XStreamSliceCmd
	XAckFn                 func(ctx context.Context, stream, group string, ids []string) *redis.IntCmd
	XPendingExtFn          func(ctx context.Context, args *redis.XPendingExtArgs) *redis.XPendingExtCmd
	XClaimFn               func(ctx context.Context, args *redis.XClaimArgs) *redis.XMessageSliceCmd
	ExpireFn               func(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	INCRFn                 func(ctx context.Context, key string) *redis.IntCmd
}

func (m *mockRedis) XAdd(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
	if m.XAddFn != nil {
		return m.XAddFn(ctx, args)
	}
	cmd := redis.NewStringCmd(ctx)
	cmd.SetVal("ok")
	return cmd
}

func (m *mockRedis) XGroupCreateMkStream(ctx context.Context, stream, group, startID string) *redis.StatusCmd {
	if m.XGroupCreateMkStreamFn != nil {
		return m.XGroupCreateMkStreamFn(ctx, stream, group, startID)
	}
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetVal("OK")
	return cmd
}

func (m *mockRedis) XReadGroup(ctx context.Context, args *redis.XReadGroupArgs) *redis.XStreamSliceCmd {
	if m.XReadGroupFn != nil {
		return m.XReadGroupFn(ctx, args)
	}
	<-ctx.Done()
	// Never return a nil cmd: consume() calls .Result() on it immediately,
	// which panics on a nil receiver when cancellation races the read.
	cmd := redis.NewXStreamSliceCmd(ctx)
	cmd.SetErr(redis.Nil)
	return cmd
}

func (m *mockRedis) XAck(ctx context.Context, stream, group string, ids []string) *redis.IntCmd {
	if m.XAckFn != nil {
		return m.XAckFn(ctx, stream, group, ids)
	}
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(1)
	return cmd
}

func (m *mockRedis) Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
	if m.ExpireFn != nil {
		return m.ExpireFn(ctx, key, expiration)
	}
	cmd := redis.NewBoolCmd(ctx)
	cmd.SetVal(true)
	return cmd
}

func (m *mockRedis) INCR(ctx context.Context, key string) *redis.IntCmd {
	if m.INCRFn != nil {
		return m.INCRFn(ctx, key)
	}
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(0)
	return cmd
}

func (m *mockRedis) XPendingExt(ctx context.Context, args *redis.XPendingExtArgs) *redis.XPendingExtCmd {
	if m.XPendingExtFn != nil {
		return m.XPendingExtFn(ctx, args)
	}
	cmd := redis.NewXPendingExtCmd(ctx)
	cmd.SetVal([]redis.XPendingExt{})
	return cmd
}

func (m *mockRedis) XClaim(ctx context.Context, args *redis.XClaimArgs) *redis.XMessageSliceCmd {
	if m.XClaimFn != nil {
		return m.XClaimFn(ctx, args)
	}
	cmd := redis.NewXMessageSliceCmd(ctx)
	cmd.SetVal([]redis.XMessage{})
	return cmd
}

func (m *mockRedis) SETNX(ctx context.Context, key string, value any, expiration time.Duration) *redis.BoolCmd {
	cmd := redis.NewBoolCmd(ctx)
	cmd.SetVal(true)
	return cmd
}

func (m *mockRedis) DEL(ctx context.Context, keys ...string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(1)
	return cmd
}

type mockDB struct {
	ExecFn     func(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	QueryRowFn func(ctx context.Context, query string, args ...any) pgx.Row

	// Transactional event_inbox model (AF-04): claims are visible inside
	// their own transaction, become globally visible on Commit and are
	// discarded on Rollback — the exactly-once contract the real unique
	// constraint provides. Like a real unique index, only one transaction
	// can hold an uncommitted claim: a concurrent second claim reads 0 rows
	// instead of blocking. Deviation from Postgres: if the holder rolled
	// back, real PG would let a blocked concurrent INSERT succeed — no test
	// overlaps that window. Guarded by mu (tests drive concurrent
	// deliveries).
	mu        sync.Mutex
	committed map[string]bool
	holders   map[string]*mockTx
}

func (m *mockDB) BeginTx(_ context.Context) (InboxTx, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.committed == nil {
		m.committed = map[string]bool{}
	}
	return &mockTx{parent: m, pending: map[string]bool{}}, nil
}

func (m *mockDB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if tag, handled, err := m.inboxExec(nil, query, args...); handled {
		return tag, err
	}
	if m.ExecFn != nil {
		return m.ExecFn(ctx, query, args...)
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (m *mockDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	if m.QueryRowFn != nil {
		return m.QueryRowFn(ctx, query, args...)
	}
	// W-LOGG DB probe ("SELECT 1") binds no arguments: answer 1 so a
	// healthy mockDB also reads as a reachable database.
	if len(args) == 0 {
		return &fakeRow{vals: []any{1}}
	}
	// Sessions registry upsert: RETURNING id — echo the inserted id ($1)
	// so assertions see the same deterministic UUID the real DB returns.
	return &fakeRow{vals: []any{args[0]}}
}

// inboxExec intercepts the durable inbox claim insert. tx is nil for
// pool-level (autocommit) Execs. Returns handled=true when the query was the
// inbox claim, mirroring INSERT ... ON CONFLICT DO NOTHING row counts.
func (m *mockDB) inboxExec(tx *mockTx, query string, args ...any) (pgconn.CommandTag, bool, error) {
	if !strings.Contains(query, "INSERT INTO event_inbox") {
		return pgconn.CommandTag{}, false, nil
	}
	key := mockDeliveryKey(args)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.committed == nil {
		m.committed = map[string]bool{}
	}
	if m.committed[key] || (tx != nil && m.holders[key] != nil && m.holders[key] != tx) {
		return pgconn.NewCommandTag("INSERT 0 0"), true, nil
	}
	if tx != nil {
		if m.holders == nil {
			m.holders = map[string]*mockTx{}
		}
		m.holders[key] = tx
		tx.pending[key] = true
	} else {
		m.committed[key] = true
	}
	return pgconn.NewCommandTag("INSERT 0 1"), true, nil
}

func mockDeliveryKey(args []any) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = fmt.Sprintf("%v", a)
	}
	return strings.Join(parts, "|")
}

// mockTx is the transactional slice of mockDB: writes route to the parent's
// stubs; the inbox claim stays provisional until Commit.
type mockTx struct {
	parent  *mockDB
	pending map[string]bool
}

func (t *mockTx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if tag, handled, err := t.parent.inboxExec(t, query, args...); handled {
		return tag, err
	}
	return t.parent.Exec(ctx, query, args...)
}

func (t *mockTx) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return t.parent.QueryRow(ctx, query, args...)
}

func (t *mockTx) Commit(_ context.Context) error {
	t.parent.mu.Lock()
	defer t.parent.mu.Unlock()
	if t.parent.committed == nil {
		t.parent.committed = map[string]bool{}
	}
	for key := range t.pending {
		t.parent.committed[key] = true
		if t.parent.holders[key] == t {
			delete(t.parent.holders, key)
		}
	}
	t.pending = map[string]bool{}
	return nil
}

func (t *mockTx) Rollback(_ context.Context) error {
	t.parent.mu.Lock()
	defer t.parent.mu.Unlock()
	for key := range t.pending {
		if t.parent.holders[key] == t {
			delete(t.parent.holders, key)
		}
	}
	t.pending = map[string]bool{}
	return nil
}

type fakeRow struct {
	vals []any
}

func (r *fakeRow) Scan(dest ...any) error {
	for i, d := range dest {
		if i < len(r.vals) {
			switch v := d.(type) {
			case *string:
				*v = r.vals[i].(string)
			case *any:
				*v = r.vals[i]
			}
		}
	}
	return nil
}

func TestConsumer_Start_UsesConfiguredStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var rdbCreated bool
	var rdbStream string
	rdb := &mockRedis{
		XGroupCreateMkStreamFn: func(ctx context.Context, stream, group, startID string) *redis.StatusCmd {
			mu.Lock()
			rdbCreated = true
			rdbStream = stream
			mu.Unlock()
			cmd := redis.NewStatusCmd(ctx)
			cmd.SetErr(errors.New("BUSYGROUP Consumer Group name already exists"))
			return cmd
		},
		XReadGroupFn: func(ctx context.Context, args *redis.XReadGroupArgs) *redis.XStreamSliceCmd {
			<-ctx.Done()
			// A nil cmd would panic in consume()'s .Result() on shutdown.
			cmd := redis.NewXStreamSliceCmd(ctx)
			cmd.SetErr(redis.Nil)
			return cmd
		},
	}

	pool := &mockDB{}
	logger := slog.Default()

	sc := New(rdb, pool, "my-custom-stream", logger)

	errChan := make(chan error, 1)
	go func() {
		errChan <- sc.Start(ctx)
	}()

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return rdbCreated
	}, 2*time.Second, 50)

	sc.Stop()

	mu.Lock()
	stream := rdbStream
	mu.Unlock()
	assert.Equal(t, "my-custom-stream", stream)
}

func TestConsumer_Start_DefaultStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var rdbCreated bool
	var rdbStream string
	rdb := &mockRedis{
		XGroupCreateMkStreamFn: func(ctx context.Context, stream, group, startID string) *redis.StatusCmd {
			mu.Lock()
			rdbCreated = true
			rdbStream = stream
			mu.Unlock()
			cmd := redis.NewStatusCmd(ctx)
			cmd.SetErr(errors.New("BUSYGROUP Consumer Group name already exists"))
			return cmd
		},
		XReadGroupFn: func(ctx context.Context, args *redis.XReadGroupArgs) *redis.XStreamSliceCmd {
			<-ctx.Done()
			// A nil cmd would panic in consume()'s .Result() on shutdown.
			cmd := redis.NewXStreamSliceCmd(ctx)
			cmd.SetErr(redis.Nil)
			return cmd
		},
	}

	pool := &mockDB{}
	logger := slog.Default()

	sc := New(rdb, pool, "", logger)

	errChan := make(chan error, 1)
	go func() {
		errChan <- sc.Start(ctx)
	}()

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return rdbCreated
	}, 2*time.Second, 50)

	sc.Stop()

	mu.Lock()
	stream := rdbStream
	mu.Unlock()
	assert.Equal(t, defaultStream, stream)
}

func TestProcessMessage_RequestCompleted(t *testing.T) {
	var query string
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			query = q
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type": "request.completed",
			"source":     "gateway",
			"session_id": "sess-123",
			"payload":    `{"event_type":"request.completed","source":"gateway","session_id":"sess-123","org_id":"org-abc","model_requested":"gpt-4","model_used":"gpt-4-turbo","upstream_url":"https://api.openai.com/v1/chat/completions","status_code":200,"duration_ms":1500,"tokens_in":100,"tokens_out":250,"method":"POST"}`,
		},
	}

	err := consumer.processMessage(context.Background(), msg)
	require.NoError(t, err)
	assert.Contains(t, query, "INSERT INTO request_logs")
	assert.Contains(t, query, "$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16")
}

func TestHandleRequestComplete_OrgIDPopulated(t *testing.T) {
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "sess-123",
			"org_id":          "org-abc",
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"upstream_url":    "https://api.openai.com/v1/chat/completions",
			"status_code":     float64(200),
			"duration_ms":     float64(1500),
			"tokens_in":       float64(100),
			"tokens_out":      float64(250),
			"method":          "POST",
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

	require.Len(t, values, 43) // +upstream_request, +upstream_response
	assert.Equal(t, "org-abc", values[1])
}

func TestHandleRequestComplete_TenantMatrixKeepsOrgIDPerEvent(t *testing.T) {
	var persistedOrgIDs []any
	pool := &mockDB{ExecFn: func(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
		if strings.Contains(query, "INSERT INTO request_logs") {
			require.Greater(t, len(args), 1)
			persistedOrgIDs = append(persistedOrgIDs, args[1])
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	consumer := New(nil, pool, "events:queue", slog.Default())

	for _, orgID := range []string{"org-tenant-a", "org-tenant-b"} {
		msg := redis.XMessage{Values: map[string]interface{}{
			"event_type": "request.completed",
			"request_id": "req-" + orgID,
			"org_id":     orgID,
		}}
		require.NoError(t, consumer.handleRequestComplete(context.Background(), msg))
	}

	require.Equal(t, []any{"org-tenant-a", "org-tenant-b"}, persistedOrgIDs,
		"one consumer handling A then B must persist each event under its own tenant")
}

func TestHandleRequestComplete_SessionIDCast(t *testing.T) {
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      12345,
			"org_id":          "org-abc",
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"upstream_url":    "https://api.openai.com/v1/chat/completions",
			"status_code":     float64(200),
			"duration_ms":     float64(1500),
			"tokens_in":       float64(100),
			"tokens_out":      float64(250),
			"method":          "POST",
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

	require.Len(t, values, 43) // +upstream_request, +upstream_response
	assert.Nil(t, values[0])
}

// LG-U1 regression: OpenCode sends its native session ids ("ses_...") in
// X-Session-Id; a verbatim insert wedged every row with SQLSTATE 22P02. The
// consumer must map any string onto a deterministic UUID instead of failing.
func TestHandleRequestComplete_NonUUIDSessionIDHashed(t *testing.T) {
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	consumer := New(nil, pool, "events:queue", slog.Default())

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "ses_f7c8cea03ffeQF8w3WLp7oRA9w",
			"org_id":          testOrgUUID,
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"upstream_url":    "https://api.openai.com/v1/chat/completions",
			"status_code":     float64(200),
			"duration_ms":     float64(1500),
			"tokens_in":       float64(100),
			"tokens_out":      float64(250),
			"method":          "POST",
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

	require.Len(t, values, 43) // +upstream_request, +upstream_response, +observability parity
	assert.Equal(t, goldenOpenCodeSession, values[0])
	// Legacy/absent observability fields must land as NULL ("unknown"),
	// not as fake zeros that would poison TTFT/retry aggregates.
	assert.Nil(t, values[30], "first_token_ms")
	assert.Nil(t, values[31], "attempt_count")
	assert.Nil(t, values[32], "retry_count")
}

// Observability parity: first_token_ms / attempt_count / retry_count from the
// gateway event must land in the trailing INSERT columns; zero first_token_ms
// (non-streaming) still reads as NULL.
func TestHandleRequestComplete_ObservabilityFieldsStored(t *testing.T) {
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	consumer := New(nil, pool, "events:queue", slog.Default())

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "ses_observability",
			"org_id":          testOrgUUID,
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"status_code":     float64(200),
			"duration_ms":     float64(1500),
			"first_token_ms":  float64(412),
			"attempt_count":   float64(2),
			"retry_count":     float64(1),
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

	require.Len(t, values, 43)
	assert.Equal(t, int64(412), values[30], "first_token_ms")
	assert.Equal(t, int64(2), values[31], "attempt_count")
	assert.Equal(t, int64(1), values[32], "retry_count")
}

func TestHandleRequestComplete_NonUUIDTeamIDHashed(t *testing.T) {
	var values []any
	var intentArgs []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			// settlement intent; only the request_logs insert pins the
			// 42-column projection here.
			if strings.Contains(q, "INSERT INTO settlement_jobs") {
				intentArgs = args
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			}
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	consumer := New(nil, pool, "events:queue", slog.Default())

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"team_id":         "team-1",
			"org_id":          "org-abc",
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"upstream_url":    "https://api.openai.com/v1/chat/completions",
			"status_code":     float64(200),
			"duration_ms":     float64(1500),
			"method":          "POST",
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

	require.Len(t, values, 43)                                          // +upstream_request, +upstream_response
	assert.Equal(t, "39a69732-8ac4-55ed-928d-98f06edba270", values[22]) // team_id
	// The team_spend intent attributes the spend to the same hashed team.
	require.Len(t, intentArgs, 6)
	assert.Equal(t, ChargeKindTeamSpend, intentArgs[2])
	assert.Contains(t, string(intentArgs[5].([]byte)), "39a69732-8ac4-55ed-928d-98f06edba270")
}

func TestHandleRequestComplete_AllFieldsForwarded(t *testing.T) {
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      testSessionUUID,
			"org_id":          testOrgUUID,
			"model_requested": "claude-3",
			"model_used":      "claude-3-opus",
			"upstream_url":    "https://api.anthropic.com/v1/messages",
			"status_code":     float64(200),
			"duration_ms":     float64(3000),
			"tokens_in":       float64(50),
			"tokens_out":      float64(100),
			"method":          "POST",
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

	require.Len(t, values, 43)                                          // +upstream_request, +upstream_response
	assert.Equal(t, testSessionUUID, values[0])                         // session_id
	assert.Equal(t, testOrgUUID, values[1])                             // org_id
	assert.Equal(t, "claude-3", values[2])                              // model_requested
	assert.Equal(t, "claude-3-opus", values[3])                         // model_used
	assert.Equal(t, "https://api.anthropic.com/v1/messages", values[4]) // upstream_url
	assert.Equal(t, "POST", values[5])                                  // method
}

func TestHandleRequestComplete_MissingSessionID(t *testing.T) {
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "",
			"org_id":          "org-ghi",
			"model_requested": "gpt-3.5",
			"model_used":      "gpt-3.5-turbo",
			"upstream_url":    "https://api.openai.com/v1/chat/completions",
			"status_code":     float64(200),
			"duration_ms":     float64(500),
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

	require.Len(t, values, 43) // +upstream_request, +upstream_response
	assert.Nil(t, values[0])   // session_id is nil
}

func TestHandleRequestComplete_ErrorField(t *testing.T) {
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "sess-789",
			"org_id":          "org-jkl",
			"model_requested": "gpt-4",
			"model_used":      "",
			"upstream_url":    "https://api.openai.com/v1/chat/completions",
			"status_code":     float64(502),
			"duration_ms":     float64(30000),
			"error":           "upstream connection timeout",
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

	require.Len(t, values, 43)                                 // +upstream_request, +upstream_response
	assert.Equal(t, "upstream connection timeout", values[10]) // error field
	assert.Equal(t, int64(502), values[6])                     // status_code
}

func TestHandleRequestComplete_DBError(t *testing.T) {
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag(""), errors.New("db connection failed")
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "sess-123",
			"org_id":          "org-abc",
			"model_requested": "gpt-4",
			"status_code":     float64(200),
			"duration_ms":     float64(500),
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insert request_log")
}

func TestProcessMessage_GenericEvent(t *testing.T) {
	pool := &mockDB{}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type": "session.created",
			"source":     "gateway",
		},
	}

	err := consumer.processMessage(context.Background(), msg)
	require.NoError(t, err)
}

func TestProcessMessage_NilPayload(t *testing.T) {
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type": "request.completed",
			"source":     "gateway",
			"session_id": "sess-123",
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

	require.Len(t, values, 43)             // +upstream_request, +upstream_response
	assert.Equal(t, "POST", values[5])     // default method
	assert.Equal(t, int64(200), values[6]) // default status code
	assert.False(t, values[21].(bool))     // evalgate_sampled defaults to false
}

func TestConsumer_Start_CreateGroupError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rdb := &mockRedis{
		XGroupCreateMkStreamFn: func(ctx context.Context, stream, group, startID string) *redis.StatusCmd {
			cmd := redis.NewStatusCmd(ctx)
			cmd.SetErr(errors.New("redis connection refused"))
			return cmd
		},
	}

	pool := &mockDB{}
	logger := slog.Default()

	consumer := New(rdb, pool, "events:queue", logger)

	errChan := make(chan error, 1)
	go func() {
		errChan <- consumer.Start(ctx)
	}()

	select {
	case err := <-errChan:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create consumer group")
	case <-ctx.Done():
		t.Fatal("Start did not return error on create failure")
	}
}

func TestConsumer_PayloadRoundTrip(t *testing.T) {
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "sess-roundtrip",
			"org_id":          "org-123",
			"model_requested": "gpt-4o",
			"model_used":      "gpt-4o-2024-05-13",
			"upstream_url":    "https://api.openai.com/v1/chat/completions",
			"status_code":     float64(200),
			"duration_ms":     float64(2500),
			"tokens_in":       float64(200),
			"tokens_out":      float64(500),
			"method":          "POST",
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

}

func TestParseFloat64_StringValues(t *testing.T) {
	// Simulate real go-redis v9 behavior: all stream fields are strings.
	fields := map[string]interface{}{
		"status_code":             "200",
		"duration_ms":             "1500",
		"tokens_in":               "100",
		"tokens_out":              "250",
		"cache_similarity":        "0.92",
		"counterfactual_cost_usd": "0.045",
		"estimated_cost_usd":      "0.012",
	}

	assert.InDelta(t, 200.0, parseFloat64(fields, "status_code"), 0.001)
	assert.InDelta(t, 1500.0, parseFloat64(fields, "duration_ms"), 0.001)
	assert.InDelta(t, 100.0, parseFloat64(fields, "tokens_in"), 0.001)
	assert.InDelta(t, 250.0, parseFloat64(fields, "tokens_out"), 0.001)
	assert.InDelta(t, 0.92, parseFloat64(fields, "cache_similarity"), 0.001)
	assert.InDelta(t, 0.045, parseFloat64(fields, "counterfactual_cost_usd"), 0.0001)
	assert.InDelta(t, 0.012, parseFloat64(fields, "estimated_cost_usd"), 0.0001)

	// Missing key returns 0
	assert.InDelta(t, float64(0), parseFloat64(fields, "nonexistent"), 0)
	// Invalid string returns 0
	fields["bad"] = "not-a-number"
	assert.InDelta(t, float64(0), parseFloat64(fields, "bad"), 0)
}

func TestParseInt64_StringValues(t *testing.T) {
	fields := map[string]interface{}{
		"status_code": "200",
		"duration_ms": "1500",
		"tokens_in":   "100",
		"tokens_out":  "250",
	}

	assert.Equal(t, int64(200), parseInt64(fields, "status_code"))
	assert.Equal(t, int64(1500), parseInt64(fields, "duration_ms"))
	assert.Equal(t, int64(100), parseInt64(fields, "tokens_in"))
	assert.Equal(t, int64(250), parseInt64(fields, "tokens_out"))

	// Missing key returns 0
	assert.Equal(t, int64(0), parseInt64(fields, "nonexistent"))
	// Invalid string returns 0
	fields["bad"] = "not-a-number"
	assert.Equal(t, int64(0), parseInt64(fields, "bad"))
}

func TestHandleRequestComplete_StringFields(t *testing.T) {
	// Simulate real go-redis v9: all values come back as strings.
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":              "request.completed",
			"source":                  "gateway",
			"session_id":              testSessionUUID,
			"org_id":                  testOrgUUID,
			"model_requested":         "gpt-4o",
			"model_used":              "gpt-4o-2024-05-13",
			"upstream_url":            "https://api.openai.com/v1/chat/completions",
			"status_code":             "200",  // string, not float64
			"duration_ms":             "2500", // string
			"tokens_in":               "200",  // string
			"tokens_out":              "500",  // string
			"method":                  "POST",
			"cache_hit_type":          "hit",
			"cache_similarity":        "0.97",  // string
			"counterfactual_cost_usd": "0.050", // string
			"estimated_cost_usd":      "0.012", // string
			// P5 classifier fields
			"tier_used":             "cheap",     // string
			"classifier_class":      "easy",      // string
			"classifier_confidence": "0.95",      // string → float64
			"classifier_source":     "rule_tier", // string
			"ab_group":              "test",      // string
			"evalgate_sampled":      "true",      // string → bool
		},
	}

	err := consumer.handleRequestComplete(context.Background(), msg)
	require.NoError(t, err)

	require.Len(t, values, 43)                  // +upstream_request, +upstream_response
	assert.Equal(t, testSessionUUID, values[0]) // session_id
	assert.Equal(t, testOrgUUID, values[1])     // org_id
	assert.Equal(t, int64(200), values[6])      // status_code from string "200"
	assert.Equal(t, int64(2500), values[7])     // duration_ms from string "2500"
	assert.Equal(t, int64(200), values[8])      // tokens_in from string "200"
	assert.Equal(t, int64(500), values[9])      // tokens_out from string "500"
	assert.Equal(t, "hit", values[12])          // cache_hit_type
	// Verify cost/similarity fields are non-zero (the bug was they were always 0)
	assert.InDelta(t, 0.97, values[13], 0.001)   // cache_similarity from string "0.97"
	assert.InDelta(t, 0.050, values[14], 0.0001) // counterfactual_cost_usd from string "0.050"
	assert.InDelta(t, 0.012, values[15], 0.0001) // cost_in_usd from string "0.012"
	// P5 classifier fields parsed from strings
	assert.Equal(t, "easy", values[16])        // classifier_class
	assert.InDelta(t, 0.95, values[17], 0.001) // classifier_confidence from string "0.95"
	assert.Equal(t, "rule_tier", values[18])   // classifier_source
	assert.Equal(t, "cheap", values[19])       // tier_used
	assert.Equal(t, "test", values[20])        // ab_group
	assert.True(t, values[21].(bool))          // evalgate_sampled from string "true"
}

func TestHandleRequestFailed_StringFields(t *testing.T) {
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		Values: map[string]interface{}{
			"event_type":         "request.failed",
			"source":             "gateway",
			"org_id":             "org-fail",
			"model_requested":    "gpt-4",
			"model_used":         "",
			"upstream_url":       "https://api.openai.com/v1/chat/completions",
			"request_id":         "req-fail-001",
			"status_code":        "503",   // string
			"duration_ms":        "30000", // string
			"tokens_in":          "50",    // string
			"tokens_out":         "0",     // string
			"method":             "POST",
			"error":              "upstream timeout",
			"estimated_cost_usd": "0.001", // string
			// P5 classifier fields
			"classifier_class": "hard",  // string
			"evalgate_sampled": "false", // string → bool
		},
	}

	err := consumer.handleRequestFailed(context.Background(), msg)
	require.NoError(t, err)

	require.Len(t, values, 43)                   // +upstream_request, +upstream_response
	assert.Equal(t, "org-fail", values[1])       // org_id
	assert.Equal(t, int64(503), values[6])       // status_code from string "503"
	assert.Equal(t, int64(30000), values[7])     // duration_ms
	assert.InDelta(t, 0.001, values[15], 0.0001) // cost_in_usd from string
	// P5 classifier fields
	assert.Equal(t, "hard", values[16]) // classifier_class
	assert.False(t, values[21].(bool))  // evalgate_sampled from string "false"
}

func TestParseFloat64_NumericTypes(t *testing.T) {
	// Also verify it handles float64/int types (for existing tests that use them).
	fields := map[string]interface{}{
		"f": float64(3.14),
		"i": int(42),
		"l": int64(99),
	}

	assert.InDelta(t, 3.14, parseFloat64(fields, "f"), 0.001)
	assert.InDelta(t, 42.0, parseFloat64(fields, "i"), 0.001)
	assert.InDelta(t, 99.0, parseFloat64(fields, "l"), 0.001)

	fields2 := map[string]interface{}{
		"i": int64(123),
	}
	assert.Equal(t, int64(123), parseInt64(fields2, "i"))

	fields3 := map[string]interface{}{
		"f": float64(99.5),
	}
	assert.Equal(t, int64(99), parseInt64(fields3, "f")) // truncated
}

// Regression: BUSYGROUP is the normal restart path (the group persists in
// Redis across loggerd restarts). It must NOT cancel the consumer group
// context — before the fix groupCancel() ran before the BUSYGROUP branch and
// the consume loop exited instantly on every restart against an existing
// stream ("stream consumer stopping, reason=context canceled" right after
// start), silently dropping all logging.
func TestConsumer_Start_BusyGroupKeepsConsumerAlive(t *testing.T) {
	var mu sync.Mutex
	var inserts int
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			mu.Lock()
			inserts++
			mu.Unlock()
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}

	served := false
	rdb := &mockRedis{
		XGroupCreateMkStreamFn: func(ctx context.Context, stream, group, startID string) *redis.StatusCmd {
			cmd := redis.NewStatusCmd(ctx)
			cmd.SetErr(errors.New("BUSYGROUP Consumer Group name already exists"))
			return cmd
		},
		XReadGroupFn: func(ctx context.Context, args *redis.XReadGroupArgs) *redis.XStreamSliceCmd {
			cmd := redis.NewXStreamSliceCmd(ctx)
			if served {
				// Nothing new: keep blocking loop busy without spinning hard.
				time.Sleep(50 * time.Millisecond)
				cmd.SetVal([]redis.XStream{})
				return cmd
			}
			served = true
			cmd.SetVal([]redis.XStream{{
				Stream: args.Streams[0],
				Messages: []redis.XMessage{{
					ID: "1-1",
					Values: map[string]interface{}{
						"event_type":      "request.completed",
						"source":          "gateway",
						"session_id":      "ses_restart_probe",
						"org_id":          "org-abc",
						"model_requested": "gpt-4",
						"model_used":      "gpt-4-turbo",
						"status_code":     float64(200),
						"duration_ms":     float64(10),
						"method":          "POST",
					},
				}},
			}})
			return cmd
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	consumer := New(rdb, pool, "events:queue", slog.Default())

	done := make(chan struct{})
	go func() {
		_ = consumer.Start(ctx)
		close(done)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := inserts
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("consumer processed nothing after BUSYGROUP start — consume loop is dead")
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
}

// QG2-D2 regression: budget-blocked requests must be persisted (status 429),
// not silently dropped at the default branch.
func TestProcessMessage_BudgetExceeded_Persisted(t *testing.T) {
	var query string
	var values []any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			query = q
			values = args
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	logger := slog.Default()
	consumer := New(nil, pool, "events:queue", logger)

	msg := redis.XMessage{
		ID: "1-1",
		Values: map[string]interface{}{
			"event_type":      "request.budget_exceeded",
			"source":          "gateway",
			"session_id":      "sess-bud-1",
			"org_id":          "org-bud",
			"team_id":         "t-1",
			"request_id":      "req-bud-1",
			"model_requested": "gpt-4",
			"payload":         `{"model":"gpt-4","messages":[]}`,
			"error":           "team budget limit reached",
		},
	}

	require.NoError(t, consumer.processMessage(context.Background(), msg))
	assert.Contains(t, query, "INSERT INTO request_logs")
	// org_id (args[1]) and request_id (args[5]) flow through; status is 429.
	assert.Equal(t, "org-bud", values[1])
	assert.Equal(t, "gpt-4", values[2])
	assert.Equal(t, 429, values[3])
	assert.Contains(t, values[4], "budget_exceeded")
	assert.Equal(t, "req-bud-1", values[5])
}
