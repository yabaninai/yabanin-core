package consumer

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AF-04 acceptance: crash/restart scenarios against disposable PG+Redis
// (testcontainers, same stand contract as credits_int_test.go). The failing
// windows are modelled deterministically at the exact boundary (request_logs
// insert, transaction commit, Redis SETNX outage) — from the database's
// point of view a killed process is an uncommitted transaction, and every
// replay here runs through a FRESH consumer instance (a restart).
//
// The tests share the binary-wide disposable stand with the credits live
// tests, so they serialize on the same mutex before truncating tables.

const inboxLiveOrgID = "e1a2b3c4-d5f6-7a8b-9c0d-1e2f3a4b5c6d"

func newInboxLiveEnv(t *testing.T) (context.Context, *pgxpool.Pool, *redis.Client) {
	t.Helper()
	pool := testdb.PostgresRegion(t, "e2e")
	redisClient := testdb.Redis(t)
	creditsIntegrationMu.Lock()
	t.Cleanup(creditsIntegrationMu.Unlock)

	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1, 'inbox-live-org', 'inbox-live')
		ON CONFLICT (id) DO NOTHING`, inboxLiveOrgID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `TRUNCATE request_logs, sessions, messages, tool_calls, tool_call_invocations, event_inbox, settlement_jobs CASCADE`)
	require.NoError(t, err)
	require.NoError(t, redisClient.FlushDB(ctx).Err())
	return ctx, pool, redisClient
}

func requireRowCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, want int64, label string) {
	t.Helper()
	var got int64
	err := pool.QueryRow(ctx, query).Scan(&got)
	require.NoError(t, err, label)
	assert.Equal(t, want, got, label)
}

func inboxLiveMsg(id string) redis.XMessage {
	return redis.XMessage{ID: id, Values: map[string]interface{}{
		"event_type":      "request.completed",
		"source":          "gateway-live",
		"request_id":      "req-live-" + id,
		"org_id":          inboxLiveOrgID,
		"session_id":      "ses_live_af04",
		"model_requested": "gpt-4",
		"model_used":      "gpt-4-turbo",
		"status_code":     "200",
		"duration_ms":     "42",
		"tokens_in":       "10",
		"tokens_out":      "20",
		"method":          "POST",
	}}
}

// execFailingDB fails the first N request_logs inserts (a transient DB
// outage), then passes everything through to the real pool.
type execFailingDB struct {
	inner                 DBOps
	failRequestLogInserts atomic.Int32
}

func (w *execFailingDB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return w.inner.Exec(ctx, query, args...)
}

func (w *execFailingDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return w.inner.QueryRow(ctx, query, args...)
}

func (w *execFailingDB) BeginTx(ctx context.Context) (InboxTx, error) {
	tx, err := w.inner.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return &execFailingTx{InboxTx: tx, w: w}, nil
}

type execFailingTx struct {
	InboxTx
	w *execFailingDB
}

func (t *execFailingTx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(query, "INSERT INTO request_logs") && t.w.failRequestLogInserts.Add(-1) >= 0 {
		return pgconn.CommandTag{}, errors.New("transient database outage")
	}
	return t.InboxTx.Exec(ctx, query, args...)
}

// commitFailingDB fails the first Commit: every statement ran inside the
// transaction, but nothing survives — the exact database-observable state of
// a process killed before commit.
type commitFailingDB struct {
	inner     DBOps
	failStart atomic.Bool
}

func (w *commitFailingDB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return w.inner.Exec(ctx, query, args...)
}

func (w *commitFailingDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return w.inner.QueryRow(ctx, query, args...)
}

func (w *commitFailingDB) BeginTx(ctx context.Context) (InboxTx, error) {
	tx, err := w.inner.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return &commitFailingTx{InboxTx: tx, w: w}, nil
}

type commitFailingTx struct {
	InboxTx
	w *commitFailingDB
}

func (t *commitFailingTx) Commit(ctx context.Context) error {
	if t.w.failStart.CompareAndSwap(true, false) {
		return errors.New("process killed before commit")
	}
	return t.InboxTx.Commit(ctx)
}

// redisOutageDB models a Redis outage: every dedup SETNX errors, so the
// consumer must fall back to the durable inbox for both dedup directions —
// never marking unprocessed events processed and never duplicating.
type redisOutage struct {
	*mockRedis
}

func (redisOutage) SETNX(ctx context.Context, _ string, _ any, _ time.Duration) *redis.BoolCmd {
	cmd := redis.NewBoolCmd(ctx)
	cmd.SetErr(errors.New("redis connection refused"))
	return cmd
}

// INSERT error -> replay through a fresh (restarted) consumer -> exactly one
// persisted row and one committed inbox claim.
func TestInboxLive_InsertErrorThenReplayPersistsExactlyOnce(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)

	flaky := &execFailingDB{inner: NewDBOps(pool)}
	flaky.failRequestLogInserts.Store(1)
	crashed := New(NewRedisOps(rdb), flaky, "events:inbox-live", silentLogger())
	msg := inboxLiveMsg("100-0")

	require.Error(t, crashed.processMessage(ctx, msg), "transient outage must fail the delivery")

	// Restart: a fresh consumer over the healthy pool replays the same
	// Redis message (it was never ACKed).
	restarted := New(NewRedisOps(rdb), NewDBOps(pool), "events:inbox-live", silentLogger())
	require.NoError(t, restarted.processMessage(ctx, msg))

	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs`, 1, "request_logs rows after insert-error replay")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM event_inbox`, 1, "event_inbox rows after insert-error replay")
	requireRowCount(t, ctx, pool,
		`SELECT count(*) FROM event_inbox WHERE source='events:inbox-live' AND consumer='loggerd-workers' AND event_id='100-0'`,
		1, "delivery identity row")
}

// kill before commit -> replay: the transaction (inbox claim + log) is lost
// atomically; the replay persists exactly once.
func TestInboxLive_KillBeforeCommitThenReplayPersistsExactlyOnce(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)

	flaky := &commitFailingDB{inner: NewDBOps(pool), failStart: atomic.Bool{}}
	flaky.failStart.Store(true)
	crashed := New(NewRedisOps(rdb), flaky, "events:inbox-live", silentLogger())
	msg := inboxLiveMsg("101-0")

	require.Error(t, crashed.processMessage(ctx, msg), "kill-before-commit must fail the delivery")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM event_inbox`, 0, "aborted claim must not survive")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs`, 0, "aborted log must not survive")

	restarted := New(NewRedisOps(rdb), NewDBOps(pool), "events:inbox-live", silentLogger())
	require.NoError(t, restarted.processMessage(ctx, msg))
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs`, 1, "exactly one row after replay")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM event_inbox`, 1, "exactly one claim after replay")
}

// commit before ACK -> the message is redelivered (even with every Redis
// marker gone) -> replay must not duplicate.
func TestInboxLive_CommitBeforeAckReplayNoDuplicate(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)

	first := New(NewRedisOps(rdb), NewDBOps(pool), "events:inbox-live", silentLogger())
	msg := inboxLiveMsg("102-0")
	require.NoError(t, first.processMessage(ctx, msg))

	// Simulate a fully lost Redis state: the ACK and the seen marker are
	// gone, only the committed inbox row remains.
	require.NoError(t, rdb.FlushDB(ctx).Err())

	restarted := New(NewRedisOps(rdb), NewDBOps(pool), "events:inbox-live", silentLogger())
	require.NoError(t, restarted.processMessage(ctx, msg), "replay after lost ACK must succeed")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs`, 1, "replay without duplicate")
}

// Two simultaneous deliveries of the same message: exactly one row.
func TestInboxLive_ConcurrentDeliveriesPersistExactlyOnce(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:inbox-live", silentLogger())
	msg := inboxLiveMsg("103-0")

	const replicas = 2
	errs := make(chan error, replicas)
	for i := 0; i < replicas; i++ {
		go func() { errs <- c.processMessage(ctx, msg) }()
	}
	for i := 0; i < replicas; i++ {
		require.NoError(t, <-errs)
	}
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs`, 1, "concurrent duplicates collapse to one row")
}

// The same entry id in two different streams: both deliveries persist.
func TestInboxLive_SameEventIDDifferentStreams(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)

	msg := inboxLiveMsg("104-0")
	require.NoError(t, New(NewRedisOps(rdb), NewDBOps(pool), "events:stream-a", silentLogger()).processMessage(ctx, msg))
	require.NoError(t, New(NewRedisOps(rdb), NewDBOps(pool), "events:stream-b", silentLogger()).processMessage(ctx, msg))

	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs`, 2, "both streams persist")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM event_inbox`, 2, "identity is per (source, consumer, event_id)")
}

// Redis outage: the durable inbox is the only authority — a processed event
// stays deduped and nothing unprocessed is ever considered done.
func TestInboxLive_RedisOutageIsNotAuthority(t *testing.T) {
	ctx, pool, _ := newInboxLiveEnv(t)

	c := New(redisOutage{}, NewDBOps(pool), "events:inbox-live", silentLogger())
	msg := inboxLiveMsg("105-0")

	require.NoError(t, c.processMessage(ctx, msg), "outage must not block the write")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs`, 1, "event persisted despite Redis outage")

	require.NoError(t, c.processMessage(ctx, msg), "replay during outage is still deduped by the inbox")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs`, 1, "no duplicate during outage")
}

// The durable settlement intent commits atomically with the request log: a
// committed log always has its pending charge job; a failed log has neither.
func TestInboxLive_SettlementIntentAtomicWithLog(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)

	msg := inboxLiveMsg("106-0")
	msg.Values["estimated_cost_usd"] = "0.05"
	msg.Values["resale_cost_usd"] = "0.07"

	c := NewWithCreditStore(NewRedisOps(rdb), NewDBOps(pool), "events:inbox-live", silentLogger(), credits.NewStore(pool, silentLogger()))
	require.NoError(t, c.processMessage(ctx, msg))

	var status string
	var amount int64
	err := pool.QueryRow(ctx,
		`SELECT status, amount_cents FROM settlement_jobs WHERE org_id=$1 AND request_id=$2 AND charge_kind=$3`,
		inboxLiveOrgID, "req-live-106-0", ChargeKindResaleDeduction).Scan(&status, &amount)
	require.NoError(t, err, "the durable charge intent must exist after commit")
	assert.Equal(t, "pending", status)
	assert.Equal(t, int64(7), amount)

	// A delivery whose insert fails leaves NO partial state behind.
	flaky := &execFailingDB{inner: NewDBOps(pool)}
	flaky.failRequestLogInserts.Store(1)
	failed := NewWithCreditStore(NewRedisOps(rdb), flaky, "events:inbox-live", silentLogger(), credits.NewStore(pool, silentLogger()))
	msg2 := inboxLiveMsg("106-1")
	msg2.Values["resale_cost_usd"] = "0.07"
	require.Error(t, failed.processMessage(ctx, msg2))
	requireRowCount(t, ctx, pool,
		`SELECT count(*) FROM settlement_jobs WHERE request_id='req-live-106-1'`, 0, "no orphan intent after failed delivery")
	requireRowCount(t, ctx, pool,
		`SELECT count(*) FROM event_inbox WHERE event_id='106-1'`, 0, "no orphan claim after failed delivery")
}

// Non-completed semantics survive the inbox rework: failed rows persist,
// shadow rows keep ab_group='shadow' and never create charge intents,
// budget-exceeded rows keep status 429, and duplicates collapse.
func TestInboxLive_SemanticsPreserved(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)

	c := NewWithCreditStore(NewRedisOps(rdb), NewDBOps(pool), "events:inbox-live", silentLogger(), credits.NewStore(pool, silentLogger()))

	failed := redis.XMessage{ID: "107-0", Values: map[string]interface{}{
		"event_type": "request.failed", "request_id": "req-live-107-0",
		"org_id": inboxLiveOrgID, "status_code": "503", "error": "upstream down",
	}}
	require.NoError(t, c.processMessage(ctx, failed))
	require.NoError(t, c.processMessage(ctx, failed), "duplicate failed delivery")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs WHERE status_code=503`, 1, "failed row persisted once")

	shadow := redis.XMessage{ID: "107-1", Values: map[string]interface{}{
		"event_type": "request.shadow_completed", "request_id": "req-live-107-0",
		"org_id": inboxLiveOrgID, "status_code": "200", "ab_group": "test",
	}}
	require.NoError(t, c.processMessage(ctx, shadow))
	var abGroup string
	require.NoError(t, pool.QueryRow(ctx, `SELECT ab_group FROM request_logs WHERE request_id='req-live-107-0' AND ab_group='shadow'`).Scan(&abGroup))
	assert.Equal(t, "shadow", abGroup, "shadow discriminator forced")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM settlement_jobs`, 0, "shadow never charges")

	budget := redis.XMessage{ID: "107-2", Values: map[string]interface{}{
		"event_type": "request.budget_exceeded", "request_id": "req-live-107-2",
		"org_id": inboxLiveOrgID, "model_requested": "gpt-4",
	}}
	require.NoError(t, c.processMessage(ctx, budget))
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs WHERE status_code=429`, 1, "budget-exceeded persisted (429)")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM settlement_jobs`, 0, "blocked demand never charges")
}

// TestInboxLive_SessionSideEffectIdempotent pins the session-registry
// side effect inventory item: the upsert is idempotent inside the delivery
// transaction, and the FK still holds after a duplicate delivery.
func TestInboxLive_SessionSideEffectIdempotent(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:inbox-live", silentLogger())
	msg := inboxLiveMsg("108-0")
	require.NoError(t, c.processMessage(ctx, msg))
	require.NoError(t, c.processMessage(ctx, msg), "duplicate delivery")

	var sessions int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE client_session='ses_live_af04'`).Scan(&sessions))
	assert.Equal(t, int64(1), sessions, "session upsert stays idempotent under replay")

	var logs int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM request_logs`).Scan(&logs))
	assert.Equal(t, int64(1), logs)
}
