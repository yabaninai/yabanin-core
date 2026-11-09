package consumer

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seenOnceRedis models the production Redis dedup marker: SETNX succeeds once
// per key, every later delivery of the same message observes the marker.
type seenOnceRedis struct {
	*mockRedis
	mu   sync.Mutex
	seen map[string]bool
}

func (r *seenOnceRedis) SETNX(ctx context.Context, key string, value any, expiration time.Duration) *redis.BoolCmd {
	r.mu.Lock()
	defer r.mu.Unlock()
	first := !r.seen[key]
	r.seen[key] = true
	cmd := redis.NewBoolCmd(ctx)
	cmd.SetVal(first)
	return cmd
}

// AF-04 regression (ported from the audit fixture
// TestReview_RetryAfterFailedInsertMustPersist): the first INSERT fails with a
// transient database outage while the Redis "msg:seen" marker is already set.
// The retry must ignore the stale marker and actually INSERT — a delivery
// that was never persisted must never be ACKed as success.
func TestHandleRequestComplete_InsertErrorThenReplayPersistsExactlyOnce(t *testing.T) {
	var mu sync.Mutex
	inserts := 0
	db := &mockDB{ExecFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
		mu.Lock()
		defer mu.Unlock()
		inserts++
		if inserts == 1 {
			return pgconn.CommandTag{}, errors.New("transient database outage")
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	c := New(&seenOnceRedis{seen: map[string]bool{}}, db, "review-stream", silentLogger())

	msg := redis.XMessage{ID: "123-0", Values: map[string]interface{}{
		"event_type": "request.completed",
		"request_id": "review-request",
	}}
	require.Error(t, c.processMessage(context.Background(), msg), "first insert should fail")
	require.NoError(t, c.processMessage(context.Background(), msg), "retry must replay the event, not fake success")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, inserts,
		"retry must really INSERT: a Redis seen marker without a DB commit must not mark the event processed")
}

func completedMsg(id string) redis.XMessage {
	return redis.XMessage{ID: id, Values: map[string]interface{}{
		"event_type":      "request.completed",
		"source":          "gateway",
		"request_id":      "req-" + id,
		"org_id":          "org-inbox",
		"model_requested": "gpt-4",
		"model_used":      "gpt-4",
		"status_code":     float64(200),
	}}
}

// A replay after a successful commit (lost ACK, PEL reclaim, restart) must
// not insert a second row: the committed event_inbox row decides, not Redis.
func TestInbox_DuplicateDeliveryPersistsExactlyOnce(t *testing.T) {
	var mu sync.Mutex
	logInserts := 0
	db := &mockDB{ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
		if strings.Contains(q, "INSERT INTO request_logs") {
			mu.Lock()
			logInserts++
			mu.Unlock()
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	c := New(&mockRedis{}, db, "events:queue", silentLogger())

	msg := completedMsg("7-1")
	require.NoError(t, c.processMessage(context.Background(), msg))
	require.NoError(t, c.processMessage(context.Background(), msg), "replay after commit must be a no-op success")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, logInserts, "duplicate delivery must not re-insert the request log")
}

// Delivery identity is (source, consumer, event_id): the same entry id in two
// different streams must not be deduped against each other.
func TestInbox_SameEventIDDifferentStreamsDoNotConflict(t *testing.T) {
	var mu sync.Mutex
	logInserts := 0
	db := &mockDB{ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
		if strings.Contains(q, "INSERT INTO request_logs") {
			mu.Lock()
			logInserts++
			mu.Unlock()
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}

	msg := completedMsg("9-3")
	require.NoError(t, New(&mockRedis{}, db, "stream-a", silentLogger()).processMessage(context.Background(), msg))
	require.NoError(t, New(&mockRedis{}, db, "stream-b", silentLogger()).processMessage(context.Background(), msg))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, logInserts, "identical event ids in different streams are distinct deliveries")
}

// Two simultaneous deliveries of the same message (two replicas): the durable
// unique claim lets exactly one persist; the other skips without an error.
func TestInbox_ConcurrentDeliveriesPersistExactlyOnce(t *testing.T) {
	var mu sync.Mutex
	logInserts := 0
	db := &mockDB{ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
		if strings.Contains(q, "INSERT INTO request_logs") {
			mu.Lock()
			logInserts++
			mu.Unlock()
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	c := New(&mockRedis{}, db, "events:queue", silentLogger())

	msg := completedMsg("11-0")
	const replicas = 8
	errs := make(chan error, replicas)
	for i := 0; i < replicas; i++ {
		go func() { errs <- c.processMessage(context.Background(), msg) }()
	}
	for i := 0; i < replicas; i++ {
		require.NoError(t, <-errs)
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, logInserts, "exactly one concurrent delivery may persist the event")
}

// A Redis marker without a committed inbox row (crash after SETNX, Redis
// flushed, or a rolled-back old writer) must never skip the delivery.
func TestInbox_StaleRedisSeenDoesNotSkipPersist(t *testing.T) {
	var mu sync.Mutex
	logInserts := 0
	db := &mockDB{ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
		if strings.Contains(q, "INSERT INTO request_logs") {
			mu.Lock()
			logInserts++
			mu.Unlock()
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	// SETNX always reports "seen" — the DB is still authoritative.
	alwaysSeen := &claimCountingRedis{claims: new(int)}
	c := New(alwaysSeen, db, "events:queue", silentLogger())

	require.NoError(t, c.processMessage(context.Background(), completedMsg("13-2")))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, logInserts, "Redis seen without a DB commit must not mark the event processed")
}

// flakyCommitDB models a process killed between the writes and the commit:
// every statement ran inside the transaction, but the commit never happens,
// so nothing (inbox claim included) survives — the replay must persist.
type flakyCommitDB struct {
	*mockDB
	failCommit atomic.Bool
	commits    atomic.Int64
}

func (f *flakyCommitDB) BeginTx(ctx context.Context) (InboxTx, error) {
	inner, err := f.mockDB.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return &flakyCommitTx{InboxTx: inner, db: f}, nil
}

type flakyCommitTx struct {
	InboxTx
	db *flakyCommitDB
}

func (t *flakyCommitTx) Commit(ctx context.Context) error {
	if t.db.failCommit.Load() {
		return errors.New("process killed before commit")
	}
	if err := t.InboxTx.Commit(ctx); err != nil {
		return err
	}
	t.db.commits.Add(1)
	return nil
}

func TestInbox_KillBeforeCommitThenReplayPersistsExactlyOnce(t *testing.T) {
	var mu sync.Mutex
	logInserts := 0
	inner := &mockDB{ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
		if strings.Contains(q, "INSERT INTO request_logs") {
			mu.Lock()
			logInserts++
			mu.Unlock()
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	db := &flakyCommitDB{mockDB: inner}
	c := New(&mockRedis{}, db, "events:queue", silentLogger())

	msg := completedMsg("17-5")
	db.failCommit.Store(true)
	require.Error(t, c.processMessage(context.Background(), msg), "commit failure must fail the delivery")

	db.failCommit.Store(false)
	require.NoError(t, c.processMessage(context.Background(), msg), "replay after the crash window must persist")
	require.NoError(t, c.processMessage(context.Background(), msg), "post-commit replay must stay a no-op")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, int64(1), db.commits.Load())
	assert.Equal(t, 2, logInserts, "the aborted attempt wrote, the replay wrote once, the duplicate did not")
}

// The durable settlement intents (mandatory monetary side effects) commit in
// the same transaction as the request log; gates mirror the legacy paths.
func TestInbox_SettlementIntentsCommitWithLog(t *testing.T) {
	var intents [][]any
	var mu sync.Mutex
	db := &mockDB{ExecFn: func(_ context.Context, q string, a ...any) (pgconn.CommandTag, error) {
		if strings.Contains(q, "INSERT INTO settlement_jobs") {
			mu.Lock()
			intents = append(intents, a)
			mu.Unlock()
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
	spender := &fakeAgentSpender{}
	c.SetAgentSpender(spender)

	msg := redis.XMessage{ID: "19-1", Values: map[string]interface{}{
		"event_type":         "request.completed",
		"request_id":         "req-charge",
		"org_id":             "org-charge",
		"model_requested":    "gpt-4",
		"model_used":         "gpt-4",
		"status_code":        float64(200),
		"agent_id":           testAgentUUID,
		"estimated_cost_usd": float64(0.0123),
		"resale_cost_usd":    float64(0.05),
	}}
	require.NoError(t, c.processMessage(context.Background(), msg))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, intents, 2, "resale deduction and agent spend intents both commit with the log")
	assert.Equal(t, "org-charge", intents[0][0])
	assert.Equal(t, "req-charge", intents[0][1])
	assert.Equal(t, ChargeKindResaleDeduction, intents[0][2])
	assert.Equal(t, int64(5), intents[0][3], "resale wins over base cost: $0.05 -> 5 cents")
	assert.Equal(t, ChargeKindAgentSpend, intents[1][2])
	assert.Equal(t, int64(1), intents[1][3], "agent intent carries the base rounded cents")
}

// No billing store / no org / zero quote -> no intent, exactly like the
// legacy Deductor gates. Shadow events never produce intents.
func TestInbox_SettlementIntentGates(t *testing.T) {
	tests := []struct {
		name    string
		consume func(t *testing.T, db *mockDB)
	}{
		{"no credit store", func(t *testing.T, db *mockDB) {
			t.Helper()
			c := New(&mockRedis{}, db, "events:queue", silentLogger())
			require.NoError(t, c.processMessage(context.Background(), chargedMsg("21-1")))
		}},
		{"no org", func(t *testing.T, db *mockDB) {
			t.Helper()
			c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
			msg := chargedMsg("21-2")
			msg.Values["org_id"] = ""
			require.NoError(t, c.processMessage(context.Background(), msg))
		}},
		{"zero quote", func(t *testing.T, db *mockDB) {
			t.Helper()
			c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))
			msg := chargedMsg("21-3")
			msg.Values["estimated_cost_usd"] = float64(0)
			msg.Values["resale_cost_usd"] = float64(0)
			require.NoError(t, c.processMessage(context.Background(), msg))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			intents := 0
			db := &mockDB{ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
				if strings.Contains(q, "INSERT INTO settlement_jobs") {
					mu.Lock()
					intents++
					mu.Unlock()
				}
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			}}
			tt.consume(t, db)
			mu.Lock()
			defer mu.Unlock()
			assert.Zero(t, intents, "no mandatory charge attempted -> no durable intent")
		})
	}
}

func chargedMsg(id string) redis.XMessage {
	msg := completedMsg(id)
	msg.Values["estimated_cost_usd"] = float64(0.05)
	return msg
}

// A failed settlement-intent insert must fail the whole delivery transaction:
// the request log may not commit without the mandatory charge intent.
func TestInbox_IntentInsertFailureFailsDelivery(t *testing.T) {
	var mu sync.Mutex
	logInserts := 0
	db := &mockDB{ExecFn: func(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
		if strings.Contains(q, "INSERT INTO settlement_jobs") {
			return pgconn.CommandTag{}, errors.New("statement budget exceeded")
		}
		if strings.Contains(q, "INSERT INTO request_logs") {
			mu.Lock()
			logInserts++
			mu.Unlock()
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	c := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))

	require.Error(t, c.processMessage(context.Background(), chargedMsg("23-1")))
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, logInserts, "the log write itself ran, but must not commit")
}

func silentLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
