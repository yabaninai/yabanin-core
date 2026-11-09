package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W-LOGG unit contract: the DLQ stores a structured, replayable envelope
// with a bounded stream and a retry-key TTL that is refreshed on EVERY
// attempt; the in-flight gauge is balanced on every path; a full Postgres
// outage pauses consumption instead of dead-lettering live traffic.

// errRow is a pgx.Row that always fails its Scan (an unreachable DB probe).
type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

func newDLQRecordingRedis(t *testing.T, count int64) (*mockRedis, *[]redis.XAddArgs, *[]string, *int) {
	t.Helper()
	var mu sync.Mutex
	var xadds []redis.XAddArgs
	var expireKeys []string
	var expireCalls int
	rdb := &mockRedis{
		INCRFn: func(ctx context.Context, key string) *redis.IntCmd {
			cmd := redis.NewIntCmd(ctx)
			cmd.SetVal(count)
			return cmd
		},
		ExpireFn: func(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
			mu.Lock()
			defer mu.Unlock()
			expireKeys = append(expireKeys, key)
			expireCalls++
			assert.Equal(t, dlqTTL, expiration, "retry-key TTL must be the dlq horizon")
			cmd := redis.NewBoolCmd(ctx)
			cmd.SetVal(true)
			return cmd
		},
		XAddFn: func(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
			mu.Lock()
			defer mu.Unlock()
			xadds = append(xadds, *args)
			cmd := redis.NewStringCmd(ctx)
			cmd.SetVal("1-1")
			return cmd
		},
	}
	return rdb, &xadds, &expireKeys, &expireCalls
}

func dlqMsg(id string) redis.XMessage {
	return redis.XMessage{ID: id, Values: map[string]interface{}{
		"event_type":         "request.completed",
		"request_id":         "req-dlq-1",
		"org_id":             "org-dlq",
		"status_code":        "200",
		"estimated_cost_usd": "0.05",
	}}
}

// The dead letter carries the ORIGINAL event verbatim inside a structured
// JSON payload (never fmt %v), the DLQ stream is bounded (MaxLen approx) and
// the retry key gets its TTL refreshed on every attempt.
func TestTrySendToDLQ_StructuredEnvelopeBoundedStreamAlwaysTTL(t *testing.T) {
	msg := dlqMsg("42-0")

	t.Run("below threshold: retry counted, TTL refreshed, no DLQ write", func(t *testing.T) {
		rdb, xadds, _, expireCalls := newDLQRecordingRedis(t, 2)
		c := New(rdb, &mockDB{}, "events:queue", silentLogger())

		poison, err := c.trySendToDLQ(context.Background(), msg)
		require.NoError(t, err)
		assert.False(t, poison)
		assert.Empty(t, *xadds, "below maxRetries the message must stay pending")
		assert.Equal(t, 1, *expireCalls, "TTL refreshed on every attempt")
	})

	t.Run("first attempt: TTL set too (the old code only set it at count==1)", func(t *testing.T) {
		rdb, _, _, expireCalls := newDLQRecordingRedis(t, 1)
		c := New(rdb, &mockDB{}, "events:queue", silentLogger())

		poison, err := c.trySendToDLQ(context.Background(), msg)
		require.NoError(t, err)
		assert.False(t, poison)
		assert.Equal(t, 1, *expireCalls)
	})

	t.Run("over threshold: structured envelope, bounded XADD, TTL refreshed", func(t *testing.T) {
		rdb, xadds, expireKeys, expireCalls := newDLQRecordingRedis(t, maxRetries+1)
		c := New(rdb, &mockDB{}, "events:queue", silentLogger())

		poison, err := c.trySendToDLQ(context.Background(), msg)
		require.NoError(t, err)
		assert.True(t, poison)

		require.Len(t, *xadds, 1)
		add := (*xadds)[0]
		assert.Equal(t, dlqStreamName, add.Stream)
		assert.Equal(t, dlqMaxLen, add.MaxLen, "DLQ must be bounded")
		assert.True(t, add.Approx, "trim must be approximate")

		addValues, vok := add.Values.(map[string]interface{})
		require.True(t, vok, "DLQ XADD must carry a field map, got %T", add.Values)
		payload, _ := addValues["payload"].(string)
		require.NotEmpty(t, payload, "the replayable payload field is required")
		env, parseErr := eventpublisher.ParseDLQEnvelope([]byte(payload))
		require.NoError(t, parseErr, "the replay command must be able to parse every DLQ entry")
		assert.Equal(t, "events:queue", env.OriginalStream)
		assert.Equal(t, "42-0", env.EntryID)
		assert.Equal(t, int64(maxRetries+1), env.RetryCount)
		assert.Equal(t, "request.completed", env.EventType())
		assert.Equal(t, "req-dlq-1", env.RequestID())
		// Field fidelity: strings round-trip verbatim (the old fmt %v path
		// flattened types).
		assert.Equal(t, "200", env.Values["status_code"])
		assert.Equal(t, "0.05", env.Values["estimated_cost_usd"])
		assert.NotEmpty(t, env.FailedAt, "envelope carries the failure time")

		// Flat debug fields stay available for XRANGE inspection.
		assert.Equal(t, "events:queue", addValues["original_stream"])
		assert.Equal(t, "request.completed", addValues["event_type"])

		assert.Equal(t, 1, *expireCalls, "TTL refreshed even on the DLQ write")
		assert.NotEmpty(t, *expireKeys)
	})
}

// The in-flight gauge must return to its baseline on EVERY path — the old
// code only decremented on success, leaking one unit per failed delivery.
func TestHandleMessage_GaugeBalancedOnEveryPath(t *testing.T) {
	successPool := &mockDB{}
	failPool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("insert failed (poison simulation)")
		},
	}

	base := testutil.ToFloat64(metrics.EventsInFlight)

	healthy := New(&mockRedis{}, successPool, "events:queue", silentLogger())
	metrics.EventsInFlight.Inc()
	healthy.handleMessage(context.Background(), redis.XMessage{ID: "1-1", Values: map[string]interface{}{
		"event_type": "request.completed", "org_id": "org", "session_id": "s",
	}})
	assert.InDelta(t, base, testutil.ToFloat64(metrics.EventsInFlight), 0, "success path must decrement")

	failing := New(&mockRedis{}, failPool, "events:queue", silentLogger())
	metrics.EventsInFlight.Inc()
	failing.handleMessage(context.Background(), redis.XMessage{ID: "1-2", Values: map[string]interface{}{
		"event_type": "request.completed",
	}})
	assert.InDelta(t, base, testutil.ToFloat64(metrics.EventsInFlight), 0, "failure path must decrement too")
}

// A full Postgres outage pauses consumption: no retry-budget burn, no DLQ
// write, no ACK — the message stays pending for the reclaim pass.
func TestHandleMessage_DBOutagePausesInsteadOfDLQ(t *testing.T) {
	var incrCalls, xaddCalls, ackCalls int
	rdb := &mockRedis{
		INCRFn: func(ctx context.Context, key string) *redis.IntCmd {
			incrCalls++
			cmd := redis.NewIntCmd(ctx)
			cmd.SetVal(99)
			return cmd
		},
		XAddFn: func(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
			xaddCalls++
			cmd := redis.NewStringCmd(ctx)
			cmd.SetVal("1-1")
			return cmd
		},
		XAckFn: func(ctx context.Context, stream, group string, ids []string) *redis.IntCmd {
			ackCalls++
			cmd := redis.NewIntCmd(ctx)
			cmd.SetVal(1)
			return cmd
		},
	}
	// The probe fails AND the delivery fails: full DB unavailability.
	outagePool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("dial tcp: connection refused")
		},
		QueryRowFn: func(ctx context.Context, q string, args ...any) pgx.Row {
			return errRow{err: errors.New("dial tcp: connection refused")}
		},
	}
	c := New(rdb, outagePool, "events:queue", silentLogger())
	c.outagePause = 5 * time.Millisecond

	start := time.Now()
	metrics.EventsInFlight.Inc()
	c.handleMessage(context.Background(), redis.XMessage{ID: "7-1", Values: map[string]interface{}{
		"event_type": "request.completed", "org_id": "org", "session_id": "s",
	}})
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, 5*time.Millisecond, "consumption must pause during the outage")
	assert.Zero(t, incrCalls, "an outage must NOT burn the DLQ retry budget")
	assert.Zero(t, xaddCalls, "an outage must NOT dead-letter live billing traffic")
	assert.Zero(t, ackCalls, "the message stays pending for the reclaim pass")
}

// With no DB configured the failure is a permanent configuration problem,
// not an outage: the message follows the normal retry/DLQ path.
func TestHandleMessage_NilDBIsNotAnOutage(t *testing.T) {
	var incrCalls int
	rdb := &mockRedis{
		INCRFn: func(ctx context.Context, key string) *redis.IntCmd {
			incrCalls++
			cmd := redis.NewIntCmd(ctx)
			cmd.SetVal(1)
			return cmd
		},
	}
	c := New(rdb, nil, "events:queue", silentLogger())
	c.outagePause = time.Second

	start := time.Now()
	metrics.EventsInFlight.Inc()
	c.handleMessage(context.Background(), redis.XMessage{ID: "8-1", Values: map[string]interface{}{
		"event_type": "request.completed", "org_id": "org", "session_id": "s",
	}})

	assert.Less(t, time.Since(start), time.Second, "no outage pause on a config error")
	assert.Equal(t, 1, incrCalls, "retry budget applies")
}

// The reclaim path must obey the same contract: gauge balance and outage
// pause (the old code leaked the gauge there too and DLQed during outages).
func TestReclaimPath_UsesDeliveryContract(t *testing.T) {
	var ackCalls int
	rdb := &mockRedis{
		XPendingExtFn: func(ctx context.Context, args *redis.XPendingExtArgs) *redis.XPendingExtCmd {
			cmd := redis.NewXPendingExtCmd(ctx)
			cmd.SetVal([]redis.XPendingExt{{ID: "9-1", Idle: 10 * pelReclaimTimeout}})
			return cmd
		},
		XClaimFn: func(ctx context.Context, args *redis.XClaimArgs) *redis.XMessageSliceCmd {
			cmd := redis.NewXMessageSliceCmd(ctx)
			cmd.SetVal([]redis.XMessage{{ID: "9-1", Values: map[string]interface{}{
				"event_type": "request.completed", "org_id": "org", "session_id": "s",
			}}})
			return cmd
		},
		XAckFn: func(ctx context.Context, stream, group string, ids []string) *redis.IntCmd {
			ackCalls++
			cmd := redis.NewIntCmd(ctx)
			cmd.SetVal(1)
			return cmd
		},
	}
	base := testutil.ToFloat64(metrics.EventsInFlight)

	c := New(rdb, &mockDB{}, "events:queue", silentLogger())
	c.reclaimStaleMessages(context.Background())

	assert.InDelta(t, base, testutil.ToFloat64(metrics.EventsInFlight), 0, "reclaim path must balance the gauge")
	assert.Equal(t, 1, ackCalls, "reclaimed message ACKed after successful delivery")
}

// Marshal failure of the envelope must not lose the dead letter: the entry
// still lands with identifiers only.
func TestTrySendToDLQ_UnmarshalableValueStillLands(t *testing.T) {
	rdb, xadds, _, _ := newDLQRecordingRedis(t, maxRetries+1)
	c := New(rdb, &mockDB{}, "events:queue", silentLogger())

	msg := redis.XMessage{ID: "50-0", Values: map[string]interface{}{
		"event_type": "request.completed",
		"bad":        make(chan int), // not JSON-marshalable
	}}

	poison, err := c.trySendToDLQ(context.Background(), msg)
	require.NoError(t, err)
	assert.True(t, poison)
	require.Len(t, *xadds, 1)
	fallback, ok := (*xadds)[0].Values.(map[string]interface{})
	require.True(t, ok)
	// The entry still lands with identifiers on the flat fields; its payload
	// carries no values, so the replay command reports it instead of
	// silently re-publishing a hollow event.
	assert.Equal(t, "events:queue", fallback["original_stream"])
	assert.Equal(t, "50-0", fallback["entry_id"])
	payload, _ := fallback["payload"].(string)
	env, parseErr := eventpublisher.ParseDLQEnvelope([]byte(payload))
	require.Error(t, parseErr, "a values-less envelope is not replayable")
	assert.Empty(t, env.Values)
}

// parseDLQEnvelope rejects an envelope without values (replaying it would
// silently drop the event).
func TestParseDLQEnvelope_RejectsEmptyValues(t *testing.T) {
	body, err := json.Marshal(eventpublisher.DLQEnvelope{OriginalStream: "events:queue"})
	require.NoError(t, err)
	_, err = eventpublisher.ParseDLQEnvelope(body)
	require.Error(t, err)
}
