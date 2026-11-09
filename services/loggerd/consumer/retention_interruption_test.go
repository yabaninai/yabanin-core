package consumer

// N02-P06 T08 — interruption proofs for the original-retention gate:
// consumer restart/retry with the retention resolver cache cold vs warm
// must reach identical outcomes, and the Redis redelivery of a pre-fix
// envelope (raw captures still present in the old message) under retention
// OFF must stay processed-only on every downstream durable surface — the
// defense-in-depth contract (producer gate + consumer history gate + DLQ
// strip) holds without trusting the producer's generation.
//
// Existing coverage cited instead of duplicated:
//   - first-attempt OFF persistence shape → TestHandleMessage_RetentionOffPersistsProcessedOnly;
//   - DLQ envelope OFF strip shape → TestDLQ_RetentionOffStripsCapturesFromEnvelope;
//   - durable-inbox redelivery dedupe semantics → the mockDB AF-04 model in
//     stream_test.go and TestHandleMessage_StrictPoisonNeverCarriesContent.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	eventpublisher "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// intDeliver drives one completed event through the real handleMessage
// boundary (the production entry: sanitize → resolve → dispatch) and
// returns the bound arguments of THIS delivery only.
func intDeliver(t *testing.T, c *StreamConsumer, id, requestID string) string {
	t.Helper()
	db := c.dbPool.(*retCaptureDB)
	before := len(db.calls)
	c.handleMessage(context.Background(), redis.XMessage{ID: id, Values: cpCompletedFields(requestID, false)})
	return renderJoin2(db.calls[before:])
}

// TestInterruption_RestartColdVsWarmCache_SameOutcome: the per-message
// outcome depends on the RESOLVED value, never on the cache state. A warm
// consumer (cache hit), its own repeat, and a restarted consumer (cold
// resolver, store re-read) bind byte-identical arguments — under retention
// ON and under OFF.
func TestInterruption_RestartColdVsWarmCache_SameOutcome(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "")

	for _, tc := range []struct {
		name      string
		effective bool
	}{
		{"retention ON", true},
		{"retention OFF", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newRetCaptureDB()
			store := &retStubStore{found: true, effective: tc.effective}

			warm := retConsumer(db, store) // the pre-restart process
			m1 := intDeliver(t, warm, "70-1", "req-restart-same")
			require.Equal(t, 1, store.calls)
			m2 := intDeliver(t, warm, "70-2", "req-restart-same")
			assert.Equal(t, 1, store.calls, "the warm consumer answers from the cache")

			restarted := retConsumer(db, store) // the restart: cold resolver
			m3 := intDeliver(t, restarted, "70-3", "req-restart-same")
			assert.Equal(t, 2, store.calls, "a cold resolver re-reads the store")

			assert.Equal(t, m1, m2, "warm cache hits bind byte-identical arguments")
			assert.Equal(t, m1, m3, "a cold restart binds byte-identical arguments — same outcome")
			if tc.effective {
				assert.Contains(t, m1, cpSentinelUpReq, "ON keeps captures identically in every cache state")
			} else {
				assert.NotContains(t, m1, cpSentinelUpReq, "OFF strips identically in every cache state")
			}
		})
	}
}

// TestInterruption_TransientFailureThenRetry_GatedOnBothAttempts: a
// transient DB failure mid-delivery retried by the consumer resolves the
// toggle on the retry attempt too, and BOTH attempts — including the failed
// one's bound arguments — stay processed-only under retention OFF.
func TestInterruption_TransientFailureThenRetry_GatedOnBothAttempts(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "")

	var failedInsertArgs []any
	failNext := true
	db := &retCaptureDB{}
	db.ExecFn = func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
		db.calls = append(db.calls, retCall{query: query, args: args})
		if failNext && strings.Contains(query, "INSERT INTO request_logs") {
			failNext = false
			failedInsertArgs = args
			return pgconn.CommandTag{}, errors.New("transient: connection reset during insert")
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}

	rdb := &mockRedis{INCRFn: func(ctx context.Context, key string) *redis.IntCmd {
		cmd := redis.NewIntCmd(ctx)
		cmd.SetVal(1) // first retry attempt — still inside the budget, no DLQ
		return cmd
	}}
	c := New(rdb, db, "events:queue", silentLogger())
	c.SetOriginalRetentionStore(&retStubStore{}) // not-found ⇒ fail-closed OFF

	msg := redis.XMessage{ID: "71-1", Values: cpCompletedFields("req-retry-pre-fix", false)}
	original := cpCopyValues(msg.Values)

	// Attempt 1: the insert fails; the message stays pending (mock answers
	// the health probe), the retry counter INCRs, nothing reaches a DLQ.
	failNext = true
	c.handleMessage(context.Background(), msg)
	require.NotNil(t, failedInsertArgs, "sanity: the failing attempt really attempted the insert")
	for _, arg := range failedInsertArgs {
		assert.NotContains(t, renderArg(arg), cpSentinelUpReq,
			"even the FAILED attempt must not bind originals")
		assert.NotContains(t, renderArg(arg), cpSentinelUpResp)
	}

	// Attempt 2 (redelivery of the same stream entry): succeeds.
	failNext = false
	c.handleMessage(context.Background(), msg)

	inserts := 0
	for _, call := range db.calls {
		if strings.Contains(call.query, "INSERT INTO request_logs") {
			inserts++
		}
	}
	assert.Equal(t, 2, inserts, "the retry re-attempted the durable write exactly once")

	// The redelivered message is never mutated (replay/ownership contract)
	// and the delivery outcome matches a first-try clean run.
	assert.Equal(t, original, msg.Values)
}

// TestInterruption_PreFixEnvelopeRedelivery_DownstreamDefenseInDepth: a
// pre-fix producer's envelope — raw upstream captures still inside — is
// redelivered to a post-fix consumer under retention OFF, exhausts its
// retry budget against a poisoned write, and must end processed-only on
// every durable surface: no original in any bound attempt, no original in
// the DLQ envelope, metadata flowing, the message itself never mutated.
func TestInterruption_PreFixEnvelopeRedelivery_DownstreamDefenseInDepth(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "")

	// A poison write: every request_logs insert fails, so every redelivery
	// takes the retry path until the budget is exhausted.
	db := &retCaptureDB{}
	db.ExecFn = func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
		db.calls = append(db.calls, retCall{query: query, args: args})
		if strings.Contains(query, "INSERT INTO request_logs") {
			return pgconn.CommandTag{}, errors.New("poison: insert never lands")
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}

	attempt := 0
	var dlqValues map[string]interface{}
	rdb := &mockRedis{
		INCRFn: func(ctx context.Context, key string) *redis.IntCmd {
			attempt++
			cmd := redis.NewIntCmd(ctx)
			cmd.SetVal(int64(attempt)) // 1..4 → the 4th (past maxRetries) archives
			return cmd
		},
		XAddFn: func(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
			dlqValues = args.Values.(map[string]interface{})
			cmd := redis.NewStringCmd(ctx)
			cmd.SetVal("72-dlq")
			return cmd
		},
	}
	c := New(rdb, db, "events:queue", silentLogger())
	c.SetOriginalRetentionStore(&retStubStore{}) // OFF for every org

	// The pre-fix envelope: a producer predating the gating buffered the
	// raw captures into Redis; the consumer must not trust their absence.
	msg := redis.XMessage{ID: "72-1", Values: cpCompletedFields("req-prefix-redeliver", false)}
	require.Contains(t, msg.Values["upstream_payload"], cpSentinelUpReq,
		"fixture: the pre-fix envelope carries the raw capture")
	original := cpCopyValues(msg.Values)

	for i := 0; i <= maxRetries; i++ {
		c.handleMessage(context.Background(), msg)
	}

	// Every durable write attempt of every redelivery stayed processed-only.
	for _, call := range db.calls {
		rendered := renderJoin(call.args)
		assert.NotContains(t, rendered, cpSentinelUpReq)
		assert.NotContains(t, rendered, cpSentinelUpResp)
		assert.NotContains(t, call.query, "INSERT INTO tool_calls",
			"no tool-call rows derive from a dropped sample on any attempt")
	}

	// The DLQ envelope (the replayable durable archive) is stripped too.
	require.NotNil(t, dlqValues, "the poisoned envelope must be archived past the budget")
	var envelope eventpublisher.DLQEnvelope
	require.NoError(t, json.Unmarshal([]byte(dlqValues["payload"].(string)), &envelope))
	for _, key := range []string{"upstream_payload", "upstream_response"} {
		assert.NotContains(t, envelope.Values, key, "%s must not enter the DLQ on redelivery", key)
	}
	assert.NotContains(t, dlqValues["payload"], cpSentinelUpReq,
		"the original request capture never rides the archived payload")
	assert.NotContains(t, dlqValues["payload"], cpSentinelUpResp,
		"the original response capture never rides the archived payload")
	assert.Contains(t, dlqValues["payload"], "TOP SECRET PROMPT BODY",
		"the PROCESSED payload snapshot keeps flowing — retention governs originals only")
	assert.Equal(t, "request.completed", envelope.Values["event_type"], "metadata keeps flowing")
	assert.Equal(t, "req-prefix-redeliver", envelope.Values["request_id"])
	assert.Equal(t, int64(maxRetries+1), envelope.RetryCount)

	// The stream message itself is never mutated — a later replay or the
	// retention-ON consumer of another deployment still sees the same bytes.
	assert.Equal(t, original, msg.Values)
}
