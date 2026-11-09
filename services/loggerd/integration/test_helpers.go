//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/events"
	"github.com/reireirei/yabanin/pkg/testdb"
)

const (
	testLoggerdOrgID = "e1a2b3c4-d5f6-7a8b-9c0d-1e2f3a4b5c6d"
)

// Unexported consumer constants the e2e suite observes from the outside
// (the consumer group name and the DLQ retry-counter key prefix are part of
// the delivery contract; see services/loggerd/consumer/stream.go).
const (
	loggerdConsumerGroup     = "loggerd-workers"
	loggerdDLQRetryKeyPrefix = "dlq:retry"
)

// NewLoggerdTestDB returns the loggerd database for the e2e suites.
//
// NEXT-05: uses the package-wide disposable, fully migrated Postgres stand
// from pkg/testdb (no shared dev stand, no skip). The pool is package-wide
// and never closed per test; ResetLoggerdTables provides the per-test clean
// slate instead.
//
// The pool must carry the app.region GUC the same way production does
// (run.Loggerd -> regionrouter.ConfigurePool): request_logs and sessions
// default home_region to current_setting('app.region', true), so a plain
// DSN insert hits the home_region NOT NULL constraint (SQLSTATE 23502).
// PostgresRegion wires the production AfterConnect hook with the e2e region,
// making the suite equivalent to a real regional deployment.
//
// It also seeds the fixture org the e2e payloads reference: request_logs.org_id
// and sessions.org_id both FK to organizations.id, so without the row the
// inserts fail SQLSTATE 23503 (surfaced only once the home_region NOT NULL
// issue above was fixed). The seed is idempotent (ON CONFLICT DO NOTHING) and
// safe to re-run on the shared pool.
func NewLoggerdTestDB(t testing.TB, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	pool := testdb.PostgresRegion(t, "e2e")
	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1, 'loggerd-e2e-org', 'loggerd-e2e')
		ON CONFLICT (id) DO NOTHING`, testLoggerdOrgID); err != nil {
		t.Fatalf("failed to seed loggerd fixture org: %v", err)
	}
	return pool
}

// NewLoggerdTestRedis returns the loggerd Redis. Same contract as
// NewLoggerdTestDB: the package-wide disposable stand from pkg/testdb;
// never closed per test (use FlushLoggerdRedis instead).
func NewLoggerdTestRedis(t testing.TB, _ context.Context) *redis.Client {
	t.Helper()
	return testdb.Redis(t)
}

// ResetLoggerdTables clears the per-binary disposable request_logs (and the
// AF-04 durable inbox/settlement tables) so each e2e test starts from a clean
// slate. GetRequestLogs asserts exact row counts with no WHERE clause, and
// the pool is a package-wide singleton, so rows would otherwise accumulate
// across the e2e cases in one binary. request_logs is a leaf table (no other
// table references it), so a plain TRUNCATE is safe.
func ResetLoggerdTables(ctx context.Context, t testing.TB, db *pgxpool.Pool) {
	t.Helper()
	if _, err := db.Exec(ctx, `TRUNCATE request_logs, event_inbox, settlement_jobs`); err != nil {
		t.Fatalf("failed to truncate loggerd tables: %v", err)
	}
}

func FlushLoggerdRedis(ctx context.Context, t testing.TB, rdb *redis.Client) {
	t.Helper()
	if err := rdb.FlushDB(ctx).Err(); err != nil && err != redis.Nil {
		t.Fatalf("failed to flush redis: %v", err)
	}
}

func SeedRequestLog(ctx context.Context, t testing.TB, db *pgxpool.Pool, payload events.Payload, statusCode int64) {
	t.Helper()
	sessionID := payload.GetSessionID()
	if sessionID == "" {
		sessionID = "test-session-id"
	}

	var errorStr interface{}
	errMsg := payload.GetError()
	if errMsg != "" {
		errorStr = errMsg
	}

	result, err := db.Exec(ctx,
		`INSERT INTO request_logs
		   (session_id, org_id, model_requested, model_used, upstream_url, method, status_code, duration_ms, tokens_in, tokens_out, error)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		sessionID,
		payload.GetOrgID(),
		payload.GetModelRequested(),
		payload.GetModelUsed(),
		payload.GetUpstreamURL(),
		payload.GetMethod(),
		statusCode,
		payload.GetDurationMs(),
		payload.GetTokensIn(),
		payload.GetTokensOut(),
		errorStr,
	)
	if err != nil {
		t.Fatalf("failed to seed request_log: %v", err)
	}
	rowsAffected := result.RowsAffected()
	if rowsAffected != 1 {
		t.Fatalf("expected 1 row affected, got %d", rowsAffected)
	}
}

func GetRequestLogs(ctx context.Context, t testing.TB, db *pgxpool.Pool) []map[string]interface{} {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT session_id, org_id, model_requested, model_used, upstream_url, method, status_code, duration_ms, tokens_in, tokens_out, error FROM request_logs ORDER BY updated_at DESC`)
	if err != nil {
		t.Fatalf("failed to query request_logs: %v", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var sessionID, orgID, modelRequested, modelUsed, upstreamURL, method string
		var statusCode, durationMs, tokensIn, tokensOut int64
		var errorStr interface{}

		if err := rows.Scan(&sessionID, &orgID, &modelRequested, &modelUsed, &upstreamURL, &method, &statusCode, &durationMs, &tokensIn, &tokensOut, &errorStr); err != nil {
			t.Fatalf("failed to scan row: %v", err)
		}

		results = append(results, map[string]interface{}{
			"session_id":      sessionID,
			"org_id":          orgID,
			"model_requested": modelRequested,
			"model_used":      modelUsed,
			"upstream_url":    upstreamURL,
			"method":          method,
			"status_code":     statusCode,
			"duration_ms":     durationMs,
			"tokens_in":       tokensIn,
			"tokens_out":      tokensOut,
			"error":           errorStr,
		})
	}

	if err := rows.Err(); err != nil {
		t.Fatalf("row iteration error: %v", err)
	}

	return results
}

// PublishEventToStream appends an event to the test stream using the SAME
// top-level field contract the production producer publishes
// (pkg/eventpublisher/redis_publisher.go). The consumer reads model_used,
// status_code, duration_ms, tokens_in/out and error from these top-level
// fields (not from the nested payload JSON), so the helper must send them
// verbatim or the e2e suite exercises a different, incomplete data path.
// Returns the Redis stream entry id so tests can await that exact delivery.
func PublishEventToStream(ctx context.Context, t testing.TB, rdb *redis.Client, streamName string, payload events.Payload) string {
	t.Helper()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	result, err := rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: streamName,
		Values: map[string]interface{}{
			"event_type":      payload.EventType,
			"source":          payload.Source,
			"request_id":      payload.GetRequestID(),
			"session_id":      payload.GetSessionID(),
			"payload":         string(payloadJSON),
			"org_id":          payload.GetOrgID(),
			"model_requested": payload.GetModelRequested(),
			"model_used":      payload.GetModelUsed(),
			"upstream_url":    payload.GetUpstreamURL(),
			"status_code":     payload.GetStatusCode(),
			"duration_ms":     payload.GetDurationMs(),
			"tokens_in":       payload.GetTokensIn(),
			"tokens_out":      payload.GetTokensOut(),
			"method":          payload.GetMethod(),
			"error":           payload.GetError(),
		},
	}).Result()
	if err != nil {
		t.Fatalf("failed to add event to stream: %v", err)
	}

	t.Logf("published event %s to stream %s", result, streamName)
	return result
}

// waitForCondition polls cond every 50ms until it holds or the timeout
// expires — the deadline-poll replacement for the suite's fixed time.Sleep
// waits (an event is awaited exactly as long as it takes to observe).
func waitForCondition(t *testing.T, timeout time.Duration, describe string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("condition not met within %s: %s", timeout, describe)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitForRequestLogCount polls request_logs until at least n rows exist —
// the committed row count is the delivery proof, replacing the fixed
// post-publish sleeps.
func waitForRequestLogCount(ctx context.Context, t *testing.T, db *pgxpool.Pool, n int) []map[string]interface{} {
	t.Helper()
	var logs []map[string]interface{}
	waitForCondition(t, 10*time.Second, fmt.Sprintf("request_logs to hold >= %d rows", n), func() bool {
		logs = GetRequestLogs(ctx, t, db)
		return len(logs) >= n
	})
	return logs
}

// waitForConsumerGroup polls until a consumer group exists on the stream —
// the observable proof that StreamConsumer.Start finished its group setup and
// the read loop is live, so anything published after this point is delivered.
// The stream is per-test and Redis is flushed per test, so any group on it
// belongs to the consumer under test.
func waitForConsumerGroup(ctx context.Context, t *testing.T, rdb *redis.Client, streamName string) {
	t.Helper()
	waitForCondition(t, 10*time.Second, "consumer group on stream "+streamName, func() bool {
		groups, err := rdb.XInfoGroups(ctx, streamName).Result()
		if err != nil {
			return false // stream not created yet
		}
		return len(groups) > 0
	})
}

// waitForStreamDelivery polls until the consumer group's last-delivered id
// has advanced past msgID and no entry is pending anymore (acked). Together
// these prove an event was fully processed even when it writes no DB rows
// (generic events) — no blind post-publish sleep.
func waitForStreamDelivery(ctx context.Context, t *testing.T, rdb *redis.Client, streamName, msgID string) {
	t.Helper()
	delivered := func() bool {
		groups, err := rdb.XInfoGroups(ctx, streamName).Result()
		if err != nil {
			return false
		}
		for _, g := range groups {
			if streamIDAtLeast(g.LastDeliveredID, msgID) {
				return true
			}
		}
		return false
	}
	acked := func() bool {
		pending, err := rdb.XPending(ctx, streamName, loggerdConsumerGroup).Result()
		return err == nil && pending.Count == 0
	}
	// Delivery first: the acked check is vacuously true before the event is
	// handed to the consumer, so phase 1 gates phase 2.
	waitForCondition(t, 10*time.Second, "event "+msgID+" delivered on "+streamName, delivered)
	waitForCondition(t, 10*time.Second, "event "+msgID+" acked on "+streamName, acked)
}

// waitForDLQRetryMark polls until the consumer recorded a failed delivery
// attempt for msgID (the dlq:retry counter INCR'd after every process
// failure) — the deterministic signal that the DLQ path ran.
func waitForDLQRetryMark(ctx context.Context, t *testing.T, rdb *redis.Client, streamName, msgID string) {
	t.Helper()
	key := fmt.Sprintf("%s:%s:%s:%s", loggerdDLQRetryKeyPrefix, streamName, loggerdConsumerGroup, msgID)
	waitForCondition(t, 10*time.Second, "dlq retry mark "+key, func() bool {
		return rdb.Exists(ctx, key).Val() > 0
	})
}

// streamIDAtLeast reports whether stream id a >= b (both "ms-seq", compared
// numerically).
func streamIDAtLeast(a, b string) bool {
	aMs, aSeq, aOK := splitStreamID(a)
	bMs, bSeq, bOK := splitStreamID(b)
	if !aOK || !bOK {
		return false
	}
	return aMs > bMs || (aMs == bMs && aSeq >= bSeq)
}

func splitStreamID(id string) (ms, seq uint64, ok bool) {
	msStr, seqStr, found := strings.Cut(id, "-")
	if !found {
		return 0, 0, false
	}
	var err error
	if ms, err = strconv.ParseUint(msStr, 10, 64); err != nil {
		return 0, 0, false
	}
	if seq, err = strconv.ParseUint(seqStr, 10, 64); err != nil {
		return 0, 0, false
	}
	return ms, seq, true
}
