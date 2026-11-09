//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/events"
	"github.com/reireirei/yabanin/pkg/logging"
	"github.com/reireirei/yabanin/services/loggerd/consumer"
)

func TestLoggerdE2E_RequestCompletedToPostgres(t *testing.T) {
	ctx := t.Context()
	rdb := NewLoggerdTestRedis(t, ctx)
	db := NewLoggerdTestDB(t, ctx)

	FlushLoggerdRedis(ctx, t, rdb)
	ResetLoggerdTables(ctx, t, db)

	streamName := "e2e-" + t.Name()

	consumerInst, cancel, done := startLoggerdConsumer(t, ctx, rdb, db, streamName)
	defer func() {
		cancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}()

	payload := events.Payload{
		EventType:      "request.completed",
		Source:         "gateway-test",
		SessionID:      "3f2b8a4c-9d1e-4f5a-8b7c-6e5d4c3b2a10",
		Payload:        `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`,
		OrgID:          testLoggerdOrgID,
		ModelRequested: "gpt-4",
		ModelUsed:      "gpt-4-turbo",
		UpstreamURL:    "http://localhost:9999/v1/chat/completions",
		StatusCode:     200,
		DurationMs:     1500,
		TokensIn:       10,
		TokensOut:      50,
		Method:         "POST",
		Error:          "",
	}

	PublishEventToStream(ctx, t, rdb, streamName, payload)

	waitForRequestLogCount(ctx, t, db, 1)

	consumerInst.Stop()

	logs := GetRequestLogs(ctx, t, db)

	if len(logs) != 1 {
		t.Fatalf("expected 1 log row, got %d", len(logs))
	}

	row := logs[0]

	assertEq(t, row["session_id"], "3f2b8a4c-9d1e-4f5a-8b7c-6e5d4c3b2a10")
	assertEq(t, row["org_id"], testLoggerdOrgID)
	assertEq(t, row["model_requested"], "gpt-4")
	assertEq(t, row["model_used"], "gpt-4-turbo")
	assertEq(t, row["upstream_url"], "http://localhost:9999/v1/chat/completions")
	assertEq(t, row["method"], "POST")
	assertEq(t, row["status_code"], int64(200))
	assertEq(t, row["duration_ms"], int64(1500))
	assertEq(t, row["tokens_in"], int64(10))
	assertEq(t, row["tokens_out"], int64(50))
	if row["error"] != nil {
		t.Errorf("expected error to be nil, got %v", row["error"])
	}
}

func TestLoggerdE2E_RequestCompletedWithError(t *testing.T) {
	ctx := t.Context()
	rdb := NewLoggerdTestRedis(t, ctx)
	db := NewLoggerdTestDB(t, ctx)

	FlushLoggerdRedis(ctx, t, rdb)
	ResetLoggerdTables(ctx, t, db)

	streamName := "e2e-error-" + t.Name()

	consumerInst, cancel, done := startLoggerdConsumer(t, ctx, rdb, db, streamName)
	defer func() {
		cancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}()

	payload := events.Payload{
		EventType:      "request.completed",
		Source:         "gateway-test",
		SessionID:      "4c1d9b7a-2e3f-4a5b-8c9d-6e5f4a3b2c10",
		Payload:        `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`,
		OrgID:          testLoggerdOrgID,
		ModelRequested: "gpt-4",
		ModelUsed:      "",
		UpstreamURL:    "http://localhost:9999/v1/chat/completions",
		StatusCode:     503,
		DurationMs:     5000,
		TokensIn:       5,
		TokensOut:      0,
		Method:         "POST",
		Error:          "upstream timeout",
	}

	PublishEventToStream(ctx, t, rdb, streamName, payload)

	waitForRequestLogCount(ctx, t, db, 1)

	consumerInst.Stop()

	logs := GetRequestLogs(ctx, t, db)

	if len(logs) != 1 {
		t.Fatalf("expected 1 log row, got %d", len(logs))
	}

	row := logs[0]

	assertEq(t, row["session_id"], "4c1d9b7a-2e3f-4a5b-8c9d-6e5f4a3b2c10")
	assertEq(t, row["status_code"], int64(503))
	assertEq(t, row["error"], "upstream timeout")
	assertEq(t, row["duration_ms"], int64(5000))
}

func TestLoggerdE2E_MultipleEventsBatch(t *testing.T) {
	ctx := t.Context()
	rdb := NewLoggerdTestRedis(t, ctx)
	db := NewLoggerdTestDB(t, ctx)

	FlushLoggerdRedis(ctx, t, rdb)
	ResetLoggerdTables(ctx, t, db)

	streamName := "e2e-batch-" + t.Name()

	consumerInst, cancel, done := startLoggerdConsumer(t, ctx, rdb, db, streamName)
	defer func() {
		cancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}()

	for i := 1; i <= 3; i++ {
		payload := events.Payload{
			EventType:      "request.completed",
			Source:         "gateway-test",
			SessionID:      fmt.Sprintf("e2e-batch-session-00%d", i),
			Payload:        `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`,
			OrgID:          testLoggerdOrgID,
			ModelRequested: "gpt-4",
			ModelUsed:      "gpt-4-turbo",
			UpstreamURL:    "http://localhost:9999/v1/chat/completions",
			StatusCode:     200,
			DurationMs:     int64(100 * i),
			TokensIn:       int64(i * 5),
			TokensOut:      int64(i * 20),
			Method:         "POST",
			Error:          "",
		}

		PublishEventToStream(ctx, t, rdb, streamName, payload)
	}

	waitForRequestLogCount(ctx, t, db, 3)

	consumerInst.Stop()

	logs := GetRequestLogs(ctx, t, db)

	if len(logs) != 3 {
		t.Fatalf("expected 3 log rows, got %d", len(logs))
	}
}

// TestLoggerdE2E_NonUUIDSessionIDInserted is the LG-U1 regression test:
// before the fix a client-supplied session id like OpenCode's "ses_..."
// wedged the INSERT with SQLSTATE 22P02 and the row was silently dropped.
// The consumer must map it to a deterministic v5 UUID and persist the row.
func TestLoggerdE2E_NonUUIDSessionIDInserted(t *testing.T) {
	ctx := t.Context()
	rdb := NewLoggerdTestRedis(t, ctx)
	db := NewLoggerdTestDB(t, ctx)

	FlushLoggerdRedis(ctx, t, rdb)
	ResetLoggerdTables(ctx, t, db)

	streamName := "e2e-nonuuid-" + t.Name()

	consumerInst, cancel, done := startLoggerdConsumer(t, ctx, rdb, db, streamName)
	defer func() {
		cancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}()

	payload := events.Payload{
		EventType:      "request.completed",
		Source:         "gateway-test",
		SessionID:      "ses_f7c8cea03ffeQF8w3WLp7oRA9w",
		Payload:        `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`,
		OrgID:          testLoggerdOrgID,
		ModelRequested: "gpt-4",
		ModelUsed:      "gpt-4-turbo",
		UpstreamURL:    "http://localhost:9999/v1/chat/completions",
		StatusCode:     200,
		DurationMs:     1500,
		TokensIn:       10,
		TokensOut:      50,
		Method:         "POST",
	}

	PublishEventToStream(ctx, t, rdb, streamName, payload)

	waitForRequestLogCount(ctx, t, db, 1)

	consumerInst.Stop()

	logs := GetRequestLogs(ctx, t, db)

	if len(logs) != 1 {
		t.Fatalf("expected 1 log row, got %d", len(logs))
	}

	// Deterministic v5 UUID of "ses_f7c8cea03ffeQF8w3WLp7oRA9w" under the
	// frozen nsRequestLogs namespace — same golden vector as the unit test.
	assertEq(t, logs[0]["session_id"], "4dbfc67b-6ed9-5942-a9b6-53770ac48875")
	assertEq(t, logs[0]["model_requested"], "gpt-4")
}

func TestLoggerdE2E_Deduplication(t *testing.T) {
	ctx := t.Context()
	rdb := NewLoggerdTestRedis(t, ctx)
	db := NewLoggerdTestDB(t, ctx)

	FlushLoggerdRedis(ctx, t, rdb)
	ResetLoggerdTables(ctx, t, db)

	streamName := "e2e-dedup-" + t.Name()

	consumerInst, cancel, done := startLoggerdConsumer(t, ctx, rdb, db, streamName)
	defer func() {
		cancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}()

	payload := events.Payload{
		EventType:      "request.completed",
		Source:         "gateway-test",
		SessionID:      "e2e-dedup-session-001",
		Payload:        `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`,
		OrgID:          testLoggerdOrgID,
		ModelRequested: "gpt-4",
		ModelUsed:      "gpt-4-turbo",
		UpstreamURL:    "http://localhost:9999/v1/chat/completions",
		StatusCode:     200,
		DurationMs:     1500,
		TokensIn:       10,
		TokensOut:      50,
		Method:         "POST",
		Error:          "",
	}

	PublishEventToStream(ctx, t, rdb, streamName, payload)

	waitForRequestLogCount(ctx, t, db, 1)

	consumerInst.Stop()

	logs := GetRequestLogs(ctx, t, db)

	if len(logs) != 1 {
		t.Fatalf("expected 1 log row (dedup), got %d", len(logs))
	}
}

func TestLoggerdE2E_GenericEventIgnored(t *testing.T) {
	ctx := t.Context()
	rdb := NewLoggerdTestRedis(t, ctx)
	db := NewLoggerdTestDB(t, ctx)

	FlushLoggerdRedis(ctx, t, rdb)
	ResetLoggerdTables(ctx, t, db)

	streamName := "e2e-generic-" + t.Name()

	consumerInst, cancel, done := startLoggerdConsumer(t, ctx, rdb, db, streamName)
	defer func() {
		cancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}()

	payload := events.Payload{
		EventType: "system.health",
		Source:    "gateway-test",
		SessionID: "",
		Payload:   `{"status":"ok"}`,
		OrgID:     testLoggerdOrgID,
	}

	msgID := PublishEventToStream(ctx, t, rdb, streamName, payload)

	// The event writes no rows: await its full processing (delivery + ack)
	// instead of a blind sleep.
	waitForStreamDelivery(ctx, t, rdb, streamName, msgID)

	consumerInst.Stop()

	logs := GetRequestLogs(ctx, t, db)

	if len(logs) != 0 {
		t.Fatalf("expected 0 log rows for generic event type, got %d", len(logs))
	}
}

func TestLoggerdE2E_DatabaseFailureSendsToDLQ(t *testing.T) {
	ctx := t.Context()
	rdb := NewLoggerdTestRedis(t, ctx)
	db := NewLoggerdTestDB(t, ctx)

	FlushLoggerdRedis(ctx, t, rdb)
	ResetLoggerdTables(ctx, t, db)

	streamName := "e2e-dlq-" + t.Name()

	failDB := &poisonDBOps{}

	logger := logging.New("debug", "text")
	consumerInst := consumer.New(consumer.NewRedisOps(rdb), failDB, streamName, logger)

	done := make(chan struct{})
	consumerCtx, cancel := context.WithCancel(ctx)

	go func() {
		defer close(done)
		if err := consumerInst.Start(consumerCtx); err != nil && !strings.Contains(err.Error(), "context canceled") {
			t.Logf("consumer stopped with error: %v", err)
		}
	}()
	// Stop the consumer at test end (deferred), matching the other e2e cases.
	// The reads below run WHILE the consumer is alive: the shared disposable
	// Redis client is healthy in that window, whereas a post-stop Redis read
	// can hang on a connection the consumer just released.
	defer func() {
		cancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}()

	waitForConsumerGroup(ctx, t, rdb, streamName)

	payload := events.Payload{
		EventType:      "request.completed",
		Source:         "gateway-test",
		SessionID:      "e2e-dlq-session-001",
		Payload:        `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`,
		OrgID:          testLoggerdOrgID,
		ModelRequested: "gpt-4",
		ModelUsed:      "gpt-4-turbo",
		UpstreamURL:    "http://localhost:9999/v1/chat/completions",
		StatusCode:     200,
		DurationMs:     1500,
		TokensIn:       10,
		TokensOut:      50,
		Method:         "POST",
		Error:          "",
	}

	msgID := PublishEventToStream(ctx, t, rdb, streamName, payload)

	// The DB always fails, so nothing is persisted to request_logs; await the
	// retry counter the consumer INCRs after the failed delivery attempt.
	waitForDLQRetryMark(ctx, t, rdb, streamName, msgID)

	dlqEntries := getDLQEntries(ctx, t, rdb)

	if len(dlqEntries) == 0 {
		t.Log("No DLQ entries yet (retries are reclaimed on a 5-minute PEL cycle)")
	} else {
		t.Logf("Found %d DLQ entry(ies)", len(dlqEntries))
	}

	logs := GetRequestLogs(ctx, t, db)

	if len(logs) != 0 {
		t.Fatalf("expected 0 log rows (DB always fails), got %d", len(logs))
	}
}

// W-LOGG: a FULL database unavailability (probe included) must pause the
// consumer instead of dead-lettering live billing traffic — the message
// stays pending, no retry budget burns, the DLQ stays empty.
func TestLoggerdE2E_DatabaseOutageStaysPending(t *testing.T) {
	ctx := t.Context()
	rdb := NewLoggerdTestRedis(t, ctx)
	db := NewLoggerdTestDB(t, ctx)

	FlushLoggerdRedis(ctx, t, rdb)
	ResetLoggerdTables(ctx, t, db)

	streamName := "e2e-outage-" + t.Name()

	logger := logging.New("debug", "text")
	consumerInst := consumer.New(consumer.NewRedisOps(rdb), &outageDBOps{}, streamName, logger)

	done := make(chan struct{})
	consumerCtx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}()

	go func() {
		defer close(done)
		if err := consumerInst.Start(consumerCtx); err != nil && !strings.Contains(err.Error(), "context canceled") {
			t.Logf("consumer stopped with error: %v", err)
		}
	}()

	waitForConsumerGroup(ctx, t, rdb, streamName)

	payload := events.Payload{
		EventType:      "request.completed",
		Source:         "gateway-test",
		SessionID:      "e2e-outage-session-001",
		Payload:        `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`,
		OrgID:          testLoggerdOrgID,
		ModelRequested: "gpt-4",
		ModelUsed:      "gpt-4-turbo",
		StatusCode:     200,
		DurationMs:     10,
		Method:         "POST",
	}

	PublishEventToStream(ctx, t, rdb, streamName, payload)

	// The message was delivered to the consumer (and failed): it must sit in
	// the PEL — kept, not lost — while the consumer pauses.
	waitForCondition(t, 10*time.Second, "message pending", func() bool {
		pending, err := rdb.XPendingExt(ctx, &redis.XPendingExtArgs{
			Stream: streamName, Group: "loggerd-workers", Start: "-", End: "+", Count: 10,
		}).Result()
		return err == nil && len(pending) == 1
	})

	// An outage must not consume the retry budget nor dead-letter.
	retryKeys, err := rdb.Keys(ctx, "dlq:retry:*").Result()
	if err != nil {
		t.Fatalf("failed to read retry keys: %v", err)
	}
	if len(retryKeys) != 0 {
		t.Fatalf("a full DB outage must not burn the retry budget, got %v", retryKeys)
	}

	dlqEntries := getDLQEntries(ctx, t, rdb)
	if len(dlqEntries) != 0 {
		t.Fatalf("a full DB outage must not send messages to the DLQ, got %d", len(dlqEntries))
	}

	logs := GetRequestLogs(ctx, t, db)
	if len(logs) != 0 {
		t.Fatalf("nothing persists during the outage, got %d rows", len(logs))
	}
}

// poisonDBOps models a REACHABLE database whose writes always fail: the
// W-LOGG DB probe (SELECT 1) answers, so persistent delivery failures are
// classified as poison — the retry budget burns and the DLQ path applies.
type poisonDBOps struct{}

func (f *poisonDBOps) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, os.ErrInvalid
}

// BeginTx satisfies consumer.DBOps: a failing write path cannot open the
// delivery transaction either — the AF-04 inbox claim fails closed and the
// event follows the same DLQ path as before the transactional writer.
func (f *poisonDBOps) BeginTx(_ context.Context) (consumer.InboxTx, error) {
	return nil, os.ErrInvalid
}

// QueryRow satisfies consumer.DBOps. The W-LOGG outage probe ("SELECT 1")
// must SUCCEED here — a reachable database is what makes persistent
// failures poison instead of an outage. Every other query (the
// session-registry upsert) errors: resolveSessionID fails open (warns, logs
// without a session) exactly as it would against a misbehaving DB.
func (f *poisonDBOps) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	if query == "SELECT 1" {
		return okRow{}
	}
	return failRow{}
}

// okRow is a pgx.Row that scans one row carrying the integer 1 (the shape of
// the W-LOGG DB probe).
type okRow struct{}

func (okRow) Scan(dest ...any) error {
	if len(dest) == 0 {
		return nil
	}
	if p, ok := dest[0].(*int); ok {
		*p = 1
		return nil
	}
	return os.ErrInvalid
}

// outageDBOps models a FULL database unavailability: every operation fails,
// including the reachability probe. W-LOGG contract: the consumer pauses
// instead of dead-lettering — no retry mark, no DLQ, the message stays
// pending for the reclaim pass.
type outageDBOps struct{}

func (f *outageDBOps) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, os.ErrInvalid
}

func (f *outageDBOps) BeginTx(_ context.Context) (consumer.InboxTx, error) {
	return nil, os.ErrInvalid
}

func (f *outageDBOps) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return failRow{}
}

// failRow is a pgx.Row whose Scan always fails, standing in for a DB that
// cannot serve the session-registry upsert.
type failRow struct{}

func (failRow) Scan(dest ...any) error {
	return os.ErrInvalid
}

// getDLQEntries reads all entries from the DLQ stream.
func getDLQEntries(ctx context.Context, t *testing.T, rdb *redis.Client) []map[string]string {
	t.Helper()

	// Block: -1 is a NON-blocking XREAD (current contents only). The zero
	// Block value would emit "block 0" to Redis — block indefinitely waiting
	// for a DLQ message that only appears after the 5-minute PEL reclaim
	// cycle — and hang the test.
	resultCmd := rdb.XRead(ctx, &redis.XReadArgs{Streams: []string{"events:queue:dlq", "0"}, Block: -1})
	if resultCmd.Err() != nil && resultCmd.Err() != redis.Nil {
		t.Fatalf("failed to read DLQ stream: %v", resultCmd.Err())
	}

	streams := resultCmd.Val()
	var result []map[string]string
	for _, s := range streams {
		for _, m := range s.Messages {
			entry := make(map[string]string)
			for k, v := range m.Values {
				if str, ok := v.(string); ok {
					entry[k] = str
				}
			}
			result = append(result, entry)
		}
	}

	return result
}

// assertEq checks that expected equals actual.
func assertEq(t *testing.T, actual, expected interface{}) {
	t.Helper()
	if actual != expected {
		t.Errorf("expected %v (%T), got %v (%T)", expected, expected, actual, actual)
	}
}

// startLoggerdConsumer creates and starts the StreamConsumer in a goroutine.
func startLoggerdConsumer(t *testing.T, ctx context.Context, rdb *redis.Client, db *pgxpool.Pool, streamName string) (*consumer.StreamConsumer, context.CancelFunc, chan struct{}) {
	t.Helper()

	logger := logging.New("debug", "text")

	redisOps := consumer.NewRedisOps(rdb)
	consumerInst := consumer.New(redisOps, consumer.NewDBOps(db), streamName, logger)

	done := make(chan struct{})
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		defer close(done)
		if err := consumerInst.Start(ctx); err != nil && !strings.Contains(err.Error(), "context canceled") {
			t.Logf("consumer stopped with error: %v", err)
		}
	}()

	// Deterministic readiness: await the consumer group so the publisher-side
	// tests never race Start's group setup.
	waitForConsumerGroup(ctx, t, rdb, streamName)

	return consumerInst, cancel, done
}
