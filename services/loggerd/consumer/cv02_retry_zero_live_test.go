package consumer

// CV-02 live acceptance: the recorded-zero correction proven on the REAL
// path — eventpublisher.RedisPublisher XAdd → Redis stream wire → consumer
// delivery → request_logs row in PostgreSQL. Two orgs share one stand:
//
//   - org A (instrumented): a chat-completions single-attempt completion —
//     AttemptCount=1, RetryCount=0, FirstTokenMs=0 exactly as the
//     chat/stream gateway publishes on a clean first try. The row MUST read
//     attempt_count=1, retry_count=0 (measured zero, NOT NULL) and
//     first_token_ms NULL (present zero = not measured).
//   - org B (uninstrumented): an embeddings-shaped event whose
//     AttemptCount/RetryCount/FirstTokenMs stay at the Go zero values —
//     pkg/gateway/embeddings_endpoint.go, images_endpoint.go and
//     audio_transcriptions.go build exactly this shape — so the WIRE
//     carries present "0"/"0" keys that must still bind NULL/NULL.
//   - org B (legacy): a pre-observability event replay without the three
//     keys at all → NULL/NULL.
//
// The wire is inspected (XRANGE) before delivery so the presence contract
// itself is pinned: the publisher emits the keys unconditionally, which is
// why attempt_count>0 — not key presence — is the attribution signal.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cv02RecordedOrgID = "3b1f0a2c-9d4e-4f67-8a15-2c6d7e8f90a1"
	cv02PlainOrgID    = "5c8e2d1a-7b3f-4c58-9d26-1e4f5a6b70c2"
	cv02LiveStream    = "events:cv02-live"
)

func newCV02LiveEnv(t *testing.T) (context.Context, *pgxpool.Pool, *redis.Client) {
	t.Helper()
	pool := testdb.PostgresRegion(t, "e2e")
	redisClient := testdb.Redis(t)
	creditsIntegrationMu.Lock()
	t.Cleanup(creditsIntegrationMu.Unlock)

	ctx := context.Background()
	for _, org := range []struct{ id, slug string }{
		{cv02RecordedOrgID, "cv02-recorded"},
		{cv02PlainOrgID, "cv02-plain"},
	} {
		_, err := pool.Exec(ctx, `
			INSERT INTO organizations (id, name, slug)
			VALUES ($1, $2, $2)
			ON CONFLICT (id) DO NOTHING`, org.id, org.slug)
		require.NoError(t, err)
	}
	_, err := pool.Exec(ctx, `TRUNCATE request_logs, sessions, messages, tool_calls, tool_call_invocations, event_inbox, settlement_jobs CASCADE`)
	require.NoError(t, err)
	require.NoError(t, redisClient.FlushDB(ctx).Err())
	return ctx, pool, redisClient
}

// cv02AttemptRow reads one request_logs row's attempt-family columns as
// nullable pointers, so NULL vs 0 is asserted exactly.
func cv02AttemptRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, requestID, orgID string) (*int64, *int64, *int64) {
	t.Helper()
	var firstToken, attempts, retries *int64
	err := pool.QueryRow(ctx,
		`SELECT first_token_ms, attempt_count, retry_count FROM request_logs
		 WHERE request_id = $1 AND org_id = $2`, requestID, orgID).
		Scan(&firstToken, &attempts, &retries)
	require.NoError(t, err)
	return firstToken, attempts, retries
}

func TestCV02Live_RecordedZeroProjection(t *testing.T) {
	ctx, pool, rdb := newCV02LiveEnv(t)
	pub := eventpublisher.NewRedisPublisher(rdb, cv02LiveStream)

	// Org A: instrumented chat shape — the gateway's clean first-try
	// completion. AttemptCount/RetryCount/FirstTokenMs are set explicitly,
	// including the real zero.
	recorded := &eventpublisher.Event{
		EventType:      "request.completed",
		Source:         "gateway",
		RequestID:      "req-cv02-recorded-zero",
		SessionID:      "ses_cv02_recorded",
		Payload:        `{"model":"gpt-4","messages":[]}`,
		OrgID:          cv02RecordedOrgID,
		ModelRequested: "gpt-4",
		ModelUsed:      "gpt-4-turbo",
		UpstreamURL:    "https://api.openai.com/v1/chat/completions",
		StatusCode:     200,
		DurationMs:     1500,
		TokensIn:       100,
		TokensOut:      250,
		Method:         "POST",
		Endpoint:       "chat.completions",
		UsageSource:    "none",
		CostStatus:     "no_usage",
		FirstTokenMs:   0, // non-streaming: present zero = not measured
		AttemptCount:   1, // primary hop only
		RetryCount:     0, // the recorded single-attempt zero
	}
	require.NoError(t, pub.Publish(ctx, recorded))

	// Org B: uninstrumented embeddings shape — AttemptCount/RetryCount/
	// FirstTokenMs left at the Go zero values exactly like
	// embeddings_endpoint.go / images_endpoint.go / audio_transcriptions.go.
	uninstrumented := &eventpublisher.Event{
		EventType:      "request.completed",
		Source:         "gateway",
		RequestID:      "req-cv02-uninstrumented",
		SessionID:      "ses_cv02_embed",
		Payload:        `{"model":"text-embedding-3-small","input":"cv-02"}`,
		OrgID:          cv02PlainOrgID,
		ModelRequested: "text-embedding-3-small",
		ModelUsed:      "text-embedding-3-small",
		UpstreamURL:    "https://api.openai.com/v1/embeddings",
		StatusCode:     200,
		DurationMs:     40,
		TokensIn:       12,
		TokensOut:      0,
		Method:         "POST",
		Endpoint:       "embeddings",
		UsageSource:    "none",
		CostStatus:     "no_usage",
		// FirstTokenMs / AttemptCount / RetryCount: deliberately unset.
	}
	require.NoError(t, pub.Publish(ctx, uninstrumented))

	// Wire presence contract: the publisher emits the counter keys
	// unconditionally (zero values stringified), which is why only
	// attempt_count>0 attributes the family.
	entries, err := rdb.XRange(ctx, cv02LiveStream, "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, entries, 2)
	wire := map[string]map[string]string{}
	for _, e := range entries {
		row := map[string]string{}
		for k, v := range e.Values {
			row[k] = fmt.Sprint(v)
		}
		wire[row["request_id"]] = row
	}
	assert.Equal(t, "1", wire["req-cv02-recorded-zero"]["attempt_count"], "wire attempt_count (org A)")
	assert.Equal(t, "0", wire["req-cv02-recorded-zero"]["retry_count"], "wire retry_count (org A) — real zero on the wire")
	assert.Equal(t, "0", wire["req-cv02-recorded-zero"]["first_token_ms"], "wire first_token_ms (org A)")
	assert.Equal(t, "0", wire["req-cv02-uninstrumented"]["attempt_count"], "wire attempt_count (org B) — uninstrumented zero STILL PRESENT on the wire")
	assert.Equal(t, "0", wire["req-cv02-uninstrumented"]["retry_count"], "wire retry_count (org B) — uninstrumented zero STILL PRESENT on the wire")

	// Deliver every published entry through the real consumer boundary.
	c := New(NewRedisOps(rdb), NewDBOps(pool), cv02LiveStream, silentLogger())
	for _, e := range entries {
		c.handleMessage(ctx, e)
	}

	// Org B legacy replay: a pre-observability event with none of the three
	// keys (the shape services/loggerd/integration replays). NULLs must hold.
	legacy := redis.XMessage{ID: "cv02-legacy-0001", Values: map[string]interface{}{
		"event_type":      "request.completed",
		"source":          "gateway",
		"request_id":      "req-cv02-legacy",
		"session_id":      "ses_cv02_legacy",
		"org_id":          cv02PlainOrgID,
		"model_requested": "gpt-4",
		"model_used":      "gpt-4-turbo",
		"status_code":     "200",
		"duration_ms":     "1500",
		"tokens_in":       "100",
		"tokens_out":      "250",
		"method":          "POST",
	}}
	c.handleMessage(ctx, legacy)

	// THE corrected SQL fact: recorded single-attempt zero lands as 0.
	firstToken, attempts, retries := cv02AttemptRow(t, ctx, pool, "req-cv02-recorded-zero", cv02RecordedOrgID)
	require.NotNil(t, attempts, "attempt_count must bind (attributed)")
	assert.Equal(t, int64(1), *attempts, "attempt_count")
	require.NotNil(t, retries, "retry_count must bind — recorded zero is NOT unknown")
	assert.Equal(t, int64(0), *retries, "retry_count — SQL 0 for a real single-attempt request")
	assert.Nil(t, firstToken, "first_token_ms — present zero still means not measured")

	// Uninstrumented shape: present 0/0 on the wire binds NULL/NULL.
	firstToken, attempts, retries = cv02AttemptRow(t, ctx, pool, "req-cv02-uninstrumented", cv02PlainOrgID)
	assert.Nil(t, attempts, "attempt_count — uninstrumented 0/0 is unknown")
	assert.Nil(t, retries, "retry_count — uninstrumented 0/0 is unknown")
	assert.Nil(t, firstToken, "first_token_ms")

	// Legacy shape: absent keys bind NULL/NULL.
	firstToken, attempts, retries = cv02AttemptRow(t, ctx, pool, "req-cv02-legacy", cv02PlainOrgID)
	assert.Nil(t, attempts, "attempt_count — legacy absent is unknown")
	assert.Nil(t, retries, "retry_count — legacy absent is unknown")
	assert.Nil(t, firstToken, "first_token_ms")

	// Org isolation on the shared stand: each org sees exactly its own rows.
	var orgARows, orgBRows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM request_logs WHERE org_id = $1`, cv02RecordedOrgID).Scan(&orgARows))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM request_logs WHERE org_id = $1`, cv02PlainOrgID).Scan(&orgBRows))
	assert.Equal(t, 1, orgARows, "org A rows")
	assert.Equal(t, 2, orgBRows, "org B rows")

	// Business-time sanity: the row carries the publisher-stamped event
	// clock (TS was zero; Publish stamps it), never a zero created_at.
	var createdAt time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT created_at FROM request_logs WHERE request_id = 'req-cv02-recorded-zero'`).Scan(&createdAt))
	assert.False(t, createdAt.IsZero(), "created_at must be stamped")
}
