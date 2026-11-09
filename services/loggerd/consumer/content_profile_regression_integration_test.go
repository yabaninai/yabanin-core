//go:build integration

package consumer

// the SELECTED content profile must be confirmed by observable behavior —
// the actual request_logs row a real Postgres stores, the real production
// logger output, the real Redis DLQ stream and the real retention archive —
// not by re-reading the implementation. Each scenario runs the real
// handleMessage boundary (NewDBOps + NewRedisOps over disposable testdb
// stands) with unique sentinels and asserts, per artifact, that content
// captures are gone while identity/accounting and the prompt digest remain;
// the legacy control proves the checks distinguish the profiles instead of
// passing vacuously (broken-vs-fixed). The gateway producer side of the

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/logging"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cprNewOrg seeds one organization and returns its uuid: request_logs.org_id
// and sessions.org_id are uuid-typed, so the regression events must carry a
// real identity exactly like production traffic. Raw SQL (not
// adminstore.CreateOrganization) so the scenario never depends on the
// org_credits row some package tests drop and recreate around themselves.
func cprNewOrg(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(context.Background(),
		"INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text", slug).Scan(&id))
	return id
}

// cprCompletedEvent builds a request.completed event in the producer wire
// shape: full content captures with unique sentinels, a malformed supplied
// digest (never persisted under any profile), uuid org identity and a
// labels object the mapper accepts. withWire stamps the wire-declared
// content_profile; an old producer event omits the key entirely.
func cprCompletedEvent(requestID, orgID string, withWire bool) map[string]interface{} {
	fields := map[string]interface{}{
		"event_type":         "request.completed",
		"source":             "gateway",
		"ts":                 "1759800000000",
		"request_id":         requestID,
		"org_id":             orgID,
		"session_id":         "sess-regression-1",
		"model_requested":    "gpt-5-mini",
		"model_used":         "gpt-5",
		"upstream_url":       "https://api.anthropic.com/v1/messages",
		"method":             "POST",
		"status_code":        "200",
		"duration_ms":        "321",
		"tokens_in":          "11",
		"tokens_out":         "7",
		"estimated_cost_usd": "0.0125",
		"payload":            cpSentinelPayload,
		"upstream_payload":   cpSentinelUpReq,
		"upstream_response":  cpSentinelUpResp,
		"error":              cpSentinelError,
		"prompt_hash":        "definitely-not-a-valid-digest",
		"labels":             `{"lane":"r023-04"}`,
	}
	if withWire {
		fields["content_profile"] = "metadata-only"
	}
	return fields
}

// cprFailedEvent is the provider-failure shape: same sentinels, HTTP 502.
func cprFailedEvent(requestID, orgID string, withWire bool) map[string]interface{} {
	fields := cprCompletedEvent(requestID, orgID, withWire)
	fields["event_type"] = "request.failed"
	fields["status_code"] = "502"
	return fields
}

// cprDeliver runs one message through the real boundary against the real
// stores and returns the stored request_logs row as decoded JSON. The logger
// is a parameter so the diagnostics scenario can bind a production
// logging.New inside the stdout capture (loggers bind os.Stdout at
// construction). The consumer carries the PRODUCTION retention wiring
// (AdminOriginalRetentionStore over the real adminstore — run.Loggerd wires
// the same whenever a DB pool exists); the strict-profile scenarios are
// retention-independent, and the legacy-control scenario opts its org in
// explicitly (an opted-in org is what "legacy keeps content" means since
// the N02-P06 toggle gates the durable write).
func cprDeliver(t *testing.T, pool *pgxpool.Pool, rdb *redis.Client, logger *slog.Logger, fields map[string]interface{}) map[string]interface{} {
	t.Helper()
	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:queue", logger)
	c.SetOriginalRetentionStore(AdminOriginalRetentionStore{Store: adminstore.New(pool, silentLogger(), nil)})
	c.handleMessage(context.Background(), redis.XMessage{Values: fields})

	var raw []byte
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT row_to_json(rl.*) FROM request_logs rl WHERE request_id = $1",
		fields["request_id"]).Scan(&raw), "request_logs row must exist for %v", fields["request_id"])
	var row map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &row))
	return row
}

// cprAssertNoContentSentinel fails when any sentinel of the regression
// fixtures survives anywhere in the serialized row.
func cprAssertNoContentSentinel(t *testing.T, row map[string]interface{}) {
	t.Helper()
	body, err := json.Marshal(row)
	require.NoError(t, err)
	for _, sentinel := range []string{"TOP SECRET", "SUPER SECRET", cpSentinelError} {
		assert.NotContains(t, string(body), sentinel, "content sentinel must never reach the stored row")
	}
}

// cprToolRowCounts returns the tool_calls / tool_call_invocations row counts
// of one request (the strict profile must write none — names and arguments
// are content-derived).
func cprToolRowCounts(t *testing.T, pool *pgxpool.Pool, requestID string) (int, int) {
	t.Helper()
	var calls, invocations int
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT count(*) FROM tool_calls WHERE request_id = $1", requestID).Scan(&calls))
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT count(*) FROM tool_call_invocations WHERE request_id = $1", requestID).Scan(&invocations))
	return calls, invocations
}

// cprFindDLQEnvelope returns the flat DLQ stream fields and the decoded
// envelope of the entry whose structured payload carries the given unique
// request id (the shared DLQ stream may hold entries from other tests).
func cprFindDLQEnvelope(t *testing.T, rdb *redis.Client, requestID string) (map[string]interface{}, eventpublisher.DLQEnvelope) {
	t.Helper()
	msgs, err := rdb.XRange(context.Background(), dlqStreamName, "-", "+").Result()
	require.NoError(t, err, "XRANGE over the DLQ stream")
	for _, m := range msgs {
		payload, _ := m.Values["payload"].(string)
		var env eventpublisher.DLQEnvelope
		if json.Unmarshal([]byte(payload), &env) != nil {
			continue
		}
		if env.Values["request_id"] == requestID {
			return m.Values, env
		}
	}
	t.Fatalf("no DLQ entry found for request %s", requestID)
	return nil, eventpublisher.DLQEnvelope{}
}

// Contract example 1 (success): gateway local legacy + wire metadata-only —
// the stored row keeps identity, accounting and the SHA-256 digest of the
// trimmed body, and loses every content capture; no tool-call rows exist.
func TestIntegration_ContentProfile_CompletedRowMatchesSelectedProfile(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	pool := testdb.PostgresRegion(t, "r023-04")
	rdb := testdb.Redis(t)
	orgID := cprNewOrg(t, pool, "r023-04-completed")

	requestID := "req-reg-strict-completed"
	row := cprDeliver(t, pool, rdb, silentLogger(), cprCompletedEvent(requestID, orgID, true))

	assert.Equal(t, orgID, row["org_id"], "trusted org identity survives")
	assert.Equal(t, requestID, row["request_id"])
	assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), row["prompt_hash"],
		"the malformed supplied digest is recomputed from the body, never persisted verbatim")
	for _, col := range []string{"response", "upstream_request", "upstream_response"} {
		assert.Nil(t, row[col], "%s must bind SQL NULL under metadata-only", col)
	}
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, row["error"],
		"the event carried an error, so the row carries exactly the fixed safe text")
	assert.Equal(t, float64(200), row["status_code"])
	assert.Equal(t, float64(11), row["tokens_in"])
	assert.Equal(t, float64(7), row["tokens_out"])
	assert.Equal(t, float64(0.0125), row["cost_in_usd"], "accounting is never suppressed by the profile")
	cprAssertNoContentSentinel(t, row)

	calls, invocations := cprToolRowCounts(t, pool, requestID)
	assert.Zero(t, calls, "metadata-only never extracts tool calls")
	assert.Zero(t, invocations)
}

// Contract example 2 (provider failure): the failed row keeps status and the
// fixed safe error, and the production logger diagnostics for the same
// delivery — JSON and text — carry no sentinel in the actual stdout stream.
func TestIntegration_ContentProfile_FailedRowRedactsErrorInDBAndDiagnostics(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	pool := testdb.PostgresRegion(t, "r023-04")
	rdb := testdb.Redis(t)
	orgID := cprNewOrg(t, pool, "r023-04-failed")

	requestID := "req-reg-strict-failed"
	fields := cprFailedEvent(requestID, orgID, true)

	var row map[string]interface{}
	out := cpCaptureStdout(t, func() {
		row = cprDeliver(t, pool, rdb, logging.New("info", "json"), fields)
	})

	assert.Equal(t, float64(502), row["status_code"], "status survives redaction")
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, row["error"])
	for _, col := range []string{"response", "upstream_request", "upstream_response"} {
		assert.Nil(t, row[col])
	}
	cprAssertNoContentSentinel(t, row)

	assert.Contains(t, out, "failed request log inserted")
	assert.Contains(t, out, requestID, "safe identity stays in the diagnostic")
	assert.Contains(t, out, logging.ContentProfileRedactedDiagnostic)
	assert.NotContains(t, out, "SUPER SECRET", "the error diagnostic must not echo the sentinel")
	assert.NotContains(t, out, "TOP SECRET")

	// The text handler is wired through the same ReplaceAttr: the same
	// delivery in text format stays sentinel-free too.
	requestIDText := "req-reg-strict-failed-text"
	outText := cpCaptureStdout(t, func() {
		cprDeliver(t, pool, rdb, logging.New("info", "text"),
			cprFailedEvent(requestIDText, orgID, true))
	})
	assert.Contains(t, outText, "failed request log inserted")
	assert.Contains(t, outText, logging.ContentProfileRedactedDiagnostic)
	assert.NotContains(t, outText, "SUPER SECRET")
	assert.NotContains(t, outText, "TOP SECRET")
}

// Contract example 4 (compatibility): a metadata-only CONSUMER covers an old
// legacy producer — the process-local env alone suppresses an event that
// carries no wire key at all.
func TestIntegration_ContentProfile_LocalStrictEnvCoversLegacyProducer(t *testing.T) {
	pool := testdb.PostgresRegion(t, "r023-04")
	rdb := testdb.Redis(t)
	orgID := cprNewOrg(t, pool, "r023-04-local-strict")
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "metadata-only")

	requestID := "req-reg-local-strict"
	fields := cprCompletedEvent(requestID, orgID, false)
	require.NotContains(t, fields, "content_profile", "old producer: no wire declaration")

	row := cprDeliver(t, pool, rdb, silentLogger(), fields)

	assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), row["prompt_hash"])
	for _, col := range []string{"response", "upstream_request", "upstream_response"} {
		assert.Nil(t, row[col])
	}
	cprAssertNoContentSentinel(t, row)
}

// Contract example 4: the legacy debug switch cannot override the strict
// profile — response stays SQL NULL even with YABANIN_DEBUG_LOG_RESPONSE=true.
func TestIntegration_ContentProfile_DebugFlagCannotOverrideStrict(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "true")
	pool := testdb.PostgresRegion(t, "r023-04")
	rdb := testdb.Redis(t)
	orgID := cprNewOrg(t, pool, "r023-04-debug-flag")

	requestID := "req-reg-debug-flag"
	row := cprDeliver(t, pool, rdb, silentLogger(), cprCompletedEvent(requestID, orgID, true))

	assert.Nil(t, row["response"], "debug logging must never resurrect strict-profile content")
	cprAssertNoContentSentinel(t, row)
}

// Broken-vs-fixed control: the same event shape under the legacy profile
// still stores content verbatim and extracts tool calls — the checks above
// really distinguish the selected profile instead of passing for any input.
// Post-N02-P06 the delivery write is toggle-gated, so "legacy keeps
// content" means an OPTED-IN org: the fixture flips the org's original
// retention on through the real store before delivering.
func TestIntegration_ContentProfile_LegacyControlKeepsContent(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "")
	pool := testdb.PostgresRegion(t, "r023-04")
	rdb := testdb.Redis(t)
	orgID := cprNewOrg(t, pool, "r023-04-legacy")
	on := true
	require.NoError(t, adminstore.New(pool, silentLogger(), nil).
		UpdateOrgOriginalRetention(context.Background(), orgID, &on),
		"fixture: the control org opts in to original retention")

	requestID := "req-reg-legacy-control"
	row := cprDeliver(t, pool, rdb, silentLogger(), cprCompletedEvent(requestID, orgID, false))

	assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), row["prompt_hash"])
	assert.NotNil(t, row["response"], "legacy storage keeps the response capture")
	assert.NotNil(t, row["upstream_request"])
	assert.NotNil(t, row["upstream_response"])
	assert.Equal(t, cpSentinelError, row["error"], "legacy error text is verbatim")

	responseBody, err := json.Marshal(row["response"])
	require.NoError(t, err)
	assert.Contains(t, string(responseBody), "TOP SECRET PROMPT BODY")
	upstreamBody, err := json.Marshal(row["upstream_response"])
	require.NoError(t, err)
	assert.Contains(t, string(upstreamBody), "TOP SECRET COMPLETION")
	assert.Contains(t, string(upstreamBody), "get_weather")

	calls, invocations := cprToolRowCounts(t, pool, requestID)
	assert.Positive(t, calls, "legacy extraction still writes tool_calls")
	assert.Positive(t, invocations)
}

// Contract example 5, negative proof over the REAL stores (no mocks): a
// poison strict event (declared org has no row → the request_logs insert
// violates the FK) redelivered past the retry budget lands in the actual
// Redis DLQ stream, and the archived envelope is the strict allowlist shape
// — content captures and unknown keys absent, error normalized, digest
// present, identity and accounting preserved.
func TestIntegration_ContentProfile_PoisonReachesRealDLQWithoutContent(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	pool := testdb.PostgresRegion(t, "r023-04")
	rdb := testdb.Redis(t)
	missingOrg := uuid.NewString() // well-formed uuid, no organizations row

	requestID := "req-reg-poison-dlq"
	msg := redis.XMessage{ID: "cpr-poison-1", Values: cprCompletedEvent(requestID, missingOrg, true)}
	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:queue", silentLogger())

	// Real retry loop: every failed delivery INCRs the retry counter; only
	// the attempt past maxRetries archives the envelope.
	for i := 0; i <= maxRetries; i++ {
		c.handleMessage(context.Background(), msg)
	}

	dlqFields, env := cprFindDLQEnvelope(t, rdb, requestID)

	assert.Equal(t, "events:queue", env.OriginalStream)
	assert.Equal(t, "cpr-poison-1", env.EntryID)
	assert.Equal(t, int64(maxRetries+1), env.RetryCount)
	assert.Equal(t, "max retries exceeded", env.Error)
	assert.Equal(t, "max retries exceeded", dlqFields["error"])

	assert.Equal(t, "request.completed", env.Values["event_type"])
	assert.Equal(t, requestID, env.Values["request_id"])
	assert.Equal(t, missingOrg, env.Values["org_id"], "trusted tenant identity is allowlisted metadata")
	assert.Equal(t, "metadata-only", env.Values["content_profile"])
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, env.Values["error"])
	assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), env.Values["prompt_hash"])
	assert.Equal(t, "200", fmt.Sprint(env.Values["status_code"]))
	assert.Equal(t, "11", fmt.Sprint(env.Values["tokens_in"]))
	assert.Equal(t, "7", fmt.Sprint(env.Values["tokens_out"]))
	for _, key := range []string{"payload", "upstream_payload", "upstream_response", "diagnostic_detail"} {
		assert.NotContains(t, env.Values, key, "content captures and unknown keys never reach the DLQ")
	}

	payload, _ := dlqFields["payload"].(string)
	assert.NotContains(t, payload, "TOP SECRET")
	assert.NotContains(t, payload, "SUPER SECRET")
}

// Contract example 7 (retention settings): a metadata-only row — content
// NULL, digest and accounting present — flows through the EXISTING per-team
// retention policy unchanged: redacted archive carries the hash and explicit
// nulls, export-before-delete removes the hot row, and the manifest pins the
// redaction. The profile changes what is stored; retention behavior is the
// same contract as before it.
func TestIntegration_ContentProfile_StrictRowArchivesUnderRetentionPolicy(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	pool := testdb.PostgresRegion(t, "r023-04")
	rdb := testdb.Redis(t)
	store := adminstore.New(pool, silentLogger(), nil)
	orgID := cprNewOrg(t, pool, fmt.Sprintf("r023-04-retention-%d", time.Now().UnixNano()))

	team, err := store.CreateTeam(context.Background(), orgID,
		"R023-04 retention team", fmt.Sprintf("r023-04-ret-team-%d", time.Now().UnixNano()), nil)
	require.NoError(t, err)

	requestID := "req-reg-retain"
	fields := cprCompletedEvent(requestID, orgID, true)
	fields["team_id"] = team.ID
	row := cprDeliver(t, pool, rdb, silentLogger(), fields)
	require.Equal(t, team.ID, row["team_id"], "fixture: the delivered row belongs to the policy's team")

	// Age the delivered row past the policy window.
	_, err = pool.Exec(context.Background(), `
		UPDATE request_logs SET created_at = now() - interval '2 days',
			updated_at = now() - interval '2 days'
		WHERE request_id = $1`, requestID)
	require.NoError(t, err)

	coldDir := t.TempDir()
	one := 1
	require.NoError(t, store.UpsertTeamRetentionPolicy(context.Background(), &adminstore.TeamRetentionPolicy{
		TeamID:              team.ID,
		RequestLogsDays:     &one,
		CacheEntriesDays:    &one,
		LineageDays:         &one,
		BackupSnapshotsDays: nil,
		RedactContent:       true,
		ColdDestination:     "file://" + coldDir,
		Enabled:             true,
	}))

	// Scope the tick to THIS team's assignment (the policy still
	// loads through the real store loader). The unscoped global sweep was
	// order-sensitive against other suites' leftovers in the shared
	// per-binary stand (their enabled policies + aged lineage rows leaked
	// into the exact-count stats; reproducible on the clean base under
	// -shuffle).
	w := NewRetentionWorker(pool, cppTeamScopedPolicies{inner: StorePolicySource{Store: store}, teamID: team.ID}, silentLogger()).
		WithConfig(RetentionConfig{Interval: time.Hour, CleanupEvery: time.Hour, BatchSize: 10, BatchesPerTick: 10})
	stats, err := w.tick(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, stats.RequestLogsExported, "the strict-profile row is exported and deleted")
	assert.Zero(t, stats.CacheEntriesExported)
	assert.Zero(t, stats.LineageExported)

	var hot int64
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT count(*) FROM request_logs WHERE request_id = $1", requestID).Scan(&hot))
	assert.Zero(t, hot, "export-before-delete removes the hot row")

	archive, err := filepath.Glob(filepath.Join(coldDir, "request_logs", team.ID, "*.jsonl"))
	require.NoError(t, err)
	require.Len(t, archive, 1)
	data, err := os.ReadFile(archive[0])
	require.NoError(t, err)
	assert.NotContains(t, string(data), "TOP SECRET")
	assert.NotContains(t, string(data), "SUPER SECRET")

	rows := splitJSONL(string(data))
	require.Len(t, rows, 1)
	var exported map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(rows[0]), &exported))

	assert.Equal(t, requestID, exported["request_id"])
	assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), exported["prompt_hash"],
		"the redacted archive retains the metadata-only digest")
	for _, col := range []string{"response", "upstream_request", "upstream_response", "error"} {
		assert.Nil(t, exported[col], "redacted %s exports as explicit null", col)
	}
	assert.Equal(t, float64(11), exported["tokens_in"], "accounting metadata is retained")
	assert.Equal(t, float64(7), exported["tokens_out"])
	assert.Equal(t, float64(0.0125), exported["cost_in_usd"])

	var mf exportManifest
	mfBytes, err := os.ReadFile(archive[0] + ".manifest.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(mfBytes, &mf))
	sum := sha256.Sum256(data)
	assert.Equal(t, hex.EncodeToString(sum[:]), mf.Sha256)
	assert.Equal(t, 1, mf.Rows)
	assert.True(t, mf.Redacted, "the redaction flag travels with the archive")
}
