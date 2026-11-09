//go:build integration

package consumer

// "Настройки записи prompt response metadata и retention" — verified through
// the ACTUAL consumer entry point, not direct helper calls. Every scenario
// here runs the real pipeline over disposable testcontainer stands:
//
//	producer (eventpublisher.RedisPublisher.Publish — the real gateway XADD
//	XREADGROUP consumer-group loop + PEL reclaim that `run.Loggerd` starts,
// boundary) → real Postgres request_logs / DLQ / retention archive.
//
// to this card is covered by asserting the WIRE entry itself (XRANGE): the
// strict wire carries content_profile + prompt_hash and no content captures;
// содержимое в ошибках") end-to-end: with the content-off profile the DB
// error column and the production logger diagnostics (JSON and text) carry
// no prompt/response content even when the wire still carried it. The
// legacy control proves the checks distinguish the profiles instead of
// passing vacuously.

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

// (full content captures with the shared golden sentinels, a malformed
// supplied digest, uuid org identity) as an eventpub.Event — the struct the
// real gateway funnel publishes. withWire stamps the wire-declared
// content_profile; an old producer event omits it entirely.
func cppEvent(requestID, orgID string, withWire bool) *eventpublisher.Event {
	event := &eventpublisher.Event{
		EventType:        "request.completed",
		Source:           "gateway",
		TS:               1759800000000,
		RequestID:        requestID,
		SessionID:        "sess-r023-05",
		OrgID:            orgID,
		ModelRequested:   "gpt-5-mini",
		ModelUsed:        "gpt-5",
		UpstreamURL:      "https://api.anthropic.com/v1/messages",
		Method:           "POST",
		StatusCode:       200,
		DurationMs:       321,
		TokensIn:         11,
		TokensOut:        7,
		EstimatedCostUSD: 0.0125,
		Payload:          cpSentinelPayload,
		UpstreamPayload:  cpSentinelUpReq,
		UpstreamResponse: cpSentinelUpResp,
		Error:            cpSentinelError,
		PromptHash:       "definitely-not-a-valid-digest",
		Labels:           map[string]string{"lane": "r023-05"},
	}
	if withWire {
		event.ContentProfile = "metadata-only"
	}
	return event
}

// cppFailedEvent is the provider-failure shape: same sentinels, HTTP 502.
func cppFailedEvent(requestID, orgID string, withWire bool) *eventpublisher.Event {
	event := cppEvent(requestID, orgID, withWire)
	event.EventType = "request.failed"
	event.StatusCode = 502
	return event
}

// cppPublish runs the REAL producer XADD step (RedisPublisher.Publish) —
// the same call the gateway publishEvent funnel makes after sanitization.
func cppPublish(t *testing.T, rdb *redis.Client, stream string, event *eventpublisher.Event) {
	t.Helper()
	require.NoError(t, eventpublisher.NewRedisPublisher(rdb, stream).Publish(context.Background(), event),
		"producer XADD must succeed against the disposable redis")
}

// cppAlwaysRetainStore is the producer-side view of an opted-in org: the
// N02-P06 producer gate resolves the org toggle through the same store
// contract, and an opted-in org keeps its captures on the wire.
type cppAlwaysRetainStore struct{}

func (cppAlwaysRetainStore) GetOrgOriginalRetention(_ context.Context, orgID string) (*adminstore.OrgOriginalRetention, error) {
	return &adminstore.OrgOriginalRetention{OrgID: orgID, Effective: true}, nil
}

// cppPublishRetained is cppPublish with the producer wired for an opted-in
// org — the pipeline shape "legacy profile + explicit retention opt-in"
// (the wire the gateway sends for such an org).
func cppPublishRetained(t *testing.T, rdb *redis.Client, stream string, event *eventpublisher.Event) {
	t.Helper()
	p := eventpublisher.NewRedisPublisher(rdb, stream)
	p.SetOriginalRetentionStore(cppAlwaysRetainStore{})
	require.NoError(t, p.Publish(context.Background(), event),
		"producer XADD must succeed against the disposable redis")
}

// cppStreamEntry returns the raw wire fields of the stream entry carrying
// the given unique request id — the producer→XADD acceptance surface the
func cppStreamEntry(t *testing.T, rdb *redis.Client, stream, requestID string) map[string]interface{} {
	t.Helper()
	msgs, err := rdb.XRange(context.Background(), stream, "-", "+").Result()
	require.NoError(t, err, "XRANGE over the produced stream")
	for _, m := range msgs {
		if id, _ := m.Values["request_id"].(string); id == requestID {
			return m.Values
		}
	}
	t.Fatalf("no stream entry found for request %s in %s", requestID, stream)
	return nil
}

// cppAssertWireHasNoContent fails when any content sentinel or content
// capture key survives on the raw wire entry.
func cppAssertWireHasNoContent(t *testing.T, wire map[string]interface{}) {
	t.Helper()
	for _, key := range []string{"payload", "upstream_payload", "upstream_response"} {
		assert.NotContains(t, wire, key, "content capture key must never ride the strict wire")
	}
	body, err := json.Marshal(wire)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "TOP SECRET")
	assert.NotContains(t, string(body), "SUPER SECRET")
}

// cppStartConsumer starts the REAL consumer entry point — StreamConsumer.Start,
// the XREADGROUP consumer-group loop plus PEL reclaim that run.Loggerd wires —
// against the disposable stands and blocks until the group is readable, so
// publishing afterwards is deterministic. reclaimIdle > 0 shrinks the
// behavioral reclaim seams (ms-scale poison/DLQ timelines); 0 keeps the
// production defaults. The returned stop cancels the loop and waits for it.
func cppStartConsumer(t *testing.T, rdb *redis.Client, pool *pgxpool.Pool, stream string, logger *slog.Logger, reclaimIdle time.Duration) func() {
	t.Helper()
	c := New(NewRedisOps(rdb), NewDBOps(pool), stream, logger)
	// Production parity: run.Loggerd wires the org original-retention
	// source whenever a DB pool exists; without it the consumer fails
	// closed to processed-only, which would silently change what these
	// scenarios assert.
	c.SetOriginalRetentionStore(AdminOriginalRetentionStore{Store: adminstore.New(pool, silentLogger(), nil)})
	if reclaimIdle > 0 {
		c.reclaimIdle = reclaimIdle
		c.reclaimEvery = reclaimIdle
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Start(ctx)
	}()
	cppWaitUntil(t, 15*time.Second, "consumer group on "+stream, func() bool {
		groups, err := rdb.XInfoGroups(context.Background(), stream).Result()
		if err != nil {
			return false // the stream key does not exist yet
		}
		for _, g := range groups {
			if g.Name == consumerGroup {
				return true
			}
		}
		return false
	})
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Log("consumer did not stop in time; continuing (row/DLQ assertions still apply)")
		}
	}
	t.Cleanup(stop)
	return stop
}

func cppWaitUntil(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// cppWaitRow polls the REAL Postgres request_logs table until the row for
// the given request id exists and returns it as decoded JSON — the DB side
// of the "logs DB confirms the selected profile" acceptance.
func cppWaitRow(t *testing.T, pool *pgxpool.Pool, requestID string) map[string]interface{} {
	t.Helper()
	var row map[string]interface{}
	cppWaitUntil(t, 20*time.Second, "request_logs row for "+requestID, func() bool {
		var raw []byte
		if err := pool.QueryRow(context.Background(),
			"SELECT row_to_json(rl.*) FROM request_logs rl WHERE request_id = $1",
			requestID).Scan(&raw); err != nil {
			return false
		}
		return json.Unmarshal(raw, &row) == nil
	})
	return row
}

// cppWaitDLQEnvelope polls the real Redis DLQ stream until the entry whose
// structured payload carries the given unique request id appears (the
// dlq:stream may hold entries from other tests) and returns the flat fields
// plus the decoded eventpublisher.DLQEnvelope — the `yb dlq replay` contract.
func cppWaitDLQEnvelope(t *testing.T, rdb *redis.Client, requestID string) (map[string]interface{}, eventpublisher.DLQEnvelope) {
	t.Helper()
	var (
		fields map[string]interface{}
		env    eventpublisher.DLQEnvelope
	)
	cppWaitUntil(t, 30*time.Second, "DLQ entry for "+requestID, func() bool {
		msgs, err := rdb.XRange(context.Background(), dlqStreamName, "-", "+").Result()
		if err != nil {
			return false
		}
		for _, m := range msgs {
			payload, _ := m.Values["payload"].(string)
			var candidate eventpublisher.DLQEnvelope
			if json.Unmarshal([]byte(payload), &candidate) != nil {
				continue
			}
			if candidate.Values["request_id"] == requestID {
				fields, env = m.Values, candidate
				return true
			}
		}
		return false
	})
	return fields, env
}

// Contract scenario "Настройки записи prompt response metadata" (wire
// direction): a producer that declares the metadata-only profile publishes
// through the real XADD step — the wire entry already carries no content
// captures, only content_profile + the recomputed prompt_hash — and the real
// consumer-group loop stores exactly the metadata-only row: identity,
// accounting and digest present, every content column SQL NULL, no
// tool-call extraction. The consumer env stays legacy here: the WIRE
// declaration alone must drive the policy (compatibility: old consumer env,
// new producer).
func TestIntegration_ContentProfilePipeline_WireProducerToDBMetadataOnly(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	pool := testdb.PostgresRegion(t, "r023-05")
	rdb := testdb.Redis(t)
	orgID := cprNewOrg(t, pool, fmt.Sprintf("r023-05-wire-%d", time.Now().UnixNano()))
	stream := fmt.Sprintf("events:r023-05-wire-%d", time.Now().UnixNano())

	requestID := "req-r023-05-wire-strict"
	cppPublish(t, rdb, stream, cppEvent(requestID, orgID, true))

	wire := cppStreamEntry(t, rdb, stream, requestID)
	assert.Equal(t, "metadata-only", wire["content_profile"])
	assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), wire["prompt_hash"],
		"the producer recomputes the malformed supplied digest from the raw body before stripping")
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, wire["error"])
	cppAssertWireHasNoContent(t, wire)

	stop := cppStartConsumer(t, rdb, pool, stream, silentLogger(), 0)
	row := cppWaitRow(t, pool, requestID)

	assert.Equal(t, orgID, row["org_id"], "trusted org identity survives the whole chain")
	assert.Equal(t, requestID, row["request_id"])
	assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), row["prompt_hash"],
		"the boundary-verified digest is stored byte-for-byte")
	for _, col := range []string{"response", "upstream_request", "upstream_response"} {
		assert.Nil(t, row[col], "%s must bind SQL NULL under metadata-only", col)
	}
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, row["error"])
	assert.Equal(t, float64(200), row["status_code"])
	assert.Equal(t, float64(11), row["tokens_in"])
	assert.Equal(t, float64(7), row["tokens_out"])
	assert.Equal(t, float64(0.0125), row["cost_in_usd"], "accounting is never suppressed by the profile")
	cprAssertNoContentSentinel(t, row)

	calls, invocations := cprToolRowCounts(t, pool, requestID)
	assert.Zero(t, calls, "metadata-only never extracts tool calls")
	assert.Zero(t, invocations)

	stop()
}

// Contract scenario "Настройки записи prompt response metadata" (deploy
// direction): the loggerd process is declared metadata-only via the deploy
// env (YABANIN_LOG_CONTENT_PROFILE) and covers an OLD legacy producer whose
// wire event still carries the full captures — the boundary strips them
// before anything downstream runs. This is the deployment compatibility
// path: the env knob alone must be sufficient.
func TestIntegration_ContentProfilePipeline_LocalStrictEnvCoversLegacyProducerWire(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "metadata-only")
	pool := testdb.PostgresRegion(t, "r023-05")
	rdb := testdb.Redis(t)
	orgID := cprNewOrg(t, pool, fmt.Sprintf("r023-05-env-%d", time.Now().UnixNano()))
	stream := fmt.Sprintf("events:r023-05-env-%d", time.Now().UnixNano())

	requestID := "req-r023-05-env-strict"
	cppPublish(t, rdb, stream, cppEvent(requestID, orgID, false))

	wire := cppStreamEntry(t, rdb, stream, requestID)
	assert.Equal(t, cpSentinelPayload, wire["payload"],
		"legacy producer wire is unchanged: the captures ride the stream")
	assert.NotContains(t, wire, "content_profile", "old producer declares no wire profile")
	assert.NotContains(t, wire, "prompt_hash")

	stop := cppStartConsumer(t, rdb, pool, stream, silentLogger(), 0)
	row := cppWaitRow(t, pool, requestID)

	assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), row["prompt_hash"],
		"the boundary recomputes the digest from the body BEFORE stripping it")
	for _, col := range []string{"response", "upstream_request", "upstream_response"} {
		assert.Nil(t, row[col], "%s must bind SQL NULL: the env declaration alone suppresses content", col)
	}
	cprAssertNoContentSentinel(t, row)

	calls, invocations := cprToolRowCounts(t, pool, requestID)
	assert.Zero(t, calls)
	assert.Zero(t, invocations)

	stop()
}

// Contract scenario "Проверка БД логов и диагностик подтверждает выбранный
// consumer entry point ("Отключение content logging оставляет содержимое в
// ошибках"): a legacy-shaped FAILED request (sentinel error, sentinel
// captures on the wire) delivered under the content-off profile — the DB
// error column carries exactly the fixed safe text, and the production
// logger diagnostics for the same delivery — JSON and text — stay
// sentinel-free in the actual stdout stream.
func TestIntegration_ContentProfilePipeline_FailedRequestDBAndDiagnosticsConfirmProfile(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "metadata-only")
	pool := testdb.PostgresRegion(t, "r023-05")
	rdb := testdb.Redis(t)
	orgID := cprNewOrg(t, pool, fmt.Sprintf("r023-05-failed-%d", time.Now().UnixNano()))

	// The loggers bind os.Stdout at construction, so the production logging.New
	// calls live inside the stdout captures; the consumer must be fully
	// stopped inside each capture so every diagnostic of the delivery is
	// flushed into the piped stream.

	requestIDJSON := "req-r023-05-failed-json"
	streamJSON := fmt.Sprintf("events:r023-05-failed-json-%d", time.Now().UnixNano())
	var row map[string]interface{}
	outJSON := cpCaptureStdout(t, func() {
		cppPublish(t, rdb, streamJSON, cppFailedEvent(requestIDJSON, orgID, false))
		stop := cppStartConsumer(t, rdb, pool, streamJSON, logging.New("info", "json"), 0)
		row = cppWaitRow(t, pool, requestIDJSON)
		stop()
	})

	assert.Equal(t, float64(502), row["status_code"], "status survives redaction")
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, row["error"])
	for _, col := range []string{"response", "upstream_request", "upstream_response"} {
		assert.Nil(t, row[col])
	}
	cprAssertNoContentSentinel(t, row)

	assert.Contains(t, outJSON, "failed request log inserted")
	assert.Contains(t, outJSON, requestIDJSON, "safe identity stays in the diagnostic")
	assert.Contains(t, outJSON, logging.ContentProfileRedactedDiagnostic)
	assert.NotContains(t, outJSON, "SUPER SECRET", "the error diagnostic must not echo the sentinel")
	assert.NotContains(t, outJSON, "TOP SECRET")

	requestIDText := "req-r023-05-failed-text"
	streamText := fmt.Sprintf("events:r023-05-failed-text-%d", time.Now().UnixNano())
	outText := cpCaptureStdout(t, func() {
		cppPublish(t, rdb, streamText, cppFailedEvent(requestIDText, orgID, false))
		stop := cppStartConsumer(t, rdb, pool, streamText, logging.New("info", "text"), 0)
		cppWaitRow(t, pool, requestIDText)
		stop()
	})

	assert.Contains(t, outText, "failed request log inserted")
	assert.Contains(t, outText, requestIDText)
	assert.Contains(t, outText, logging.ContentProfileRedactedDiagnostic)
	assert.NotContains(t, outText, "SUPER SECRET")
	assert.NotContains(t, outText, "TOP SECRET")
}

// Contract example 5 through the REAL entry point: a poison strict event
// (declared org has no row → the request_logs insert violates the FK) is
// delivered by the actual XREADGROUP loop, retried through the real PEL
// reclaim pass, and archived in the actual Redis DLQ past the retry budget —
// the envelope is the strict allowlist shape (content captures and unknown
// keys absent, error normalized, digest present, identity preserved), the
// flat replay surface stays sentinel-free, the message is ACKed and nothing
// ever persisted. The `yb dlq replay` contract (eventpublisher.DLQEnvelope)
// decodes the archive.
func TestIntegration_ContentProfilePipeline_PoisonReachesDLQThroughRealLoop(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	pool := testdb.PostgresRegion(t, "r023-05")
	rdb := testdb.Redis(t)
	missingOrg := uuid.NewString() // well-formed uuid, no organizations row
	stream := fmt.Sprintf("events:r023-05-poison-%d", time.Now().UnixNano())

	requestID := "req-r023-05-poison-dlq"
	cppPublish(t, rdb, stream, cppEvent(requestID, missingOrg, true))

	// The reclaim seam shrinks to ms scale so the real PEL pass redelivers
	// the unACKed message past the retry budget within the test deadline.
	stop := cppStartConsumer(t, rdb, pool, stream, silentLogger(), 10*time.Millisecond)

	dlqFields, env := cppWaitDLQEnvelope(t, rdb, requestID)

	assert.Equal(t, stream, env.OriginalStream)
	assert.NotEmpty(t, env.EntryID, "the real stream entry id is archived")
	assert.Equal(t, int64(maxRetries+1), env.RetryCount)
	assert.Equal(t, "max retries exceeded", env.Error)
	assert.Equal(t, "max retries exceeded", dlqFields["error"])
	assert.Equal(t, "request.completed", dlqFields["event_type"])

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

	cppWaitUntil(t, 10*time.Second, "poison message ACKed after DLQ", func() bool {
		pending, err := rdb.XPendingExt(context.Background(), &redis.XPendingExtArgs{
			Stream: stream, Group: consumerGroup, Start: "-", End: "+", Count: 10,
		}).Result()
		return err == nil && len(pending) == 0
	})

	var rows int64
	require.NoError(t, pool.QueryRow(context.Background(),
		"SELECT count(*) FROM request_logs WHERE request_id = $1", requestID).Scan(&rows))
	assert.Zero(t, rows, "the poison event must never persist a request_logs row")

	stop()
}

// Broken-vs-fixed control through the same real pipeline: the same producer
// shape under the legacy profile keeps the content on the wire, stores it
// verbatim in the DB and extracts tool calls — the metadata-only checks
// above really distinguish the selected profile instead of passing for any
// input.
func TestIntegration_ContentProfilePipeline_LegacyControlKeepsContent(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "")
	pool := testdb.PostgresRegion(t, "r023-05")
	rdb := testdb.Redis(t)
	orgID := cprNewOrg(t, pool, fmt.Sprintf("r023-05-legacy-%d", time.Now().UnixNano()))
	stream := fmt.Sprintf("events:r023-05-legacy-%d", time.Now().UnixNano())

	// The delivery write is toggle-gated (original-text retention): "legacy
	// keeps content" means an org that opted in. Flip the toggle through
	// the real store before the consumer starts.
	on := true
	require.NoError(t, adminstore.New(pool, silentLogger(), nil).
		UpdateOrgOriginalRetention(context.Background(), orgID, &on),
		"fixture: the control org opts in to original retention")

	requestID := "req-r023-05-legacy-control"
	cppPublishRetained(t, rdb, stream, cppEvent(requestID, orgID, false))

	wire := cppStreamEntry(t, rdb, stream, requestID)
	assert.Equal(t, cpSentinelPayload, wire["payload"], "legacy wire keeps the captures")

	stop := cppStartConsumer(t, rdb, pool, stream, silentLogger(), 0)
	row := cppWaitRow(t, pool, requestID)

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

	stop()
}

// Contract scenario "retention" end-to-end: a metadata-only row produced by
// the real pipeline (producer XADD → consumer-group loop → Postgres) flows
// through the EXISTING per-team retention policy unchanged — the redacted
// archive carries the hash and explicit nulls, export-before-delete removes
// the hot row, and the manifest pins the redaction. The profile changes what
// is stored; retention behavior is the same contract as before it.
//
// cppTeamScopedPolicies scopes the REAL store-backed policy source to one
// team's assignment: the tick under test still loads its policy through the
// production loader path, while leftovers of other suites in the shared
// per-binary stand (their enabled policies and aged cache/lineage rows) can
// never leak into this tick's stats — the worker sweeps exactly the
// assignments the source lists.
type cppTeamScopedPolicies struct {
	inner  StorePolicySource
	teamID string
}

func (s cppTeamScopedPolicies) ListEnabledTeamRetentionAssignments(ctx context.Context) ([]adminstore.TeamRetentionAssignment, error) {
	all, err := s.inner.ListEnabledTeamRetentionAssignments(ctx)
	if err != nil {
		return nil, err
	}
	scoped := make([]adminstore.TeamRetentionAssignment, 0, 1)
	for _, a := range all {
		if a.TeamID == s.teamID {
			scoped = append(scoped, a)
		}
	}
	return scoped, nil
}

func (s cppTeamScopedPolicies) EffectiveOrgRetention(ctx context.Context, orgID string) (*adminstore.OrgRetention, error) {
	return s.inner.EffectiveOrgRetention(ctx, orgID)
}
func TestIntegration_ContentProfilePipeline_StrictRowArchivesUnderRetentionPolicy(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	pool := testdb.PostgresRegion(t, "r023-05")
	rdb := testdb.Redis(t)
	store := adminstore.New(pool, silentLogger(), nil)
	orgID := cprNewOrg(t, pool, fmt.Sprintf("r023-05-retain-%d", time.Now().UnixNano()))

	team, err := store.CreateTeam(context.Background(), orgID,
		"R023-05 retention team", fmt.Sprintf("r023-05-ret-team-%d", time.Now().UnixNano()), nil)
	require.NoError(t, err)

	stream := fmt.Sprintf("events:r023-05-retain-%d", time.Now().UnixNano())
	requestID := "req-r023-05-retain"
	event := cppEvent(requestID, orgID, true)
	event.TeamID = team.ID
	cppPublish(t, rdb, stream, event)

	stop := cppStartConsumer(t, rdb, pool, stream, silentLogger(), 0)
	row := cppWaitRow(t, pool, requestID)
	require.Equal(t, team.ID, row["team_id"], "fixture: the delivered row belongs to the policy's team")
	assert.Nil(t, row["response"], "fixture: the row is metadata-only")
	stop()

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
	data, err := os.ReadFile(archive[0]) //nolint:gosec // G304: t.TempDir()-scoped archive path
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
	mfBytes, err := os.ReadFile(archive[0] + ".manifest.json") //nolint:gosec // G304: t.TempDir()-scoped manifest path
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(mfBytes, &mf))
	sum := sha256.Sum256(data)
	assert.Equal(t, hex.EncodeToString(sum[:]), mf.Sha256)
	assert.Equal(t, 1, mf.Rows)
	assert.True(t, mf.Redacted, "the redaction flag travels with the archive")
}
