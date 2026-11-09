package consumer

// metadata-only profile, process-local and wire-declared) must leave no
// request/response/error content in the loggerd logs, SQL bindings, tool
// extraction or DLQ envelopes — while safe event metadata (identity,
// tokens, money, status, the prompt digest) keeps flowing and legacy
// behavior stays byte-for-byte unchanged.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cpSentinelPayload = `TOP SECRET PROMPT BODY {"messages":[{"role":"user","content":"secret"}]}`
	cpSentinelUpReq   = `TOP SECRET UPSTREAM REQUEST BODY`
	cpSentinelUpResp  = `{"choices":[{"message":{"content":"TOP SECRET COMPLETION","tool_calls":[{"function":{"name":"get_weather","arguments":"{}"}}]}}]}`
	cpSentinelError   = "upstream exploded with SUPER SECRET STACK TRACE"
)

// cpCompletedFields builds a fully populated request.completed event with
// every content capture a legacy event carries. The wire profile is set
// when withProfile is true; requestID disambiguates assertions.
func cpCompletedFields(requestID string, withProfile bool) map[string]interface{} {
	fields := map[string]interface{}{
		"event_type":         "request.completed",
		"source":             "gateway",
		"ts":                 "1759800000000",
		"request_id":         requestID,
		"org_id":             "org-cp-1",
		"session_id":         "sess-cp-1",
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
		"labels":             []interface{}{"beta"},
		"diagnostic_detail":  "unknown-key " + cpSentinelError,
	}
	if withProfile {
		fields["content_profile"] = "metadata-only"
	}
	return fields
}

func cpCopyValues(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// cpCaptureStdout runs fn with os.Stdout swapped for a pipe and returns the
// production logger output (logging.New binds os.Stdout at construction).
func cpCaptureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = old })
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	require.NoError(t, w.Close())
	out := <-done
	_ = r.Close()
	return out
}

func cpExecContentError() (func(context.Context, string, ...any) (pgconn.CommandTag, error), *[]string) {
	var queries []string
	return func(_ context.Context, query string, _ ...any) (pgconn.CommandTag, error) {
		queries = append(queries, query)
		if strings.Contains(query, "INSERT INTO request_logs") {
			return pgconn.CommandTag{}, fmt.Errorf("insert request_log: %s", cpSentinelError)
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}, &queries
}

func cpIncrPastRetries(ctx context.Context, key string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(4) // past maxRetries → DLQ
	return cmd
}

// TestResolveMessageContentProfile_Matrix pins the effective-profile rule:
// strictest of the local declaration and the wire value, presence-checked
// before typing, malformed values fail closed.
func TestResolveMessageContentProfile_Matrix(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	cases := []struct {
		name  string
		local config.LogContentProfile
		wire  any
		want  config.LogContentProfile
	}{
		{"local legacy, no wire key", config.LogContentProfileLegacy, nil, config.LogContentProfileLegacy},
		{"local legacy, wire legacy", config.LogContentProfileLegacy, "legacy", config.LogContentProfileLegacy},
		{"local legacy, wire strict", config.LogContentProfileLegacy, "metadata-only", config.LogContentProfileMetadataOnly},
		{"local legacy, wire unknown fails closed", config.LogContentProfileLegacy, "verbose", config.LogContentProfileMetadataOnly},
		{"local legacy, wire non-string fails closed", config.LogContentProfileLegacy, 123, config.LogContentProfileMetadataOnly},
		{"local strict, no wire key", config.LogContentProfileMetadataOnly, nil, config.LogContentProfileMetadataOnly},
		{"local strict, wire legacy stays strict", config.LogContentProfileMetadataOnly, "legacy", config.LogContentProfileMetadataOnly},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]interface{}{"event_type": "request.completed"}
			present := false
			if tc.wire != nil {
				fields["content_profile"] = tc.wire
				present = true
			}
			assert.Equal(t, tc.want, resolveMessageContentProfile(fields, tc.local))
			// A present nil wire value must fail closed too — distinct
			// from an absent key.
			if !present {
				assert.Equal(t, config.LogContentProfileMetadataOnly,
					resolveMessageContentProfile(map[string]interface{}{"content_profile": nil}, tc.local))
			}
		})
	}
}

func TestSanitizeStreamMessage_StrictStripsContentOnACopy(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	msg := redis.XMessage{ID: "1-1", Values: cpCompletedFields("req-san-1", true)}

	sanitized, profile := sanitizeStreamMessageForContentProfile(msg, config.LogContentProfileLegacy)
	require.Equal(t, config.LogContentProfileMetadataOnly, profile)
	require.Equal(t, msg.ID, sanitized.ID)

	// The copy loses every content capture; unknown metadata keys stay in
	// the delivery path (attribution reads them) and are dropped by the
	// DLQ allowlist instead.
	for _, key := range []string{"payload", "upstream_payload", "upstream_response"} {
		assert.NotContains(t, sanitized.Values, key)
	}
	// The malformed supplied hash is recomputed from the body BEFORE the
	// strip; error becomes the fixed safe notice; identity survives.
	assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), sanitized.Values["prompt_hash"])
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, sanitized.Values["error"])
	assert.Equal(t, "metadata-only", sanitized.Values["content_profile"])
	assert.Equal(t, "req-san-1", sanitized.Values["request_id"])
	assert.Equal(t, "org-cp-1", sanitized.Values["org_id"])
	assert.Equal(t, []interface{}{"beta"}, sanitized.Values["labels"])

	// The received message and its map are untouched (copy ownership):
	// legacy consumers, replay and the DLQ assertions below rely on it.
	assert.Equal(t, cpSentinelPayload, msg.Values["payload"])
	assert.Equal(t, cpSentinelError, msg.Values["error"])
	assert.Equal(t, "definitely-not-a-valid-digest", msg.Values["prompt_hash"])
	assert.NotEqual(t, reflect.ValueOf(sanitized.Values).Pointer(), reflect.ValueOf(msg.Values).Pointer(),
		"the sanitizer must own a fresh map, never mutate the received one")
}

func TestSanitizeStreamMessage_StrictDigestRules(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	valid := eventpublisher.PromptDigest("some body")
	body := cpSentinelPayload

	cases := []struct {
		name        string
		supplied    any
		withPayload bool
		payload     string
		want        any // expected prompt_hash value; nil = key deleted
	}{
		{"valid supplied wins byte-for-byte", valid, true, body, valid},
		{"malformed recomputed from body", "garbage", true, body, eventpublisher.PromptDigest(body)},
		{"uppercase recomputed from body", strings.ToUpper(valid), true, body, eventpublisher.PromptDigest(body)},
		{"valid supplied without body preserved", valid, false, "", valid},
		{"malformed without body dropped", "garbage", false, "", nil},
		{"blank body drops hash", "garbage", true, "   \n\t ", nil},
		{"absent supplied with body recomputed", nil, true, body, eventpublisher.PromptDigest(body)},
		{"non-string supplied recomputed", 42, true, body, eventpublisher.PromptDigest(body)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]interface{}{"content_profile": "metadata-only"}
			if tc.supplied != nil {
				values["prompt_hash"] = tc.supplied
			}
			if tc.withPayload {
				values["payload"] = tc.payload
			}
			sanitized, profile := sanitizeStreamMessageForContentProfile(
				redis.XMessage{ID: "d-1", Values: values}, config.LogContentProfileLegacy)
			require.Equal(t, config.LogContentProfileMetadataOnly, profile)
			got, ok := sanitized.Values["prompt_hash"]
			if tc.want == nil {
				assert.False(t, ok, "prompt_hash must be deleted")
				return
			}
			require.True(t, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// Legacy retains full content but scrubs recognized secrets on an owned copy.
func TestSanitizeStreamMessage_LegacyScrubsSecretsBeforePersistence(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	msg := redis.XMessage{ID: "2-1", Values: cpCompletedFields("req-san-2", false)}
	msg.Values["payload"] = `{"Authorization":"Bearer loggerd-secret-token"}`
	msg.Values["error"] = "upstream failed: api_key=loggerd-error-secret"

	sanitized, profile := sanitizeStreamMessageForContentProfile(msg, config.LogContentProfileLegacy)
	require.Equal(t, config.LogContentProfileLegacy, profile)
	assert.NotEqual(t, reflect.ValueOf(sanitized.Values).Pointer(), reflect.ValueOf(msg.Values).Pointer())
	assert.NotContains(t, sanitized.Values["payload"], "loggerd-secret-token")
	assert.NotContains(t, sanitized.Values["error"], "loggerd-error-secret")
	assert.Contains(t, sanitized.Values["payload"], "[REDACTED]")
	assert.JSONEq(t, `{"Authorization":"Bearer loggerd-secret-token"}`, msg.Values["payload"].(string), "source event is immutable")
}

func TestSanitizeStreamMessage_ToolArgumentsAreSafeBeforeDurableEvent(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	msg := redis.XMessage{Values: map[string]interface{}{
		"event_type":        "request.completed",
		"upstream_response": `{"choices":[{"message":{"tool_calls":[{"function":{"name":"query","arguments":"{\"headers\":{\"X-Api-Key\":\"tool-secret-456\"},\"query\":\"public status\"}"}}]}}]}`,
	}}
	sanitized, _ := sanitizeStreamMessageForContentProfile(msg, config.LogContentProfileLegacy)
	invocations := extractToolCallInvocations(sanitized.Values["upstream_response"].(string))
	require.Len(t, invocations, 1)
	assert.NotContains(t, invocations[0].Args, "tool-secret-456")
	assert.Contains(t, invocations[0].Args, "[REDACTED]")
	assert.Contains(t, invocations[0].Args, "public status")
	assert.Contains(t, msg.Values["upstream_response"], "tool-secret-456", "the input map remains unchanged")
}

// insert fails must land in the DLQ without any content — envelope, flat
// fields — while the received message stays untouched for replay.
func TestHandleMessage_StrictPoisonNeverCarriesContent(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	msg := redis.XMessage{ID: "10-1", Values: cpCompletedFields("req-poison-strict", true)}
	original := cpCopyValues(msg.Values)

	var xaddValues map[string]interface{}
	execFn, queries := cpExecContentError()
	db := &mockDB{ExecFn: execFn}
	rdb := &mockRedis{
		INCRFn: cpIncrPastRetries,
		XAddFn: func(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
			xaddValues = args.Values.(map[string]interface{})
			cmd := redis.NewStringCmd(ctx)
			cmd.SetVal("10-1")
			return cmd
		},
	}
	c := New(rdb, db, "events:queue", silentLogger())

	c.handleMessage(context.Background(), msg)

	require.NotNil(t, xaddValues, "poison event must be archived in the DLQ")
	assert.Equal(t, "max retries exceeded", xaddValues["error"])
	assert.Equal(t, "events:queue", xaddValues["original_stream"])
	assert.Equal(t, "10-1", xaddValues["entry_id"])

	var envelope eventpublisher.DLQEnvelope
	require.NoError(t, json.Unmarshal([]byte(xaddValues["payload"].(string)), &envelope))
	assert.Equal(t, "10-1", envelope.EntryID)
	assert.Equal(t, "request.completed", envelope.Values["event_type"])
	assert.Equal(t, "req-poison-strict", envelope.Values["request_id"])
	assert.Equal(t, "metadata-only", envelope.Values["content_profile"])
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, envelope.Values["error"])
	assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), envelope.Values["prompt_hash"])
	for _, key := range []string{"payload", "upstream_payload", "upstream_response", "diagnostic_detail"} {
		assert.NotContains(t, envelope.Values, key, "content captures and unknown keys never reach the DLQ")
	}
	// The flat envelope surface carries no sentinel either.
	assert.NotContains(t, xaddValues["payload"], "TOP SECRET")
	assert.NotContains(t, xaddValues["payload"], "SUPER SECRET")
	// The failed delivery attempt must not have persisted anything: only
	// the inbox claim ran before the DLQ detour.
	for _, q := range *queries {
		assert.NotContains(t, q, "INSERT INTO request_logs committed",
			"sanity: failed inserts never report success")
	}

	// The received message stays byte-for-byte intact (replay/ownership).
	assert.Equal(t, original, msg.Values)
}

// Every error diagnostic a strict message can produce — processing/SQL,
// TTL, DLQ writer — is sanitized in the actual production logger output,
// in both JSON and text formats, while safe metadata stays.
func TestHandleMessage_StrictDiagnosticErrorsSanitized(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			msg := redis.XMessage{ID: "11-1", Values: cpCompletedFields("req-diag-strict", true)}
			execFn, _ := cpExecContentError()
			db := &mockDB{ExecFn: execFn}
			rdb := &mockRedis{
				INCRFn: cpIncrPastRetries,
				ExpireFn: func(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
					cmd := redis.NewBoolCmd(ctx)
					cmd.SetErr(fmt.Errorf("redis ttl write failed: %s", cpSentinelError))
					return cmd
				},
				XAddFn: func(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
					cmd := redis.NewStringCmd(ctx)
					cmd.SetErr(fmt.Errorf("xadd rejected: %s", cpSentinelError))
					return cmd
				},
			}

			out := cpCaptureStdout(t, func() {
				c := New(rdb, db, "events:queue", logging.New("info", format))
				c.handleMessage(context.Background(), msg)
			})

			assert.Contains(t, out, "process message failed", format)
			assert.Contains(t, out, "set dlq retry ttl failed", format)
			assert.Contains(t, out, "failed to send poison message to DLQ", format)
			assert.Contains(t, out, "11-1", format, "safe identity (stream id) stays")
			assert.NotContains(t, out, "SUPER SECRET", format)
			assert.NotContains(t, out, "TOP SECRET", format)
			assert.Contains(t, out, logging.ContentProfileRedactedDiagnostic, format)
		})
	}
}

// Legacy failure behavior is unchanged: the DLQ envelope still carries the
// original values verbatim (payload included).
func TestHandleMessage_LegacyDLQEnvelopeKeepsPayload(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	msg := redis.XMessage{ID: "12-1", Values: cpCompletedFields("req-poison-legacy", false)}

	var xaddValues map[string]interface{}
	execFn, _ := cpExecContentError()
	db := &mockDB{ExecFn: execFn}
	rdb := &mockRedis{
		INCRFn: cpIncrPastRetries,
		XAddFn: func(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
			xaddValues = args.Values.(map[string]interface{})
			cmd := redis.NewStringCmd(ctx)
			cmd.SetVal("12-1")
			return cmd
		},
	}
	c := New(rdb, db, "events:queue", silentLogger())

	c.handleMessage(context.Background(), msg)

	require.NotNil(t, xaddValues)
	var envelope eventpublisher.DLQEnvelope
	require.NoError(t, json.Unmarshal([]byte(xaddValues["payload"].(string)), &envelope))
	assert.Equal(t, cpSentinelPayload, envelope.Values["payload"],
		"legacy profile keeps the original envelope contract, unchanged")
	assert.Equal(t, cpSentinelError, envelope.Values["error"])
}

// Strict DLQ envelopes are rebuilt from the bounded allowlist: exactly the
// declared keys survive, error is normalized, nothing else is serialized.
func TestTrySendToDLQProfile_StrictAllowlistExactness(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	values := map[string]interface{}{
		"payload":           "SHOULD NEVER APPEAR",
		"upstream_response": "NEITHER SHOULD THIS",
		"weaponized":        "UNKNOWN KEY SECRET",
		"error":             123,
		"labels":            []interface{}{"beta"},
	}
	for _, key := range strictDLQAllowlistKeys {
		if _, ok := values[key]; !ok {
			values[key] = "v-" + key
		}
	}

	var xaddValues map[string]interface{}
	db := &mockDB{}
	rdb := &mockRedis{
		INCRFn: cpIncrPastRetries,
		XAddFn: func(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
			xaddValues = args.Values.(map[string]interface{})
			cmd := redis.NewStringCmd(ctx)
			cmd.SetVal("13-1")
			return cmd
		},
	}
	c := New(rdb, db, "events:queue", silentLogger())

	isPoison, err := c.trySendToDLQProfile(context.Background(),
		redis.XMessage{ID: "13-1", Values: values},
		deliveryPolicy{profile: config.LogContentProfileMetadataOnly, retainOriginal: true})
	require.NoError(t, err)
	require.True(t, isPoison)

	var envelope eventpublisher.DLQEnvelope
	require.NoError(t, json.Unmarshal([]byte(xaddValues["payload"].(string)), &envelope))
	require.Len(t, envelope.Values, len(strictDLQAllowlistKeys),
		"exactly the allowlist survives — no more, no less")
	for _, key := range strictDLQAllowlistKeys {
		assert.Contains(t, envelope.Values, key)
	}
	assert.NotContains(t, envelope.Values, "weaponized")
	assert.NotContains(t, envelope.Values, "payload")
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, envelope.Values["error"],
		"a non-string error value is normalized to the fixed safe text")
	assert.Equal(t, []interface{}{"beta"}, envelope.Values["labels"])
	assert.NotContains(t, xaddValues["payload"], "SECRET")
}

func TestTrySendToDLQProfile_TenantMatrixDoesNotCrossReveal(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	var writes []map[string]interface{}
	rdb := &mockRedis{
		INCRFn: func(ctx context.Context, key string) *redis.IntCmd {
			cmd := redis.NewIntCmd(ctx)
			cmd.SetVal(maxRetries + 1)
			return cmd
		},
		XAddFn: func(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
			values, ok := args.Values.(map[string]interface{})
			require.True(t, ok)
			writes = append(writes, values)
			cmd := redis.NewStringCmd(ctx)
			cmd.SetVal("1-1")
			return cmd
		},
	}
	c := New(rdb, &mockDB{}, "events:queue", silentLogger())
	fixtures := []struct {
		orgID, requestID, private string
	}{
		{"org-tenant-a", "req-tenant-a", "private-payload-and-error-A"},
		{"org-tenant-b", "req-tenant-b", "private-payload-and-error-B"},
	}
	for _, fixture := range fixtures {
		poison, err := c.trySendToDLQProfile(context.Background(), redis.XMessage{
			ID: fixture.requestID,
			Values: map[string]interface{}{
				"event_type":      "request.failed",
				"request_id":      fixture.requestID,
				"org_id":          fixture.orgID,
				"content_profile": "metadata-only",
				"payload":         fixture.private,
				"error":           fixture.private,
			},
		}, deliveryPolicy{profile: config.LogContentProfileMetadataOnly, retainOriginal: true})
		require.NoError(t, err)
		require.True(t, poison)
	}

	require.Len(t, writes, len(fixtures))
	for i, fixture := range fixtures {
		encoded, ok := writes[i]["payload"].(string)
		require.True(t, ok)
		var envelope eventpublisher.DLQEnvelope
		require.NoError(t, json.Unmarshal([]byte(encoded), &envelope))
		assert.Equal(t, fixture.orgID, envelope.Values["org_id"])
		assert.Equal(t, fixture.requestID, envelope.RequestID())
		assert.NotContains(t, encoded, "private-payload-and-error-A")
		assert.NotContains(t, encoded, "private-payload-and-error-B")
		assert.Equal(t, eventpublisher.ContentProfileRedactedError, envelope.Values["error"])
		assert.NotContains(t, envelope.Values, "payload")
	}
}

// The strict mapper binds SQL NULL for every content column and trusts only
// the boundary-verified digest — even when raw captures are still present
func TestParseRequestEventProfile_StrictBindsNullContent(t *testing.T) {
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "true")

	valid := eventpublisher.PromptDigest(cpSentinelPayload)

	// Post-boundary shape: content stripped, valid digest carried.
	fields := cpCompletedFields("req-map-strict-1", true)
	fields["prompt_hash"] = valid
	delete(fields, "payload")
	delete(fields, "upstream_payload")
	delete(fields, "upstream_response")

	ev := parseRequestEventProfile(fields, config.LogContentProfileMetadataOnly, true)
	assert.Equal(t, valid, ev.promptHash, "a valid boundary digest is kept byte-for-byte")
	assert.Nil(t, ev.responseJSON)
	assert.Nil(t, ev.upstreamReqJSON)
	assert.Nil(t, ev.upstreamRespJSON)
	assert.Empty(t, ev.upstreamResponse)

	// Fail closed: a raw event whose captures somehow survived loses them
	// in the mapper; a malformed digest with no body binds NULL.
	raw := cpCompletedFields("req-map-strict-2", true)
	evRaw := parseRequestEventProfile(raw, config.LogContentProfileMetadataOnly, true)
	assert.Nil(t, evRaw.promptHash)
	assert.Nil(t, evRaw.responseJSON)
	assert.Nil(t, evRaw.upstreamReqJSON)
	assert.Nil(t, evRaw.upstreamRespJSON)
	assert.Empty(t, evRaw.upstreamResponse)

	// Legacy mapping is unchanged: content captured, hash of the payload.
	legacy := cpCompletedFields("req-map-legacy", false)
	evLegacy := parseRequestEventProfile(legacy, config.LogContentProfileLegacy, true)
	assert.Equal(t, eventpublisher.PromptDigest(cpSentinelPayload), evLegacy.promptHash)
	assert.NotNil(t, evLegacy.responseJSON)
	assert.NotEmpty(t, evLegacy.upstreamResponse)
}

// Strict delivery never extracts tool calls and never binds content, while
// the legacy delivery of the same shape still extracts them.
func TestHandleRequestCompleteProfile_StrictSkipsToolCalls(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")

	run := func(requestID string, profile config.LogContentProfile) []string {
		fields := cpCompletedFields(requestID, profile == config.LogContentProfileMetadataOnly)
		fields["prompt_hash"] = eventpublisher.PromptDigest(cpSentinelPayload)
		delete(fields, "payload")
		delete(fields, "upstream_payload")

		var queries []string
		db := &mockDB{ExecFn: func(_ context.Context, query string, _ ...any) (pgconn.CommandTag, error) {
			queries = append(queries, query)
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		}}
		c := New(&mockRedis{}, db, "events:queue", silentLogger())
		msg := redis.XMessage{ID: "14-0", Values: fields}
		require.NoError(t, c.handleRequestCompleteProfile(context.Background(), msg,
			deliveryPolicy{profile: profile, retainOriginal: true}))
		return queries
	}

	strictQueries := run("req-tools-strict", config.LogContentProfileMetadataOnly)
	for _, q := range strictQueries {
		assert.NotContains(t, q, "INSERT INTO tool_calls",
			"strict mode must never extract tool calls from a dropped sample")
	}

	legacyQueries := run("req-tools-legacy", config.LogContentProfileLegacy)
	toolInsert := false
	for _, q := range legacyQueries {
		if strings.Contains(q, "INSERT INTO tool_calls") {
			toolInsert = true
		}
	}
	assert.True(t, toolInsert, "legacy behavior unchanged: tool calls still extracted")
}

// The PEL reclaim path shares the same boundary: a reclaimed strict message
// is processed from a sanitized copy, and the claimed map stays intact.
func TestReclaimStaleMessages_StrictUsesBoundary(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	msg := redis.XMessage{ID: "9-1", Values: cpCompletedFields("req-reclaim-strict", true)}

	var capturedArgs []any
	var acked []string
	db := &mockDB{ExecFn: func(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
		capturedArgs = append(capturedArgs, args...)
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	rdb := &mockRedis{
		XPendingExtFn: func(ctx context.Context, args *redis.XPendingExtArgs) *redis.XPendingExtCmd {
			cmd := redis.NewXPendingExtCmd(ctx)
			cmd.SetVal([]redis.XPendingExt{{ID: "9-1", Idle: 6 * time.Minute}})
			return cmd
		},
		XClaimFn: func(ctx context.Context, args *redis.XClaimArgs) *redis.XMessageSliceCmd {
			cmd := redis.NewXMessageSliceCmd(ctx)
			cmd.SetVal([]redis.XMessage{msg})
			return cmd
		},
		XAckFn: func(ctx context.Context, stream, group string, ids []string) *redis.IntCmd {
			acked = append(acked, ids...)
			cmd := redis.NewIntCmd(ctx)
			cmd.SetVal(int64(len(ids)))
			return cmd
		},
	}
	c := New(rdb, db, "events:queue", silentLogger())

	c.reclaimStaleMessages(context.Background())

	assert.Equal(t, []string{"9-1"}, acked, "successful redelivery is ACKed")
	assert.Equal(t, cpSentinelPayload, msg.Values["payload"],
		"the reclaimed map is never mutated")
	for _, arg := range capturedArgs {
		assert.NotContains(t, fmt.Sprintf("%v", arg), "TOP SECRET",
			"strict redelivery binds no content")
	}
	assert.NotContains(t, fmt.Sprintf("%v", capturedArgs), "SUPER SECRET")
}

// strictDiagnosticValue (via safeDiagnostic) is what shields the consumer
// log attributes; pin its contract directly.
func TestSafeDiagnostic(t *testing.T) {
	assert.Equal(t, cpSentinelError, safeDiagnostic(config.LogContentProfileLegacy, cpSentinelError))
	assert.Equal(t, logging.ContentProfileRedactedDiagnostic,
		safeDiagnostic(config.LogContentProfileMetadataOnly, cpSentinelError))
}
