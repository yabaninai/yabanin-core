package eventpublisher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCtx = context.Background()

func TestLabelsValue(t *testing.T) {
	if labelsValue(nil) != "" || labelsValue(map[string]string{}) != "" {
		t.Fatal("empty labels must publish as an empty field")
	}
	got := labelsValue(map[string]string{"issue": "PAY-1", "ci.pipeline": "42"})
	var parsed map[string]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["issue"] != "PAY-1" || parsed["ci.pipeline"] != "42" {
		t.Fatalf("%s", got)
	}
}

func TestComputeDurationMs(t *testing.T) {
	start := time.Now().Add(-100 * time.Millisecond)
	ms := ComputeDurationMs(start)
	assert.GreaterOrEqual(t, ms, int64(90))
	assert.LessOrEqual(t, ms, int64(200))
}

func TestNewRedisPublisher(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	p := NewRedisPublisher(rdb, "test-stream")
	assert.Equal(t, rdb, p.RDB)
	assert.Equal(t, "test-stream", p.Stream)
}

func TestComputeDurationMs_positive(t *testing.T) {
	start := time.Now()
	time.Sleep(50 * time.Millisecond)
	d := ComputeDurationMs(start)
	assert.GreaterOrEqual(t, d, int64(40))
	assert.LessOrEqual(t, d, int64(300))
}

func TestComputeDurationMs_pastTime(t *testing.T) {
	start := time.Now().Add(-100 * time.Millisecond)
	d := ComputeDurationMs(start)
	assert.GreaterOrEqual(t, d, int64(90))
}

func TestPublish_success(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: ":0"}) // will fail to connect, skip if no Redis
	// We use a real Redis via testcontainers or skip.
	// For now, test with mock-like approach using a closed connection.
	p := NewRedisPublisher(rdb, "test-events")
	event := &Event{
		EventType:      "request.completed",
		Source:         "gateway",
		SessionID:      "sess-123",
		Payload:        `{"model":"gpt-4"}`,
		OrgID:          "org-1",
		ModelRequested: "gpt-4",
		ModelUsed:      "gpt-4",
		UpstreamURL:    "https://api.openai.com",
		StatusCode:     200,
		DurationMs:     42,
		TokensIn:       10,
		TokensOut:      5,
		Method:         "POST",
	}

	err := p.Publish(testCtx, event)
	// With :0 addr, connection will fail immediately
	assert.Error(t, err)
}

func TestPublish_valuesMapped(t *testing.T) {
	// Use a real Redis instance if available via TEST_REDIS_ADDR env var.
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	ctx := testCtx

	p := NewRedisPublisher(rdb, "eventpublisher-test-stream")
	event := &Event{
		EventType:      "request.completed",
		Source:         "gateway",
		SessionID:      "sess-456",
		Payload:        `{"test":true}`,
		OrgID:          "org-789",
		ModelRequested: "claude-3",
		ModelUsed:      "claude-3-opus",
		UpstreamURL:    "https://api.anthropic.com",
		StatusCode:     200,
		DurationMs:     150,
		TokensIn:       20,
		TokensOut:      100,
		Method:         "POST",
		Error:          "",
	}

	err := p.Publish(ctx, event)
	require.NoError(t, err)

	streamKey := "eventpublisher-test-stream"
	vals, err := rdb.XRange(ctx, streamKey, "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)

	entry := vals[0]
	assert.Equal(t, "request.completed", entry.Values["event_type"])
	assert.Equal(t, "gateway", entry.Values["source"])
	assert.Equal(t, "sess-456", entry.Values["session_id"])
	assert.Equal(t, `{"test":true}`, entry.Values["payload"])
	assert.Equal(t, "org-789", entry.Values["org_id"])
	assert.Equal(t, "claude-3", entry.Values["model_requested"])
	assert.Equal(t, "claude-3-opus", entry.Values["model_used"])
	assert.Equal(t, "https://api.anthropic.com", entry.Values["upstream_url"])
	assert.Equal(t, int64(200), parseInt64(entry.Values["status_code"]))
	assert.Equal(t, int64(150), parseInt64(entry.Values["duration_ms"]))
	assert.Equal(t, int64(20), parseInt64(entry.Values["tokens_in"]))
	assert.Equal(t, int64(100), parseInt64(entry.Values["tokens_out"]))
	assert.Equal(t, "POST", entry.Values["method"])
}

// TestPublish_policyFieldRidesTheStreamWire pins the OP-8 producer→wire
// field — the exact field the loggerd consumer's parsePolicyDecision reads —
// and a request without an evaluated pipeline publishes the empty field,
// the consumer-side legacy shape.
func TestPublish_policyFieldRidesTheStreamWire(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	stream := "eventpublisher-policy-stream"
	p := NewRedisPublisher(rdb, stream)
	golden := `[{"policy_id":"55555555-5555-5555-5555-555555555555","name":"sovereign-default","version":2,` +
		`"mode":"shadow","verdict":"allow","duration_ms":3,"findings":[` +
		`{"step":"scan.pii","category":"innsnils","severity":"high","action":"flag"}]}]`
	require.NoError(t, p.Publish(testCtx, &Event{
		EventType: "request.completed",
		Source:    "gateway",
		RequestID: "req-policy-wire",
		OrgID:     "org-wire",
		Policy:    golden,
	}))

	vals, err := rdb.XRange(testCtx, stream, "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	assert.Equal(t, golden, vals[0].Values["policy"],
		"Event.Policy must reach the wire verbatim as the policy stream field")

	require.NoError(t, p.Publish(testCtx, &Event{
		EventType: "request.completed",
		Source:    "gateway",
		RequestID: "req-policy-wire-legacy",
		OrgID:     "org-wire",
	}))
	vals, err = rdb.XRange(testCtx, stream, "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 2)
	assert.Empty(t, vals[1].Values["policy"],
		"no pipeline evaluated: the policy field stays empty (the legacy shape)")
}

func TestPublish_withCostFields(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	ctx := testCtx

	p := NewRedisPublisher(rdb, "eventpublisher-cost-stream")
	event := &Event{
		EventType:             "request.completed",
		Source:                "gateway",
		SessionID:             "sess-cost",
		Payload:               `{"cost":true}`,
		OrgID:                 "org-billing",
		ModelRequested:        "gpt-4o",
		ModelUsed:             "gpt-4o",
		UpstreamURL:           "https://api.openai.com/v1/chat/completions",
		StatusCode:            200,
		DurationMs:            300,
		TokensIn:              50,
		TokensOut:             200,
		CacheHitType:          "exact",
		CacheSimilarity:       0.98,
		CounterfactualCostUSD: 0.015,
		EstimatedCostUSD:      0.003,
		CacheReadTokens:       40,
		CacheCreationTokens:   10,
		Method:                "POST",
		TierUsed:              "smart",
		ClassifierClass:       "medium",
		ClassifierConfidence:  0.75,
		ClassifierSource:      "ml_v1",
		EvalgateSampled:       true,
		EvalgateShouldUpgrade: false,
		ABGroup:               "test",
	}

	err := p.Publish(ctx, event)
	require.NoError(t, err)

	streamKey := "eventpublisher-cost-stream"
	vals, err := rdb.XRange(ctx, streamKey, "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)

	entry := vals[0]
	// Verify all fields are present in stream
	assert.Equal(t, "exact", entry.Values["cache_hit_type"])
	assert.Equal(t, "smart", entry.Values["tier_used"])
	assert.Equal(t, "medium", entry.Values["classifier_class"])
	assert.Equal(t, "ml_v1", entry.Values["classifier_source"])
	assert.Equal(t, "test", entry.Values["ab_group"])

	// Redis returns numeric values as strings — parse and verify
	if v := entry.Values["estimated_cost_usd"]; v != nil {
		sv, ok := v.(string)
		require.True(t, ok, "estimated_cost_usd should be string from Redis, got %T", v)
		fv, err := strconv.ParseFloat(sv, 64)
		require.NoError(t, err)
		assert.InDelta(t, 0.003, fv, 0.0001, "estimated_cost_usd mismatch")
	} else {
		t.Error("estimated_cost_usd not in stream values")
	}

	if v := entry.Values["counterfactual_cost_usd"]; v != nil {
		sv, ok := v.(string)
		require.True(t, ok, "counterfactual_cost_usd should be string from Redis, got %T", v)
		fv, err := strconv.ParseFloat(sv, 64)
		require.NoError(t, err)
		assert.InDelta(t, 0.015, fv, 0.0001, "counterfactual_cost_usd mismatch")
	} else {
		t.Error("counterfactual_cost_usd not in stream values")
	}

	if v := entry.Values["cache_read_tokens"]; v != nil {
		assert.Equal(t, int64(40), parseInt64(v))
	} else {
		t.Error("cache_read_tokens not in stream values")
	}

	if v := entry.Values["evalgate_sampled"]; v != nil {
		sv, ok := v.(string)
		require.True(t, ok, "evalgate_sampled should be string from Redis, got %T", v)
		assert.True(t, sv == "true" || sv == "1" || sv == "True", "evalgate_sampled should be truthy, got %q", sv)
	} else {
		t.Error("evalgate_sampled not in stream values")
	}

	if v := entry.Values["ab_group"]; v != nil {
		assert.Equal(t, "test", v)
	} else {
		t.Error("ab_group not in stream values")
	}
}

func TestEvent_JSONRoundTrip(t *testing.T) {
	e := &Event{
		EventType:      "request.failed",
		Source:         "gateway",
		SessionID:      "sess-789",
		Payload:        `{"messages":[{"role":"user","content":"hello"}]}`,
		OrgID:          "org-billing",
		ModelRequested: "gpt-3.5-turbo",
		ModelUsed:      "",
		UpstreamURL:    "https://api.openai.com/v1/chat/completions",
		StatusCode:     0,
		DurationMs:     5000,
		TokensIn:       5,
		TokensOut:      0,
		Method:         "POST",
		Error:          "upstream failed: connection refused",
	}

	data, err := json.Marshal(e)
	require.NoError(t, err)

	var decoded Event
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, e.EventType, decoded.EventType)
	assert.Equal(t, e.Source, decoded.Source)
	assert.Equal(t, e.SessionID, decoded.SessionID)
	assert.Equal(t, e.Payload, decoded.Payload)
	assert.Equal(t, e.OrgID, decoded.OrgID)
	assert.Equal(t, e.ModelRequested, decoded.ModelRequested)
	assert.Equal(t, e.UpstreamURL, decoded.UpstreamURL)
	assert.Equal(t, e.StatusCode, decoded.StatusCode)
	assert.Equal(t, e.DurationMs, decoded.DurationMs)
	assert.Equal(t, e.TokensIn, decoded.TokensIn)
	assert.Equal(t, e.TokensOut, decoded.TokensOut)
	assert.Equal(t, e.Method, decoded.Method)
	assert.Equal(t, e.Error, decoded.Error)

	// Verify new fields round-trip
	assert.Equal(t, e.EvalgateSampled, decoded.EvalgateSampled)
	assert.Equal(t, e.EvalgateShouldUpgrade, decoded.EvalgateShouldUpgrade)
	assert.Equal(t, e.ABGroup, decoded.ABGroup)
}

func TestEvent_OmitEmptyError(t *testing.T) {
	e := &Event{
		EventType:  "request.completed",
		Source:     "gateway",
		SessionID:  "sess-1",
		Payload:    "{}",
		Method:     "POST",
		StatusCode: 200,
	}

	data, err := json.Marshal(e)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	// Error field should be omitted when empty
	_, hasError := raw["error"]
	assert.False(t, hasError, "error field should be omitted when empty")

	// With error set, it should be present
	e.Error = "something went wrong"
	data, err = json.Marshal(e)
	require.NoError(t, err)
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)
	_, hasError = raw["error"]
	assert.True(t, hasError, "error field should be present when set")
}

func TestPublish_nilEvent(t *testing.T) {
	rdb := testdb.Redis(t)
	ctx := testCtx

	p := NewRedisPublisher(rdb, "test-nil-event")
	err := p.Publish(ctx, nil)
	require.Error(t, err) // nil event should return error, not panic
	assert.Contains(t, err.Error(), "nil event", "error message should mention nil event")
}

func TestRedactSensitiveURL_noCredentials(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://api.openai.com/v1/chat/completions", "https://api.openai.com/v1/chat/completions"},
		{"https://api.anthropic.com", "https://api.anthropic.com"},
		{"http://localhost:8080/v1/classify", "http://localhost:8080/v1/classify"},
	}

	for _, tt := range tests {
		result := redactSensitiveURL(tt.input)
		assert.Equal(t, tt.expected, result, "input=%s", tt.input)
	}
}

func TestRedactSensitiveURL_withCredentials(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://user:pass@api.openai.com/v1", "https://***REDACTED***@api.openai.com/v1"},
		{"http://admin:secret123@localhost:8080/api", "http://***REDACTED***@localhost:8080/api"},
	}

	for _, tt := range tests {
		result := redactSensitiveURL(tt.input)
		assert.Equal(t, tt.expected, result, "input=%s", tt.input)
	}
}

func TestRedactSensitiveURL_emptyInput(t *testing.T) {
	assert.Empty(t, redactSensitiveURL(""))
}

func TestPublish_nilEvent_WithRedis(t *testing.T) {
	rdb := testdb.Redis(t)
	ctx := testCtx

	p := NewRedisPublisher(rdb, "test-nil-event-redis")
	err := p.Publish(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil event")
}

func parseInt64(v interface{}) int64 {
	switch val := v.(type) {
	case int64:
		return val
	case float64:
		return int64(val)
	case int:
		return int64(val)
	case string:
		// Redis returns strings sometimes; parse from string
		i, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return 0
		}
		return i
	default:
		return 0
	}
}

// TestPublish_usedOrgKeyWiring: the BYOK attribution flag must survive the
// string-only Redis stream wire ("true") and stay omitted-equivalent ("")
// when false — the W-VER acceptance run caught this exact omission.
func TestPublish_usedOrgKeyWiring(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	ctx := testCtx

	p := NewRedisPublisher(rdb, "eventpublisher-byok-stream")
	require.NoError(t, p.Publish(ctx, &Event{EventType: "request.completed", UsedOrgKey: true}))
	require.NoError(t, p.Publish(ctx, &Event{EventType: "request.completed", UsedOrgKey: false}))

	vals, err := rdb.XRange(ctx, "eventpublisher-byok-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 2)
	assert.Equal(t, "true", vals[0].Values["used_org_key"], "true must ride the stream as \"true\"")
	v, ok := vals[1].Values["used_org_key"]
	assert.True(t, !ok || v == "", "false must be omitted-equivalent on the stream wire")
}

// payload, lower-case hex; blank or whitespace-only bodies have no digest.
func TestPromptDigest(t *testing.T) {
	assert.Empty(t, PromptDigest(""))
	assert.Empty(t, PromptDigest("   \n\t"))
	want := sha256.Sum256([]byte(`{"messages":[]}`))
	assert.Equal(t, hex.EncodeToString(want[:]), PromptDigest(`{"messages":[]}`))
	assert.Equal(t, hex.EncodeToString(want[:]), PromptDigest("  {\"messages\":[]} \n"),
		"surrounding whitespace is trimmed before hashing")
}

// TestResolvePromptHash pins the supplied-vs-computed digest rule.
func TestResolvePromptHash(t *testing.T) {
	computed := PromptDigest(`{"a":1}`)
	assert.Equal(t, computed, ResolvePromptHash("", `{"a":1}`))
	assert.Equal(t, computed, ResolvePromptHash("nothex", `{"a":1}`))
	assert.Equal(t, computed, ResolvePromptHash(strings.ToUpper(computed), `{"a":1}`),
		"upper-case digests are malformed (lower-case wire rule) and get recomputed")
	assert.Equal(t, computed, ResolvePromptHash(computed[:63], `{"a":1}`),
		"a 63-char digest is invalid and gets recomputed")

	// A valid supplied digest is preserved byte-for-byte, even with no body.
	assert.Equal(t, computed, ResolvePromptHash(computed, ""))
	assert.Equal(t, computed, ResolvePromptHash(computed, `{"other":true}`))

	// Malformed supplied digest with no body → no hash at all.
	assert.Empty(t, ResolvePromptHash("", ""))
	assert.Empty(t, ResolvePromptHash("zz", ""))
}

// TestStrictContentProfile: only an exact empty/legacy declaration may widen
// retention; everything else — recognized or not — fails closed to strict.
func TestStrictContentProfile(t *testing.T) {
	assert.False(t, StrictContentProfile(""))
	assert.False(t, StrictContentProfile("legacy"))
	assert.True(t, StrictContentProfile("metadata-only"))
	assert.True(t, StrictContentProfile("unknown-profile"))
	assert.True(t, StrictContentProfile("LEGACY"),
		"the wire value must match exactly; casing is not normalized on the wire")
}

// new JSON fields at all — absent keys stay legacy-compatible downstream.
func TestEvent_ContentProfileOmittedInLegacy(t *testing.T) {
	data, err := json.Marshal(&Event{EventType: "request.completed"})
	require.NoError(t, err)
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.NotContains(t, raw, "content_profile")
	assert.NotContains(t, raw, "prompt_hash")

	data, err = json.Marshal(&Event{EventType: "request.completed", ContentProfile: "metadata-only", PromptHash: "ab"})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.Equal(t, "metadata-only", raw["content_profile"])
	assert.Equal(t, "ab", raw["prompt_hash"])
}

// TestPublish_metadataOnlyStripsContent drives a real XADD: the strict event
// reaches the stream with no content captures, the fixed redaction notice,
// the declared profile and the prompt digest — while the metadata fields
// survive intact.
func TestPublish_metadataOnlyStripsContent(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-profile-stream")
	body := `  {"messages":[{"role":"user","content":"secret-profile-body"}]}  `
	err := p.Publish(testCtx, &Event{
		EventType:        "request.completed",
		Source:           "gateway",
		SessionID:        "sess-prof",
		OrgID:            "org-prof",
		Payload:          body,
		UpstreamPayload:  body,
		UpstreamResponse: `{"completion":"secret-response"}`,
		ModelUsed:        "gpt-4o",
		TokensIn:         7,
		TokensOut:        3,
		Method:           "POST",
		ContentProfile:   "metadata-only",
	})
	require.NoError(t, err)

	vals, err := rdb.XRange(testCtx, "eventpublisher-profile-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	entry := vals[0].Values

	for _, key := range []string{"payload", "upstream_payload", "upstream_response"} {
		_, has := entry[key]
		assert.False(t, has, "%s must not ride the metadata-only stream", key)
	}
	assert.Equal(t, "metadata-only", entry["content_profile"])
	assert.Equal(t, PromptDigest(body), entry["prompt_hash"],
		"the digest hashes the trimmed raw body, computed before the captures were dropped")
	assert.Equal(t, "request.completed", entry["event_type"])
	assert.Equal(t, "org-prof", entry["org_id"])
	assert.Equal(t, "gpt-4o", entry["model_used"])
	assert.Equal(t, int64(7), parseInt64(entry["tokens_in"]))
	assert.Equal(t, int64(3), parseInt64(entry["tokens_out"]))
}

// TestPublish_metadataOnlyRedactsError: a failed strict event carries the
// fixed redaction notice instead of the upstream error body; a successful one
// keeps error empty (no notice injected).
func TestPublish_metadataOnlyRedactsError(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	p := NewRedisPublisher(rdb, "eventpublisher-profile-error-stream")

	require.NoError(t, p.Publish(testCtx, &Event{
		EventType:      "request.failed",
		Error:          `upstream error 500: {"error":"leaked upstream detail"}`,
		Payload:        `{"q":"x"}`,
		ContentProfile: "metadata-only",
	}))
	require.NoError(t, p.Publish(testCtx, &Event{
		EventType:      "request.completed",
		ContentProfile: "metadata-only",
	}))

	vals, err := rdb.XRange(testCtx, "eventpublisher-profile-error-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 2)
	assert.Equal(t, ContentProfileRedactedError, vals[0].Values["error"])
	assert.NotContains(t, vals[0].Values["error"], "leaked upstream detail")
	assert.Empty(t, vals[1].Values["error"], "no redaction notice for an empty error")
}

func TestPublish_secretNeverAppearsInRedisStreamValues(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	const secret = "probe-token-123"
	stream := "eventpublisher-secret-redaction-stream"
	p := NewRedisPublisher(rdb, stream)

	require.NoError(t, p.Publish(testCtx, &Event{
		EventType: "request.failed",
		Source:    "gateway",
		Payload:   `{"authorization":"Bearer ` + secret + `"}`,
		Error:     "upstream rejected api_key=" + secret,
	}))

	entries, err := rdb.XRange(testCtx, stream, "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	for field, value := range entries[0].Values {
		assert.NotContains(t, value, secret, "secret must not be stored in Redis stream field %q", field)
	}
}

// TestPublish_metadataOnlyUnknownProfileFailsClosed: an unrecognized wire
// declaration is treated as strict; the declared value itself rides verbatim
// (never rewritten, never echoed as an error).
func TestPublish_metadataOnlyUnknownProfileFailsClosed(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	p := NewRedisPublisher(rdb, "eventpublisher-profile-unknown-stream")

	require.NoError(t, p.Publish(testCtx, &Event{
		EventType:      "request.completed",
		Payload:        `{"q":"secret"}`,
		ContentProfile: "MOODY",
		PromptHash:     "supplied-but-not-a-digest",
	}))

	vals, err := rdb.XRange(testCtx, "eventpublisher-profile-unknown-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	entry := vals[0].Values
	_, hasPayload := entry["payload"]
	assert.False(t, hasPayload, "an unknown profile must fail closed to strict")
	assert.Equal(t, "MOODY", entry["content_profile"], "the declared value rides verbatim")
	assert.Equal(t, PromptDigest(`{"q":"secret"}`), entry["prompt_hash"],
		"the invalid supplied digest is recomputed from the body")
}

// TestPublish_metadataOnlySuppliedHashPreserved: a valid producer digest is
// preserved byte-for-byte even without a body.
func TestPublish_metadataOnlySuppliedHashPreserved(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	p := NewRedisPublisher(rdb, "eventpublisher-profile-hash-stream")

	hash := PromptDigest("body that never rides the wire")
	require.NoError(t, p.Publish(testCtx, &Event{
		EventType:      "request.completed",
		ContentProfile: "metadata-only",
		PromptHash:     hash,
	}))

	vals, err := rdb.XRange(testCtx, "eventpublisher-profile-hash-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	assert.Equal(t, hash, vals[0].Values["prompt_hash"])
}

// TestPublish_metadataOnlyBlankBodyNoHash: no body and no valid supplied
// digest → the hash key is omitted-equivalent (empty) on the wire.
func TestPublish_metadataOnlyBlankBodyNoHash(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	p := NewRedisPublisher(rdb, "eventpublisher-profile-blank-stream")

	require.NoError(t, p.Publish(testCtx, &Event{
		EventType:      "request.completed",
		Payload:        "   ",
		ContentProfile: "metadata-only",
	}))

	vals, err := rdb.XRange(testCtx, "eventpublisher-profile-blank-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	assert.Empty(t, vals[0].Values["prompt_hash"])
}

// TestPublish_legacyProfileUnchanged: legacy events (empty declaration)
func TestPublish_legacyProfileUnchanged(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)
	p := NewRedisPublisher(rdb, "eventpublisher-profile-legacy-stream")

	require.NoError(t, p.Publish(testCtx, &Event{
		EventType: "request.completed",
		Payload:   `{"q":"kept"}`,
	}))

	vals, err := rdb.XRange(testCtx, "eventpublisher-profile-legacy-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	entry := vals[0].Values
	wantPayload := `{"q":"kept"}` // byte-exact pin: legacy wire must not change shape
	assert.Equal(t, wantPayload, entry["payload"])
	assert.NotContains(t, entry, "content_profile")
	assert.NotContains(t, entry, "prompt_hash")
}

// attribution rides the event as org_credential_ref and stays OFF the wire
// The value is id8:last4 only; there is no field anywhere on the event that
// could carry key material.
func TestOrgCredentialRefWireContract(t *testing.T) {
	maskedRef := "3f2ac1b2:9c11" // fixture: id8:last4 display mask, not a credential
	withRef, err := json.Marshal(&Event{
		EventType:        "request.completed",
		UsedOrgKey:       true,
		OrgCredentialRef: maskedRef,
	})
	require.NoError(t, err)
	assert.Contains(t, string(withRef), `"used_org_key":true`)
	assert.Contains(t, string(withRef), `"org_credential_ref":"3f2ac1b2:9c11"`)

	withoutRef, err := json.Marshal(&Event{EventType: "request.completed"})
	require.NoError(t, err)
	assert.NotContains(t, string(withoutRef), "org_credential_ref", "an unused ref must stay off the wire")

	// optional key — the consumer (loggerd) decodes into the struct and
	// ignores unknown fields, so omitempty keeps old streams readable.
	var back Event
	require.NoError(t, json.Unmarshal(withoutRef, &back))
	assert.Empty(t, back.OrgCredentialRef)
}

// retPubStubStore is a configurable OriginalRetentionStore fake for the
// producer-side tests.
type retPubStubStore struct {
	calls     int
	err       error
	effective bool
	found     bool
}

func (s *retPubStubStore) GetOrgOriginalRetention(_ context.Context, orgID string) (*adminstore.OrgOriginalRetention, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if !s.found {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	return &adminstore.OrgOriginalRetention{OrgID: orgID, Effective: s.effective}, nil
}

// retPublishEvent is a legacy-profile event carrying both raw upstream
// captures — the exact shape the chat/stream finish paths build.
func retPublishEvent() *Event {
	return &Event{
		EventType:        "request.completed",
		Source:           "gateway",
		SessionID:        "sess-ret",
		OrgID:            "org-ret",
		Payload:          `{"model":"gpt-4","messages":[{"role":"user","content":"TOP SECRET PROMPT"}]}`,
		UpstreamPayload:  `{"model":"gpt-4o","messages":[{"role":"user","content":"TOP SECRET SENT BODY"}]}`,
		UpstreamResponse: `{"choices":[{"message":{"content":"TOP SECRET COMPLETION"}}]}`,
		ModelUsed:        "gpt-4o",
		TokensIn:         11,
		TokensOut:        4,
		Method:           "POST",
	}
}

// TestPublish_retentionOffStripsUpstreamCaptures is the core producer
// negative (N02-P06 T03/T06): retention OFF under the legacy profile must
// withhold the raw upstream captures BEFORE the XADD — read back from the
// real stream, not from the in-memory event.
func TestPublish_retentionOffStripsUpstreamCaptures(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-retention-off-stream")
	p.SetOriginalRetentionStore(&retPubStubStore{}) // org not found ⇒ fail-closed OFF

	require.NoError(t, p.Publish(testCtx, retPublishEvent()))

	vals, err := rdb.XRange(testCtx, "eventpublisher-retention-off-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	entry := vals[0].Values

	for _, key := range []string{"upstream_payload", "upstream_response"} {
		_, has := entry[key]
		assert.False(t, has, "%s must not enter the durable buffer when retention is off", key)
	}
	// The processed payload, the digest-free metadata and the event shape
	// keep flowing — retention governs the ORIGINAL captures only.
	assert.Equal(t, retPublishEvent().Payload, entry["payload"])
	assert.Equal(t, "org-ret", entry["org_id"])
	assert.Equal(t, "gpt-4o", entry["model_used"])
	assert.Equal(t, int64(11), parseInt64(entry["tokens_in"]))
	assert.NotContains(t, entry, "content_profile", "the legacy declaration stays absent")
}

// TestPublish_retentionLookupErrorFailsClosed: a broken toggle source at the
// producer degrades to processed-only buffering, never to raw captures.
func TestPublish_retentionLookupErrorFailsClosed(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-retention-err-stream")
	p.SetOriginalRetentionStore(&retPubStubStore{err: errors.New("retention lookup failed")})

	require.NoError(t, p.Publish(testCtx, retPublishEvent()))

	vals, err := rdb.XRange(testCtx, "eventpublisher-retention-err-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	for _, key := range []string{"upstream_payload", "upstream_response"} {
		_, has := vals[0].Values[key]
		assert.False(t, has, "%s must not ride the stream when the toggle source is broken", key)
	}
}

// TestPublish_retentionUnwiredFailsClosed: an unwired store resolves OFF for
// every org — the same fail-closed matrix as the consumer's resolver.
func TestPublish_retentionUnwiredFailsClosed(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-retention-unwired-stream")
	// no SetOriginalRetentionStore — nil resolver

	require.NoError(t, p.Publish(testCtx, retPublishEvent()))

	vals, err := rdb.XRange(testCtx, "eventpublisher-retention-unwired-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	for _, key := range []string{"upstream_payload", "upstream_response"} {
		_, has := vals[0].Values[key]
		assert.False(t, has, "%s must not ride the stream without a wired toggle source", key)
	}
}

// TestPublish_retentionOnKeepsCapturesByteIdentical pins the opt-in parity:
// with the org explicitly opted in, the wire event is byte-for-byte the
// pre-gate contract — captures ride verbatim, no field is dropped or
// rewritten.
func TestPublish_retentionOnKeepsCapturesByteIdentical(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-retention-on-stream")
	store := &retPubStubStore{found: true, effective: true}
	p.SetOriginalRetentionStore(store)
	require.Equal(t, 0, store.calls, "no lookup happens outside Publish")

	ev := retPublishEvent()
	require.NoError(t, p.Publish(testCtx, ev))
	require.Equal(t, 1, store.calls, "one resolution per Publish")

	// The in-process event is never mutated (observer/hook contract).
	assert.NotEmpty(t, ev.UpstreamPayload, "the caller's event keeps its captures")

	vals, err := rdb.XRange(testCtx, "eventpublisher-retention-on-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	entry := vals[0].Values
	assert.Equal(t, ev.UpstreamPayload, entry["upstream_payload"], "opt-in keeps the sent-body capture verbatim")
	assert.Equal(t, ev.UpstreamResponse, entry["upstream_response"], "opt-in keeps the response capture verbatim")
	assert.Equal(t, ev.Payload, entry["payload"])
}

// TestPublish_strictProfileIgnoresRetention: the metadata-only contract is
// profile-keyed, not retention-keyed — even an opted-in org gets no content
// captures under the strict profile.
func TestPublish_strictProfileIgnoresRetention(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-retention-strict-stream")
	p.SetOriginalRetentionStore(&retPubStubStore{found: true, effective: true}) // ON

	body := `{"messages":[{"role":"user","content":"secret-profile-body"}]}`
	require.NoError(t, p.Publish(testCtx, &Event{
		EventType:        "request.completed",
		OrgID:            "org-ret-strict",
		Payload:          body,
		UpstreamPayload:  body,
		UpstreamResponse: `{"completion":"secret-response"}`,
		ContentProfile:   "metadata-only",
	}))

	vals, err := rdb.XRange(testCtx, "eventpublisher-retention-strict-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	entry := vals[0].Values
	for _, key := range []string{"payload", "upstream_payload", "upstream_response"} {
		_, has := entry[key]
		assert.False(t, has, "%s must not ride the metadata-only stream regardless of retention", key)
	}
	assert.Equal(t, "metadata-only", entry["content_profile"])
}

// processedEnvelope is the FIX-20 processed_response fixture: the
// self-describing envelope exactly as pkg/gateway marshals it (v1,
// model_response) — the field the loggerd consumer binds into response_view.
const processedEnvelope = `{"v":1,"kind":"model_response","status":"complete","model":"gpt-4o","content":"Hello!","finish_reason":"stop"}`

// TestPublish_metadataOnlyDeletesProcessedResponse pins the FIX-20 strict
// decision (DESIGN §9): the processed envelope is deleted from the
// metadata-only wire — the key is absent from the stream entry entirely
// (delete, not filter), riding the same content-class boundary as
// payload/upstream captures. Without this pin a leak past the metadata-only
// boundary would pass CI (the consumer's strict NULL has no producer teeth).
func TestPublish_metadataOnlyDeletesProcessedResponse(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-profile-processed-stream")
	body := `{"messages":[{"role":"user","content":"secret-profile-body"}]}`
	require.NoError(t, p.Publish(testCtx, &Event{
		EventType:         "request.completed",
		OrgID:             "org-prof",
		Payload:           body,
		UpstreamPayload:   body,
		UpstreamResponse:  `{"completion":"secret-response"}`,
		ProcessedResponse: processedEnvelope,
		ContentProfile:    "metadata-only",
	}))

	vals, err := rdb.XRange(testCtx, "eventpublisher-profile-processed-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	entry := vals[0].Values
	for _, key := range []string{"payload", "upstream_payload", "upstream_response", "processed_response"} {
		_, has := entry[key]
		assert.False(t, has, "%s must not ride the metadata-only stream", key)
	}
	assert.Equal(t, "metadata-only", entry["content_profile"])
	assert.Equal(t, "org-prof", entry["org_id"], "metadata keeps flowing")
}

// TestPublish_retentionOffKeepsProcessedResponse pins the opposite profile
// decision (DESIGN §9): an explicitly OFF retention resolution strips the
// ORIGINAL captures but keeps the PROCESSED client-facing envelope — the
// same retention tier as payload.
func TestPublish_retentionOffKeepsProcessedResponse(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	p := NewRedisPublisher(rdb, "eventpublisher-retention-processed-stream")
	p.SetOriginalRetentionStore(&retPubStubStore{found: true, effective: false}) // explicit org OFF

	ev := retPublishEvent()
	ev.ProcessedResponse = processedEnvelope
	require.NoError(t, p.Publish(testCtx, ev))

	vals, err := rdb.XRange(testCtx, "eventpublisher-retention-processed-stream", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	entry := vals[0].Values
	for _, key := range []string{"upstream_payload", "upstream_response"} {
		_, has := entry[key]
		assert.False(t, has, "%s must not enter the buffer when retention is off", key)
	}
	kept, hasProcessed := entry["processed_response"]
	require.True(t, hasProcessed, "retention OFF keeps the field: processed_response must ride the stream")
	assert.JSONEq(t, processedEnvelope, kept.(string),
		"retention OFF governs the ORIGINAL captures only — the processed envelope keeps flowing")
	assert.Equal(t, ev.Payload, entry["payload"], "payload shares the processed envelope's retention tier")
}

// TestPublish_processedResponseProfileRoundTrip drives the full wire
// round-trip (DESIGN §9): one envelope-bearing event emitted under each
// profile decision, then read back from the real stream — strict deletes
// the field even over an opted-in org, retention OFF keeps it while
// stripping the raw captures, retention ON keeps it byte-identical. Each
// non-strict arm uses its own org so the resolver TTL cache never serves a
// stale decision across the store flips.
func TestPublish_processedResponseProfileRoundTrip(t *testing.T) {
	rdb := testdb.Redis(t)
	testdb.FlushDB(t, rdb)

	stream := "eventpublisher-processed-roundtrip-stream"
	p := NewRedisPublisher(rdb, stream)
	store := &retPubStubStore{found: true, effective: true}
	p.SetOriginalRetentionStore(store)

	strict := retPublishEvent()
	strict.OrgID = "org-rt-strict"
	strict.ProcessedResponse = processedEnvelope
	strict.ContentProfile = "metadata-only"
	require.NoError(t, p.Publish(testCtx, strict))

	off := retPublishEvent()
	off.OrgID = "org-rt-off"
	off.ProcessedResponse = processedEnvelope
	store.effective = false
	require.NoError(t, p.Publish(testCtx, off))

	on := retPublishEvent()
	on.OrgID = "org-rt-on"
	on.ProcessedResponse = processedEnvelope
	store.effective = true
	require.NoError(t, p.Publish(testCtx, on))

	vals, err := rdb.XRange(testCtx, stream, "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, vals, 3)

	_, has := vals[0].Values["processed_response"]
	assert.False(t, has, "strict: deleted before XADD even with retention ON")
	keptOff, hasOff := vals[1].Values["processed_response"]
	require.True(t, hasOff, "retention OFF keeps the field: processed_response must survive the round-trip")
	assert.JSONEq(t, processedEnvelope, keptOff.(string),
		"retention OFF: the processed envelope survives the round-trip")
	_, hasUp := vals[1].Values["upstream_payload"]
	assert.False(t, hasUp, "retention OFF still strips the raw captures")
	keptOn, hasOn := vals[2].Values["processed_response"]
	require.True(t, hasOn, "retention ON keeps the field: processed_response must survive the round-trip")
	assert.JSONEq(t, processedEnvelope, keptOn.(string),
		"retention ON: the processed envelope rides verbatim")
	assert.Equal(t, on.UpstreamResponse, vals[2].Values["upstream_response"])
}

// TestPublish_SetOriginalRetentionStoreFirstWins: re-wiring must not
// silently drop the warm resolver (attachRetentionGate runs per request).
func TestPublish_SetOriginalRetentionStoreFirstWins(t *testing.T) {
	p := NewRedisPublisher(nil, "stream")
	p.SetOriginalRetentionStore(&retPubStubStore{found: true, effective: true})
	first := p.OriginalRetention()
	require.NotNil(t, first)

	p.SetOriginalRetentionStore(&retPubStubStore{found: true, effective: false})
	assert.Same(t, first, p.OriginalRetention(), "the first wiring must stick")

	// nil publisher/receiver must be nil-safe (minimal test gateways).
	var nilPub *RedisPublisher
	assert.Nil(t, nilPub.OriginalRetention())
}
