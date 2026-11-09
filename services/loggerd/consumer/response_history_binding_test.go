package consumer

// FIX-20 RESPONSE-HISTORY: the mapper's response binding. A valid
// processed-response envelope IS the `response` column content; everything
// else (absent field, malformed JSON, foreign kind/version/status, strict
// profile) keeps the pre-FIX-20 behavior byte-for-byte.

import (
	"encoding/json"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fxEnvelope = `{"v":1,"kind":"model_response","status":"complete","model":"gpt-5",` +
		`"content":"Hello! How can I help?","finish_reason":"stop"}`
	fxEnvelopeTools = `{"v":1,"kind":"model_response","status":"partial","reason":"capture_limit",` +
		`"model":"gpt-5","content":"","tool_calls":[{"index":0,"id":"call_1","name":"get_weather","arguments":"{\"city\":\"Oslo\"}"}],"truncated":true}`
)

// fxLegacyFields is a legacy-profile completed event with the given
// processed_response wire value ("" = field absent).
func fxLegacyFields(requestID, processed string) map[string]interface{} {
	fields := cpCompletedFields(requestID, false)
	delete(fields, "processed_response")
	if processed != "" {
		fields["processed_response"] = processed
	}
	return fields
}

// boundResponse re-reads what the mapper bound for the JSONB column.
func boundResponse(t *testing.T, ev requestEvent) *adminstore.RequestResponseView {
	t.Helper()
	require.NotNil(t, ev.responseJSON, "expected an envelope binding, got NULL")
	raw, ok := ev.responseJSON.([]byte)
	require.True(t, ok, "responseJSON must be ResponseForStorage bytes, got %T", ev.responseJSON)
	return adminstore.ParseResponseEnvelope(json.RawMessage(raw))
}

func TestMapper_ProcessedResponseEnvelopeBindsVerbatim(t *testing.T) {
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "false")

	ev := parseRequestEventProfile(fxLegacyFields("req-fx20-1", fxEnvelope), config.LogContentProfileLegacy, true)

	view := boundResponse(t, ev)
	require.NotNil(t, view)
	assert.Equal(t, "complete", view.Status)
	assert.Equal(t, "gpt-5", view.Model)
	assert.Equal(t, "Hello! How can I help?", view.Content)
	assert.Empty(t, view.Reason)
	assert.False(t, view.Truncated)
	// The stored bytes are the envelope, not the payload snapshot.
	stored := string(ev.responseJSON.([]byte))
	assert.Contains(t, stored, `"kind":"model_response"`)
	assert.NotContains(t, stored, "TOP SECRET PROMPT BODY")
}

func TestMapper_ProcessedResponsePartialEnvelopeBinds(t *testing.T) {
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "false")

	ev := parseRequestEventProfile(fxLegacyFields("req-fx20-2", fxEnvelopeTools), config.LogContentProfileLegacy, true)

	view := boundResponse(t, ev)
	require.NotNil(t, view)
	assert.Equal(t, "partial", view.Status)
	assert.Equal(t, "capture_limit", view.Reason)
	assert.True(t, view.Truncated)
	require.Len(t, view.ToolCalls, 1)
	assert.Equal(t, 0, view.ToolCalls[0].Index)
	assert.Equal(t, "get_weather", view.ToolCalls[0].Name)
	assert.JSONEq(t, `{"city":"Oslo"}`, view.ToolCalls[0].Arguments)
}

func TestMapper_LegacyFallbackWhenEnvelopeAbsent(t *testing.T) {
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "false")

	ev := parseRequestEventProfile(fxLegacyFields("req-fx20-3", ""), config.LogContentProfileLegacy, true)

	require.NotNil(t, ev.responseJSON)
	stored := string(ev.responseJSON.([]byte))
	// Pre-FIX-20 binding: the truncated payload snapshot.
	assert.Contains(t, stored, "TOP SECRET PROMPT BODY")
	assert.NotContains(t, stored, `"kind":"model_response"`)
	assert.Nil(t, adminstore.ParseResponseEnvelope(json.RawMessage(stored)))
}

func TestMapper_LegacyFallbackWhenEnvelopeInvalid(t *testing.T) {
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "false")

	cases := []struct {
		name  string
		field string
	}{
		{"malformed JSON", `{"v":1,"kind":"model_response","status":`},
		{"foreign kind", `{"v":1,"kind":"other_thing","status":"complete","content":"x"}`},
		{"future version", `{"v":2,"kind":"model_response","status":"complete","content":"x"}`},
		{"unknown status", `{"v":1,"kind":"model_response","status":"meh","content":"x"}`},
		{"plain string", `just the raw answer text`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := parseRequestEventProfile(fxLegacyFields("req-fx20-4", tc.field), config.LogContentProfileLegacy, true)
			require.NotNil(t, ev.responseJSON)
			stored := string(ev.responseJSON.([]byte))
			assert.NotContains(t, stored, `"kind"`)
			assert.Nil(t, adminstore.ParseResponseEnvelope(json.RawMessage(stored)),
				"a rejected envelope must never come back as a parseable view")
		})
	}
}

func TestMapper_StrictProfileIgnoresEnvelope(t *testing.T) {
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "true")

	// Even if a stray processed_response survived the strict boundary (it is
	// deleted at the publisher), the strict mapper binds NULL content — the
	// envelope is response content and never reaches the durable write.
	fields := fxLegacyFields("req-fx20-5", fxEnvelope)
	fields["content_profile"] = "metadata-only"
	delete(fields, "payload")

	ev := parseRequestEventProfile(fields, config.LogContentProfileMetadataOnly, true)
	assert.Nil(t, ev.responseJSON)
	assert.Nil(t, ev.upstreamReqJSON)
	assert.Nil(t, ev.upstreamRespJSON)
}
