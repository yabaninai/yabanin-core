package cli

// FIX-20 RESPONSE-HISTORY producer tests: envelope construction from a
// served completion document, SSE capture through the writer chain, budget
// truncation, and the frozen-once finish semantics.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fxChunkFrame wraps one chat.completion.chunk CHOICE object
// (e.g. {"index":0,"delta":{"content":"x"}}) into a data: SSE frame.
func fxChunkFrame(t *testing.T, choice string) []byte {
	t.Helper()
	return []byte(`data: {"id":"chatcmpl-1","created":1,"model":"gpt-5","choices":[` +
		choice + `]}` + "\n\n")
}

func TestEnvelopeFromCompletionDoc_Complete(t *testing.T) {
	doc := []byte(`{"object":"chat.completion","model":"gpt-5","choices":[{"index":0,` +
		`"finish_reason":"stop","message":{"role":"assistant","content":"Hello there",` +
		`"reasoning_content":"hmm","tool_calls":[{"id":"call_1","type":"function",` +
		`"function":{"name":"get_weather","arguments":"{\"city\":\"Oslo\"}"}}]}}]}`)

	env := envelopeFromCompletionDoc(doc, "fallback-model")
	require.NotNil(t, env)
	assert.Equal(t, 1, env.Version)
	assert.Equal(t, responseHistoryKind, env.Kind)
	assert.Equal(t, responseHistoryStatusComplete, env.Status)
	assert.Empty(t, env.Reason)
	assert.Equal(t, "gpt-5", env.Model)
	assert.Equal(t, "Hello there", env.Content)
	assert.Equal(t, "hmm", env.ReasoningContent)
	assert.Equal(t, "stop", env.FinishReason)
	assert.False(t, env.Truncated)
	require.Len(t, env.ToolCalls, 1)
	assert.Equal(t, responseHistoryToolCall{Index: 0, ID: "call_1", Name: "get_weather", Arguments: `{"city":"Oslo"}`}, env.ToolCalls[0])

	// Wire contract: the producer envelope must parse on the read side.
	view := adminstore.ParseResponseEnvelope(json.RawMessage(env.marshal()))
	require.NotNil(t, view, "producer envelope must satisfy the adminstore reader")
	assert.Equal(t, adminstore.ResponseStatusComplete, view.Status)
	assert.Equal(t, "Hello there", view.Content)
	require.Len(t, view.ToolCalls, 1)
}

func TestEnvelopeFromCompletionDoc_ModelFallsBack(t *testing.T) {
	doc := []byte(`{"choices":[{"finish_reason":null,"message":{"content":"answer"}}]}`)
	env := envelopeFromCompletionDoc(doc, "routed-model")
	require.NotNil(t, env)
	assert.Equal(t, "routed-model", env.Model)
	assert.Empty(t, env.FinishReason)
}

func TestEnvelopeFromCompletionDoc_HonestAbsence(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"not json", []byte("gateway internal error page")},
		{"empty object", []byte(`{}`)},
		{"no choices", []byte(`{"model":"gpt-5","choices":[]}`)},
		{"role-only message", []byte(`{"choices":[{"message":{"role":"assistant","content":""}}]}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Nil(t, envelopeFromCompletionDoc(tc.body, "m"))
		})
	}
}

func TestEnvelopeFromCompletionDoc_CaptureLimit(t *testing.T) {
	big := strings.Repeat("x", responseHistoryCaptureLimit+10)
	doc := []byte(`{"model":"gpt-5","choices":[{"message":{"content":"` + big + `"}}]}`)

	env := envelopeFromCompletionDoc(doc, "m")
	require.NotNil(t, env)
	assert.Equal(t, responseHistoryStatusPartial, env.Status)
	assert.Equal(t, responseHistoryReasonCaptureLimit, env.Reason)
	assert.True(t, env.Truncated)
	assert.Len(t, env.Content, responseHistoryCaptureLimit)
}

func TestResponseHistoryCapture_StreamContentAndDone(t *testing.T) {
	inner := httptest.NewRecorder()
	c := newResponseHistoryCapture(inner)

	for _, frame := range []string{
		`{"index":0,"delta":{"role":"assistant"}}`,
		`{"index":0,"delta":{"content":"Hel"}}`,
		`{"index":0,"delta":{"content":"lo!"}}`,
		`{"index":0,"delta":{},"finish_reason":"stop"}`,
	} {
		n, err := c.Write(fxChunkFrame(t, frame))
		require.NoError(t, err)
		assert.Equal(t, len(fxChunkFrame(t, frame)), n, "capture must pass bytes through unchanged")
	}
	_, err := c.Write([]byte("data: [DONE]\n\n"))
	require.NoError(t, err)

	env := c.finishEnvelope(responseHistoryStatusComplete, "")
	require.NotNil(t, env)
	assert.Equal(t, responseHistoryStatusComplete, env.Status)
	assert.Empty(t, env.Reason)
	assert.Equal(t, "Hello!", env.Content)
	assert.Equal(t, "gpt-5", env.Model)
	assert.Equal(t, "stop", env.FinishReason)
	assert.False(t, env.Truncated)
	assert.True(t, c.sawDone)
}

func TestResponseHistoryCapture_ToolCallFragmentsMerged(t *testing.T) {
	c := newResponseHistoryCapture(httptest.NewRecorder())

	_, err := c.Write(fxChunkFrame(t, `{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_9","function":{"name":"get_weather","arguments":""}}]}}`))
	require.NoError(t, err)
	_, err = c.Write(fxChunkFrame(t, `{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"ci"}}]}}`))
	require.NoError(t, err)
	_, err = c.Write(fxChunkFrame(t, `{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ty\":\"Oslo\"}"}}]}}`))
	require.NoError(t, err)

	env := c.finishEnvelope(responseHistoryStatusComplete, "")
	require.NotNil(t, env)
	require.Len(t, env.ToolCalls, 1)
	assert.Equal(t, "call_9", env.ToolCalls[0].ID)
	assert.Equal(t, "get_weather", env.ToolCalls[0].Name)
	assert.JSONEq(t, `{"city":"Oslo"}`, env.ToolCalls[0].Arguments)
	assert.Empty(t, env.Content, "tool-call-only answers carry explicit empty content")
}

func TestResponseHistoryCapture_BudgetTruncates(t *testing.T) {
	c := newResponseHistoryCapture(httptest.NewRecorder())

	// Two frames whose combined text exceeds the budget: the second is
	// refused by the accumulator, the envelope reports the shortfall.
	_, err := c.Write(fxChunkFrame(t, `{"index":0,"delta":{"content":"`+strings.Repeat("a", responseHistoryCaptureLimit)+`"}}`))
	require.NoError(t, err)
	_, err = c.Write(fxChunkFrame(t, `{"index":0,"delta":{"content":"tail"}}`))
	require.NoError(t, err)

	env := c.finishEnvelope(responseHistoryStatusComplete, "")
	require.NotNil(t, env)
	assert.Equal(t, responseHistoryStatusPartial, env.Status, "complete upgrades to partial on truncation")
	assert.Equal(t, responseHistoryReasonCaptureLimit, env.Reason)
	assert.True(t, env.Truncated)
	assert.Len(t, env.Content, responseHistoryCaptureLimit)
}

func TestResponseHistoryCapture_PendingOverflowDropsAndResumes(t *testing.T) {
	c := newResponseHistoryCapture(httptest.NewRecorder())

	// A single write with no newline larger than the pending bound: the
	// buffered bytes are dropped whole (dropped=true) and the capture
	// resumes at the next complete line.
	_, err := fmt.Fprintf(c, "data: {\"junk\":\"%s\"}", strings.Repeat("x", responseHistoryPendingLimit+1024))
	require.NoError(t, err)
	assert.True(t, c.dropped)
	assert.Empty(t, c.pending)

	_, err = c.Write(fxChunkFrame(t, `{"index":0,"delta":{"content":"kept"}}`))
	require.NoError(t, err)
	_, err = c.Write([]byte("data: [DONE]\n\n"))
	require.NoError(t, err)

	env := c.finishEnvelope(responseHistoryStatusComplete, "")
	require.NotNil(t, env)
	assert.Equal(t, "kept", env.Content)
	assert.True(t, env.Truncated, "a dropped frame must surface as truncated")
	assert.Equal(t, responseHistoryStatusPartial, env.Status)
	assert.Equal(t, responseHistoryReasonCaptureLimit, env.Reason)
}

func TestResponseHistoryCapture_FinishFreezesOnce(t *testing.T) {
	c := newResponseHistoryCapture(httptest.NewRecorder())
	_, err := c.Write(fxChunkFrame(t, `{"index":0,"delta":{"content":"stable"}}`))
	require.NoError(t, err)

	first := c.finishEnvelope(responseHistoryStatusComplete, "")
	require.NotNil(t, first)
	second := c.finishEnvelope(responseHistoryStatusPartial, responseHistoryReasonClientCancel)
	require.Same(t, first, second, "finishEnvelope freezes: later calls return the first envelope")
	assert.Equal(t, responseHistoryStatusComplete, second.Status)
}

func TestResponseHistoryCapture_EmptyStaysAbsent(t *testing.T) {
	c := newResponseHistoryCapture(httptest.NewRecorder())
	// Role-only chunk and a non-data line: nothing client-facing captured.
	_, err := c.Write(fxChunkFrame(t, `{"index":0,"delta":{"role":"assistant"}}`))
	require.NoError(t, err)
	_, err = c.Write([]byte(": keep-alive comment\n\n"))
	require.NoError(t, err)

	assert.Nil(t, c.finishEnvelope(responseHistoryStatusComplete, ""))
	assert.Empty(t, c.wire(), "no captured content → empty wire value, never a fabricated envelope")
}

func TestResponseHistoryCapture_CRLFAndMalformedLines(t *testing.T) {
	c := newResponseHistoryCapture(httptest.NewRecorder())

	_, err := c.Write([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"win\"}}]}\r\n"))
	require.NoError(t, err)
	_, err = c.Write([]byte("data: not-json-at-all\n"))
	require.NoError(t, err)
	_, err = c.Write([]byte("event: ping\n"))
	require.NoError(t, err)

	env := c.finishEnvelope(responseHistoryStatusComplete, "")
	require.NotNil(t, env)
	assert.Equal(t, "win", env.Content)
}

func TestResponseHistoryCapture_FlushPassesThrough(t *testing.T) {
	rec := httptest.NewRecorder()
	c := newResponseHistoryCapture(rec)
	require.NotPanics(t, func() { c.Flush() })
	assert.True(t, rec.Flushed)
}

// The envelope marshals with content always present (no omitempty): an
// explicit empty string must survive the round trip as `"content":""`.
func TestResponseHistoryEnvelope_ContentAlwaysInJSON(t *testing.T) {
	env := &responseHistoryEnvelope{
		Version: 1,
		Kind:    responseHistoryKind,
		Status:  responseHistoryStatusComplete,
		Model:   "gpt-5",
	}
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(env.marshal()), &raw))
	assert.JSONEq(t, `""`, string(raw["content"]))
	assert.NotContains(t, env.marshal(), `"reasoning_content"`)
	assert.NotContains(t, env.marshal(), `"tool_calls"`)
}

// finishEnvelope on a nil receiver stays safe (drain paths may carry a nil
// capture when the writer chain never wrapped — e.g. policy-denied requests).
func TestResponseHistoryCapture_NilSafe(t *testing.T) {
	var c *responseHistoryCapture
	assert.Nil(t, c.finishEnvelope(responseHistoryStatusComplete, ""))
	assert.Empty(t, c.wire())
}
