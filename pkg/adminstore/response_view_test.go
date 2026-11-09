package adminstore

// Contract tests for the FIX-20 processed-response envelope parser. The
// JSON literals pin the WIRE contract (what pkg/gateway marshals and the
// mapper stores), not a Go struct, so a producer-side shape change that
// breaks readers fails here.

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseResponseEnvelope_Full(t *testing.T) {
	raw := json.RawMessage(`{"v":1,"kind":"model_response","status":"partial",` +
		`"reason":"client_cancel","model":"gpt-5","content":"Partial ans",` +
		`"reasoning_content":"thinking...","tool_calls":[{"index":0,"id":"c1","name":"f","arguments":"{}"}],` +
		`"finish_reason":"stop","truncated":true}`)

	view := ParseResponseEnvelope(raw)
	require.NotNil(t, view)
	assert.Equal(t, ResponseStatusPartial, view.Status)
	assert.Equal(t, "client_cancel", view.Reason)
	assert.Equal(t, "gpt-5", view.Model)
	assert.Equal(t, "Partial ans", view.Content)
	assert.Equal(t, "thinking...", view.ReasoningContent)
	assert.Equal(t, "stop", view.FinishReason)
	assert.True(t, view.Truncated)
	require.Len(t, view.ToolCalls, 1)
	assert.Equal(t, RequestResponseToolCall{Index: 0, ID: "c1", Name: "f", Arguments: "{}"}, view.ToolCalls[0])
}

func TestParseResponseEnvelope_Minimal(t *testing.T) {
	// content without omitempty: explicit empty beats absent.
	raw := json.RawMessage(`{"v":1,"kind":"model_response","status":"complete","content":""}`)

	view := ParseResponseEnvelope(raw)
	require.NotNil(t, view)
	assert.Equal(t, ResponseStatusComplete, view.Status)
	assert.Empty(t, view.Content)
	assert.Empty(t, view.Model)
	assert.Empty(t, view.Reason)
	assert.False(t, view.Truncated)
	assert.Nil(t, view.ToolCalls)
}

func TestParseResponseEnvelope_RejectsNonEnvelopes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"sql null", `null`},
		{"empty", ``},
		{"legacy object snapshot", `{"choices":[{"message":{"content":"hi"}}]}`},
		{"legacy jsonb string", `"truncated plain text"`},
		{"wrong kind", `{"v":1,"kind":"dlq_envelope","status":"complete"}`},
		{"missing kind", `{"v":1,"status":"complete","content":"x"}`},
		{"future version", `{"v":2,"kind":"model_response","status":"complete","content":"x"}`},
		{"unknown status", `{"v":1,"kind":"model_response","status":"maybe","content":"x"}`},
		{"missing status", `{"v":1,"kind":"model_response","content":"x"}`},
		{"truncated json", `{"v":1,"kind":"model_response","status":"comp`},
		{"json array", `[1,2,3]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Nil(t, ParseResponseEnvelope(json.RawMessage(tc.raw)))
		})
	}
}

func TestParseResponseEnvelope_ContentAlwaysPresent(t *testing.T) {
	// The API contract: response_view.content is always a string on a parsed
	// view — never absent — so clients can render an empty answer without a
	// nil check.
	raw := json.RawMessage(`{"v":1,"kind":"model_response","status":"complete"}`)
	view := ParseResponseEnvelope(raw)
	require.NotNil(t, view)
	assert.Empty(t, view.Content)

	out, err := json.Marshal(view)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"content":""`)
}
