package provider

// Characterization tests pinning the chatToVertexGenerate request mapping:
// golden wire bytes, message-shape edges (empty/system/tool merge rules),
// generationConfig emission and precise rejections. Expected values are
// hand-derived from the documented adapter mapping, not from the code.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenBody exercises every payload section at once: system fold, user
// text, assistant text+tool_calls mixture, tool-result wrap, tools,
// named tool_choice, generationConfig with response_format.
const goldenBody = `{
	"model": "  gemini-2.5-flash  ",
	"messages": [
		{"role": "system", "content": "be terse"},
		{"role": "user", "content": "weather?"},
		{"role": "assistant", "content": "checking", "tool_calls": [
			{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Moscow\"}"}}
		]},
		{"role": "tool", "tool_call_id": "call_1", "content": "{\"temp\":-5}"}
	],
	"tools": [{"type": "function", "function": {"name": "get_weather"}}],
	"tool_choice": {"type": "function", "function": {"name": "get_weather"}},
	"max_completion_tokens": 64,
	"temperature": 0.5,
	"response_format": {"type": "json_object"}
}`

// Hand-counted oracle: exact generateContent bytes (struct field order is
// part of the wire contract; the model appears only in the envelope).
const wantGoldenPayload = `{"contents":[` +
	`{"role":"user","parts":[{"text":"weather?"}]},` +
	`{"role":"model","parts":[{"text":"checking"},{"functionCall":{"name":"get_weather","args":{"city":"Moscow"}}}]},` +
	`{"role":"user","parts":[{"functionResponse":{"name":"get_weather","response":{"temp":-5}}}]}` +
	`],"systemInstruction":{"parts":[{"text":"be terse"}]},` +
	`"tools":[{"functionDeclarations":[{"name":"get_weather"}]}],` +
	`"toolConfig":{"functionCallingConfig":{"mode":"ANY","allowedFunctionNames":["get_weather"]}},` +
	`"generationConfig":{"maxOutputTokens":64,"temperature":0.5,"responseMimeType":"application/json"}}`

func TestChatToVertexGenerate_GoldenWireBytes(t *testing.T) {
	t.Parallel()

	got, model, err := chatToVertexGenerate([]byte(goldenBody))
	require.NoError(t, err)
	assert.Equal(t, "gemini-2.5-flash", model, "model is trimmed")
	assert.JSONEq(t, wantGoldenPayload, string(got), "payload semantics")
	// Byte equality pins the wire emission (field order, no extra keys)
	// that JSONEq deliberately ignores; plain bytes.Equal because byte
	// identity, not JSON equivalence, is the contract under test.
	if !bytes.Equal(got, []byte(wantGoldenPayload)) {
		t.Errorf("payload bytes = %s, want %s", got, wantGoldenPayload)
	}

	env, err := (*Vertex)(nil).TranslateRequest([]byte(goldenBody))
	require.NoError(t, err)
	wantEnvelope := `{"model":"gemini-2.5-flash","gemini":` + wantGoldenPayload + `}`
	if !bytes.Equal(env, []byte(wantEnvelope)) {
		t.Errorf("envelope bytes = %s, want %s", env, wantEnvelope)
	}
}

func TestChatToVertexGenerate_MinimalPayloadHasOnlyContents(t *testing.T) {
	t.Parallel()

	got, model, err := chatToVertexGenerate([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	require.NoError(t, err)
	assert.Equal(t, "m", model)
	wantMinimal := `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`
	if !bytes.Equal(got, []byte(wantMinimal)) {
		t.Errorf("payload bytes = %s, want %s (unset sections must not be emitted)", got, wantMinimal)
	}
}

func TestChatToVertexGenerate_EmptySystemMessagesEmitNoInstruction(t *testing.T) {
	t.Parallel()

	body := `{"model":"m","messages":[
		{"role":"system","content":""},
		{"role":"developer","content":null},
		{"role":"user","content":"hi"}]}`
	got, _, err := chatToVertexGenerate([]byte(body))
	require.NoError(t, err)
	assert.NotContains(t, string(got), "systemInstruction", "empty system text folds to nothing")
	wantFolded := `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`
	if !bytes.Equal(got, []byte(wantFolded)) {
		t.Errorf("payload bytes = %s, want %s", got, wantFolded)
	}

	_, _, err = chatToVertexGenerate([]byte(`{"model":"m","messages":[{"role":"system","content":"only rules"}]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no user/assistant messages")
}

func TestChatToVertexGenerate_StopStringCoercedToArray(t *testing.T) {
	t.Parallel()

	got, _, err := chatToVertexGenerate([]byte(`{"model":"m","messages":[{"role":"user","content":"x"}],"stop":"END"}`))
	require.NoError(t, err)
	assert.Contains(t, string(got), `"stopSequences":["END"]`,
		`a JSON string stop must behave like a one-element array`)
}

func TestChatToVertexGenerate_AssistantTextAndToolCallsShareOneModelContent(t *testing.T) {
	t.Parallel()

	body := `{"model":"m","messages":[
		{"role":"user","content":"x"},
		{"role":"assistant","content":"note","tool_calls":[
			{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}},
			{"id":"c2","function":{"name":"g","arguments":"null"}}
		]}]}`
	got, _, err := chatToVertexGenerate([]byte(body))
	require.NoError(t, err)
	wantModel := `{"role":"model","parts":[` +
		`{"text":"note"},` +
		`{"functionCall":{"name":"f","args":{"a":1}}},` +
		`{"functionCall":{"name":"g","args":{}}}` +
		`]}`
	assert.Contains(t, string(got), wantModel,
		"text precedes functionCall parts; absent tool_call type is accepted; null arguments become {}")
}

// toolTurnMessages ends with two tool results separated only by a carrier
// message that appends no content — both results must land in ONE user
// content (Gemini's parallel-call shape).
func toolMergeBody(separator string) string {
	return `{"model":"m","messages":[` +
		`{"role":"user","content":"x"},` +
		`{"role":"assistant","tool_calls":[` +
		`{"id":"c1","type":"function","function":{"name":"f1","arguments":"{}"}},` +
		`{"id":"c2","type":"function","function":{"name":"f2","arguments":"{}"}}]},` +
		`{"role":"tool","tool_call_id":"c1","content":"r1"},` +
		separator +
		`{"role":"tool","tool_call_id":"c2","content":"r2"}]}`
}

func TestChatToVertexGenerate_ToolResultMergeBoundaries(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, separator string
		wantContents    int
		wantMergedParts int
	}{
		// An empty assistant (no content, no tool_calls) carries no
		// semantics and must not break the merge.
		{"empty assistant between results", `{"role":"assistant","content":null},`, 3, 2},
		// System/developer messages append no content either.
		{"system between results", `{"role":"system","content":"mid"},`, 3, 2},
		// A real user turn between results starts a new user content.
		{"user between results", `{"role":"user","content":"next"},`, 5, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := chatToVertexGenerate([]byte(toolMergeBody(tc.separator)))
			require.NoError(t, err)
			var gen vertexGenerateRequest
			require.NoError(t, json.Unmarshal(got, &gen))
			require.Len(t, gen.Contents, tc.wantContents)
			last := gen.Contents[len(gen.Contents)-1]
			assert.Equal(t, "user", last.Role)
			require.Len(t, last.Parts, tc.wantMergedParts)
			if tc.wantMergedParts == 2 {
				assert.Contains(t, string(got), `{"functionResponse":{"name":"f1","response":{"result":"r1"}}},{"functionResponse":{"name":"f2","response":{"result":"r2"}}}`)
			}
		})
	}
}

func TestChatToVertexGenerate_ToolResultNameResolution(t *testing.T) {
	t.Parallel()

	// Explicit message.name wins even with no prior tool_call id match.
	byName := `{"model":"m","messages":[{"role":"user","content":"x"},` +
		`{"role":"tool","name":"named_fn","tool_call_id":"ignored","content":"r"}]}`
	got, _, err := chatToVertexGenerate([]byte(byName))
	require.NoError(t, err)
	assert.Contains(t, string(got), `{"name":"named_fn","response":{"result":"r"}}`)

	// Empty tool content wraps as {"result":""}, still an object.
	empty := `{"model":"m","messages":[` +
		`{"role":"user","content":"x"},` +
		`{"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}]},` +
		`{"role":"tool","tool_call_id":"c"}]}`
	got, _, err = chatToVertexGenerate([]byte(empty))
	require.NoError(t, err)
	assert.Contains(t, string(got), `{"name":"f","response":{"result":""}}`)
}

func TestChatToVertexGenerate_GenerationConfigEmission(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, extra, wantGenerationConfig string
	}{
		// Default/text/null response_format leaves no mime type — and no
		// generationConfig at all when nothing else is set.
		{"response_format text", `"response_format":{"type":"text"}`, ""},
		{"response_format empty type", `"response_format":{"type":""}`, ""},
		{"response_format null", `"response_format":null`, ""},
		{"json_object sets mime", `"response_format":{"type":"json_object"}`,
			`"generationConfig":{"responseMimeType":"application/json"}`},
		{"temperature alone", `"temperature":0.25`, `"generationConfig":{"temperature":0.25}`},
		{"max_tokens alone", `"max_tokens":8`, `"generationConfig":{"maxOutputTokens":8}`},
		{"top_p alone", `"top_p":0.5`, `"generationConfig":{"topP":0.5}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := chatToVertexGenerate([]byte(`{"model":"m","messages":[{"role":"user","content":"x"}],` + tc.extra + `}`))
			require.NoError(t, err)
			if tc.wantGenerationConfig == "" {
				assert.NotContains(t, string(got), "generationConfig")
			} else {
				assert.Contains(t, string(got), tc.wantGenerationConfig)
			}
		})
	}
}

func TestChatToVertexGenerate_Rejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, body, wantErr string
	}{
		{
			"body not JSON",
			`nope`,
			"vertex: decode openai request",
		},
		{
			"whitespace-only model",
			`{"model":"   ","messages":[{"role":"user","content":"x"}]}`,
			"has no model field",
		},
		{
			"tool call type not function",
			`{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"c","type":"custom","function":{"name":"f"}}]}]}`,
			`unsupported tool call type "custom"`,
		},
		{
			"tool call without name",
			`{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"arguments":"{}"}}]}]}`,
			"tool call without a function name",
		},
		{
			"response_format not an object",
			`{"model":"m","messages":[{"role":"user","content":"x"}],"response_format":"json"}`,
			"response_format is not a {type} object",
		},
		{
			"tool result after registry lost",
			`{"model":"m","messages":[{"role":"user","content":"x"},{"role":"tool","tool_call_id":"ghost","content":"y"}]}`,
			"cannot be resolved to a function name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := chatToVertexGenerate([]byte(tc.body))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// Negative control for the golden path: a second candidate translation of
// the same dialog must not leak OpenAI-only fields (model, stop as string,
// user hint, stream flags) into the Gemini payload.
func TestChatToVertexGenerate_NoOpenAIOnlyFieldsLeak(t *testing.T) {
	t.Parallel()

	got, _, err := chatToVertexGenerate([]byte(`{"model":"m","messages":[{"role":"user","content":"x"}],"user":"alice","stream":true,"stream_options":{"include_usage":true}}`))
	require.NoError(t, err)
	lower := strings.ToLower(string(got))
	for _, banned := range []string{`"model"`, `"user":"alice"`, `"stream"`, `"include_usage"`, `"tool_calls"`} {
		assert.NotContains(t, lower, strings.ToLower(banned))
	}
}
