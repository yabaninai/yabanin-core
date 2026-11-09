package provider

// Tests for the Vertex OpenAI⇄Gemini payload translation: request envelope
// construction, tool round-trips, precise rejections, response mapping
// (text / tool calls / finish reasons / usage) and usage shape-sniffing.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVertexTranslateRequest_TextFlow(t *testing.T) {
	t.Parallel()

	body := `{
		"model": "client-model",
		"messages": [
			{"role": "system", "content": "be terse"},
			{"role": "developer", "content": "no emoji"},
			{"role": "user", "content": "hi"},
			{"role": "assistant", "content": "hello"},
			{"role": "user", "content": [{"type": "text", "text": "bye"}, {"type": "text", "text": "now"}]}
		],
		"max_tokens": 128,
		"temperature": 0.5,
		"top_p": 0.9,
		"stop": ["END"]
	}`
	env, err := (*Vertex)(nil).TranslateRequest([]byte(body))
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}

	// Envelope shape: exactly model + gemini keys; the inner payload never
	// carries a model field (Gemini proto rejects unknown top-level fields).
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(env, &outer); err != nil {
		t.Fatalf("envelope not JSON: %v", err)
	}
	if len(outer) != 2 {
		t.Fatalf("envelope keys = %v, want exactly model+gemini", outer)
	}
	var parsed vertexEnvelope
	if err := json.Unmarshal(env, &parsed); err != nil {
		t.Fatalf("envelope parse: %v", err)
	}
	if parsed.Model != "client-model" {
		t.Fatalf("envelope model = %q", parsed.Model)
	}
	var req map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Gemini, &req); err != nil {
		t.Fatalf("gemini payload not JSON: %v", err)
	}
	if _, ok := req["model"]; ok {
		t.Fatal("gemini payload must not carry a model field")
	}

	var gen vertexGenerateRequest
	if err := json.Unmarshal(parsed.Gemini, &gen); err != nil {
		t.Fatalf("generateContent parse: %v", err)
	}
	if gen.SystemInstruction == nil || len(gen.SystemInstruction.Parts) != 2 ||
		gen.SystemInstruction.Parts[0].Text != "be terse" || gen.SystemInstruction.Parts[1].Text != "no emoji" {
		t.Fatalf("systemInstruction = %+v, want two text parts", gen.SystemInstruction)
	}
	if len(gen.Contents) != 3 {
		t.Fatalf("contents = %d entries, want 3 (system+developer fold into systemInstruction)", len(gen.Contents))
	}
	want := []struct {
		role  string
		parts []string
	}{
		{"user", []string{"hi"}},
		{"model", []string{"hello"}},
		{"user", []string{"byenow"}},
	}
	for i, w := range want {
		c := gen.Contents[i]
		if c.Role != w.role {
			t.Errorf("contents[%d].role = %q, want %q", i, c.Role, w.role)
		}
		if len(c.Parts) != 1 || c.Parts[0].Text != w.parts[0] {
			t.Errorf("contents[%d].parts = %+v, want text %q", i, c.Parts, w.parts[0])
		}
	}
	if gen.GenerationConfig == nil ||
		gen.GenerationConfig.MaxOutputTokens == nil || *gen.GenerationConfig.MaxOutputTokens != 128 ||
		gen.GenerationConfig.Temperature == nil || *gen.GenerationConfig.Temperature != 0.5 ||
		gen.GenerationConfig.TopP == nil || *gen.GenerationConfig.TopP != 0.9 ||
		len(gen.GenerationConfig.StopSequences) != 1 || gen.GenerationConfig.StopSequences[0] != "END" {
		t.Fatalf("generationConfig = %+v", gen.GenerationConfig)
	}
}

func TestVertexTranslateRequest_MaxCompletionTokensWins(t *testing.T) {
	t.Parallel()

	body := `{"model":"m","messages":[{"role":"user","content":"x"}],"max_tokens":10,"max_completion_tokens":20}`
	env, err := (*Vertex)(nil).TranslateRequest([]byte(body))
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	var parsed vertexEnvelope
	if err := json.Unmarshal(env, &parsed); err != nil {
		t.Fatalf("envelope parse: %v", err)
	}
	var gen vertexGenerateRequest
	if err := json.Unmarshal(parsed.Gemini, &gen); err != nil {
		t.Fatalf("payload parse: %v", err)
	}
	if gen.GenerationConfig == nil || gen.GenerationConfig.MaxOutputTokens == nil || *gen.GenerationConfig.MaxOutputTokens != 20 {
		t.Fatalf("generationConfig = %+v, want max_completion_tokens=20", gen.GenerationConfig)
	}
}

func TestVertexTranslateRequest_ToolRoundTrip(t *testing.T) {
	t.Parallel()

	body := `{
		"model": "m",
		"messages": [
			{"role": "user", "content": "weather in Moscow?"},
			{"role": "assistant", "content": null, "tool_calls": [
				{"id": "call_a", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Moscow\"}"}},
				{"id": "call_b", "type": "function", "function": {"name": "get_time", "arguments": ""}}
			]},
			{"role": "tool", "tool_call_id": "call_a", "content": "{\"temp\":-5,\"unit\":\"C\"}"},
			{"role": "tool", "tool_call_id": "call_b", "content": "noon"},
			{"role": "assistant", "content": "cold"}
		],
		"tools": [
			{"type": "function", "function": {"name": "get_weather", "description": "weather", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}}},
			{"type": "function", "function": {"name": "get_time"}}
		]
	}`
	env, err := (*Vertex)(nil).TranslateRequest([]byte(body))
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	var parsed vertexEnvelope
	if err := json.Unmarshal(env, &parsed); err != nil {
		t.Fatalf("envelope parse: %v", err)
	}
	var gen vertexGenerateRequest
	if err := json.Unmarshal(parsed.Gemini, &gen); err != nil {
		t.Fatalf("payload parse: %v", err)
	}

	// Tools map onto functionDeclarations with the schema passed through.
	if len(gen.Tools) != 1 || len(gen.Tools[0].FunctionDeclarations) != 2 {
		t.Fatalf("tools = %+v, want two declarations in one tool group", gen.Tools)
	}
	decl := gen.Tools[0].FunctionDeclarations[0]
	if decl.Name != "get_weather" || decl.Description != "weather" ||
		!strings.Contains(string(decl.Parameters), `"city"`) {
		t.Fatalf("declaration[0] = %+v", decl)
	}
	// No tool_choice → no toolConfig (Gemini default AUTO).
	if gen.ToolConfig != nil {
		t.Fatalf("toolConfig = %+v, want omitted", gen.ToolConfig)
	}

	// Assistant tool_calls map to functionCall parts on a model content.
	if len(gen.Contents) != 4 {
		t.Fatalf("contents = %d, want user/model(toolcalls)/user(toolresponses)/model", len(gen.Contents))
	}
	model := gen.Contents[1]
	if model.Role != "model" || len(model.Parts) != 2 {
		t.Fatalf("assistant content = %+v, want two functionCall parts", model)
	}
	fc0 := model.Parts[0].FunctionCall
	if fc0 == nil || fc0.Name != "get_weather" || string(fc0.Args) != `{"city":"Moscow"}` {
		t.Fatalf("functionCall[0] = %+v", fc0)
	}
	fc1 := model.Parts[1].FunctionCall
	if fc1 == nil || fc1.Name != "get_time" || string(fc1.Args) != `{}` {
		t.Fatalf("functionCall[1] = %+v, want empty args as {}", fc1)
	}
	// Assistant message with null content must not emit a text part.
	if model.Parts[0].Text != "" {
		t.Fatalf("functionCall part carries text %q", model.Parts[0].Text)
	}

	// Consecutive tool messages merge into ONE user content of
	// functionResponse parts: JSON-object output verbatim, plain text
	// wrapped as {"result": …}.
	resp := gen.Contents[2]
	if resp.Role != "user" || len(resp.Parts) != 2 {
		t.Fatalf("tool responses content = %+v, want one user content with two parts", resp)
	}
	fr0 := resp.Parts[0].FunctionResponse
	if fr0 == nil || fr0.Name != "get_weather" || string(fr0.Response) != `{"temp":-5,"unit":"C"}` {
		t.Fatalf("functionResponse[0] = %+v", fr0)
	}
	fr1 := resp.Parts[1].FunctionResponse
	if fr1 == nil || fr1.Name != "get_time" || string(fr1.Response) != `{"result":"noon"}` {
		t.Fatalf("functionResponse[1] = %+v, want wrapped plain-text output", fr1)
	}
	if fr0.Response[0] != '{' || fr1.Response[0] != '{' {
		t.Fatal("functionResponse.response must be a JSON object")
	}
}

func TestVertexTranslateRequest_ToolChoiceModes(t *testing.T) {
	t.Parallel()

	base := func(choice string) string {
		return `{"model":"m","messages":[{"role":"user","content":"x"}],` +
			`"tools":[{"type":"function","function":{"name":"f"}}],"tool_choice":` + choice + `}`
	}
	okCases := []struct {
		name, choice, wantMode string
		wantAllowed            []string
	}{
		{"auto", `"auto"`, "AUTO", nil},
		{"none", `"none"`, "NONE", nil},
		{"required", `"required"`, "ANY", nil},
		{"named", `{"type":"function","function":{"name":"f"}}`, "ANY", []string{"f"}},
	}
	for _, tc := range okCases {
		env, err := (*Vertex)(nil).TranslateRequest([]byte(base(tc.choice)))
		if err != nil {
			t.Errorf("%s: TranslateRequest: %v", tc.name, err)
			continue
		}
		var parsed vertexEnvelope
		if err := json.Unmarshal(env, &parsed); err != nil {
			t.Errorf("%s: envelope parse: %v", tc.name, err)
			continue
		}
		var gen vertexGenerateRequest
		if err := json.Unmarshal(parsed.Gemini, &gen); err != nil {
			t.Errorf("%s: payload parse: %v", tc.name, err)
			continue
		}
		if gen.ToolConfig == nil || gen.ToolConfig.FunctionCallingConfig.Mode != tc.wantMode {
			t.Errorf("%s: toolConfig = %+v, want mode %s", tc.name, gen.ToolConfig, tc.wantMode)
			continue
		}
		got := gen.ToolConfig.FunctionCallingConfig.AllowedFunctionNames
		if len(got) != len(tc.wantAllowed) {
			t.Errorf("%s: allowed = %v, want %v", tc.name, got, tc.wantAllowed)
		}
		for i := range got {
			if got[i] != tc.wantAllowed[i] {
				t.Errorf("%s: allowed = %v, want %v", tc.name, got, tc.wantAllowed)
			}
		}
	}
}

func TestVertexTranslateRequest_Rejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, body, wantErr string
	}{
		{
			"image part",
			`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x/y.png"}}]}]}`,
			"image inputs are not mapped",
		},
		{
			"audio part",
			`{"model":"m","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`,
			`content part type "input_audio" is not mapped`,
		},
		{
			"unknown role",
			`{"model":"m","messages":[{"role":"function","content":"x"}]}`,
			`unsupported message role "function"`,
		},
		{
			"json_schema response format",
			`{"model":"m","messages":[{"role":"user","content":"x"}],"response_format":{"type":"json_schema","json_schema":{"name":"o","schema":{}}}}`,
			"json_schema is not mapped",
		},
		{
			"unknown response format",
			`{"model":"m","messages":[{"role":"user","content":"x"}],"response_format":{"type":"xml"}}`,
			`unsupported response_format type "xml"`,
		},
		{
			"strict tool",
			`{"model":"m","messages":[{"role":"user","content":"x"}],"tools":[{"type":"function","function":{"name":"f","strict":true}}]}`,
			"strict structured outputs",
		},
		{
			"non-function tool type",
			`{"model":"m","messages":[{"role":"user","content":"x"}],"tools":[{"type":"code_interpreter","function":{"name":"f"}}]}`,
			`unsupported tool type "code_interpreter"`,
		},
		{
			"tool without name",
			`{"model":"m","messages":[{"role":"user","content":"x"}],"tools":[{"type":"function","function":{}}]}`,
			"tool without a function name",
		},
		{
			"tool_choice without tools",
			`{"model":"m","messages":[{"role":"user","content":"x"}],"tool_choice":"auto"}`,
			"tool_choice requires tools",
		},
		{
			"assistant arguments not an object",
			`{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"[1,2]"}}]}]}`,
			"arguments are not a JSON object",
		},
		{
			"orphan tool result",
			`{"model":"m","messages":[{"role":"user","content":"x"},{"role":"tool","tool_call_id":"ghost","content":"y"}]}`,
			"cannot be resolved to a function name",
		},
		{
			"empty user message",
			`{"model":"m","messages":[{"role":"user","content":null}]}`,
			"no translatable content",
		},
		{
			"no messages",
			`{"model":"m","messages":[]}`,
			"no user/assistant messages",
		},
		{
			"no model",
			`{"messages":[{"role":"user","content":"x"}]}`,
			"has no model field",
		},
		{
			"content not a string or array",
			`{"model":"m","messages":[{"role":"user","content":42}]}`,
			"neither a string nor a content-part array",
		},
	}
	for _, tc := range cases {
		_, err := (*Vertex)(nil).TranslateRequest([]byte(tc.body))
		if err == nil {
			t.Errorf("%s: want error containing %q, got nil", tc.name, tc.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error = %q, want containing %q", tc.name, err, tc.wantErr)
		}
	}
}

// N07-P05-T02: vertex's deterministic media/part rejections are typed
// UnsupportedFeatureError so the gateway answers an explicit 400
// unsupported_feature instead of an opaque upstream_outcome_unknown 502.
func TestVertexUnsupportedFeatureErrorsAreTyped(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, body, wantReason string
	}{
		{
			"image part",
			`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x/y.png"}}]}]}`,
			"image inputs are not mapped",
		},
		{
			"unknown input_audio part",
			`{"model":"m","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`,
			`content part type "input_audio" is not mapped`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := (*Vertex)(nil).TranslateRequest([]byte(tc.body))
			require.Error(t, err)
			var ufe *UnsupportedFeatureError
			require.ErrorAs(t, err, &ufe, "media rejection must be typed: %v", err)
			assert.Equal(t, "vertex", ufe.Provider)
			assert.Contains(t, ufe.Reason, tc.wantReason)
			assert.True(t, IsUnsupportedFeature(err))
			assert.Contains(t, err.Error(), "vertex adapter:")
		})
	}
}

func TestVertexTranslateRequest_ParallelToolCallsFalseRejected(t *testing.T) {
	// N07-P01-T03 negative criterion: parallel_tool_calls=false is a
	// no-parallel contract Gemini cannot honor (no disable flag) — a
	// silent drop would let the model fan out tool calls the client
	// explicitly forbade. Reject loudly (I51).
	t.Parallel()

	withTools := `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}]`
	if _, _, err := chatToVertexGenerate([]byte(withTools + `,"parallel_tool_calls":false}`)); err == nil {
		t.Fatal("parallel_tool_calls=false with tools must be rejected, not silently ignored")
	} else {
		if !strings.Contains(err.Error(), "parallel_tool_calls=false") {
			t.Fatalf("rejection must name the field, got: %v", err)
		}
		if !strings.Contains(err.Error(), "rejecting") {
			t.Fatalf("rejection must state the fail-closed decision, got: %v", err)
		}
	}

	// parallel_tool_calls=true or absent stays accepted.
	if _, _, err := chatToVertexGenerate([]byte(withTools + `,"parallel_tool_calls":true}`)); err != nil {
		t.Fatalf("parallel_tool_calls=true must stay accepted: %v", err)
	}
	if _, _, err := chatToVertexGenerate([]byte(withTools + `}`)); err != nil {
		t.Fatalf("absent parallel_tool_calls must stay accepted: %v", err)
	}

	// Without tools the field governs nothing (no capability in play) and
	// must not turn an otherwise valid request into an error.
	if _, _, err := chatToVertexGenerate([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"parallel_tool_calls":false}`)); err != nil {
		t.Fatalf("parallel_tool_calls=false without tools must stay accepted: %v", err)
	}
}

func TestVertexTranslateResponse_Text(t *testing.T) {
	t.Parallel()

	body := `{
		"candidates": [{
			"content": {"role": "model", "parts": [
				{"text": "thinking hard"},
				{"text": "Hel", "thought": true},
				{"text": "lo"}
			]},
			"finishReason": "STOP",
			"index": 0
		}],
		"usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": 3, "totalTokenCount": 15, "cachedContentTokenCount": 4},
		"modelVersion": "gemini-2.0-flash-001"
	}`
	out, err := (*Vertex)(nil).TranslateResponse([]byte(body))
	if err != nil {
		t.Fatalf("TranslateResponse: %v", err)
	}
	var resp struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
				Role             string `json:"role"`
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
			Details          *struct {
				CachedTokens int64 `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("translated body not JSON: %v", err)
	}
	if !strings.HasPrefix(resp.ID, "chatcmpl-vertex-") || resp.Object != "chat.completion" {
		t.Fatalf("id/object = %s/%s", resp.ID, resp.Object)
	}
	if resp.Model != "gemini-2.0-flash-001" {
		t.Fatalf("model = %q, want the modelVersion echo", resp.Model)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("choices = %d", len(resp.Choices))
	}
	c := resp.Choices[0]
	if c.Message.Role != "assistant" {
		t.Fatalf("role = %q", c.Message.Role)
	}
	// Non-thought text concatenates; thought parts land in reasoning_content.
	if c.Message.Content != "thinking hardlo" || c.Message.ReasoningContent != "Hel" {
		t.Fatalf("content/reasoning = %q/%q", c.Message.Content, c.Message.ReasoningContent)
	}
	if c.FinishReason != "stop" {
		t.Fatalf("finish_reason = %q", c.FinishReason)
	}
	if resp.Usage.PromptTokens != 12 || resp.Usage.CompletionTokens != 3 || resp.Usage.TotalTokens != 15 {
		t.Fatalf("usage = %+v", resp.Usage)
	}
	if resp.Usage.Details == nil || resp.Usage.Details.CachedTokens != 4 {
		t.Fatalf("cached details = %+v", resp.Usage.Details)
	}
}

func TestVertexTranslateResponse_ToolCalls(t *testing.T) {
	t.Parallel()

	body := `{
		"candidates": [{
			"content": {"role": "model", "parts": [
				{"text": "checking"},
				{"functionCall": {"name": "get_weather", "args": {"city": "Moscow"}}},
				{"functionCall": {"name": "get_time"}}
			]},
			"finishReason": "STOP"
		}],
		"modelVersion": "gemini-2.0-flash-001"
	}`
	out, err := (*Vertex)(nil).TranslateResponse([]byte(body))
	if err != nil {
		t.Fatalf("TranslateResponse: %v", err)
	}
	var resp struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("translated body not JSON: %v", err)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("choices = %d", len(resp.Choices))
	}
	c := resp.Choices[0]
	if c.Message.Content != "checking" {
		t.Fatalf("content = %q", c.Message.Content)
	}
	if len(c.Message.ToolCalls) != 2 {
		t.Fatalf("tool_calls = %d, want 2", len(c.Message.ToolCalls))
	}
	tc0 := c.Message.ToolCalls[0]
	if !strings.HasPrefix(tc0.ID, "call_") || tc0.Type != "function" || tc0.Function.Name != "get_weather" {
		t.Fatalf("tool_call[0] = %+v", tc0)
	}
	// The arguments must round-trip to the same object Gemini sent.
	var args map[string]any
	if err := json.Unmarshal([]byte(tc0.Function.Arguments), &args); err != nil {
		t.Fatalf("arguments not JSON: %v", err)
	}
	if args["city"] != "Moscow" {
		t.Fatalf("arguments = %v", args)
	}
	tc1 := c.Message.ToolCalls[1]
	if tc1.Function.Name != "get_time" || tc1.Function.Arguments != "{}" {
		t.Fatalf("tool_call[1] = %+v, want absent args as {}", tc1)
	}
	if c.FinishReason != "tool_calls" {
		t.Fatalf("finish_reason = %q, want tool_calls", c.FinishReason)
	}
}

func TestVertexTranslateResponse_Mapping(t *testing.T) {
	t.Parallel()

	okCases := []struct {
		name, body, wantFinish string
	}{
		{"stop", `{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"STOP"}]}`, "stop"},
		{"absent finish", `{"candidates":[{"content":{"parts":[{"text":"x"}]}}]}`, "stop"},
		{"length", `{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"MAX_TOKENS"}]}`, "length"},
		{"safety", `{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"SAFETY"}]}`, "content_filter"},
		{"recitation", `{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"RECITATION"}]}`, "content_filter"},
		{"blocklist", `{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"BLOCKLIST"}]}`, "content_filter"},
		{"prohibited", `{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"PROHIBITED_CONTENT"}]}`, "content_filter"},
		{"spii", `{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"SPII"}]}`, "content_filter"},
		{"unknown reason defaults to stop", `{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"OTHER"}]}`, "stop"},
	}
	for _, tc := range okCases {
		out, err := (*Vertex)(nil).TranslateResponse([]byte(tc.body))
		if err != nil {
			t.Errorf("%s: TranslateResponse: %v", tc.name, err)
			continue
		}
		var resp struct {
			Choices []struct {
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Errorf("%s: parse: %v", tc.name, err)
			continue
		}
		if len(resp.Choices) != 1 || resp.Choices[0].FinishReason != tc.wantFinish {
			t.Errorf("%s: finish = %+v, want %q", tc.name, resp.Choices, tc.wantFinish)
		}
	}

	errCases := []struct {
		name, body, wantErr string
	}{
		{
			"malformed function call",
			`{"candidates":[{"finishReason":"MALFORMED_FUNCTION_CALL"}]}`,
			"MALFORMED_FUNCTION_CALL",
		},
		{
			"blocked prompt",
			`{"promptFeedback":{"blockReason":"SAFETY"}}`,
			"blockReason SAFETY",
		},
		{
			"no candidates",
			`{}`,
			"has no candidates",
		},
		{
			"unsupported part kind",
			`{"candidates":[{"content":{"parts":[{"inlineData":{"mimeType":"image/png","data":"AAAA"}}]}}]}`,
			`unsupported part kind "inlineData"`,
		},
		{
			"not json",
			`nope`,
			"decode generateContent response",
		},
	}
	for _, tc := range errCases {
		_, err := (*Vertex)(nil).TranslateResponse([]byte(tc.body))
		if err == nil {
			t.Errorf("%s: want error containing %q, got nil", tc.name, tc.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error = %q, want containing %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestVertexTranslateResponse_MultipleCandidates(t *testing.T) {
	t.Parallel()

	body := `{
		"candidates": [
			{"content":{"parts":[{"text":"a"}]},"finishReason":"STOP","index":0},
			{"content":{"parts":[{"text":"b"}]},"finishReason":"STOP","index":1}
		],
		"modelVersion": "m"
	}`
	out, err := (*Vertex)(nil).TranslateResponse([]byte(body))
	if err != nil {
		t.Fatalf("TranslateResponse: %v", err)
	}
	var resp struct {
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(resp.Choices) != 2 {
		t.Fatalf("choices = %d, want 2", len(resp.Choices))
	}
	if resp.Choices[0].Index != 0 || resp.Choices[0].Message.Content != "a" ||
		resp.Choices[1].Index != 1 || resp.Choices[1].Message.Content != "b" {
		t.Fatalf("choices = %+v", resp.Choices)
	}
}

// TestVertexTranslateResponse_OmitsUsageWhenAbsent guards the metering
// discipline: no provider-reported usage must not translate into a zero
// usage block that ParseUsage would read as real metering.
func TestVertexTranslateResponse_OmitsUsageWhenAbsent(t *testing.T) {
	t.Parallel()

	out, err := (*Vertex)(nil).TranslateResponse([]byte(`{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"STOP"}]}`))
	if err != nil {
		t.Fatalf("TranslateResponse: %v", err)
	}
	if strings.Contains(string(out), `"usage"`) {
		t.Fatalf("translated body carries a usage block without provider metering: %s", out)
	}
	// And the gateway-side parse of the same body reports no usage.
	if got := (*Vertex)(nil).ParseUsage(out); got != (Usage{Source: UsageSourceNone}) {
		t.Fatalf("ParseUsage = %+v, want none", got)
	}
}

// TestChatToVertexGenerate_ReasoningEffortRejected (N07-P01-T05) pins the
// negative criterion: `reasoning_effort` is a modeled request field with no
// mapped Gemini equivalent yet — reject loudly with the precise reason
// (I51), never silently ignore the requested reasoning level.
func TestChatToVertexGenerate_ReasoningEffortRejected(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"x"}],"reasoning_effort":"medium"}`
	_, _, err := chatToVertexGenerate([]byte(body))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reasoning_effort", "the field at fault must be named")
	assert.Contains(t, err.Error(), "rejecting", "the refusal must state the loud-reject contract")
}

// TestChatToVertexGenerate_UserFieldDocumentedGap pins the T05 review
// classification (record §field-verdicts): `user` (the OpenAI end-user
// abuse-monitoring hint) is modeled but has no mapped Gemini field here yet.
// The Anthropic adapter maps it to metadata.user_id; the Gemini mapping
// needs live-API verification, and rejecting a field many SDK clients
// always send would break common consumers — so this stays a documented
// drop flagged for the owner decision, not an acceptance of a guarantee.
// The pin flips loudly when the mapping lands.
func TestChatToVertexGenerate_UserFieldDocumentedGap(t *testing.T) {
	got, _, err := chatToVertexGenerate([]byte(`{"model":"m","messages":[{"role":"user","content":"x"}],"user":"alice"}`))
	require.NoError(t, err)
	assert.NotContains(t, string(got), "alice", "the user hint is not forwarded to Gemini (documented gap)")
}
