package provider_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/provider"
)

func TestOpenAI_Name(t *testing.T) {
	assert.Equal(t, "openai", provider.OpenAI{}.Name())
}

func TestOpenAI_Path(t *testing.T) {
	assert.Equal(t, "/v1/chat/completions", provider.OpenAI{}.Path(false))
	assert.Equal(t, "/v1/chat/completions", provider.OpenAI{}.Path(true))
}

func TestOpenAI_PrepareRequest_BearerAuth(t *testing.T) {
	req, err := provider.OpenAI{}.PrepareRequest(
		context.Background(),
		"https://api.openai.com", "/v1/chat/completions",
		[]byte(`{"model":"gpt-4"}`), "sk-key", false,
	)
	require.NoError(t, err)
	assert.Equal(t, "Bearer sk-key", req.Header.Get("Authorization"))
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.NotContains(t, []string(req.Header.Values("Accept")), "text/event-stream")
}

func TestOpenAI_PrepareRequest_StreamAcceptHeader(t *testing.T) {
	req, err := provider.OpenAI{}.PrepareRequest(
		context.Background(),
		"https://api.openai.com", "/v1/chat/completions",
		[]byte(`{}`), "k", true,
	)
	require.NoError(t, err)
	assert.Equal(t, "text/event-stream", req.Header.Get("Accept"))
}

func TestOpenAI_PrepareRequest_TrimTrailingSlash(t *testing.T) {
	req, err := provider.OpenAI{}.PrepareRequest(
		context.Background(),
		"https://api.openai.com/", "/v1/chat/completions",
		[]byte(`{}`), "k", false,
	)
	require.NoError(t, err)
	assert.Equal(t, "https://api.openai.com/v1/chat/completions", req.URL.String())
}

func TestOpenAI_TranslateRequest_Identity(t *testing.T) {
	out, err := provider.OpenAI{}.TranslateRequest([]byte(`{"model":"gpt-4"}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"model":"gpt-4"}`, string(out))
}

func TestOpenAI_TranslateResponse_Identity(t *testing.T) {
	out, err := provider.OpenAI{}.TranslateResponse([]byte(`{"id":"x"}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"id":"x"}`, string(out))
}

func TestOpenAI_ParseUsage_WithCacheTokens(t *testing.T) {
	body := []byte(`{
		"usage": {
			"prompt_tokens": 100,
			"completion_tokens": 50,
			"total_tokens": 150,
			"prompt_tokens_details": {"cached_tokens": 30}
		}
	}`)
	u := provider.OpenAI{}.ParseUsage(body)
	assert.Equal(t, int64(100), u.PromptTokens)
	assert.Equal(t, int64(50), u.CompletionTokens)
	assert.Equal(t, int64(150), u.TotalTokens)
	assert.Equal(t, int64(30), u.CacheReadTokens)
}

func TestOpenAI_ParseUsage_NoUsage(t *testing.T) {
	u := provider.OpenAI{}.ParseUsage([]byte(`{}`))
	assert.Equal(t, provider.Usage{Source: provider.UsageSourceNone}, u)
}

func TestFactory_New_OpenAI(t *testing.T) {
	p, err := provider.New("openai")
	require.NoError(t, err)
	assert.Equal(t, "openai", p.Name())
	assert.Equal(t, "/v1/chat/completions", p.Path(false))
}

func TestFactory_New_OpenAICompatAlias(t *testing.T) {
	p, err := provider.New("openai-compat")
	require.NoError(t, err)
	_, ok := p.(provider.OpenAI)
	assert.True(t, ok)
}

func TestFactory_New_EmptyNameDefaultsToOpenAI(t *testing.T) {
	p, err := provider.New("")
	require.NoError(t, err)
	assert.Equal(t, "/v1/chat/completions", p.Path(false))
}

func TestFactory_New_Anthropic(t *testing.T) {
	p, err := provider.New("anthropic")
	require.NoError(t, err)
	assert.Equal(t, "anthropic", p.Name())
	assert.Equal(t, "/v1/messages", p.Path(false))
}

func TestFactory_New_UnknownReturnsError(t *testing.T) {
	_, err := provider.New("grok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

// --- Anthropic adapter tests ---

func TestAnthropic_PrepareRequest_HeadersCorrect(t *testing.T) {
	req, err := provider.NewAnthropic().PrepareRequest(
		context.Background(),
		"https://api.anthropic.com", "/v1/messages",
		[]byte(`{"model":"claude-3"}`), "ant-key", false,
	)
	require.NoError(t, err)
	assert.Equal(t, "ant-key", req.Header.Get("x-api-key"))
	assert.Equal(t, "2023-06-01", req.Header.Get("anthropic-version"))
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "https://api.anthropic.com/v1/messages", req.URL.String())
	assert.Empty(t, req.Header.Get("Authorization"), "Anthropic must NOT use Bearer auth")
}

func TestAnthropic_PrepareRequest_StreamAccept(t *testing.T) {
	req, err := provider.NewAnthropic().PrepareRequest(
		context.Background(),
		"https://api.anthropic.com", "/v1/messages",
		[]byte(`{}`), "k", true,
	)
	require.NoError(t, err)
	assert.Equal(t, "text/event-stream", req.Header.Get("Accept"))
}

func TestAnthropic_TranslateRequest_SystemToTopLevel(t *testing.T) {
	in := []byte(`{
		"model": "claude-3-5-sonnet",
		"messages": [
			{"role":"system","content":"You are helpful."},
			{"role":"user","content":"hi"}
		]
	}`)
	out, err := provider.NewAnthropic().TranslateRequest(in)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, "You are helpful.", got["system"])
	msgs := got["messages"].([]any)
	require.Len(t, msgs, 1)
	first := msgs[0].(map[string]any)
	assert.Equal(t, "user", first["role"])
	assert.Equal(t, "hi", first["content"])
	assert.Equal(t, "claude-3-5-sonnet", got["model"])
}

func TestAnthropic_TranslateRequest_MaxTokensDefault(t *testing.T) {
	out, err := provider.NewAnthropic().TranslateRequest([]byte(`{"model":"m","messages":[]}`))
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	// default of 4096 when caller omits max_tokens
	assert.EqualValues(t, 4096, got["max_tokens"])
}

func TestAnthropic_TranslateRequest_MaxTokensHonoured(t *testing.T) {
	in := []byte(`{"model":"m","messages":[],"max_tokens":123}`)
	out, err := provider.NewAnthropic().TranslateRequest(in)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.EqualValues(t, 123, got["max_tokens"])
}

func TestAnthropic_TranslateRequest_MultipleSystemMessagesJoined(t *testing.T) {
	in := []byte(`{
		"model":"m",
		"messages":[
			{"role":"system","content":"rule1"},
			{"role":"system","content":"rule2"},
			{"role":"user","content":"q"}
		]
	}`)
	out, err := provider.NewAnthropic().TranslateRequest(in)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, "rule1\n\nrule2", got["system"])
}

func TestAnthropic_TranslateRequest_StreamPropagated(t *testing.T) {
	in := []byte(`{"model":"m","messages":[],"stream":true}`)
	out, err := provider.NewAnthropic().TranslateRequest(in)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, true, got["stream"])
}

func TestAnthropic_TranslateRequest_InvalidJSON(t *testing.T) {
	_, err := provider.NewAnthropic().TranslateRequest([]byte(`not json`))
	require.Error(t, err)
}

func TestAnthropic_TranslateResponse_SingleChoice(t *testing.T) {
	body := []byte(`{
		"id":"msg_1",
		"model":"claude-3",
		"content":[{"type":"text","text":"hello"}],
		"stop_reason":"end_turn",
		"usage":{"input_tokens":5,"output_tokens":3}
	}`)
	out, err := provider.NewAnthropic().TranslateResponse(body)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, "msg_1", got["id"])
	assert.Equal(t, "chat.completion", got["object"])
	assert.Equal(t, "claude-3", got["model"])

	choices := got["choices"].([]any)
	require.Len(t, choices, 1)
	choice := choices[0].(map[string]any)
	msg := choice["message"].(map[string]any)
	assert.Equal(t, "assistant", msg["role"])
	assert.Equal(t, "hello", msg["content"])
	assert.Equal(t, "stop", choice["finish_reason"])

	usage := got["usage"].(map[string]any)
	assert.EqualValues(t, 5, usage["prompt_tokens"])
	assert.EqualValues(t, 3, usage["completion_tokens"])
	assert.EqualValues(t, 8, usage["total_tokens"])
}

func TestAnthropic_TranslateResponse_StopReasonMapping(t *testing.T) {
	cases := map[string]string{
		"end_turn":      "stop",
		"stop_sequence": "stop",
		"max_tokens":    "length",
		"tool_use":      "tool_calls",
		"":              "stop",
		"weird":         "stop",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			body := []byte(`{"id":"x","model":"m","content":[],"stop_reason":"` + in + `","usage":{}}`)
			out, err := provider.NewAnthropic().TranslateResponse(body)
			require.NoError(t, err)
			var got map[string]any
			require.NoError(t, json.Unmarshal(out, &got))
			choice := got["choices"].([]any)[0].(map[string]any)
			assert.Equal(t, want, choice["finish_reason"])
		})
	}
}

func TestAnthropic_TranslateResponse_MultipleTextBlocksConcatenated(t *testing.T) {
	body := []byte(`{
		"id":"x","model":"m",
		"content":[{"type":"text","text":"a"},{"type":"text","text":"b"}],
		"stop_reason":"end_turn","usage":{}
	}`)
	out, err := provider.NewAnthropic().TranslateResponse(body)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	choice := got["choices"].([]any)[0].(map[string]any)
	msg := choice["message"].(map[string]any)
	assert.Equal(t, "ab", msg["content"])
}

func TestAnthropic_ParseUsage_IncludesCacheTokens(t *testing.T) {
	body := []byte(`{
		"usage":{
			"input_tokens":10,
			"output_tokens":20,
			"cache_creation_input_tokens":5,
			"cache_read_input_tokens":2
		}
	}`)
	u := provider.NewAnthropic().ParseUsage(body)
	assert.Equal(t, int64(17), u.PromptTokens) // 10 input + 5 creation + 2 read
	assert.Equal(t, int64(20), u.CompletionTokens)
	assert.Equal(t, int64(37), u.TotalTokens)
	assert.Equal(t, int64(2), u.CacheReadTokens)
	assert.Equal(t, int64(5), u.CacheCreationTokens)
}

// normalized it to the OpenAI contract — the cache fields must survive that
// round-trip or cache billing (and the x-yabanin-prompt-cache header) reads
// zeros on every anthropic-routed chat request.
func TestAnthropic_CacheTokens_SurviveTranslationRoundTrip(t *testing.T) {
	native := []byte(`{
		"id":"msg_r103","model":"claude-3",
		"content":[{"type":"text","text":"ok"}],
		"stop_reason":"end_turn",
		"usage":{"input_tokens":10,"output_tokens":5,"cache_creation_input_tokens":2,"cache_read_input_tokens":4}
	}`)
	translated, err := provider.NewAnthropic().TranslateResponse(native)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(translated, &got))
	usage := got["usage"].(map[string]any)
	assert.EqualValues(t, 16, usage["prompt_tokens"], "canonical prompt includes cache read and write")
	details := usage["prompt_tokens_details"].(map[string]any)
	assert.EqualValues(t, 4, details["cached_tokens"])
	assert.EqualValues(t, 2, details["cache_creation_input_tokens"])

	u := provider.NewAnthropic().ParseUsage(translated)
	assert.Equal(t, int64(16), u.PromptTokens)
	assert.Equal(t, int64(5), u.CompletionTokens)
	assert.Equal(t, int64(4), u.CacheReadTokens)
	assert.Equal(t, int64(2), u.CacheCreationTokens)
	assert.Equal(t, provider.UsageSourceProvider, u.Source)
}

// A translated usage block without cache details parses cleanly (miss), and
// an explicit native input_tokens:0 still takes the native branch — absent
// and zero must not be confused.
func TestAnthropic_ParseUsage_ShapeToleranceEdges(t *testing.T) {
	u := provider.NewAnthropic().ParseUsage([]byte(`{"usage":{"prompt_tokens":7,"completion_tokens":2,"total_tokens":9}}`))
	assert.Equal(t, int64(7), u.PromptTokens)
	assert.Equal(t, int64(0), u.CacheReadTokens)
	assert.Equal(t, provider.UsageSourceProvider, u.Source)

	u = provider.NewAnthropic().ParseUsage([]byte(`{"usage":{"input_tokens":0,"output_tokens":0}}`))
	assert.Equal(t, int64(0), u.PromptTokens)
	assert.Equal(t, provider.UsageSourceProvider, u.Source, "explicit native zeros are native, not the fallback shape")
}

// --- Stream translator tests ---

func TestAnthropic_Stream_MessageStartEmitsRole(t *testing.T) {
	tr := provider.NewAnthropicStreamTranslator("claude-3")
	chunk, done, err := tr.Translate("message_start", `{}`)
	require.NoError(t, err)
	assert.False(t, done)
	assert.Contains(t, chunk, `"role":"assistant"`)
	assert.Contains(t, chunk, `"model":"claude-3"`)
}

func TestAnthropic_Stream_ContentBlockDeltaEmitsContent(t *testing.T) {
	tr := provider.NewAnthropicStreamTranslator("claude-3")
	chunk, done, err := tr.Translate("content_block_delta", `{"delta":{"type":"text_delta","text":"hello"}}`)
	require.NoError(t, err)
	assert.False(t, done)
	assert.Contains(t, chunk, `"content":"hello"`)
}

func TestAnthropic_Stream_ContentBlockDelta_IgnoresNonText(t *testing.T) {
	tr := provider.NewAnthropicStreamTranslator("claude-3")
	chunk, done, err := tr.Translate("content_block_delta", `{"delta":{"type":"input_json_delta","partial_json":"{}"}}`)
	require.NoError(t, err)
	assert.False(t, done)
	assert.Empty(t, chunk)
}

func TestAnthropic_Stream_MessageStopEmitsDone(t *testing.T) {
	tr := provider.NewAnthropicStreamTranslator("claude-3")
	chunk, done, err := tr.Translate("message_stop", `{}`)
	require.NoError(t, err)
	assert.True(t, done)
	assert.Empty(t, chunk)
}

func TestAnthropic_Stream_PingNoChunk(t *testing.T) {
	tr := provider.NewAnthropicStreamTranslator("claude-3")
	chunk, done, err := tr.Translate("ping", `{}`)
	require.NoError(t, err)
	assert.False(t, done)
	assert.Empty(t, chunk)
}

func TestAnthropic_Stream_ErrorReturnsErr(t *testing.T) {
	tr := provider.NewAnthropicStreamTranslator("claude-3")
	_, _, err := tr.Translate("error", `{"type":"overloaded_error"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "overloaded_error")
}

func TestAnthropic_Stream_MalformedDeltaReturnsErr(t *testing.T) {
	tr := provider.NewAnthropicStreamTranslator("claude-3")
	_, _, err := tr.Translate("content_block_delta", `not-json`)
	require.Error(t, err)
}

// --- End-to-end mock server test ---

func TestAnthropic_E2E_Mock(t *testing.T) {
	const apiKey = "test-key"
	var gotHeaders http.Header
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"msg_abc","model":"claude-3-5-sonnet",
			"content":[{"type":"text","text":"Hi"}],
			"stop_reason":"end_turn",
			"usage":{"input_tokens":3,"output_tokens":1}
		}`))
	}))
	defer srv.Close()

	adapter := provider.NewAnthropic()
	body := []byte(`{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello"}]}`)

	translated, err := adapter.TranslateRequest(body)
	require.NoError(t, err)

	req, err := adapter.PrepareRequest(
		context.Background(),
		srv.URL, adapter.Path(false),
		translated, apiKey, false,
	)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify request was Anthropic-shaped.
	require.Contains(t, string(gotBody), `"messages"`)
	assert.NotContains(t, string(gotBody), `"messages":[{}]`)
	assert.Equal(t, apiKey, gotHeaders.Get("x-api-key"))
	assert.Equal(t, "2023-06-01", gotHeaders.Get("anthropic-version"))
	assert.Empty(t, gotHeaders.Get("Authorization"))

	// Verify response was translated to OpenAI shape.
	out, err := adapter.TranslateResponse(respBody)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"chat.completion"`)
	assert.Contains(t, string(out), `"prompt_tokens":3`)
}

// ---------------------------------------------------------------------------
// P3.9 — Prompt-caching: anthropic-beta header + cache_control passthrough.
// ---------------------------------------------------------------------------

func TestAnthropic_TranslateRequest_CacheControlPreserved(t *testing.T) {
	in := []byte(`{
		"model": "claude-3-5-sonnet",
		"messages": [
			{"role":"system","content":[{"type":"text","text":"Act as assistant.","cache_control":{"type":"ephemeral"}}]},
			{"role":"user","content":"hi"}
		]
	}`)
	out, err := provider.NewAnthropic().TranslateRequest(in)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))

	// System content should contain cache_control block (system lifted to top-level).
	systemRaw, ok := got["system"]
	require.True(t, ok)
	assert.Contains(t, systemRaw.(string), "cache_control", "system content should preserve cache_control")
	assert.Contains(t, systemRaw.(string), "ephemeral")

	// The entire translated body must contain cache_control — it survives the
	// json.Unmarshal → any → json.Marshal round-trip for system and user msgs.
	assert.Contains(t, string(out), "cache_control", "full translated body should preserve cache_control")
}

func TestAnthropic_TranslateRequest_CacheControlInSystemArrayPreserved(t *testing.T) {
	// When system content is a structured array (not plain string),
	// it gets joined as JSON text — the raw bytes should include cache_control.
	in := []byte(`{
		"model": "claude-3-5-sonnet",
		"messages": [
			{"role":"system","content":[{"type":"text","text":"rules","cache_control":{"type":"ephemeral"}}]},
			{"role":"user","content":"hi"}
		]
	}`)
	out, err := provider.NewAnthropic().TranslateRequest(in)
	require.NoError(t, err)

	// The entire translated body should contain cache_control — it's preserved
	// through the json.Unmarshal → any → json.Marshal round-trip.
	assert.Contains(t, string(out), "cache_control")
	assert.Contains(t, string(out), "ephemeral")
}

func TestAnthropic_PrepareRequest_CacheControlEnablesBetaHeader(t *testing.T) {
	// Body with cache_control → beta header present.
	bodyWithCache := []byte(`{"model":"claude-3","messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`)
	req, err := provider.NewAnthropic().PrepareRequest(
		context.Background(),
		"https://api.anthropic.com", "/v1/messages",
		bodyWithCache, "ant-key", false,
	)
	require.NoError(t, err)
	assert.Equal(t, "prompt-caching-2024-07-31", req.Header.Get("anthropic-beta"))

	// Body without cache_control → no beta header.
	bodyNoCache := []byte(`{"model":"claude-3","messages":[{"role":"user","content":"hi"}]}`)
	req2, err := provider.NewAnthropic().PrepareRequest(
		context.Background(),
		"https://api.anthropic.com", "/v1/messages",
		bodyNoCache, "ant-key", false,
	)
	require.NoError(t, err)
	assert.Empty(t, req2.Header.Get("anthropic-beta"))
}
