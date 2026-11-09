package provider

// Tests for the Vertex translating stream handler: Gemini SSE events →
// OpenAI chat.completion.chunk frames, terminal usage, [DONE] emission and
// the precise per-failure error boundaries.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseVertexStreamFrames splits the handler's raw output into SSE frames,
// asserts the trailing [DONE] and returns the decoded chunk objects.
func parseVertexStreamFrames(t *testing.T, raw string) []map[string]any {
	t.Helper()
	frames := strings.Split(strings.TrimSpace(raw), "\n\n")
	require.GreaterOrEqual(t, len(frames), 1)
	require.Equal(t, "data: [DONE]", frames[len(frames)-1], "stream must terminate with [DONE], got:\n%s", raw)

	var chunks []map[string]any
	for _, f := range frames[:len(frames)-1] {
		require.True(t, strings.HasPrefix(f, "data: "), "frame %q", f)
		var c map[string]any
		require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(f, "data: ")), &c), "frame %q", f)
		require.Equal(t, "chat.completion.chunk", c["object"], "frame %q", f)
		chunks = append(chunks, c)
	}
	return chunks
}

func vertexChoice(t *testing.T, chunk map[string]any) map[string]any {
	t.Helper()
	choices, ok := chunk["choices"].([]any)
	require.True(t, ok, "choices = %v", chunk["choices"])
	require.Len(t, choices, 1)
	c, ok := choices[0].(map[string]any)
	require.True(t, ok)
	return c
}

func TestVertexStreamHandler_TextChunks(t *testing.T) {
	t.Parallel()

	const sse = "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hel\"}]},\"index\":0}],\"modelVersion\":\"gemini-2.0-flash-001\"}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"lo\"}]},\"index\":0}]}\n\n" +
		"data: {\"candidates\":[{\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":12,\"candidatesTokenCount\":2,\"totalTokenCount\":14,\"cachedContentTokenCount\":3},\"modelVersion\":\"gemini-2.0-flash-001\"}\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close()
	w, buf := newRecorder()

	usage, err := NewStreamHandler("vertex", "gemini-2.0-flash").HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	chunks := parseVertexStreamFrames(t, buf.String())
	require.Len(t, chunks, 5, "role + 2 deltas + finish + usage-only, got:\n%s", buf.String())

	// Shared identity across the stream.
	for _, c := range chunks {
		assert.Equal(t, "gemini-2.0-flash-001", c["model"], "model echoes modelVersion")
		id, _ := c["id"].(string)
		assert.True(t, strings.HasPrefix(id, "chatcmpl-vertex-"), "id %q", id)
	}

	// role → content → content → finish → usage-only.
	first := vertexChoice(t, chunks[0])
	assert.Equal(t, map[string]any{"role": "assistant"}, first["delta"])
	assert.Nil(t, first["finish_reason"])

	assert.Equal(t, map[string]any{"content": "Hel"}, vertexChoice(t, chunks[1])["delta"])
	assert.Equal(t, map[string]any{"content": "lo"}, vertexChoice(t, chunks[2])["delta"])

	finish := vertexChoice(t, chunks[3])
	assert.Equal(t, "stop", finish["finish_reason"])
	assert.Equal(t, map[string]any{}, finish["delta"])

	usageChunk := chunks[4]
	assert.Equal(t, []any{}, usageChunk["choices"])
	u, ok := usageChunk["usage"].(map[string]any)
	require.True(t, ok)
	assert.InDelta(t, float64(12), u["prompt_tokens"], 0)
	assert.InDelta(t, float64(2), u["completion_tokens"], 0)
	assert.InDelta(t, float64(14), u["total_tokens"], 0)
	assert.InDelta(t, float64(3), u["prompt_tokens_details"].(map[string]any)["cached_tokens"], 0)

	// Returned usage mirrors the metadata event.
	assert.Equal(t, Usage{PromptTokens: 12, CompletionTokens: 2, TotalTokens: 14, CacheReadTokens: 3, Source: UsageSourceProvider}, usage)
}

func TestVertexStreamHandler_ToolCallChunk(t *testing.T) {
	t.Parallel()

	const sse = "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"city\":\"Moscow\"}}}]},\"finishReason\":\"STOP\",\"index\":0}]}\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close()
	w, buf := newRecorder()

	usage, err := NewStreamHandler("vertex", "gemini-2.0-flash").HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	chunks := parseVertexStreamFrames(t, buf.String())
	require.Len(t, chunks, 4, "role + tool_call + finish + usage-only, got:\n%s", buf.String())

	assert.Equal(t, map[string]any{"role": "assistant"}, vertexChoice(t, chunks[0])["delta"])

	tool := vertexChoice(t, chunks[1])
	calls, ok := tool["delta"].(map[string]any)["tool_calls"].([]any)
	require.True(t, ok, "delta = %v", tool["delta"])
	require.Len(t, calls, 1)
	call, ok := calls[0].(map[string]any)
	require.True(t, ok)
	assert.InDelta(t, float64(0), call["index"], 1e-9)
	id, _ := call["id"].(string)
	assert.True(t, strings.HasPrefix(id, "call_"), "tool call id %q", id)
	assert.Equal(t, "function", call["type"])
	fn, ok := call["function"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "get_weather", fn["name"])
	// Gemini delivers the complete functionCall — the fragment carries it whole.
	assert.JSONEq(t, `{"city":"Moscow"}`, fn["arguments"].(string))

	// A stream that emitted tool calls finishes as tool_calls, not stop.
	assert.Equal(t, "tool_calls", vertexChoice(t, chunks[2])["finish_reason"])
	assert.Equal(t, UsageSourceNone, usage.Source, "no usageMetadata in this fixture")
}

func TestVertexStreamHandler_ThoughtToReasoning(t *testing.T) {
	t.Parallel()

	const sse = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"pondering\",\"thought\":true},{\"text\":\"answer\"}]},\"finishReason\":\"STOP\"}]}\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close()
	w, buf := newRecorder()

	_, err := NewStreamHandler("vertex", "m").HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	chunks := parseVertexStreamFrames(t, buf.String())
	require.Len(t, chunks, 5, "role + reasoning + content + finish + usage-only, got:\n%s", buf.String())
	assert.Equal(t, map[string]any{"reasoning_content": "pondering"}, vertexChoice(t, chunks[1])["delta"])
	assert.Equal(t, map[string]any{"content": "answer"}, vertexChoice(t, chunks[2])["delta"])
}

func TestVertexStreamHandler_Errors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, sse, wantErr string
	}{
		{
			name:    "upstream error object",
			sse:     "data: {\"error\":{\"code\":429,\"message\":\"quota exceeded\",\"status\":\"RESOURCE_EXHAUSTED\"}}\n\n",
			wantErr: "vertex stream error (status RESOURCE_EXHAUSTED): quota exceeded",
		},
		{
			name:    "malformed event payload",
			sse:     "data: {not json}\n\n",
			wantErr: "vertex stream: decode event",
		},
		{
			name:    "blocked prompt",
			sse:     "data: {\"promptFeedback\":{\"blockReason\":\"SAFETY\"}}\n\n",
			wantErr: "blockReason SAFETY",
		},
		{
			name:    "unsupported part kind",
			sse:     "data: {\"candidates\":[{\"content\":{\"parts\":[{\"inlineData\":{\"mimeType\":\"image/png\",\"data\":\"AAAA\"}}]}}]}\n\n",
			wantErr: `unsupported response part kind "inlineData"`,
		},
		{
			name:    "malformed function call finish",
			sse:     "data: {\"candidates\":[{\"finishReason\":\"MALFORMED_FUNCTION_CALL\"}]}\n\n",
			wantErr: "MALFORMED_FUNCTION_CALL",
		},
	}
	for _, tc := range cases {
		resp := newSSEResponse(tc.sse)
		defer resp.Body.Close()
		w, buf := newRecorder()
		_, err := NewStreamHandler("vertex", "m").HandleStream(context.Background(), w, w, resp)
		if err == nil {
			t.Errorf("%s: want error containing %q, got nil; output:\n%s", tc.name, tc.wantErr, buf.String())
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error = %q, want containing %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestVertexStreamHandler_CtxCancel(t *testing.T) {
	t.Parallel()

	resp := newSSEResponse("data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"x\"}]}}]}\n\n")
	defer resp.Body.Close()
	w, _ := newRecorder()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewStreamHandler("vertex", "m").HandleStream(ctx, w, w, resp)
	require.ErrorIs(t, err, context.Canceled)
}

// TestVertexStreamHandler_EOFWithoutFinish pins the graceful-degradation
// contract: an upstream that closes without a finishReason event still gets
// a clean [DONE] termination (no extra usage frame is fabricated), and the
// returned usage reports Source "none" (no estimate is possible without
// wiring state — an accepted limitation).
func TestVertexStreamHandler_EOFWithoutFinish(t *testing.T) {
	t.Parallel()

	resp := newSSEResponse("data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"partial\"}]}}]}\n\n")
	defer resp.Body.Close()
	w, buf := newRecorder()

	usage, err := NewStreamHandler("vertex", "gemini-2.0-flash").HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	chunks := parseVertexStreamFrames(t, buf.String())
	require.Len(t, chunks, 2, "role + content, then [DONE] from the EOF path, got:\n%s", buf.String())
	assert.Equal(t, map[string]any{"content": "partial"}, vertexChoice(t, chunks[1])["delta"])
	assert.Equal(t, Usage{Source: UsageSourceNone}, usage)
}

func TestVertexStreamHandler_EmptyStream(t *testing.T) {
	t.Parallel()

	resp := newSSEResponse("")
	defer resp.Body.Close()
	w, buf := newRecorder()

	usage, err := NewStreamHandler("vertex", "m").HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)
	assert.Equal(t, "data: [DONE]\n\n", buf.String())
	assert.Equal(t, Usage{Source: UsageSourceNone}, usage)
}

// TestVertexStreamHandler_UsageChunkWithoutCacheRead: the cached_tokens
// detail appears only when the provider reported a positive count — zeros
// are not fabricated.
func TestVertexStreamHandler_UsageChunkWithoutCacheRead(t *testing.T) {
	t.Parallel()

	const sse = "data: {\"candidates\":[{\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":5,\"candidatesTokenCount\":1}}\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close()
	w, buf := newRecorder()

	usage, err := NewStreamHandler("vertex", "m").HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	chunks := parseVertexStreamFrames(t, buf.String())
	require.Len(t, chunks, 2, "finish + usage-only, got:\n%s", buf.String())
	u := chunks[1]["usage"].(map[string]any)
	assert.InDelta(t, float64(6), u["total_tokens"], 0, "total falls back to prompt+completion")
	assert.NotContains(t, u, "prompt_tokens_details")
	assert.Equal(t, Usage{PromptTokens: 5, CompletionTokens: 1, TotalTokens: 6, Source: UsageSourceProvider}, usage)
}
