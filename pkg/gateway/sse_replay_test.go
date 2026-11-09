package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression: streaming clients (OpenAI-compatible SDKs) must receive SSE
// frames when a cache hit is replayed. The gateway previously wrote the raw
// cached JSON document with no `data:` framing, which left callers waiting
// for chunks that never arrived.

func parseSSEFrames(t *testing.T, body []byte) []string {
	t.Helper()
	var frames []string
	for _, line := range strings.Split(string(body), "\n\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		require.True(t, strings.HasPrefix(line, "data: "), "frame must start with 'data: ', got %q", line)
		frames = append(frames, strings.TrimPrefix(line, "data: "))
	}
	return frames
}

func TestSSEReplayFrames_ValidCompletion(t *testing.T) {
	completion := map[string]any{
		"id":      "resp-1",
		"created": int64(1700000000),
		"model":   "glm-5.3-flash",
		"choices": []map[string]any{{
			"index": 0,
			"message": map[string]any{
				"role":    "assistant",
				"content": "hello world",
			},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 2,
			"total_tokens":      12,
		},
	}
	data, err := json.Marshal(completion)
	require.NoError(t, err)

	frames, err := sseReplayFrames(data)
	require.NoError(t, err)

	parsed := parseSSEFrames(t, frames)
	require.Len(t, parsed, 3, "content chunk, finish chunk, [DONE]")

	assert.Equal(t, "[DONE]", parsed[2])

	var contentChunk struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Index int `json:"index"`
			Delta struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"delta"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal([]byte(parsed[0]), &contentChunk))
	assert.Equal(t, "chat.completion.chunk", contentChunk.Object)
	assert.Equal(t, "resp-1", contentChunk.ID)
	assert.Equal(t, "glm-5.3-flash", contentChunk.Model)
	require.Len(t, contentChunk.Choices, 1)
	assert.Equal(t, "assistant", contentChunk.Choices[0].Delta.Role)
	assert.Equal(t, "hello world", contentChunk.Choices[0].Delta.Content)
	assert.Nil(t, contentChunk.Choices[0].FinishReason)

	var finishChunk struct {
		Usage *map[string]any `json:"usage"`
	}
	require.NoError(t, json.Unmarshal([]byte(parsed[1]), &finishChunk))
	assert.NotNil(t, finishChunk.Usage, "usage must ride the terminal frame")

	// The finish chunk terminates the message.
	var fr struct {
		Choices []struct {
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal([]byte(parsed[1]), &fr))
	require.Len(t, fr.Choices, 1)
	require.NotNil(t, fr.Choices[0].FinishReason)
	assert.Equal(t, "stop", *fr.Choices[0].FinishReason)
}

func TestSSEReplayFrames_ReasoningContentPreserved(t *testing.T) {
	completion := map[string]any{
		"id":      "resp-2",
		"created": int64(1700000001),
		"model":   "glm-5.3",
		"choices": []map[string]any{{
			"index": 0,
			"message": map[string]any{
				"role":              "assistant",
				"content":           "answer",
				"reasoning_content": "thinking hard",
			},
			"finish_reason": "stop",
		}},
	}
	data, err := json.Marshal(completion)
	require.NoError(t, err)

	frames, err := sseReplayFrames(data)
	require.NoError(t, err)

	parsed := parseSSEFrames(t, frames)
	require.Len(t, parsed, 3)

	var chunk struct {
		Choices []struct {
			Delta struct {
				ReasoningContent string `json:"reasoning_content"`
				Content          string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal([]byte(parsed[0]), &chunk))
	require.Len(t, chunk.Choices, 1)
	assert.Equal(t, "thinking hard", chunk.Choices[0].Delta.ReasoningContent)
	assert.Equal(t, "answer", chunk.Choices[0].Delta.Content)
}

func TestSSEReplayFrames_MultipleChoices(t *testing.T) {
	completion := map[string]any{
		"id":      "resp-3",
		"created": int64(1700000002),
		"model":   "m",
		"choices": []map[string]any{
			{"index": 0, "message": map[string]any{"role": "assistant", "content": "a"}, "finish_reason": "stop"},
			{"index": 1, "message": map[string]any{"role": "assistant", "content": "b"}, "finish_reason": "stop"},
		},
	}
	data, err := json.Marshal(completion)
	require.NoError(t, err)

	frames, err := sseReplayFrames(data)
	require.NoError(t, err)

	parsed := parseSSEFrames(t, frames)
	require.Len(t, parsed, 5, "two content chunks + two finish chunks + [DONE]")
	assert.Equal(t, "[DONE]", parsed[4])
}

func TestSSEReplayFrames_MissingFieldsGetDefaults(t *testing.T) {
	// H3: the finish_reason itself is load-bearing (a null/absent one is the
	// truncated-stream shape and is refused — pinned in the H3 tests); the
	// cosmetic fields below are what this pin covers.
	completion := map[string]any{
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]any{"content": "x"},
			"finish_reason": "stop",
		}},
	}
	data, err := json.Marshal(completion)
	require.NoError(t, err)

	frames, err := sseReplayFrames(data)
	require.NoError(t, err)

	parsed := parseSSEFrames(t, frames)
	require.Len(t, parsed, 3)

	var chunk struct {
		ID      string `json:"id"`
		Created int64  `json:"created"`
		Model   string `json:"model"`
		Choices []struct {
			Delta struct {
				Role string `json:"role"`
			} `json:"delta"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal([]byte(parsed[0]), &chunk))
	assert.Equal(t, "cache-replay", chunk.ID)
	assert.Equal(t, "cache-replay", chunk.Model)
	assert.Positive(t, chunk.Created, "created must default to now")
	assert.Equal(t, "assistant", chunk.Choices[0].Delta.Role)
}

func TestSSEReplayFrames_ToolCallsPreserved(t *testing.T) {
	// N07-P01-T03 negative criterion: a cached completion produced with
	// parallel tool calls must replay them — the old replay carried only
	// role/content/reasoning, silently stripping the tool calls from the
	// stream and leaving the client waiting for results that never come.
	completion := map[string]any{
		"id":      "resp-tools",
		"created": int64(1700000003),
		"model":   "m",
		"choices": []map[string]any{{
			"index": 0,
			"message": map[string]any{
				"role": "assistant",
				"tool_calls": []map[string]any{
					{"id": "call_0", "type": "function", "function": map[string]any{"name": "get_weather", "arguments": `{"city":"Paris"}`}},
					{"id": "call_1", "type": "function", "function": map[string]any{"name": "get_time", "arguments": `{"tz":"UTC"}`}},
				},
			},
			"finish_reason": "tool_calls",
		}},
	}
	data, err := json.Marshal(completion)
	require.NoError(t, err)

	frames, err := sseReplayFrames(data)
	require.NoError(t, err)

	parsed := parseSSEFrames(t, frames)
	require.Len(t, parsed, 3, "tool-call chunk, finish chunk, [DONE]")

	var chunk struct {
		Choices []struct {
			Delta struct {
				ToolCalls []struct {
					Index    int    `json:"index"`
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal([]byte(parsed[0]), &chunk))
	require.Len(t, chunk.Choices, 1)
	calls := chunk.Choices[0].Delta.ToolCalls
	require.Len(t, calls, 2)
	for i, want := range []struct{ id, name, args string }{
		{"call_0", "get_weather", `{"city":"Paris"}`},
		{"call_1", "get_time", `{"tz":"UTC"}`},
	} {
		assert.Equal(t, i, calls[i].Index, "streaming consumers merge tool-call fragments by index")
		assert.Equal(t, want.id, calls[i].ID)
		assert.Equal(t, want.name, calls[i].Function.Name)
		assert.Equal(t, want.args, calls[i].Function.Arguments)
	}

	var fr struct {
		Choices []struct {
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal([]byte(parsed[1]), &fr))
	require.NotNil(t, fr.Choices[0].FinishReason)
	assert.Equal(t, "tool_calls", *fr.Choices[0].FinishReason)
}

func TestSSEReplayFrames_RefusalPreserved(t *testing.T) {
	// N07-P01-T03: a cached refusal must replay the refusal text and the
	// content_filter finish, not a completed-looking plain answer.
	completion := map[string]any{
		"id":      "resp-refusal",
		"created": int64(1700000004),
		"model":   "m",
		"choices": []map[string]any{{
			"index": 0,
			"message": map[string]any{
				"role":    "assistant",
				"content": nil,
				"refusal": "I can't help with that request.",
			},
			"finish_reason": "content_filter",
		}},
	}
	data, err := json.Marshal(completion)
	require.NoError(t, err)

	frames, err := sseReplayFrames(data)
	require.NoError(t, err)

	parsed := parseSSEFrames(t, frames)
	require.Len(t, parsed, 3)

	var chunk struct {
		Choices []struct {
			Delta struct {
				Content *string `json:"content"`
				Refusal string  `json:"refusal"`
			} `json:"delta"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal([]byte(parsed[0]), &chunk))
	require.Len(t, chunk.Choices, 1)
	assert.Equal(t, "I can't help with that request.", chunk.Choices[0].Delta.Refusal)
	assert.Nil(t, chunk.Choices[0].Delta.Content, "refusal replay must not fabricate content")

	var fr struct {
		Choices []struct {
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal([]byte(parsed[1]), &fr))
	require.NotNil(t, fr.Choices[0].FinishReason)
	assert.Equal(t, "content_filter", *fr.Choices[0].FinishReason)
}

func TestSSEReplayFrames_UndecodableToolCallsAreMisses(t *testing.T) {
	// A tool_calls block that cannot be framed faithfully must fail the
	// replay (callers treat that as a cache miss and go upstream) instead of
	// silently streaming a completion without its tool calls.
	data := []byte(`{"id":"x","choices":[{"index":0,"message":{"role":"assistant","tool_calls":{"id":"not-an-array"}},"finish_reason":"tool_calls"}]}`)
	_, err := sseReplayFrames(data)
	assert.Error(t, err, "callers must fall through to upstream instead of replaying a lossy stream")
}

func TestSSEReplayFrames_InvalidDocumentsAreMisses(t *testing.T) {
	for name, data := range map[string][]byte{
		"not json":        []byte("hello, this is not json"),
		"empty":           {},
		"json no choices": []byte(`{"id":"x"}`),
		"empty choices":   []byte(`{"id":"x","choices":[]}`),
		"error object":    []byte(`{"error":{"message":"boom"}}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := sseReplayFrames(data)
			assert.Error(t, err, "callers must fall through to upstream")
		})
	}
}
