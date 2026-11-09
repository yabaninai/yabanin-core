package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: build an *http.Response whose body streams the given SSE bytes.
func newSSEResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// recorderFlusher captures everything written to it and satisfies
// http.Flusher so the handlers' flush calls don't panic.
type recorderFlusher struct {
	*httptest.ResponseRecorder
}

func (recorderFlusher) Flush() {}

func newRecorder() (*recorderFlusher, *bytes.Buffer) {
	var buf bytes.Buffer
	r := httptest.NewRecorder()
	r.Body = &buf
	return &recorderFlusher{ResponseRecorder: r}, &buf
}

// --- OpenAI handler tests ----------------------------------------------------

func TestOpenAIStreamHandler_Passthrough(t *testing.T) {
	// Three chunks + [DONE] from a (mock) OpenAI upstream.
	const sse = "data: {\"id\":\"1\",\"choices\":[]}\n\n" +
		"data: {\"id\":\"2\",\"choices\":[]}\n\n" +
		"data: [DONE]\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close() // NopCloser: Close is a no-op
	w, buf := newRecorder()

	h := NewStreamHandler("openai", "gpt-4")
	usage, err := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	// Passthrough contract: output must equal input verbatim.
	assert.Equal(t, sse, buf.String())
	// No usage in this fixture.
	assert.Equal(t, int64(0), usage.PromptTokens)
}

func TestOpenAIStreamHandler_CompletesFinalEventSeparator(t *testing.T) {
	const sse = "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"bash\",\"arguments\":\"{}\"}}]}}]}\n\n" +
		"data: {\"choices\":[{\"finish_reason\":\"tool_calls\",\"delta\":{}}]}\n\n" +
		"data: [DONE]"
	resp := newSSEResponse(sse)
	defer resp.Body.Close()
	w, buf := newRecorder()
	_, err := NewStreamHandler("openai-compatible", "glm-5.3").HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)
	assert.Equal(t, sse+"\n\n", buf.String())
}

func TestOpenAIStreamHandler_UsageParsedFromFinalChunk(t *testing.T) {
	// OpenAI streams include usage only in the final chunk before [DONE].
	const sse = "data: {\"id\":\"1\",\"choices\":[{}]}\n\n" +
		"data: {\"id\":\"2\",\"choices\":[],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":7,\"total_tokens\":49}}\n\n" +
		"data: [DONE]\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close() // NopCloser: Close is a no-op
	w, _ := newRecorder()

	h := NewStreamHandler("", "gpt-4") // empty provider defaults to OpenAI
	usage, err := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	assert.Equal(t, int64(42), usage.PromptTokens)
	assert.Equal(t, int64(7), usage.CompletionTokens)
	assert.Equal(t, int64(49), usage.TotalTokens)
}

func TestOpenAIStreamHandler_ContextCancelStops(t *testing.T) {
	// Use a response body that yields one line then blocks. Cancellation
	// should make HandleStream return before EOF.
	resp := newSSEResponse("data: {\"id\":\"1\"}\n\n")
	defer resp.Body.Close() // NopCloser: Close is a no-op
	w, _ := newRecorder()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	h := NewStreamHandler("openai", "gpt-4")
	_, err := h.HandleStream(ctx, w, w, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

// --- Anthropic handler tests -------------------------------------------------

func TestAnthropicStreamHandler_TranslatesEvents(t *testing.T) {
	// Canonical Anthropic SSE stream: message_start, two deltas, message_stop.
	const sse = "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"lo\"}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close() // NopCloser: Close is a no-op
	w, buf := newRecorder()

	h := NewStreamHandler("anthropic", "claude-3")
	_, err := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	out := buf.String()

	// First chunk: role-only delta from message_start.
	assert.Contains(t, out, "\"role\":\"assistant\"")
	// Two content deltas forwarded as separate chunks.
	assert.Contains(t, out, "\"content\":\"Hel\"")
	assert.Contains(t, out, "\"content\":\"lo\"")
	// Stream terminates with [DONE] (emitted by handler on message_stop).
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"),
		"expected output to end with [DONE], got: %q", out)
	// All chunks are shaped as OpenAI chat.completion.chunk objects.
	assert.Contains(t, out, "\"object\":\"chat.completion.chunk\"")
	assert.Contains(t, out, "\"model\":\"claude-3\"")
}

func TestAnthropicStreamHandler_UsageExtractedFromMessageDelta(t *testing.T) {
	// Anthropic emits usage in the message_delta event (not message_stop).
	const sse = "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":11,\"output_tokens\":22}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close() // NopCloser: Close is a no-op
	w, _ := newRecorder()

	h := NewStreamHandler("anthropic", "claude-3")
	usage, err := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	assert.Equal(t, int64(11), usage.PromptTokens)
	assert.Equal(t, int64(22), usage.CompletionTokens)
	assert.Equal(t, int64(33), usage.TotalTokens)
}

func TestAnthropicStream_UsageFromMessageStart(t *testing.T) {
	const sse = "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":100,\"cache_read_input_tokens\":50000,\"cache_creation_input_tokens\":2000,\"output_tokens\":0}}}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":500}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close()
	w, _ := newRecorder()

	h := NewStreamHandler("anthropic", "claude-3-5-sonnet-20241022")
	usage, err := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	assert.Equal(t, Usage{
		PromptTokens:        52100,
		CompletionTokens:    500,
		TotalTokens:         52600,
		CacheReadTokens:     50000,
		CacheCreationTokens: 2000,
		Source:              UsageSourceProvider,
	}, usage)
}

func TestAnthropicStreamHandler_PingDoesNotEmitChunk(t *testing.T) {
	const sse = "event: ping\ndata: {\"type\":\"ping\"}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close() // NopCloser: Close is a no-op
	w, buf := newRecorder()

	h := NewStreamHandler("anthropic", "claude-3")
	_, err := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	// Ping emits nothing. message_stop with the default handler (emitUsage on,
	// because SuppressUsageOnlyChunk is false) writes a usage chunk, then [DONE].
	assert.NotContains(t, buf.String(), `"content"`)
	assert.Contains(t, buf.String(), `"usage"`)
	assert.True(t, strings.HasSuffix(buf.String(), "data: [DONE]\n\n"), buf.String())
}

func TestAnthropicStream_Tools(t *testing.T) {
	raw, err := os.ReadFile("testdata/anthropic_stream_tools.sse")
	require.NoError(t, err)
	for _, emit := range []bool{false, true} {
		t.Run(map[bool]string{false: "no_usage", true: "usage"}[emit], func(t *testing.T) {
			resp := newSSEResponse(string(raw))
			defer resp.Body.Close()
			w, buf := newRecorder()
			h := NewStreamHandlerWithOptions("anthropic", "claude", StreamOptions{SuppressUsageOnlyChunk: !emit})
			_, err := h.HandleStream(context.Background(), w, w, resp)
			require.NoError(t, err)
			out := buf.String()
			require.NoError(t, apiformat.ValidateChatStream(strings.Split(out, "\n")))
			args := map[int]string{}
			var dataPayloads []string
			var sawFinish bool
			var sawUsage bool
			for _, line := range strings.Split(out, "\n") {
				if !strings.HasPrefix(line, "data: ") || strings.TrimPrefix(line, "data: ") == "[DONE]" {
					continue
				}
				payload := strings.TrimPrefix(line, "data: ")
				dataPayloads = append(dataPayloads, payload)
				var chunk struct {
					ID      string `json:"id"`
					Choices []struct {
						FinishReason *string `json:"finish_reason"`
						Delta        struct {
							ToolCalls []struct {
								Index    int `json:"index"`
								Function struct {
									Arguments string `json:"arguments"`
								} `json:"function"`
							} `json:"tool_calls"`
						} `json:"delta"`
					} `json:"choices"`
					Usage *struct {
						PromptTokens int64 `json:"prompt_tokens"`
					} `json:"usage"`
				}
				require.NoError(t, json.Unmarshal([]byte(payload), &chunk))
				assert.Contains(t, chunk.ID, "chatcmpl-msg_tools")
				if chunk.Usage != nil {
					sawUsage = true
					assert.Equal(t, int64(10), chunk.Usage.PromptTokens)
				}
				for _, choice := range chunk.Choices {
					if choice.FinishReason != nil && *choice.FinishReason == "tool_calls" {
						sawFinish = true
					}
					for _, call := range choice.Delta.ToolCalls {
						args[call.Index] += call.Function.Arguments
					}
				}
			}
			require.True(t, sawFinish)
			for _, idx := range []int{0, 1} {
				var obj map[string]any
				require.NoError(t, json.Unmarshal([]byte(args[idx]), &obj), args[idx])
			}
			assert.Equal(t, "Paris", mustArg(t, args[0], "city"))
			assert.Equal(t, "UTC", mustArg(t, args[1], "tz"))
			if emit {
				require.True(t, sawUsage)
				assert.Contains(t, dataPayloads[len(dataPayloads)-1], `"usage"`)
			} else {
				assert.False(t, sawUsage)
				assert.Contains(t, dataPayloads[len(dataPayloads)-1], `"finish_reason":"tool_calls"`)
			}
		})
	}
}

func TestAnthropicStream_Refusal(t *testing.T) {
	// N07-P01-T03: the terminal refusal stop_reason must end the translated
	// stream with finish_reason content_filter — never "stop", which would
	// tell pinned SDK clients the answer completed normally.
	//
	// Documented limitation (record, not fixed here): Anthropic signals the
	// refusal only in the terminal message_delta, after the refusal text has
	// already streamed as ordinary text_delta events. Emulating OpenAI's
	// delta.refusal framing would require buffering the whole response and
	// destroying streaming latency for every request, so the text stays in
	// content and finish_reason content_filter is the refusal signal.
	raw, err := os.ReadFile("testdata/anthropic_stream_refusal.sse")
	require.NoError(t, err)
	resp := newSSEResponse(string(raw))
	defer resp.Body.Close() // NopCloser: Close is a no-op
	w, buf := newRecorder()

	h := NewStreamHandler("anthropic", "claude")
	_, err = h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)
	out := buf.String()
	require.NoError(t, apiformat.ValidateChatStream(strings.Split(out, "\n")))

	var finish string
	var refusalDelta bool
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				FinishReason *string `json:"finish_reason"`
				Delta        struct {
					Content string `json:"content"`
					Refusal string `json:"refusal"`
				} `json:"delta"`
			} `json:"choices"`
		}
		require.NoError(t, json.Unmarshal([]byte(payload), &chunk))
		for _, c := range chunk.Choices {
			if c.FinishReason != nil {
				finish = *c.FinishReason
			}
			if c.Delta.Refusal != "" {
				refusalDelta = true
			}
		}
	}
	assert.Equal(t, "content_filter", finish)
	assert.Contains(t, out, "I can't help with that.")
	assert.False(t, refusalDelta, "delta.refusal is not emulated without full-response buffering (documented limitation)")
}

func mustArg(t *testing.T, raw, key string) string {
	t.Helper()
	var obj map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &obj))
	s, _ := obj[key].(string)
	return s
}

func TestAnthropicStreamHandler_NoMessageStopStillTerminates(t *testing.T) {
	// Upstream closed without sending message_stop. The handler still emits
	// [DONE] so OpenAI clients terminate cleanly (pinned client compat),
	// and — H3 — reports the run as incomplete (ErrStreamIncomplete) so the
	// gateway never caches or accounts the prefix as a completed request.
	const sse = "event: message_start\n" +
		"data: {\"type\":\"message_start\"}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"}}\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close() // NopCloser: Close is a no-op
	w, buf := newRecorder()

	h := NewStreamHandler("anthropic", "claude-3")
	_, err := h.HandleStream(context.Background(), w, w, resp)
	require.ErrorIs(t, err, ErrStreamIncomplete,
		"EOF without message_stop is an incomplete run")
	assert.True(t, strings.HasSuffix(buf.String(), "data: [DONE]\n\n"),
		"the client-compat [DONE] still terminates the stream")
}

// --- Factory tests -----------------------------------------------------------

func TestOpenAIStreamHandler_EstimatesWhenNoUsage(t *testing.T) {
	const sse = "data: {\"choices\":[{\"delta\":{\"content\":\"abcd\",\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"xy\"}}]}}]}\n\n" +
		"data: [DONE]\n\n"
	resp := newSSEResponse(sse)
	defer resp.Body.Close()
	w, _ := newRecorder()
	h := NewStreamHandlerWithOptions("openai", "m", StreamOptions{RequestBytes: 5})
	usage, err := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)
	assert.Equal(t, UsageSourceEstimated, usage.Source)
	assert.Equal(t, int64(2), usage.PromptTokens)     // ceil(5/4)
	assert.Equal(t, int64(2), usage.CompletionTokens) // ceil((4+2)/4)
	assert.Equal(t, usage.PromptTokens+usage.CompletionTokens, usage.TotalTokens)
}

func TestOpenAIStreamHandler_EstimatesCompletionText(t *testing.T) {
	const sse = "data: {\"choices\":[{\"text\":\"abcd\"}]}\n\n" +
		"data: [DONE]\n\n"
	resp := newSSEResponse(sse)
	defer resp.Body.Close()
	w, _ := newRecorder()
	h := NewStreamHandlerWithOptions("openai", "m", StreamOptions{RequestBytes: 4})
	usage, err := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)
	assert.Equal(t, UsageSourceEstimated, usage.Source)
	assert.Equal(t, int64(1), usage.PromptTokens)
	assert.Equal(t, int64(1), usage.CompletionTokens) // ceil(len("abcd")/4)
}

func TestNewStreamHandler_DefaultsToOpenAI(t *testing.T) {
	assert.IsType(t, &openAIStreamHandler{}, NewStreamHandler("", "x"))
	assert.IsType(t, &openAIStreamHandler{}, NewStreamHandler("openai", "x"))
	assert.IsType(t, &openAIStreamHandler{}, NewStreamHandler("openai-compat", "x"))
	assert.IsType(t, &anthropicStreamHandler{}, NewStreamHandler("anthropic", "x"))
}

// --- RM-03: usage-only chunk suppression + cached-token parsing ---------------

func TestOpenAIStreamHandler_SuppressUsageOnlyChunk(t *testing.T) {
	// Two content chunks, then the trailing usage-only chunk upstreams send
	// when the gateway asked for stream_options.include_usage, then [DONE].
	const content1 = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\n"
	const content2 = "data: {\"id\":\"2\",\"choices\":[{\"delta\":{\"content\":\"y\"}}]}\n\n"
	const usageChunk = "data: {\"id\":\"3\",\"choices\":[],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":7," +
		"\"total_tokens\":49,\"prompt_tokens_details\":{\"cached_tokens\":5}}}\n\n"
	const done = "data: [DONE]\n\n"
	const sse = content1 + content2 + usageChunk + done

	t.Run("suppressed", func(t *testing.T) {
		resp := newSSEResponse(sse)
		defer resp.Body.Close() // NopCloser: Close is a no-op
		w, buf := newRecorder()

		h := NewStreamHandlerWithOptions("openai", "gpt-4", StreamOptions{SuppressUsageOnlyChunk: true})
		usage, err := h.HandleStream(context.Background(), w, w, resp)
		require.NoError(t, err)

		// The usage-only chunk AND its blank separator must not reach the
		// client; everything else byte-for-byte as upstream sent it.
		assert.Equal(t, content1+content2+done, buf.String())
		// Usage is still parsed from the suppressed chunk.
		assert.Equal(t, int64(42), usage.PromptTokens)
		assert.Equal(t, int64(7), usage.CompletionTokens)
		assert.Equal(t, int64(49), usage.TotalTokens)
		assert.Equal(t, int64(5), usage.CacheReadTokens)
	})

	t.Run("not suppressed is verbatim passthrough", func(t *testing.T) {
		resp := newSSEResponse(sse)
		defer resp.Body.Close() // NopCloser: Close is a no-op
		w, buf := newRecorder()

		h := NewStreamHandler("openai", "gpt-4") // zero options = pre-RM-03 behaviour
		usage, err := h.HandleStream(context.Background(), w, w, resp)
		require.NoError(t, err)

		assert.Equal(t, sse, buf.String())
		assert.Equal(t, int64(42), usage.PromptTokens)
		assert.Equal(t, int64(5), usage.CacheReadTokens)
	})
}

func TestOpenAIStreamHandler_SuppressKeepsContentChunksWithUsage(t *testing.T) {
	// A chunk with NON-empty choices is never a usage-only chunk — even when
	// it carries usage (some upstreams do) it must pass through byte-for-byte.
	const sse = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"x\"}}],\"usage\":{\"prompt_tokens\":3,\"total_tokens\":4}}\n\n" +
		"data: [DONE]\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close() // NopCloser: Close is a no-op
	w, buf := newRecorder()

	h := NewStreamHandlerWithOptions("openai-compat", "m", StreamOptions{SuppressUsageOnlyChunk: true})
	usage, err := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err)

	assert.Equal(t, sse, buf.String())
	assert.Equal(t, int64(3), usage.PromptTokens)
}

func TestParseOpenAIChunkUsage_CachedTokens(t *testing.T) {
	line := []byte(`data: {"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110,` +
		`"prompt_tokens_details":{"cached_tokens":64}}}`)
	u := parseOpenAIChunkUsage(line, Usage{})
	assert.Equal(t, int64(100), u.PromptTokens)
	assert.Equal(t, int64(10), u.CompletionTokens)
	assert.Equal(t, int64(110), u.TotalTokens)
	assert.Equal(t, int64(64), u.CacheReadTokens, "prompt_tokens_details.cached_tokens must feed CacheReadTokens")
}

func TestParseOpenAIChunkUsage_DeepSeekHitTokens(t *testing.T) {
	// DeepSeek reports cache hits as prompt_cache_hit_tokens inside usage,
	// without prompt_tokens_details.
	line := []byte(`data: {"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110,` +
		`"prompt_cache_hit_tokens":64}}`)
	u := parseOpenAIChunkUsage(line, Usage{})
	assert.Equal(t, int64(64), u.CacheReadTokens, "prompt_cache_hit_tokens must feed CacheReadTokens when details are absent")
	assert.Equal(t, int64(0), u.CacheCreationTokens)
}

func TestParseOpenAIChunkUsage_DetailsWinOverDeepSeek(t *testing.T) {
	// When both shapes are present, the OpenAI detail object wins.
	line := []byte(`data: {"choices":[],"usage":{"prompt_tokens":1,"total_tokens":1,` +
		`"prompt_tokens_details":{"cached_tokens":7},"prompt_cache_hit_tokens":9}}`)
	u := parseOpenAIChunkUsage(line, Usage{})
	assert.Equal(t, int64(7), u.CacheReadTokens)
}

// --- error & boundary fixtures (contract §9) -------------------------

// errReader returns err after its bytes are exhausted, simulating a mid-stream
// upstream disconnect deterministically.
type errReader struct {
	data []byte
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

// TestOpenAIStreamHandler_MalformedLinePassthrough (contract §9, malformed
// SSE): a JSON-invalid data line passes through byte-identical, is not an
// error, does not abort the stream, and usage parsing silently skips it
// (fail-open) so usage falls back to the byte estimate.
func TestOpenAIStreamHandler_MalformedLinePassthrough(t *testing.T) {
	const sse = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n" +
		"data: {not-json\n\n" +
		"data: {\"id\":\"2\",\"choices\":[{\"delta\":{\"content\":\"!\"}}]}\n\n" +
		"data: [DONE]\n\n"

	resp := newSSEResponse(sse)
	defer resp.Body.Close()
	w, buf := newRecorder()

	h := NewStreamHandlerWithOptions("openai", "m", StreamOptions{RequestBytes: 40})
	usage, err := h.HandleStream(context.Background(), w, w, resp)
	require.NoError(t, err, "malformed lines are fail-open passthrough, not errors")

	assert.Equal(t, sse, buf.String(), "malformed line must reach the client verbatim")
	assert.Equal(t, UsageSourceEstimated, usage.Source)
	assert.Equal(t, int64(10), usage.PromptTokens, "ceil(40/4)")
	assert.Equal(t, int64(1), usage.CompletionTokens, "delta bytes \"ok!\" → ceil(3/4)")
}

// TestOpenAIStreamHandler_TruncatedStream_EstimatesPrefixUsage pins the
// mid-stream disconnect usage contract (§8.2): when the upstream dies after
// partial delivery, the handler returns an error AND usage estimated from the
// bytes actually streamed — the consumed prefix is never billed as zero.
func TestOpenAIStreamHandler_TruncatedStream_EstimatesPrefixUsage(t *testing.T) {
	partial := "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"par\"}}]}\n\n" +
		"data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"tial\"}}]}\n\n"

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(&errReader{data: []byte(partial), err: errors.New("unexpected EOF")}),
	}
	defer resp.Body.Close()
	w, buf := newRecorder()

	h := NewStreamHandlerWithOptions("openai", "m", StreamOptions{RequestBytes: 40})
	usage, err := h.HandleStream(context.Background(), w, w, resp)
	require.Error(t, err, "a mid-stream read failure must surface as an error")
	assert.Contains(t, err.Error(), "stream read failed")

	assert.Equal(t, partial, buf.String(), "partial frames already flushed are kept")
	assert.Equal(t, UsageSourceEstimated, usage.Source)
	assert.Equal(t, int64(10), usage.PromptTokens, "ceil(40/4)")
	assert.Equal(t, int64(2), usage.CompletionTokens, "delta bytes \"partial\" → ceil(7/4)")
	assert.Equal(t, int64(12), usage.TotalTokens)
}
