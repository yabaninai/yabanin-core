package provider

// Handler-level pins for the saw-terminal contract: every StreamHandler
// must report EOF-without-terminal as an error wrapping ErrStreamIncomplete.
// The anthropic and bedrock handlers keep synthesizing the client-facing
// [DONE] (the OpenAI wire contract for already-streamed frames stays
// well-formed); the OpenAI passthrough tracks the forwarded [DONE] line and
// owns no synthesized terminator — the gateway's drain-failure path emits
// the error frame + [DONE] for it.
//
// These pins reference provider.ErrStreamIncomplete directly, so a source
// tree without the sentinel fails to compile here by design: the typed API
// is the pin. The gateway-side counterpart that runs against any tree is
// pkg/gateway/h3_stream_terminal_cache_test.go.

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	eventstream "github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func h3Resp(body []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

// h3HandleStream builds the response, drains it through the handler and
// closes the body (the existing stream_test.go pattern; NopCloser Close is
// a no-op, the defer keeps bodyclose honest).
func h3HandleStream(t *testing.T, h StreamHandler, body []byte) (Usage, *bytes.Buffer, error) {
	t.Helper()
	w, buf := newRecorder()
	resp := h3Resp(body)
	defer resp.Body.Close() // NopCloser: Close is a no-op
	usage, err := h.HandleStream(t.Context(), w, w, resp)
	return usage, buf, err
}

// --- OpenAI passthrough -------------------------------------------------------

func TestH3_OpenAIHandler_ReportsMissingDoneTerminator(t *testing.T) {
	const truncated = "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n"

	h := NewStreamHandler("", "gpt-4")
	usage, buf, err := h3HandleStream(t, h, []byte(truncated))

	require.Error(t, err, "EOF without [DONE] is a truncated stream")
	require.ErrorIs(t, err, ErrStreamIncomplete)
	assert.NotContains(t, buf.String(), "[DONE]",
		"the passthrough must not synthesize a terminator — the gateway drain-failure path owns the error frame + [DONE]")
	assert.Contains(t, buf.String(), `"content":"hi"`,
		"the already-flushed prefix stays untouched")
	assert.Equal(t, UsageSourceEstimated, usage.Source,
		"partial usage is still estimated from the consumed prefix (contract §8.2)")
}

func TestH3_OpenAIHandler_DoneTerminatorIsComplete(t *testing.T) {
	const complete = "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: [DONE]\n\n"

	h := NewStreamHandler("", "gpt-4")
	_, _, err := h3HandleStream(t, h, []byte(complete))
	require.NoError(t, err, "a stream that carried [DONE] is complete")
}

func TestH3_OpenAIHandler_AcceptsNoSpaceDoneVariant(t *testing.T) {
	// Some compatible upstreams omit the space after "data:". The [DONE]
	// tracking must accept both spellings or every such stream would be
	// refused as truncated.
	const complete = "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data:[DONE]\n\n"

	h := NewStreamHandler("", "gpt-4")
	_, _, err := h3HandleStream(t, h, []byte(complete))
	require.NoError(t, err)
}

func TestH3_IsDoneDataLine(t *testing.T) {
	cases := map[string]bool{
		"data: [DONE]":         true,
		"data:[DONE]":          true,
		"data: [DONE]extra":    false,
		"data: {\"id\":1}":     false,
		"event: message_stop":  false,
		"":                     false,
		": keep-alive comment": false,
	}
	for line, want := range cases {
		assert.Equal(t, want, isDoneDataLine([]byte(line)), "line %q", line)
	}
}

// --- Anthropic translation ----------------------------------------------------

const h3AnthropicTruncated = "event: message_start\n" +
	"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":5,\"output_tokens\":1}}}\n\n" +
	"event: content_block_delta\n" +
	"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}\n\n" +
	"event: message_delta\n" +
	"data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":5,\"output_tokens\":3}}\n\n"

func TestH3_AnthropicHandler_ReportsMissingMessageStop(t *testing.T) {
	h := NewStreamHandler("anthropic", "claude-3")
	usage, buf, err := h3HandleStream(t, h, []byte(h3AnthropicTruncated))

	require.Error(t, err, "EOF without message_stop is a truncated stream")
	require.ErrorIs(t, err, ErrStreamIncomplete)
	assert.True(t, strings.HasSuffix(strings.TrimSpace(buf.String()), "data: [DONE]"),
		"client compat (pinned): the handler still terminates the OpenAI wire, got:\n%s", buf.String())
	assert.Equal(t, int64(5), usage.PromptTokens, "usage parsed before the cut is preserved for honest partial accounting")
	assert.Equal(t, int64(3), usage.CompletionTokens)
}

func TestH3_AnthropicHandler_MessageStopIsComplete(t *testing.T) {
	complete := h3AnthropicTruncated +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"

	h := NewStreamHandler("anthropic", "claude-3")
	_, _, err := h3HandleStream(t, h, []byte(complete))
	require.NoError(t, err, "a stream that carried message_stop is complete")
}

// --- Bedrock eventstream ------------------------------------------------------

// h3BedrockEvent is one ConverseStream eventstream frame (same shape the
// external wire tests use; duplicated here because this file is the internal
// test package).
type h3BedrockEvent struct {
	eventType string
	payload   string
}

// h3BedrockFrames encodes ConverseStream frames without the pool/SDK stubs —
// the handler decodes resp.Body directly, CRC-checked AWS framing included.
func h3BedrockFrames(t *testing.T, events []h3BedrockEvent) []byte {
	t.Helper()
	enc := eventstream.NewEncoder()
	var buf bytes.Buffer
	for _, ev := range events {
		hdrs := eventstream.Headers{
			{Name: ":message-type", Value: eventstream.StringValue("event")},
			{Name: ":event-type", Value: eventstream.StringValue(ev.eventType)},
			{Name: ":content-type", Value: eventstream.StringValue("application/json")},
		}
		require.NoError(t, enc.Encode(&buf, eventstream.Message{Headers: hdrs, Payload: []byte(ev.payload)}))
	}
	return buf.Bytes()
}

func TestH3_BedrockHandler_ReportsMissingMetadata(t *testing.T) {
	frames := h3BedrockFrames(t, []h3BedrockEvent{
		{eventType: "messageStart", payload: `{"role":"assistant"}`},
		{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"text":"He"}}`},
		{eventType: "messageStop", payload: `{"stopReason":"end_turn"}`},
		// no metadata frame: usage is lost and the stream is truncated
	})

	h := NewStreamHandler("bedrock", "anthropic.claude-3-5-sonnet")
	usage, buf, err := h3HandleStream(t, h, frames)

	require.Error(t, err, "EOF without the metadata event is a truncated stream")
	require.ErrorIs(t, err, ErrStreamIncomplete)
	assert.True(t, strings.HasSuffix(strings.TrimSpace(buf.String()), "data: [DONE]"),
		"client compat (pinned): the handler still terminates the OpenAI wire, got:\n%s", buf.String())
	assert.Contains(t, buf.String(), `"finish_reason":"stop"`,
		"the messageStop finish chunk stays on the wire")
	assert.NotEqual(t, UsageSourceProvider, usage.Source,
		"without metadata no provider usage may be claimed")
}

func TestH3_BedrockHandler_MetadataIsComplete(t *testing.T) {
	frames := h3BedrockFrames(t, []h3BedrockEvent{
		{eventType: "messageStart", payload: `{"role":"assistant"}`},
		{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"text":"He"}}`},
		{eventType: "messageStop", payload: `{"stopReason":"end_turn"}`},
		{eventType: "metadata", payload: `{"usage":{"inputTokens":10,"outputTokens":3,"totalTokens":13},"metrics":{"latencyMs":42}}`},
	})

	h := NewStreamHandler("bedrock", "anthropic.claude-3-5-sonnet")
	_, _, err := h3HandleStream(t, h, frames)
	require.NoError(t, err, "a stream that carried the metadata event is complete")
}

// Sentinel hygiene: the sentinel must never compare equal to arbitrary
// caller errors (guards against it being re-pointed at a sentinel-value
// pattern later).
func TestH3_ErrStreamIncompleteIdentity(t *testing.T) {
	require.NotErrorIs(t, errStreamSentinelProbe{}, ErrStreamIncomplete)
	wrapped := h3Wrap(ErrStreamIncomplete)
	require.ErrorIs(t, wrapped, ErrStreamIncomplete)
}

type errStreamSentinelProbe struct{}

func (errStreamSentinelProbe) Error() string { return "probe" }

func h3Wrap(err error) error { return &h3Wrapped{err} }

type h3Wrapped struct{ err error }

func (w *h3Wrapped) Error() string { return "wrapped: " + w.err.Error() }
func (w *h3Wrapped) Unwrap() error { return w.err }
