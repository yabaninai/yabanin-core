package cli

// Gateway-seam pins for the saw-terminal contract: a stream that ends
// without its provider terminal event (OpenAI [DONE], anthropic
// message_stop, bedrock metadata) is indistinguishable from a complete one
// downstream of the handler: the anthropic and bedrock handlers synthesize
// `data: [DONE]` + nil on EOF-without-terminal and the OpenAI passthrough
// never tracks [DONE] at all. serveStream then caches the truncated prefix
// (the cache gate only checks drainErr == nil) and the SSE replay re-serves
// the truncated document forever (TTL).
//
// These pins anchor the GATEWAY-SEAM half of the fix (erratum obligation):
// (a) a truncated provider stream must never be cached — the control proves
// complete streams still are; (b) the replay seam must refuse documents
// whose choices carry no finish_reason — exactly what a truncated
// accumulator produces (the finish chunk is the last frame a truncation
// loses). All assertions here use pre-fix APIs only, so this file compiles
// and runs RED on the pre-addendum baseline.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
)

// h3AnthropicUpstream serves an anthropic SSE body; truncation is expressed
// by simply not sending the terminal events.
func h3AnthropicUpstream(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// h3ServeStream drives the production serveStream path against upstreamURL
// with the stream-cache recording + rt05 cache double wired (mirrors the
// gateway_stream_test.go invocation shape).
func h3ServeStream(t *testing.T, gw *gateway, info resolver.ModelInfo) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, info.ModelName, "hi"), false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)
	return rec
}

func h3Gateway(t *testing.T, upstreamURL string) (*gateway, *rt05Cache) {
	t.Helper()
	gw := streamTestGateway(upstreamURL)
	c := newRT05Cache()
	gw.cache = c
	gw.cfg.CacheStreamEnabled = true
	return gw, c
}

// --- (a) truncated stream must never be cached --------------------------------

func TestH3_TruncatedAnthropicStreamIsNotCached(t *testing.T) {
	// message_start + one content delta, then EOF — no message_stop.
	const truncated = "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}\n\n"

	srv := h3AnthropicUpstream(t, truncated)
	gw, c := h3Gateway(t, srv.URL)
	anthropicFixtureValue := "test-anthropic-key" // neutral name: gosec G101
	info := resolver.ModelInfo{ModelName: "claude-3", Provider: "anthropic", UpstreamAPIKey: anthropicFixtureValue, Enabled: true}

	rec := h3ServeStream(t, gw, info)

	// Client compat (pinned decision, pre-existing behavior): the handler
	// still terminates the client stream with [DONE] and — because the
	// client already saw the terminator — the gateway must NOT append a
	// second terminal or an error frame (pkg/apiformat stream validity).
	out := rec.Body.String()
	assert.Contains(t, out, `"content":"Hel"`)
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"), "body: %q", out)
	assert.NotContains(t, out, "stream interrupted")

	// The fix: the truncated prefix must never land in the cache.
	require.Never(t, func() bool { return c.writeCount() > 0 },
		200*time.Millisecond, 10*time.Millisecond,
		"a stream that ended without message_stop must not be cached")
}

func TestH3_TruncatedOpenAIStreamIsNotCached(t *testing.T) {
	const truncated = "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n"

	srv := h3AnthropicUpstream(t, truncated) // same SSE fixture server shape
	gw, c := h3Gateway(t, srv.URL)
	info := resolver.ModelInfo{ModelName: "gpt-4", Enabled: true}

	rec := h3ServeStream(t, gw, info)

	out := rec.Body.String()
	assert.Contains(t, out, `"content":"hi"`)
	// The passthrough never synthesizes [DONE] itself; the gateway's
	// drain-failure path owes the client the error frame + terminator.
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"), "body: %q", out)

	require.Never(t, func() bool { return c.writeCount() > 0 },
		200*time.Millisecond, 10*time.Millisecond,
		"a passthrough stream that ended without [DONE] must not be cached")
}

// --- control: complete streams are still cached --------------------------------

func TestH3_CompleteStreamsStillCached(t *testing.T) {
	t.Run("anthropic", func(t *testing.T) {
		const complete = "event: message_start\n" +
			"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n" +
			"event: content_block_delta\n" +
			"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n" +
			"event: message_delta\n" +
			"data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":5,\"output_tokens\":3}}\n\n" +
			"event: message_stop\n" +
			"data: {\"type\":\"message_stop\"}\n\n"
		srv := h3AnthropicUpstream(t, complete)
		gw, c := h3Gateway(t, srv.URL)
		anthropicFixtureValue := "test-anthropic-key" // neutral name: gosec G101
		info := resolver.ModelInfo{ModelName: "claude-3", Provider: "anthropic", UpstreamAPIKey: anthropicFixtureValue, Enabled: true}

		rec := h3ServeStream(t, gw, info)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		require.Eventually(t, func() bool { return c.writeCount() == 1 },
			2*time.Second, 10*time.Millisecond,
			"a stream that carried its terminal event must still be cached")
	})

	t.Run("openai", func(t *testing.T) {
		const complete = "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n" +
			"data: [DONE]\n\n"
		srv := h3AnthropicUpstream(t, complete)
		gw, c := h3Gateway(t, srv.URL)
		info := resolver.ModelInfo{ModelName: "gpt-4", Enabled: true}

		rec := h3ServeStream(t, gw, info)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		require.Eventually(t, func() bool { return c.writeCount() == 1 },
			2*time.Second, 10*time.Millisecond)
	})
}

// --- (b) the replay seam refuses finish_reason-less documents ------------------
//
// A truncated accumulator never emits the finish chunk, so the recorded
// document's choices carry finish_reason null/absent. Both replay seams
// (SSE replay of a cached hit for streaming clients, and the non-stream
// read probe) must treat such a document as a miss.

func TestH3_SSEReplayRefusesFinishReasonlessDocument(t *testing.T) {
	truncated := []byte(`{"id":"x","object":"chat.completion","model":"m",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"partial"},"finish_reason":null}]}`)

	frames, err := sseReplayFrames(truncated)
	require.Error(t, err, "a finish_reason-less document is the truncated-stream shape and must not replay")
	assert.Nil(t, frames)

	// Control: the same document with a finish replay fine.
	complete := []byte(`{"id":"x","object":"chat.completion","model":"m",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	frames, err = sseReplayFrames(complete)
	require.NoError(t, err)
	assert.Contains(t, string(frames), `"finish_reason":"stop"`)
	assert.Contains(t, string(frames), "data: [DONE]")
}

func TestH3_CachedCompletionReadRefusesFinishReasonlessDocument(t *testing.T) {
	truncated := []byte(`{"id":"x","object":"chat.completion","model":"m",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"partial"},"finish_reason":null}]}`)

	_, err := cachedCompletionUsable(truncated)
	require.Error(t, err, "the FIX-10 read probe must refuse the truncated-stream shape")

	// Control: a complete document passes.
	complete := []byte(`{"id":"x","object":"chat.completion","model":"m",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	_, err = cachedCompletionUsable(complete)
	require.NoError(t, err)
}

// TestH3_ShouldCacheRefusesFinishReasonlessDocument pins the write side of
// the same contract: refusing the read without refusing the write would
// poison the entry (always-miss-always-rewrite) instead of degrading it.
func TestH3_ShouldCacheRefusesFinishReasonlessDocument(t *testing.T) {
	truncated := []byte(`{"id":"x","object":"chat.completion","model":"m",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"partial"},"finish_reason":null}]}`)
	assert.False(t, shouldCache(truncated),
		"a finish_reason-less document must not be written under the shared FIX-10 contract")

	complete := []byte(`{"id":"x","object":"chat.completion","model":"m",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	assert.True(t, shouldCache(complete))
}
