package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// --- RM-03: ensureStreamUsage -------------------------------------------------

func TestEnsureStreamUsage(t *testing.T) {
	enabled := streamUsageEnabled([]string{"openai", "openai-compat", "vllm"})
	require.NotNil(t, enabled)

	baseMsgs := `"messages":[{"role":"user","content":"hi"}]`

	t.Run("adds stream_options when absent", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4","stream":true,` + baseMsgs + `}`)
		out, clientRequested := ensureStreamUsage(body, "openai", enabled)
		assert.False(t, clientRequested)

		var got map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out, &got))
		var so map[string]any
		require.NoError(t, json.Unmarshal(got["stream_options"], &so))
		assert.Equal(t, true, so["include_usage"])
		// Sibling top-level fields survive.
		var model string
		require.NoError(t, json.Unmarshal(got["model"], &model))
		assert.Equal(t, "gpt-4", model)
	})

	t.Run("flips explicit false to true", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4","stream":true,` + baseMsgs + `,"stream_options":{"include_usage":false}}`)
		out, clientRequested := ensureStreamUsage(body, "openai", enabled)
		assert.False(t, clientRequested)

		var got map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out, &got))
		var so map[string]any
		require.NoError(t, json.Unmarshal(got["stream_options"], &so))
		assert.Equal(t, true, so["include_usage"])
	})

	t.Run("client already asked keeps body unchanged", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4","stream":true,` + baseMsgs + `,"stream_options":{"include_usage":true}}`)
		out, clientRequested := ensureStreamUsage(body, "openai", enabled)
		assert.True(t, clientRequested)
		assert.Equal(t, string(body), string(out), "body with include_usage:true must pass through byte-for-byte")
	})

	t.Run("preserves sibling stream_options keys", func(t *testing.T) {
		body := []byte(`{"model":"gpt-4","stream":true,` + baseMsgs + `,"stream_options":{"x":1}}`)
		out, clientRequested := ensureStreamUsage(body, "openai", enabled)
		assert.False(t, clientRequested)

		var got map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out, &got))
		var so map[string]any
		require.NoError(t, json.Unmarshal(got["stream_options"], &so))
		assert.Equal(t, true, so["include_usage"])
		assert.InDelta(t, 1.0, so["x"], 0.0001, "sibling stream_options keys must survive")
	})

	t.Run("disabled provider untouched", func(t *testing.T) {
		body := []byte(`{"model":"claude-3","stream":true,` + baseMsgs + `}`)
		out, clientRequested := ensureStreamUsage(body, "anthropic", enabled)
		assert.True(t, clientRequested)
		assert.Equal(t, string(body), string(out))
	})

	t.Run("broken json untouched", func(t *testing.T) {
		body := []byte(`{not json`)
		out, clientRequested := ensureStreamUsage(body, "openai", enabled)
		assert.True(t, clientRequested)
		assert.Equal(t, string(body), string(out))
	})

	t.Run("empty provider name counts as openai-compat", func(t *testing.T) {
		body := []byte(`{"model":"m","stream":true,` + baseMsgs + `}`)
		out, clientRequested := ensureStreamUsage(body, "", enabled)
		assert.False(t, clientRequested)

		var got map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out, &got))
		assert.Contains(t, string(got["stream_options"]), `"include_usage":true`)
	})
}

func TestStreamUsageEnabled(t *testing.T) {
	assert.Nil(t, streamUsageEnabled(nil))
	m := streamUsageEnabled([]string{"openai", "openai-compat"})
	assert.True(t, m["openai"])
	assert.True(t, m["openai-compat"])
	assert.False(t, m["anthropic"])
}

// --- RM-03: serveStream end-to-end --------------------------------------------

// usageSSEFixture is an upstream stream that honours include_usage: content
// chunk, then the trailing usage-only chunk (with cached tokens), then [DONE].
const usageSSEFixture = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n" +
	"data: {\"id\":\"2\",\"choices\":[],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":7," +
	"\"total_tokens\":49,\"prompt_tokens_details\":{\"cached_tokens\":5}}}\n\n" +
	"data: [DONE]\n\n"

// TestServeStream_InjectsIncludeUsage: a client that did NOT ask for usage
// still gets usage recorded — the gateway injects stream_options.include_usage
// upstream and hides the extra usage-only chunk from the client.
func TestServeStream_InjectsIncludeUsage(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, usageSSEFixture)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})
	metrics.UpstreamTokensTotal.Reset() // make -count>1 runs deterministic

	info := resolver.ModelInfo{ModelName: "usage-probe-model", Provider: "", Enabled: true}

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "usage-probe-model", "hi"), false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())

	// Upstream must have been asked for usage.
	var up map[string]any
	require.NoError(t, json.Unmarshal([]byte(gotBody), &up))
	so, ok := up["stream_options"].(map[string]any)
	require.True(t, ok, "upstream body must carry stream_options, got: %s", gotBody)
	assert.Equal(t, true, so["include_usage"], "gateway must inject include_usage upstream")

	out := rec.Body.String()
	// Client sees the content chunk and the terminator…
	assert.Contains(t, out, "\"content\":\"ok\"")
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"), "got: %q", out)
	// …but NOT the usage-only chunk it never asked for.
	assert.NotContains(t, out, "prompt_tokens", "usage-only chunk must be hidden from the client")

	// Usage must still be recorded (metrics stand in for the event; no
	// publisher is wired in stream tests — decision_test.go:194).
	assert.InDelta(t, 42.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "usage-probe-model", "prompt")), 0.0001)
	assert.InDelta(t, 7.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "usage-probe-model", "completion")), 0.0001)
	assert.InDelta(t, 5.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "usage-probe-model", "cache_read")), 0.0001)
}

// TestServeStream_ClientAsksUsage_ChunkPassedThrough: when the client itself
// set include_usage, the usage-only chunk must reach it verbatim.
func TestServeStream_ClientAsksUsage_ChunkPassedThrough(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, usageSSEFixture)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})

	info := resolver.ModelInfo{ModelName: "usage-ask-model", Provider: "", Enabled: true}

	body, err := json.Marshal(map[string]any{
		"model":          "usage-ask-model",
		"stream":         true,
		"messages":       []map[string]string{{"role": "user", "content": "hi"}},
		"stream_options": map[string]any{"include_usage": true},
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		body, false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())

	// Body forwarded with the client's flag intact (no double-injection).
	assert.Contains(t, gotBody, `"include_usage":true`)

	out := rec.Body.String()
	assert.Contains(t, out, "\"content\":\"ok\"")
	assert.Contains(t, out, "\"prompt_tokens\":42", "client asked for usage — chunk must be delivered")
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"), "got: %q", out)
}

// TestServeStream_RawBody_NoInjectionUsagePassedThrough: raw-body mode must
// not rewrite the body (no include_usage injection) and must not suppress
// anything upstream sends — usage recording still works via parsing.
func TestServeStream_RawBody_NoInjectionUsagePassedThrough(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, usageSSEFixture)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})
	metrics.UpstreamTokensTotal.Reset() // make -count>1 runs deterministic

	info := resolver.ModelInfo{ModelName: "usage-raw-model", Provider: "", Enabled: true}

	rawBody := []byte(`{"model":"usage-raw-model","stream":true,"messages":[{"role":"user","content":"hi"}]}`)

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		rawBody, true, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())

	// Raw contract: upstream got the exact bytes, no stream_options added.
	assert.JSONEq(t, string(rawBody), gotBody)
	assert.NotContains(t, gotBody, "include_usage")

	// Raw contract: no suppression — the usage chunk reaches the client.
	out := rec.Body.String()
	assert.Contains(t, out, "\"prompt_tokens\":42")
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"), "got: %q", out)

	// Usage still recorded.
	assert.InDelta(t, 42.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "usage-raw-model", "prompt")), 0.0001)
}

// TestServeStream_DisabledProvider_NoInjection: a provider outside the
// stream-usage set (mistral here) gets no injection and no suppression — the
// passthrough stream path for it is unchanged. (Anthropic itself is covered
// separately: it routes to the translating handler; usage via RM-04.)
func TestServeStream_DisabledProvider_NoInjection(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, usageSSEFixture)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai"})

	info := resolver.ModelInfo{ModelName: "usage-skip-model", Provider: "mistral", Enabled: true}

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "usage-skip-model", "hi"), false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())

	assert.NotContains(t, gotBody, "include_usage", "mistral is not in the stream-usage set — body must be untouched")
	assert.Contains(t, rec.Body.String(), "\"prompt_tokens\":42", "without injection there is nothing to suppress")
}

// toolUsageSSEFrames is the canonical OpenCode-shaped upstream stream for the
// packet's main scenario (tools + streaming + usage in ONE stream), as its
// five SSE frames: role+tool fragment (index 0, id+name), two argument
// fragments sharing index 0, finish_reason:"tool_calls", the usage-only chunk
// an injected stream_options.include_usage produces, then [DONE].
var toolUsageSSEFrames = []string{
	"data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_r\",\"type\":\"function\",\"function\":{\"name\":\"apply_patch\",\"arguments\":\"\"}}]}}]}\n\n",
	"data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"input\\\":\\\"*** Begin Patch\\\"}\"}}]}}]}\n\n",
	"data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"input\\\":\\\"@@ -1 +1@@\\\"}\"}}]}}]}\n\n",
	"data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"finish_reason\":\"tool_calls\"}]}\n\n",
	"data: {\"id\":\"1\",\"choices\":[],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":7," +
		"\"total_tokens\":49,\"prompt_tokens_details\":{\"cached_tokens\":5}}}\n\n",
	"data: [DONE]\n\n",
}

// toolUsageSSEFixture is the full canonical upstream stream.
var toolUsageSSEFixture = strings.Join(toolUsageSSEFrames, "")

// opencodeToolBody builds the OpenCode-shaped request: content-part array,
// tools declared, stream on. streamOptions is spliced in verbatim; nil omits
// the key entirely (gateway-injection variant).
func opencodeToolBody(t *testing.T, model string, streamOptions map[string]any) []byte {
	t.Helper()
	body := map[string]any{
		"model":  model,
		"stream": true,
		"messages": []map[string]any{{
			"role": "user",
			"content": []map[string]string{
				{"type": "text", "text": "patch"},
			},
		}},
		"tools": []map[string]any{{
			"type": "function",
			"function": map[string]any{
				"name":        "apply_patch",
				"description": "Apply a patch",
				"parameters":  map[string]any{"type": "object"},
			},
		}},
	}
	if streamOptions != nil {
		body["stream_options"] = streamOptions
	}
	out, err := json.Marshal(body)
	require.NoError(t, err)
	return out
}

// TestServeStream_ToolCalls_UsageUnderSuppression closes the usage-under-tools
// fixture gap (contract §4.2): tool fragments and the usage-only chunk in one
// stream. Suppression must hide ONLY the usage-only chunk from the client —
// tool fragments and finish_reason:"tool_calls" pass through byte-identical —
// while provider usage is still parsed and recorded.
func TestServeStream_ToolCalls_UsageUnderSuppression(t *testing.T) {
	t.Run("injected_chunk_suppressed", func(t *testing.T) {
		var gotBody string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			w.Header().Set("Content-Type", "text/event-stream")
			printSSEFixture(t, w, toolUsageSSEFixture)
		}))
		defer srv.Close()

		gw := streamTestGateway(srv.URL)
		gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})
		metrics.UpstreamTokensTotal.Reset() // make -count>1 runs deterministic

		info := resolver.ModelInfo{ModelName: "tools-inject-model", Provider: "", Enabled: true}

		rec := httptest.NewRecorder()
		gw.serveStream(rec, context.Background(), info,
			opencodeToolBody(t, "tools-inject-model", nil), false, "sess", "org", "", "task", "req",
			testLogger(), routingDecision{}, "", 0, "", "", "", false)

		require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())

		// Upstream was asked for usage; tools survived the guarded rewrite.
		var up map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(gotBody), &up))
		assert.Contains(t, string(up["stream_options"]), `"include_usage":true`,
			"gateway must inject include_usage upstream")
		assert.Contains(t, string(up["tools"]), `"name":"apply_patch"`,
			"tools must be forwarded through the body rewrite")

		// Client bytes are the upstream stream minus ONLY the usage-only
		// chunk and its frame separator — tool fragments and
		// finish_reason:"tool_calls" are byte-identical (contract §6).
		want := toolUsageSSEFrames[0] + toolUsageSSEFrames[1] + toolUsageSSEFrames[2] +
			toolUsageSSEFrames[3] + toolUsageSSEFrames[5]
		assert.Equal(t, want, rec.Body.String(), "client bytes must be the upstream stream minus the usage-only chunk")

		// The visible stream still validates as a well-formed chat stream.
		require.NoError(t, apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")))

		// Provider usage parsed from the suppressed chunk is still recorded.
		assert.InDelta(t, 42.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "tools-inject-model", "prompt")), 0.0001)
		assert.InDelta(t, 7.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "tools-inject-model", "completion")), 0.0001)
		assert.InDelta(t, 5.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "tools-inject-model", "cache_read")), 0.0001)
	})

	t.Run("client_asked_chunk_delivered", func(t *testing.T) {
		var gotBody string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			w.Header().Set("Content-Type", "text/event-stream")
			printSSEFixture(t, w, toolUsageSSEFixture)
		}))
		defer srv.Close()

		gw := streamTestGateway(srv.URL)
		gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})
		metrics.UpstreamTokensTotal.Reset()

		info := resolver.ModelInfo{ModelName: "tools-ask-model", Provider: "", Enabled: true}

		rec := httptest.NewRecorder()
		gw.serveStream(rec, context.Background(), info,
			opencodeToolBody(t, "tools-ask-model", map[string]any{"include_usage": true}),
			false, "sess", "org", "", "task", "req",
			testLogger(), routingDecision{}, "", 0, "", "", "", false)

		require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())

		// The client's flag reaches upstream verbatim (no double injection).
		assert.Equal(t, 1, strings.Count(gotBody, `"include_usage":true`),
			"client flag must be forwarded exactly once")

		// Client asked: the full stream, including the usage-only chunk,
		// reaches the client byte-identical.
		assert.Equal(t, toolUsageSSEFixture, rec.Body.String())
		require.NoError(t, apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n")))

		assert.InDelta(t, 42.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "tools-ask-model", "prompt")), 0.0001)
		assert.InDelta(t, 7.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "tools-ask-model", "completion")), 0.0001)
	})
}

// ---: error & boundary fixtures (contract §9, §8.2, §8.5) -------------

// ceil4 mirrors provider estimatedStreamUsage's ceil(bytes/4) prompt/completion
// estimate so gateway fixtures can pin the recorded token counts exactly.
func ceil4(n int) float64 {
	if n <= 0 {
		return 0
	}
	return float64((n + 3) / 4)
}

// TestServeStream_MalformedSSE_PassThroughNoErrorInjection (§9 malformed SSE):
// a JSON-invalid data line reaches the client byte-identical, never aborts the
// stream and never injects an error frame; usage parsing silently skips it and
// the stream still ends with the [DONE] terminator and estimated usage.
func TestServeStream_MalformedSSE_PassThroughNoErrorInjection(t *testing.T) {
	sse := "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n" +
		"data: {not-json\n\n" +
		"data: [DONE]\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, sse)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})
	metrics.UpstreamTokensTotal.Reset() // make -count>1 runs deterministic

	info := resolver.ModelInfo{ModelName: "malformed-model", Provider: "", Enabled: true}
	body := streamBody(t, "malformed-model", "hi")

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		body, false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())
	out := rec.Body.String()
	assert.Equal(t, sse, out, "malformed data line must pass through byte-identical")
	assert.NotContains(t, out, "\"error\"", "fail-open passthrough must not inject an error frame")
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"))

	// Fail-open accounting: the malformed line contributes no usage, the
	// consumed stream is still billed via the byte estimate ("hi" → 2 bytes).
	assert.InDelta(t, ceil4(len(body)), testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "malformed-model", "prompt")), 0.0001)
	assert.InDelta(t, ceil4(2), testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "malformed-model", "completion")), 0.0001)
}

// TestServeStream_TruncatedStream_EOFErrorFrame (§9 truncated SSE, §4.3;
// H3 supersession of the prior "EOF is not a drain failure" pin): an upstream
// that ends at EOF without finish_reason or [DONE] is an incomplete run —
// the client keeps the delivered frames and receives the drain-failure
// terminal (error frame + [DONE]), and the consumed prefix is still billed
// as estimated usage (billing contract unchanged).
func TestServeStream_TruncatedStream_EOFErrorFrame(t *testing.T) {
	frames := "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n" +
		"data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, frames)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})
	metrics.UpstreamTokensTotal.Reset()

	info := resolver.ModelInfo{ModelName: "truncated-model", Provider: "", Enabled: true}
	body := streamBody(t, "truncated-model", "hi")

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		body, false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())
	out := rec.Body.String()
	assert.True(t, strings.HasPrefix(out, frames), "the delivered prefix stays byte-faithful, got %q", out)
	assert.Contains(t, out, "\"error\"", "EOF without [DONE] is an incomplete run — the client is told")
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"), "the failure terminal closes the stream")

	// Estimated accounting for the truncated stream ("partial" → 7 bytes),
	// unchanged by H3: the consumed prefix still bills.
	assert.InDelta(t, ceil4(len(body)), testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "truncated-model", "prompt")), 0.0001)
	assert.InDelta(t, ceil4(7), testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "truncated-model", "completion")), 0.0001)
}

// TestServeStream_MidStreamDisconnect_PartialFramesThenErrorFrame (§8.2):
// when the upstream dies mid-stream AFTER the 200 committed, the client keeps
// the partial frames, gets a terminal SSE error frame + [DONE], the request
// is NOT retried (no retry after 200), and the consumed prefix is billed as
// estimated usage instead of silently dropped to zero.
func TestServeStream_MidStreamDisconnect_PartialFramesThenErrorFrame(t *testing.T) {
	frames := "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n" +
		"data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n"
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(frames))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})
	gw.retryPolicy = retry.Policy{MaxAttempts: 3} // retries exist, but never after 200
	metrics.UpstreamTokensTotal.Reset()

	info := resolver.ModelInfo{ModelName: "disconnect-model", Provider: "", Enabled: true}
	body := streamBody(t, "disconnect-model", "hi")

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		body, false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits), "stream committed at 200 — no retry may dial upstream again")

	out := rec.Body.String()
	assert.True(t, strings.HasPrefix(out, frames), "partial frames already flushed must stay delivered, got: %q", out)
	assert.Contains(t, out, "data: {\"error\":", "terminal SSE error frame required")
	assert.Contains(t, out, "stream interrupted")
	assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"), "error path must still terminate the stream, got: %q", out)

	// The consumed prefix is billed from the byte estimate, not zero.
	assert.InDelta(t, ceil4(len(body)), testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "disconnect-model", "prompt")), 0.0001)
	assert.InDelta(t, ceil4(7), testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "disconnect-model", "completion")), 0.0001)
}

// TestServeStream_RoleOnlyStream_ClientPassthroughEstimated (§9 empty content,
// §8.5): a role-only / null-delta stream reaches the client byte-for-byte
// unchanged (the cache guard is pinned in stream_cache_test.go) and usage is
// estimated with zero completion tokens.
func TestServeStream_RoleOnlyStream_ClientPassthroughEstimated(t *testing.T) {
	sse := "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n" +
		"data: [DONE]\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, sse)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})
	metrics.UpstreamTokensTotal.Reset()

	info := resolver.ModelInfo{ModelName: "roleonly-model", Provider: "", Enabled: true}
	body := streamBody(t, "roleonly-model", "hi")

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		body, false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())
	assert.Equal(t, sse, rec.Body.String(), "empty-content stream must pass through byte-identical")

	assert.InDelta(t, ceil4(len(body)), testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "roleonly-model", "prompt")), 0.0001)
	assert.InDelta(t, 0.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "roleonly-model", "completion")), 0.0001,
		"role-only deltas contribute no completion bytes")
}

// runToolGateStream streams the canonical toolUsageSSEFixture through
// serveStream for org-1 with the given tool policies and returns the client
// bytes. Everything except the policy list is held constant so the two arms
// below are a controlled negative proof.
func runToolGateStream(t *testing.T, policies []toolpolicy.Policy) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, toolUsageSSEFixture)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: policies}, time.Minute)
	metrics.UpstreamTokensTotal.Reset() // make -count>1 runs deterministic

	info := resolver.ModelInfo{ModelName: "gate-model", Provider: "", Enabled: true}

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		opencodeToolBody(t, "gate-model", nil), false, "sess", "org-1", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())
	return rec.Body.String()
}

// TestServeStream_ToolGateDenial_ClientObservableMatrix (§9 finish reason +
// tool delta): identical upstream tool stream, identical request body — the
// only variable is the org's deny policy. This pair is the negative proof the
// card asks for: the observable client outcome distinguishes gated from
// ungated behavior (broken = stranded finish_reason/denied args, fixed =
// suppressed delta + normalized stop), and the ungated arm pins that the
// gate never touches orgs without deny policies.
func TestServeStream_ToolGateDenial_ClientObservableMatrix(t *testing.T) {
	t.Run("no_deny_policy_byte_identical_passthrough", func(t *testing.T) {
		out := runToolGateStream(t, nil)

		// Without a deny policy the client bytes are the upstream stream
		// minus only the injected usage-only chunk — tool fragments and
		// finish_reason:"tool_calls" untouched.
		want := toolUsageSSEFrames[0] + toolUsageSSEFrames[1] + toolUsageSSEFrames[2] +
			toolUsageSSEFrames[3] + toolUsageSSEFrames[5]
		assert.Equal(t, want, out)
		assert.Contains(t, out, `"finish_reason":"tool_calls"`)
		assert.Contains(t, out, `"name":"apply_patch"`)

		// Usage is still parsed from the suppressed chunk and recorded.
		assert.InDelta(t, 42.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "gate-model", "prompt")), 0.0001)
		assert.InDelta(t, 7.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "gate-model", "completion")), 0.0001)
	})

	t.Run("deny_all_suppresses_delta_and_rewrites_finish_reason", func(t *testing.T) {
		out := runToolGateStream(t, []toolpolicy.Policy{denyTool("apply_patch")})

		// Every fragment of the denied call index is suppressed — the tool
		// name and its argument bytes never reach the client.
		assert.NotContains(t, out, "apply_patch")
		assert.NotContains(t, out, "Begin Patch")
		assert.NotContains(t, out, "tool_calls", "stranded finish_reason must be rewritten")

		// The terminal chunk normalizes finish_reason:"tool_calls" → "stop"
		// and the stream still terminates correctly.
		assert.Contains(t, out, `"finish_reason":"stop"`)
		assert.True(t, strings.HasSuffix(out, "data: [DONE]\n\n"), "got: %q", out)

		// Gating filters bytes, not accounting: provider usage is still
		// parsed upstream and recorded for the gated stream.
		assert.InDelta(t, 42.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "gate-model", "prompt")), 0.0001)
		assert.InDelta(t, 7.0, testutil.ToFloat64(metrics.UpstreamTokensTotal.WithLabelValues("", "gate-model", "completion")), 0.0001)
	})
}

// TestServeStream_ToolDeltaRegress_LivePassthrough_ValidatorFlags (§9 tool
// delta regress, contract decision D2): a decreasing tool_calls index is NOT
// rejected or rewritten on the live proxy path — the bytes pass through
// unchanged — while ValidateChatStream, the fixture-level checker, flags
// exactly the same bytes. Pins the D2 default: enforcement stays fixture-only.
func TestServeStream_ToolDeltaRegress_LivePassthrough_ValidatorFlags(t *testing.T) {
	regress := "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_a\",\"type\":\"function\",\"function\":{\"name\":\"read\",\"arguments\":\"\"}}]}}]}\n\n" +
		"data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n" +
		"data: [DONE]\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, regress)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})

	info := resolver.ModelInfo{ModelName: "regress-model", Provider: "", Enabled: true}

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "regress-model", "hi"), false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, "response: %s", rec.Body.String())

	// Live contract (fail-open passthrough): byte-identical, no error frame.
	assert.Equal(t, regress, rec.Body.String(), "live path must not rewrite or reject the regress stream")
	assert.NotContains(t, rec.Body.String(), "\"error\"")

	// The same bytes fail the fixture validator — broken vs fixed is
	// distinguishable at the fixture level, exactly the D2 boundary.
	err := apiformat.ValidateChatStream(strings.Split(rec.Body.String(), "\n"))
	assert.Error(t, err, "ValidateChatStream must flag the decreasing tool_call index")
}
