package cli

// N03-P06-T02 — provider prompt-cache transparency on every in-boundary
// surface. The JSON header already existed on the OpenAI-compat
// /v1/chat/completions non-stream path (see r103_prompt_cache_test.go);
// these tests pin the additions:
//
//   - native /v1/messages JSON            → X-Yabanin-Prompt-Cache header
//   - native /v1/responses JSON           → header
//   - legacy /v1/completions JSON         → header (hit/miss from real usage)
//   - openai-compat SSE (serveStream)     → HTTP trailer (http.TrailerPrefix)
//   - native /v1/messages SSE             → HTTP trailer
//   - native /v1/responses SSE            → HTTP trailer
//   - legacy /v1/completions SSE          → HTTP trailer
//   - no provider usage (estimated/none)  → header/trailer absent, request OK
//
// httptest.ResponseRecorder does not emulate the HTTP/1.1 network layer, so
// a trailer set via http.TrailerPrefix is asserted directly on the header map
// (equivalent to Result().Trailer after net/http strips the prefix).

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
)

const promptCacheTrailerKey = http.TrailerPrefix + PromptCacheHeader

// --- native /v1/messages: JSON header + SSE trailer ---------------------------

func TestPromptCache_MessagesNativeJSON_Header(t *testing.T) {
	// Anthropic native JSON reply WITH cache fields → "hit".
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-upstream",` +
			`"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn",` +
			`"usage":{"input_tokens":10,"output_tokens":2,"cache_read_input_tokens":4,"cache_creation_input_tokens":2}}`))
	}))
	t.Cleanup(up.Close)

	gw := nativeMessagesGateway(t, up.URL)
	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader),
		"native messages JSON must report provider prompt-cache hit like the OpenAI-compat JSON path")
}

func TestPromptCache_MessagesNativeJSON_MissAndAbsent(t *testing.T) {
	// Without cache fields the same real-usage reply is a "miss".
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-upstream",` +
			`"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn",` +
			`"usage":{"input_tokens":10,"output_tokens":2}}`))
	}))
	t.Cleanup(up.Close)
	gw := nativeMessagesGateway(t, up.URL)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "miss", rec.Header().Get(PromptCacheHeader),
		"provider usage without cache reads must report miss on the native JSON path too")

	// No provider usage at all (upstream error → error envelope): no header.
	upErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"api_error","message":"boom"}}`))
	}))
	t.Cleanup(upErr.Close)
	gwErr := nativeMessagesGateway(t, upErr.URL)

	recErr := postMessages(t, gwErr, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`)
	require.NotEqual(t, http.StatusOK, recErr.Code)
	assert.Empty(t, recErr.Header().Get(PromptCacheHeader),
		"outcome must never be fabricated when no provider usage was parsed")
}

func TestPromptCache_MessagesNativeSSE_Trailer(t *testing.T) {
	// Anthropic native SSE: message_delta carries the cache usage.
	const sse = "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":9}}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2,\"cache_read_input_tokens\":4,\"cache_creation_input_tokens\":1}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, sse)
	}))
	t.Cleanup(up.Close)

	gw := nativeMessagesGateway(t, up.URL)
	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	assert.Equal(t, "hit", rec.Header().Get(promptCacheTrailerKey),
		"native messages SSE must report the provider prompt-cache outcome as an HTTP trailer")
	// Trailer value equals the real provider usage carried in the events.
	assert.Contains(t, rec.Body.String(), `"cache_read_input_tokens":4`)
	assert.NotContains(t, rec.Header().Get("Trailer"), PromptCacheHeader,
		"no pre-declared Trailer needed — prefix form only")
}

func TestPromptCache_MessagesNativeSSE_MissAndAbsent(t *testing.T) {
	// Same stream without cache fields → trailer "miss".
	const sseMiss = "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":9}}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, sseMiss)
	}))
	t.Cleanup(up.Close)

	gw := nativeMessagesGateway(t, up.URL)
	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "miss", rec.Header().Get(promptCacheTrailerKey),
		"real provider usage without cache reads must report miss via trailer")
}

// --- native /v1/responses: JSON header + SSE trailer ---------------------------

func responsesNativeGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	gw := responsesTestGateway(t, upstreamURL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	return gw
}

func TestPromptCache_ResponsesNativeJSON_Header(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","model":"gpt-4o","output":[],` +
			`"usage":{"input_tokens":9,"output_tokens":2,"input_tokens_details":{"cached_tokens":3}}}`))
	}))
	t.Cleanup(up.Close)

	gw := responsesNativeGateway(t, up.URL)
	rec := postResponses(t, gw, `{"model":"gpt-5-codex","input":"hi"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "hit", rec.Header().Get(PromptCacheHeader),
		"native responses JSON must report provider prompt-cache hit")
}

func TestPromptCache_ResponsesNativeSSE_Trailer(t *testing.T) {
	// Responses-native SSE terminated by response.completed (usage inside).
	const sse = "event: response.output_text.delta\n" +
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n" +
		"event: response.completed\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"model\":\"gpt-4o\"," +
		"\"usage\":{\"input_tokens\":9,\"output_tokens\":2,\"input_tokens_details\":{\"cached_tokens\":3}}}}\n\n"

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, sse)
	}))
	t.Cleanup(up.Close)

	gw := responsesNativeGateway(t, up.URL)
	rec := postResponses(t, gw, `{"model":"gpt-5-codex","input":"hi","stream":true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "hit", rec.Header().Get(promptCacheTrailerKey),
		"native responses SSE must report the provider prompt-cache outcome as an HTTP trailer")
}

// TestPromptCache_ResponsesNativeSSE_MissAndAbsent pins the other two
// outcomes of the native responses SSE trailer (N03-P06 review F2): real
// provider usage without cached tokens is a "miss", and a stream whose
// terminal event carries no usage at all reports nothing.
func TestPromptCache_ResponsesNativeSSE_MissAndAbsent(t *testing.T) {
	cases := []struct {
		name string
		sse  string
		want string
	}{
		{
			name: "miss",
			sse: "event: response.output_text.delta\n" +
				"data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n" +
				"event: response.completed\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"model\":\"gpt-4o\"," +
				"\"usage\":{\"input_tokens\":9,\"output_tokens\":2}}}\n\n",
			want: "miss",
		},
		{
			name: "absent without usage",
			sse: "event: response.output_text.delta\n" +
				"data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n" +
				"event: response.completed\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"model\":\"gpt-4o\",\"status\":\"completed\"}}\n\n",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				printSSEFixture(t, w, tc.sse)
			}))
			t.Cleanup(up.Close)

			gw := responsesNativeGateway(t, up.URL)
			rec := postResponses(t, gw, `{"model":"gpt-5-codex","input":"hi","stream":true}`)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, tc.want, rec.Header().Get(promptCacheTrailerKey),
				"native responses SSE trailer must derive from the provider usage block")

			// The relay stays verbatim; the trailer adds no SSE byte.
			body := rec.Body.String()
			assert.Contains(t, body, "response.completed")
			assert.NotContains(t, body, "response.failed")
		})
	}
}

// TestPromptCache_ResponsesNativeSSE_DrainFailure_Trailer pins the
// drain-failure branch of the same trailer (N03-P06 review F2): the partial
// usage parsed before the break is still the real upstream usage, so the
// failure stream carries the outcome too. Unlike the recorder-based tests
// above this rides a real HTTP/1.1 roundtrip — the TrailerPrefix value must
// materialize as an actual trailer after the chunked body (exactly what
// trailer-tolerant clients read).
func TestPromptCache_ResponsesNativeSSE_DrainFailure_Trailer(t *testing.T) {
	upstream := breakServer(t, "event: response.created\n"+
		"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"usage\":{\"input_tokens\":7,\"output_tokens\":0,\"input_tokens_details\":{\"cached_tokens\":4}}}}\n\n"+
		"event: response.output_item.added\n"+
		"data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_1\"}}\n\n")
	defer upstream.Close()

	gw := responsesNativeGateway(t, upstream.URL)
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	t.Cleanup(gwServer.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gwServer.URL+"/v1/responses",
		strings.NewReader(`{"model":"m","input":"hi","stream":true}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "the gateway→client leg ends cleanly even on an upstream break")

	// The partial usage from response.created (cached_tokens=4) rides the
	// trailer of the failure stream.
	assert.Equal(t, "hit", resp.Trailer.Get(PromptCacheHeader),
		"the drain-failure branch must report the partial provider usage as a real HTTP trailer")
	// Failure stream shape is unchanged: the protocol-shaped failure frame,
	// never a completed event.
	assert.Contains(t, string(raw), "response.failed")
	assert.NotContains(t, string(raw), "response.completed")
}

// --- legacy /v1/completions: JSON header + SSE trailer --------------------------

func completionsGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	return responsesTestGateway(t, upstreamURL)
}

// postCompletions is shared with completions_endpoint_test.go.

func TestPromptCache_CompletionsJSON_HeaderFromRealUsage(t *testing.T) {
	// Since the w17-06 seam fix completionsUsage parses
	// prompt_tokens_details.cached_tokens too (see
	// TestCompletions_JSON_CachedTokensHitHeader); this test pins the plain
	// usage block reporting a miss from real provider usage.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl_1","object":"text_completion","model":"gpt-4o","choices":[{"text":"hi","index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}`))
	}))
	t.Cleanup(up.Close)

	gw := completionsGateway(t, up.URL)
	rec := postCompletions(t, gw, `{"model":"gpt-4o","prompt":"hi"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "miss", rec.Header().Get(PromptCacheHeader),
		"legacy completions JSON must report the outcome from real provider usage")
}

func TestPromptCache_CompletionsJSON_AbsentOnEstimated(t *testing.T) {
	// Upstream error → error envelope, no provider usage → no header.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"boom"}}`))
	}))
	t.Cleanup(up.Close)

	gw := completionsGateway(t, up.URL)
	rec := postCompletions(t, gw, `{"model":"gpt-4o","prompt":"hi"}`)
	require.NotEqual(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get(PromptCacheHeader),
		"outcome must never be fabricated without provider usage")
}

// TestPromptCache_CompletionsSSE_Trailer pins the completions_stream trailer
// (N03-P06-T02 review F1: the header comment advertised this test, the
// implementation at completions_endpoint.go:setPromptCacheTrailer was
// untested). Hit and miss come from the trailing usage-only chunk (parsed
// even when suppressed from the client bytes); absent is the stream with no
// usage chunk at all (estimated usage → no outcome, never fabricated).
func TestPromptCache_CompletionsSSE_Trailer(t *testing.T) {
	const contentChunk = "data: {\"id\":\"cmpl_1\",\"choices\":[{\"text\":\"hi\",\"index\":0}]}\n\n"
	const done = "data: [DONE]\n\n"
	cases := []struct {
		name string
		sse  string
		want string
	}{
		{
			name: "hit",
			sse: contentChunk +
				"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2,\"total_tokens\":11,\"prompt_tokens_details\":{\"cached_tokens\":5}}}\n\n" +
				done,
			want: "hit",
		},
		{
			name: "miss",
			sse: contentChunk +
				"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2,\"total_tokens\":11}}\n\n" +
				done,
			want: "miss",
		},
		{
			name: "absent without provider usage",
			sse:  contentChunk + done,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				printSSEFixture(t, w, tc.sse)
			}))
			t.Cleanup(up.Close)

			gw := completionsGateway(t, up.URL)
			rec := postCompletions(t, gw, `{"model":"m","prompt":"hi","stream":true}`)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, tc.want, rec.Header().Get(promptCacheTrailerKey),
				"legacy completions SSE must report the provider prompt-cache outcome as an HTTP trailer")

			// The trailer is additive transparency: the relayed stream stays
			// the OpenAI passthrough — content delivered, usage-only chunk
			// suppressed (the gateway injected include_usage), single [DONE].
			body := rec.Body.String()
			assert.Contains(t, body, `"text":"hi"`)
			assert.True(t, strings.HasSuffix(body, done), "got: %q", body)
			assert.Equal(t, 1, strings.Count(body, "[DONE]"), "got: %q", body)
			if tc.want != "" {
				assert.NotContains(t, body, `"prompt_tokens"`,
					"the gateway-injected usage chunk must stay suppressed from the client bytes")
			}
		})
	}
}

// --- openai-compat SSE (serveStream): trailer in finishSuccess -------------------

func TestPromptCache_OpenAICompatSSE_Trailer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, usageSSEFixture) // content chunk + trailing usage (cached_tokens:5) + [DONE]
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamUsageProviders = streamUsageEnabled([]string{"openai", "openai-compat"})
	info := resolver.ModelInfo{ModelName: "prompt-cache-probe", Provider: "", Enabled: true}

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "prompt-cache-probe", "hi"), false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "hit", rec.Header().Get(promptCacheTrailerKey),
		"serveStream must deliver the provider prompt-cache outcome as an HTTP trailer")
	// The stream body itself is unchanged by trailer reporting.
	assert.Contains(t, rec.Body.String(), "\"content\":\"ok\"")
	assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"), "got: %q", rec.Body.String())
}

func TestPromptCache_OpenAICompatSSE_AbsentWithoutUsage(t *testing.T) {
	const sse = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: [DONE]\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, sse)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL) // no streamUsageProviders → usage never parsed
	info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}

	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "gpt-4", "hi"), false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Empty(t, rec.Header().Get(promptCacheTrailerKey),
		"no provider usage parsed → no outcome, never fabricated")
	assert.True(t, strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n"), "body must stay byte-identical")
}

// --- outcome mapping is provider-usage-gated (unit, exhaustiveness) --------------

func TestPromptCacheOutcome_TransparencyGates(t *testing.T) {
	assert.Empty(t, promptCacheOutcome(provider.Usage{}), "no usage → no outcome")
	assert.Empty(t, promptCacheOutcome(provider.Usage{PromptTokens: 9, Source: provider.UsageSourceEstimated}),
		"estimated usage never fabricates an outcome")
	assert.Equal(t, "miss", promptCacheOutcome(provider.Usage{PromptTokens: 9, Source: provider.UsageSourceProvider}))
	assert.Equal(t, "hit", promptCacheOutcome(provider.Usage{PromptTokens: 9, CacheReadTokens: 3, Source: provider.UsageSourceProvider}))
}

// helper parity: JSON helper must stay outcome-identical to the trailer helper.
func TestPromptCacheHeaderAndTrailerAgree(t *testing.T) {
	usages := []provider.Usage{
		{},
		{PromptTokens: 9, Source: provider.UsageSourceEstimated},
		{PromptTokens: 9, Source: provider.UsageSourceProvider},
		{PromptTokens: 9, CacheReadTokens: 3, Source: provider.UsageSourceProvider},
	}
	for _, u := range usages {
		rec := httptest.NewRecorder()
		setPromptCacheHeader(rec, u)
		setPromptCacheTrailer(rec, u)
		got := rec.Header().Get(PromptCacheHeader)
		want := rec.Header().Get(promptCacheTrailerKey)
		assert.Equal(t, want, got, "header and trailer must carry the same outcome for %+v", u)
	}
}

// --- N03-P06-T04: savings follow real usage; unsupported hints degrade -------

// TestPromptCache_SavingsFollowRealUsage_HeaderAndBillAgree pins the (d)
// clause on the OpenAI-compat JSON path: the transparency header and the
// billed cost are derived from the SAME provider-returned usage on one flow.
// A cache discount is shown only when the upstream actually reported cached
// tokens — never when a hint was merely sent.
func TestPromptCache_SavingsFollowRealUsage_HeaderAndBillAgree(t *testing.T) {
	const usageWithCache = `{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105,` +
		`"prompt_tokens_details":{"cached_tokens":30}}}`
	const usageNoCache = `{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105}}`

	cases := []struct {
		name          string
		upstreamUsage string
		wantHeader    string
		wantCached    int64
	}{
		{"hit", usageWithCache, "hit", 30},
		{"miss", usageNoCache, "miss", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.upstreamUsage))
			}))
			t.Cleanup(up.Close)

			gw := goldenChatGateway(t, up.URL)
			cap := captureAll(t)

			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				"/v1/chat/completions", strings.NewReader(goldenChatBody))
			r.Header.Set("Content-Type", "application/json")
			goldenIdentity(r)
			rec := httptest.NewRecorder()
			gw.chatCompletions(rec, r)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

			assert.Equal(t, tc.wantHeader, rec.Header().Get(PromptCacheHeader),
				"header must be derived from the provider usage returned on this request")

			ev := cap.last(t)
			assert.Equal(t, int64(100), ev.TokensIn)
			assert.Equal(t, tc.wantCached, ev.CacheReadTokens,
				"event cache-read tokens must equal the provider-reported value, not the sent hint")
			assert.Equal(t, "provider", ev.UsageSource)

			// The bill matches the same usage exactly — including the cache
			// discount only when the provider actually reported cached tokens.
			want := provider.ComputeCost(provider.Usage{
				PromptTokens:     100,
				CompletionTokens: 5,
				TotalTokens:      105,
				CacheReadTokens:  tc.wantCached,
				Source:           provider.UsageSourceProvider,
			}, "openai", "gpt-4o").EstimatedCostUSD
			assert.InDelta(t, want, ev.EstimatedCostUSD, 1e-12,
				"billed cost must be computed from the same provider usage the header reports")
			fullInput := (100*2.5 + 5*10.0) / 1e6 // gpt-4o input+output at list rates
			if tc.wantCached > 0 {
				assert.Less(t, ev.EstimatedCostUSD, fullInput,
					"a provider-reported cache read must show up as a real discount")
			} else {
				assert.InDelta(t, fullInput, ev.EstimatedCostUSD, 1e-9,
					"without provider-reported cache reads the bill is the full list-rate input cost")
			}
		})
	}
}

// TestPromptCache_UnsupportedHint_AnthropicShapeToOpenAI_Graceful pins the
// (c) clause: an anthropic cache_control hint on a request routed to a
// provider without explicit caching support must not break the request, must
// not leak the marker upstream as a broken promise, and must not claim or
// fabricate a discount.
func TestPromptCache_UnsupportedHint_AnthropicShapeToOpenAI_Graceful(t *testing.T) {
	var sentUpstream []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		sentUpstream = append([]byte(nil), raw...)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105}}`))
	}))
	t.Cleanup(up.Close)

	gw := responsesTestGateway(t, up.URL)
	gw.res = stubModelResolver{
		"gpt-4o": {ModelName: "gpt-4o", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
	}
	cap := captureAll(t)

	body := `{"model":"gpt-4o","max_tokens":16,` +
		`"system":[{"type":"text","text":"rules","cache_control":{"type":"ephemeral"}}],` +
		`"messages":[{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}]}`
	rec := postMessages(t, gw, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"type":"message"`,
		"the request must complete with a normal anthropic envelope")

	assert.NotContains(t, string(sentUpstream), "cache_control",
		"a hint the routed provider cannot honor must never be forwarded upstream")
	assert.Equal(t, "miss", rec.Header().Get(PromptCacheHeader),
		"no cache hit may be claimed when the provider cannot explicitly cache")

	ev := cap.last(t)
	assert.Equal(t, int64(0), ev.CacheReadTokens)
	fullInput := (100*2.5 + 5*10.0) / 1e6
	assert.InDelta(t, fullInput, ev.EstimatedCostUSD, 1e-9,
		"no discount may be fabricated for an unsupported hint combination")
}

// --- N03-P06-T05: unsupported-hint matrix, savings surfaces, negative billing --

// TestPromptCacheOutcome_EstimatedAndNone_NeverClaimHit hardens the outcome
// gate itself: the "estimated-cached" and "none-cached" shapes (cache fields
// set on a non-provider usage source — impossible by construction today, so
// this is a defensive pin) must never display an outcome, and a non-positive
// cache-read count can never claim a hit.
func TestPromptCacheOutcome_EstimatedAndNone_NeverClaimHit(t *testing.T) {
	assert.Empty(t, promptCacheOutcome(provider.Usage{PromptTokens: 9, CacheReadTokens: 5, Source: provider.UsageSourceEstimated}),
		"estimated usage must never display a prompt-cache outcome even if cache fields are set")
	assert.Empty(t, promptCacheOutcome(provider.Usage{PromptTokens: 9, CacheReadTokens: 5, Source: provider.UsageSourceNone}),
		"no-usage must never display a prompt-cache outcome even if cache fields are set")
	assert.Equal(t, "miss", promptCacheOutcome(provider.Usage{PromptTokens: 9, CacheReadTokens: -5, Source: provider.UsageSourceProvider}),
		"a non-positive cache-read count can never claim a hit")
}

// TestPromptCache_UnsupportedHint_MalformedCacheControlShapes_MessagesToOpenAI
// broadens the (c) matrix from the one well-formed marker to the malformed
// shapes a confused client can send: wrong JSON types, unknown marker types,
// objects missing "type". Every shape must behave identically on the
// unsupported route (anthropic-shaped /v1/messages → openai provider): the
// request completes with a normal envelope, no marker crosses upstream, no
// hit is claimed, and the bill stays at the full list rate.
func TestPromptCache_UnsupportedHint_MalformedCacheControlShapes_MessagesToOpenAI(t *testing.T) {
	cases := []struct{ name, marker string }{
		{"string marker", `"cache_control":"ephemeral"`},
		{"unknown marker type", `"cache_control":{"type":"1h-fixed"}`},
		{"missing type field", `"cache_control":{"ttl":"1h"}`},
		{"number marker", `"cache_control":1`},
		{"array marker", `"cache_control":[]`},
		{"null marker", `"cache_control":null`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sentUpstream []byte
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				sentUpstream = append([]byte(nil), raw...)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
					`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
					`"usage":{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105}}`))
			}))
			t.Cleanup(up.Close)

			gw := responsesTestGateway(t, up.URL)
			gw.res = stubModelResolver{
				"gpt-4o": {ModelName: "gpt-4o", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
			}
			cap := captureAll(t)

			body := `{"model":"gpt-4o","max_tokens":16,` +
				`"system":[{"type":"text","text":"rules",` + tc.marker + `}],` +
				`"messages":[{"role":"user","content":[{"type":"text","text":"hi",` + tc.marker + `}]}]}`
			rec := postMessages(t, gw, body)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), `"type":"message"`,
				"the request must complete with a normal anthropic envelope")

			assert.NotContains(t, string(sentUpstream), "cache_control",
				"a malformed marker on an unsupported route must never cross upstream")
			assert.Equal(t, "miss", rec.Header().Get(PromptCacheHeader),
				"no hit may be claimed for a marker the serving provider cannot honor")

			ev := cap.last(t)
			assert.Equal(t, int64(0), ev.CacheReadTokens)
			fullInput := (100*2.5 + 5*10.0) / 1e6
			assert.InDelta(t, fullInput, ev.EstimatedCostUSD, 1e-9,
				"the bill must stay at the full list rate regardless of the malformed marker")
		})
	}
}

// TestPromptCache_AnthropicBetaHeader_NeverForwardedOffAnthropicPath pins the
// header half of the matrix: an anthropic caching beta header sent by the
// client is only ever relayed on the native anthropic path (pinned by
// TestMessagesNative_StreamPassthrough). On openai-routed surfaces the
// upstream egress is rebuilt by the adapter (no client-header forwarding), so
// the header must not appear there — and must not change the bill either.
func TestPromptCache_AnthropicBetaHeader_NeverForwardedOffAnthropicPath(t *testing.T) {
	type gotHeaders struct {
		mu      sync.Mutex
		beta    string
		version string
	}
	usageNoCache := `{"id":"cmpl","object":"chat.completion","model":"gpt-4o",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105}}`
	assertNotForwarded := func(t *testing.T, got *gotHeaders, rec *httptest.ResponseRecorder, cap *goldenCapture) {
		t.Helper()
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		got.mu.Lock()
		defer got.mu.Unlock()
		assert.Empty(t, got.beta, "the anthropic caching beta header must not cross to a non-anthropic upstream")
		assert.Empty(t, got.version, "the anthropic-version header must not cross to a non-anthropic upstream")
		assert.Equal(t, "miss", rec.Header().Get(PromptCacheHeader))
		ev := cap.last(t)
		assert.Equal(t, int64(0), ev.CacheReadTokens)
		fullInput := (100*2.5 + 5*10.0) / 1e6
		assert.InDelta(t, fullInput, ev.EstimatedCostUSD, 1e-9,
			"a beta header is not usage: the bill must stay at the full list rate")
	}

	t.Run("openai chat completions", func(t *testing.T) {
		got := &gotHeaders{}
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got.mu.Lock()
			got.beta, got.version = r.Header.Get("Anthropic-Beta"), r.Header.Get("anthropic-version")
			got.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(usageNoCache))
		}))
		t.Cleanup(up.Close)

		gw := goldenChatGateway(t, up.URL)
		cap := captureAll(t)
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/v1/chat/completions", strings.NewReader(goldenChatBody))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("anthropic-version", "2023-06-01")
		r.Header.Set("anthropic-beta", "prompt-caching-2024-07-31")
		goldenIdentity(r)
		rec := httptest.NewRecorder()
		gw.chatCompletions(rec, r)
		assertNotForwarded(t, got, rec, cap)
	})

	t.Run("messages translation to openai", func(t *testing.T) {
		got := &gotHeaders{}
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got.mu.Lock()
			got.beta, got.version = r.Header.Get("Anthropic-Beta"), r.Header.Get("anthropic-version")
			got.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(usageNoCache))
		}))
		t.Cleanup(up.Close)

		gw := responsesTestGateway(t, up.URL)
		gw.res = stubModelResolver{
			"gpt-4o": {ModelName: "gpt-4o", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
		}
		cap := captureAll(t)

		body := `{"model":"gpt-4o","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("anthropic-beta", "prompt-caching-2024-07-31")
		rec := httptest.NewRecorder()
		router := chi.NewRouter()
		gw.routes(router)
		router.ServeHTTP(rec, req)
		assertNotForwarded(t, got, rec, cap)
	})
}

// TestPromptCache_HintShapedBodies_NonChatSurfaces_NoOutcomeNoBreak walks the
// non-chat in-boundary surfaces with cache_control-shaped bodies: none of
// them has a prompt-cache outcome surface, so none may ever set
// X-Yabanin-Prompt-Cache, and a foreign marker must not break the request or
// alter the real-usage accounting.
func TestPromptCache_HintShapedBodies_NonChatSurfaces_NoOutcomeNoBreak(t *testing.T) {
	const marker = `"cache_control":{"type":"ephemeral"}`

	t.Run("rerank", func(t *testing.T) {
		const upstreamBody = `{"id":"rr-1","model":"rerank-v1-canon","results":[{"index":0,"relevance_score":0.9}],` +
			`"usage":{"prompt_tokens":23,"total_tokens":23}}`
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(raw), `"query":"find paris"`) {
				t.Errorf("upstream body lost the query: %s", raw)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(upstreamBody))
		}))
		defer server.Close()

		info := resolver.ModelInfo{ModelName: "rerank-v1-canon", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
		gw := r105TestGateway(t, info)
		var ev *eventpub.Event
		gw.eventNote = func(e *eventpub.Event) { ev = e }

		body := `{"model":"m","query":"find paris","documents":[{"text":"paris is the capital of france",` + marker + `}],` + marker + `}`
		rec := postR105(t, gw, "/v1/rerank", body, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Empty(t, rec.Header().Get(PromptCacheHeader),
			"rerank has no prompt-cache outcome surface — the header must stay absent")
		require.NotNil(t, ev, "the served rerank must still publish its analytics event")
		assert.Equal(t, int64(0), ev.CacheReadTokens,
			"the upstream reported no cached tokens — the event must not invent them from the marker")
		assert.Equal(t, int64(23), ev.TokensIn)
	})

	t.Run("images", func(t *testing.T) {
		upstreamBody := `{"created":1790000000,"data":[{"b64_json":"` +
			base64.StdEncoding.EncodeToString(testTinyPNG) +
			`"}],"usage":{"input_tokens":20,"output_tokens":100,"total_tokens":120}}`
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(raw), `"prompt":"a red cube"`) {
				t.Errorf("upstream body lost the prompt: %s", raw)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(upstreamBody))
		}))
		defer server.Close()

		info := resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
		gw := imagesTestGateway(t, info, server.URL)
		var ev *eventpub.Event
		gw.eventNote = func(e *eventpub.Event) { ev = e }

		rec := postImages(t, gw, `{"model":"m","prompt":"a red cube",`+marker+`}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Empty(t, rec.Header().Get(PromptCacheHeader),
			"images has no prompt-cache outcome surface — the header must stay absent")
		require.NotNil(t, ev)
		assert.Equal(t, int64(0), ev.CacheReadTokens)
	})

	t.Run("realtime", func(t *testing.T) {
		const upstreamStream = "event: session.created\n" +
			`data: {"type":"session.created","session":{"id":"sess_1","model":"gpt-4o-realtime-canon"}}` + "\n\n" +
			"event: response.done\n" +
			`data: {"type":"response.done","response":{"id":"resp_1","usage":{"input_tokens":42,"output_tokens":7,"total_tokens":49}}}` + "\n\n"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(upstreamStream))
		}))
		defer server.Close()

		gw := r105TestGateway(t, realtimeTestModel(server.URL))
		var ev *eventpub.Event
		gw.eventNote = func(e *eventpub.Event) { ev = e }

		rec := postR105(t, gw, "/v1/realtime", `{"model":"m","session":{"voice":"alloy"},`+marker+`}`, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
		assert.Empty(t, rec.Header().Get(PromptCacheHeader),
			"realtime has no prompt-cache outcome surface — the header must stay absent")
		require.NotNil(t, ev)
		assert.Equal(t, int64(0), ev.CacheReadTokens)
	})

	t.Run("count_tokens estimated", func(t *testing.T) {
		var upstreamCalls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"input_tokens":17}`))
		}))
		defer server.Close()

		gw := nativeMessagesGateway(t, server.URL)
		gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: server.URL, Enabled: true}}
		noEvents := observeEvent(func(*eventpub.Event) {
			t.Error("count_tokens must not publish an event")
		})
		t.Cleanup(noEvents)

		body := `{"model":"m","system":"sys","messages":[{"role":"user","content":[{"type":"text","text":"Hi",` + marker + `}]}]}`
		rec := postCount(t, gw, body, false)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "true", rec.Header().Get("X-Yabanin-Estimated"),
			"a non-anthropic count_tokens stays estimated")
		assert.Empty(t, rec.Header().Get(PromptCacheHeader),
			"count_tokens has no prompt-cache outcome surface — the header must stay absent")
		assert.Zero(t, upstreamCalls.Load(), "the estimated count path must not call the upstream")
	})
}
