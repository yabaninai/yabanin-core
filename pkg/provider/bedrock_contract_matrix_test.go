// Package provider — N08-P02-T03 Bedrock contract matrix.
//
// One table-driven suite pinning the adapter's client-facing contract as
// built in T02 and completed in T03:
//
//	request translation   — which OpenAI features map to Converse, which
//	                        reject explicitly (I50/I51), which drop (as-is
//	                        contract, I51 tension owned by the N07 lanes);
//	response translation  — stopReason map, canonical usage fold, usage
//	                        omission, cache-details round trip;
//	stream shapes         — ConverseStream eventstream → OpenAI SSE chunks,
//	                        incl. mid-stream ThrottlingException verbatim;
//	negative refusals     — throttling / credential expiry / denied region /
//	                        validation surface as typed *upstream.Error with
//	                        the exact status and the provider's refusal body
//	                        unrewritten (I51), and their STATUS-LEVEL
//	                        retryability through the shared classifiers
//	                        (retry.DefaultClassifier, router.DefaultRetryable):
//	                        429 throttling is a retryable status; 403 auth /
//	                        region, 400 validation and 404 model errors are
//	                        final;
//	preflight fail-closed — identity/region resolution failures carry NO HTTP
//	                        status (never *upstream.Error), classify as
//	                        OutcomeUnknown (terminal, no auto-repeat), and
//	                        stay deterministic.
//
// All AWS interactions are deterministic fakes (httptest stubs speaking the
// Bedrock wire shapes); no live AWS endpoint is contacted — the real-AWS
// leg is the limited live smoke on the owner stand (packet acceptance T12 /
// owner decision, see the T01–T02 record §Live smoke), not part of this
// hermetic lane delivery.
package provider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ————————————————————————————————————————————————————————————————
// Mirrors of the adapter-internal envelope / Converse shapes for assertion
// from the external test package (same JSON as the internal structs).
// ————————————————————————————————————————————————————————————————

type bedrockMatrixEnvelope struct {
	Model    string          `json:"model"`
	Converse json.RawMessage `json:"converse"`
}

type bedrockMatrixConverse struct {
	System []struct {
		Text string `json:"text"`
	} `json:"system"`
	Messages []struct {
		Role    string `json:"role"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	} `json:"messages"`
	InferenceConfig *struct {
		MaxTokens     *int     `json:"maxTokens"`
		Temperature   *float64 `json:"temperature"`
		TopP          *float64 `json:"topP"`
		StopSequences []string `json:"stopSequences"`
	} `json:"inferenceConfig"`
}

// ————————————————————————————————————————————————————————————————
// Request translation matrix.
// ————————————————————————————————————————————————————————————————

// TestBedrockContractMatrix_RequestTranslation pins the OpenAI→Converse
// feature contract: accepted features and their Converse shape, explicit
// rejections (fail-closed, I50/I51), and the as-is drop convention for
// unknown roles / unknown content-part types (pre-known pin
// bedrock_translate.go:227-230; the I51 tension there is owned by the N07
// w4b lanes — documented here, not changed).
func TestBedrockContractMatrix_RequestTranslation(t *testing.T) {
	t.Parallel()
	adapter, err := provider.New("bedrock")
	require.NoError(t, err)

	cases := []struct {
		name       string
		body       string
		wantErr    string // empty = accepted
		assertConv func(t *testing.T, conv bedrockMatrixConverse)
	}{
		{
			name: "system and developer fold into system blocks",
			body: `{"model":"m1","messages":[{"role":"system","content":"s"},{"role":"developer","content":"d"},{"role":"user","content":"u"}]}`,
			assertConv: func(t *testing.T, conv bedrockMatrixConverse) {
				t.Helper()
				require.Len(t, conv.System, 2)
				assert.Equal(t, "s", conv.System[0].Text)
				assert.Equal(t, "d", conv.System[1].Text)
			},
		},
		{
			name: "user string content maps to one text block",
			body: `{"model":"m1","messages":[{"role":"user","content":"hi"}]}`,
			assertConv: func(t *testing.T, conv bedrockMatrixConverse) {
				t.Helper()
				require.Len(t, conv.Messages, 1)
				require.Len(t, conv.Messages[0].Content, 1)
				assert.Equal(t, "hi", conv.Messages[0].Content[0].Text)
			},
		},
		{
			name: "user multipart text parts keep order",
			body: `{"model":"m1","messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}]}`,
			assertConv: func(t *testing.T, conv bedrockMatrixConverse) {
				t.Helper()
				require.Len(t, conv.Messages, 1)
				blocks := conv.Messages[0].Content
				require.Len(t, blocks, 2)
				assert.Equal(t, "a", blocks[0].Text)
				assert.Equal(t, "b", blocks[1].Text)
			},
		},
		{
			name: "assistant turns map as assistant role",
			body: `{"model":"m1","messages":[{"role":"user","content":"q"},{"role":"assistant","content":"a"}]}`,
			assertConv: func(t *testing.T, conv bedrockMatrixConverse) {
				t.Helper()
				require.Len(t, conv.Messages, 2)
				assert.Equal(t, "user", conv.Messages[0].Role)
				assert.Equal(t, "assistant", conv.Messages[1].Role)
			},
		},
		{
			name: "max_tokens maps to inferenceConfig.maxTokens",
			body: `{"model":"m1","messages":[{"role":"user","content":"x"}],"max_tokens":42}`,
			assertConv: func(t *testing.T, conv bedrockMatrixConverse) {
				t.Helper()
				require.NotNil(t, conv.InferenceConfig)
				require.NotNil(t, conv.InferenceConfig.MaxTokens)
				assert.Equal(t, 42, *conv.InferenceConfig.MaxTokens)
			},
		},
		{
			name: "max_completion_tokens wins over max_tokens",
			body: `{"model":"m1","messages":[{"role":"user","content":"x"}],"max_tokens":1,"max_completion_tokens":99}`,
			assertConv: func(t *testing.T, conv bedrockMatrixConverse) {
				t.Helper()
				require.NotNil(t, conv.InferenceConfig.MaxTokens)
				assert.Equal(t, 99, *conv.InferenceConfig.MaxTokens)
			},
		},
		{
			name: "stop string coerces to one stop sequence",
			body: `{"model":"m1","messages":[{"role":"user","content":"x"}],"stop":"END"}`,
			assertConv: func(t *testing.T, conv bedrockMatrixConverse) {
				t.Helper()
				assert.Equal(t, []string{"END"}, conv.InferenceConfig.StopSequences)
			},
		},
		{
			name: "stop array maps to stopSequences",
			body: `{"model":"m1","messages":[{"role":"user","content":"x"}],"stop":["A","B"]}`,
			assertConv: func(t *testing.T, conv bedrockMatrixConverse) {
				t.Helper()
				assert.Equal(t, []string{"A", "B"}, conv.InferenceConfig.StopSequences)
			},
		},
		{
			name: "temperature and top_p map to inferenceConfig",
			body: `{"model":"m1","messages":[{"role":"user","content":"x"}],"temperature":0.25,"top_p":0.75}`,
			assertConv: func(t *testing.T, conv bedrockMatrixConverse) {
				t.Helper()
				require.NotNil(t, conv.InferenceConfig.Temperature)
				assert.InDelta(t, 0.25, float64(*conv.InferenceConfig.Temperature), 1e-9)
				require.NotNil(t, conv.InferenceConfig.TopP)
				assert.InDelta(t, 0.75, float64(*conv.InferenceConfig.TopP), 1e-9)
			},
		},
		// Explicit rejections (I50/I51 — reject, never silent downgrade).
		{
			name:    "tools reject",
			body:    `{"model":"m1","messages":[{"role":"user","content":"x"}],"tools":[{"type":"function","function":{"name":"f"}}]}`,
			wantErr: "tools/tool_choice are not supported",
		},
		{
			name:    "tool_choice rejects",
			body:    `{"model":"m1","messages":[{"role":"user","content":"x"}],"tool_choice":"auto"}`,
			wantErr: "tools/tool_choice are not supported",
		},
		{
			name:    "tool role rejects",
			body:    `{"model":"m1","messages":[{"role":"tool","content":"r"}]}`,
			wantErr: "tools/tool_choice are not supported",
		},
		{
			name:    "assistant tool_calls reject",
			body:    `{"model":"m1","messages":[{"role":"assistant","tool_calls":[{"id":"1"}]}]}`,
			wantErr: "tools/tool_choice are not supported",
		},
		{
			name:    "image part rejects (I61 media deferred)",
			body:    `{"model":"m1","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x/y.png"}}]}]}`,
			wantErr: "image inputs are not supported",
		},
		{
			name:    "missing model rejects",
			body:    `{"messages":[{"role":"user","content":"x"}]}`,
			wantErr: "no model field",
		},
		{
			name:    "no conversable message rejects",
			body:    `{"model":"m1","messages":[{"role":"system","content":"only-system"}]}`,
			wantErr: "no user/assistant messages",
		},
		// Unknown part types reject (typed UnsupportedFeatureError): the N07
		// I51 follow-up landed on the union lineage (72bf9a23 / 8ea0c255 /
		// d5463414), superseding the base-era as-is drop convention this
		// matrix pinned at lane base a6f0b017. Same fail-closed contract as
		// the bedrock_test.go unknown-part rows.
		{
			name:    "unknown content-part type rejects (typed, never silent drop)",
			body:    `{"model":"m1","messages":[{"role":"user","content":[{"type":"text","text":"keep"},{"type":"audio_url","audio_url":{"url":"https://x/a.mp3"}}]}]}`,
			wantErr: `content part type "audio_url" is not mapped`,
		},
		{
			name: "unknown role drops silently (anthropic convention)",
			body: `{"model":"m1","messages":[{"role":"custom_role","content":"x"},{"role":"user","content":"u"}]}`,
			assertConv: func(t *testing.T, conv bedrockMatrixConverse) {
				t.Helper()
				require.Len(t, conv.Messages, 1)
				assert.Equal(t, "user", conv.Messages[0].Role)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			encoded, terr := adapter.TranslateRequest([]byte(tc.body))
			if tc.wantErr != "" {
				require.Error(t, terr)
				assert.Contains(t, terr.Error(), tc.wantErr)
				return
			}
			require.NoError(t, terr)
			var env bedrockMatrixEnvelope
			require.NoError(t, json.Unmarshal(encoded, &env))
			assert.Equal(t, "m1", env.Model)
			require.NotEmpty(t, env.Converse)
			assert.NotContains(t, string(env.Converse), `"model"`,
				"modelId rides the envelope, never the Converse payload")
			var conv bedrockMatrixConverse
			require.NoError(t, json.Unmarshal(env.Converse, &conv))
			tc.assertConv(t, conv)
		})
	}
}

// ————————————————————————————————————————————————————————————————
// Response translation matrix.
// ————————————————————————————————————————————————————————————————

// TestBedrockContractMatrix_ResponseTranslation pins the ConverseOutput →
// OpenAI response contract: the full stopReason map, the canonical usage
// fold (prompt includes cache reads AND writes), usage omission when the
// provider reported none, and the prompt_tokens_details round trip.
func TestBedrockContractMatrix_ResponseTranslation(t *testing.T) {
	t.Parallel()
	adapter, err := provider.New("bedrock")
	require.NoError(t, err)

	t.Run("stop_reason map", func(t *testing.T) {
		t.Parallel()
		cases := []struct{ stopReason, wantFinish string }{
			{"end_turn", "stop"},
			{"stop_sequence", "stop"},
			{"", "stop"},
			{"max_tokens", "length"},
			{"tool_use", "tool_calls"},
			{"content_filtered", "content_filter"},
			{"guardrail_intervened", "content_filter"},
			{"some_future_reason", "stop"},
		}
		for _, tc := range cases {
			body := `{"output":{"message":{"role":"assistant","content":[{"text":"x"}]}},"stopReason":"` + tc.stopReason + `"}`
			out, err := adapter.TranslateResponse([]byte(body))
			require.NoError(t, err, "stopReason %q", tc.stopReason)
			assert.Contains(t, string(out), `"finish_reason":"`+tc.wantFinish+`"`, "stopReason %q", tc.stopReason)
		}
	})

	t.Run("usage fold and omission", func(t *testing.T) {
		t.Parallel()
		body := `{"output":{"message":{"role":"assistant","content":[{"text":"x"}]}},"stopReason":"end_turn","usage":{"inputTokens":7,"outputTokens":3,"totalTokens":10,"cacheReadInputTokens":5,"cacheWriteInputTokens":2}}`
		out, err := adapter.TranslateResponse([]byte(body))
		require.NoError(t, err)
		var resp struct {
			Usage struct {
				PromptTokens     float64             `json:"prompt_tokens"`
				CompletionTokens float64             `json:"completion_tokens"`
				TotalTokens      float64             `json:"total_tokens"`
				Details          *map[string]float64 `json:"prompt_tokens_details"`
			} `json:"usage"`
		}
		require.NoError(t, json.Unmarshal(out, &resp))
		// Canonical fold: prompt = input + cacheRead + cacheWrite.
		assert.InDelta(t, float64(14), resp.Usage.PromptTokens, 1e-9)
		assert.InDelta(t, float64(3), resp.Usage.CompletionTokens, 1e-9)
		assert.InDelta(t, float64(10), resp.Usage.TotalTokens, 1e-9)
		require.NotNil(t, resp.Usage.Details)
		assert.InDelta(t, float64(5), (*resp.Usage.Details)["cached_tokens"], 1e-9)
		assert.InDelta(t, float64(2), (*resp.Usage.Details)["cache_creation_input_tokens"], 1e-9)
		// The translated body round-trips through ParseUsage with identical
		// numbers (cache billing survives translation, D5).
		u := adapter.ParseUsage(out)
		assert.Equal(t, provider.UsageSourceProvider, u.Source)
		assert.Equal(t, int64(14), u.PromptTokens)
		assert.Equal(t, int64(3), u.CompletionTokens)
		assert.Equal(t, int64(5), u.CacheReadTokens)
		assert.Equal(t, int64(2), u.CacheCreationTokens)
	})

	t.Run("no provider usage omits the usage key entirely", func(t *testing.T) {
		t.Parallel()
		body := `{"output":{"message":{"role":"assistant","content":[{"text":"x"}]}},"stopReason":"end_turn"}`
		out, err := adapter.TranslateResponse([]byte(body))
		require.NoError(t, err)
		assert.NotContains(t, string(out), `"usage"`, "zero usage must not masquerade as provider metering")
		u := adapter.ParseUsage(out)
		assert.Equal(t, provider.UsageSourceNone, u.Source)
	})
}

// ————————————————————————————————————————————————————————————————
// Stream shapes matrix.
// ————————————————————————————————————————————————————————————————

// TestBedrockContractMatrix_StreamShapes pins the ConverseStream → OpenAI
// SSE contract through the production pool/stream-handler seams: event →
// chunk mapping, terminal [DONE], suppress-usage mode, boundary/unknown
// events, abrupt close, and the mid-stream ThrottlingException surfaced
// verbatim (I51).
func TestBedrockContractMatrix_StreamShapes(t *testing.T) {
	bedrockStubEnv(t) // process-global env: sequential (same as wire tests)

	cases := []struct {
		name           string
		frames         []bedrockEvent
		suppressUsage  bool
		wantContent    []string // content deltas in order; empty slice = none expected
		wantFinish     string   // finish_reason on the finish chunk
		wantUsage      *provider.Usage
		wantUsageChunk bool   // choices:[] usage-only chunk present
		wantErrSubstr  string // handler error substring (empty = no error)
		wantIncomplete bool   // H3 saw-terminal: handler error wraps ErrStreamIncomplete yet the client wire still terminates with [DONE]
	}{
		{
			name: "happy path end_turn",
			frames: []bedrockEvent{
				{eventType: "messageStart", payload: `{"role":"assistant"}`},
				{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"text":"He"}}`},
				{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"text":"y"}}`},
				{eventType: "messageStop", payload: `{"stopReason":"end_turn"}`},
				{eventType: "metadata", payload: `{"usage":{"inputTokens":10,"outputTokens":3,"totalTokens":13,"cacheReadInputTokens":4}}`},
			},
			wantContent: []string{"He", "y"},
			wantFinish:  "stop",
			wantUsage: &provider.Usage{PromptTokens: 14, CompletionTokens: 3, TotalTokens: 13,
				CacheReadTokens: 4, Source: provider.UsageSourceProvider},
			wantUsageChunk: true,
		},
		{
			name: "max_tokens finish and suppressed usage chunk",
			frames: []bedrockEvent{
				{eventType: "messageStart", payload: `{"role":"assistant"}`},
				{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"text":"hi"}}`},
				{eventType: "messageStop", payload: `{"stopReason":"max_tokens"}`},
				{eventType: "metadata", payload: `{"usage":{"inputTokens":2,"outputTokens":1,"totalTokens":3}}`},
			},
			suppressUsage:  true,
			wantContent:    []string{"hi"},
			wantFinish:     "length",
			wantUsage:      &provider.Usage{PromptTokens: 2, CompletionTokens: 1, TotalTokens: 3, Source: provider.UsageSourceProvider},
			wantUsageChunk: false,
		},
		{
			name: "content block boundaries emit no chunks",
			frames: []bedrockEvent{
				{eventType: "contentBlockStart", payload: `{"contentBlockIndex":0,"start":{}}`},
				{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"text":"mid"}}`},
				{eventType: "contentBlockStop", payload: `{"contentBlockIndex":0}`},
				{eventType: "messageStop", payload: `{"stopReason":"end_turn"}`},
				{eventType: "metadata", payload: `{"usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2}}`},
			},
			wantContent:    []string{"mid"},
			wantFinish:     "stop",
			wantUsage:      &provider.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2, Source: provider.UsageSourceProvider},
			wantUsageChunk: true,
		},
		{
			name: "unknown future event types are skipped, not fatal",
			frames: []bedrockEvent{
				{eventType: "messageStart", payload: `{"role":"assistant"}`},
				{eventType: "futureEventName", payload: `{"opaque":true}`},
				{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"text":"ok"}}`},
				{eventType: "messageStop", payload: `{"stopReason":"end_turn"}`},
				{eventType: "metadata", payload: `{"usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2}}`},
			},
			wantContent:    []string{"ok"},
			wantFinish:     "stop",
			wantUsage:      &provider.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2, Source: provider.UsageSourceProvider},
			wantUsageChunk: true,
		},
		{
			name: "empty text delta (e.g. reasoningContent) emits no chunk",
			frames: []bedrockEvent{
				{eventType: "messageStart", payload: `{"role":"assistant"}`},
				{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"reasoningContent":{"text":"thinking"}}}`},
				{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":1,"delta":{"text":"final"}}`},
				{eventType: "messageStop", payload: `{"stopReason":"end_turn"}`},
				{eventType: "metadata", payload: `{"usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2}}`},
			},
			wantContent:    []string{"final"},
			wantFinish:     "stop",
			wantUsage:      &provider.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2, Source: provider.UsageSourceProvider},
			wantUsageChunk: true,
		},
		{
			name: "abrupt close without metadata terminates with [DONE], no metering, handler reports incomplete",
			frames: []bedrockEvent{
				{eventType: "messageStart", payload: `{"role":"assistant"}`},
				{eventType: "contentBlockDelta", payload: `{"contentBlockIndex":0,"delta":{"text":"partial"}}`},
			},
			wantContent:    []string{"partial"},
			wantFinish:     "", // no messageStop → no finish_reason chunk
			wantUsage:      &provider.Usage{Source: provider.UsageSourceNone},
			wantUsageChunk: false,
			wantIncomplete: true,
		},
		{
			name: "mid-stream ThrottlingException surfaces verbatim",
			frames: []bedrockEvent{
				{eventType: "messageStart", payload: `{"role":"assistant"}`},
				{exceptionType: "ThrottlingException", payload: `{"message":"Rate exceeded for model ` + bedrockModelID + `"}`},
			},
			wantContent:   nil,
			wantErrSubstr: "bedrock stream exception ThrottlingException: Rate exceeded for model " + bedrockModelID,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frames := encodeEvents(t, tc.frames)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
				_, _ = w.Write(frames)
			}))
			t.Cleanup(srv.Close)

			client, err := newBedrockPool(t, srv.URL).Get(srv.URL, "bedrock")
			require.NoError(t, err)

			chat := upstream.OverrideModel([]byte(`{"model":"any-alias","messages":[{"role":"user","content":"hi"}],"stream":true}`), bedrockModelID)
			resp, err := client.Stream(context.Background(), chat, "")
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })

			w, buf := newWireRecorder()
			h := provider.NewStreamHandlerWithOptions("bedrock", bedrockModelID, provider.StreamOptions{SuppressUsageOnlyChunk: tc.suppressUsage})
			usage, derr := h.HandleStream(context.Background(), w, w, resp)

			if tc.wantErrSubstr != "" {
				require.Error(t, derr)
				assert.Contains(t, derr.Error(), tc.wantErrSubstr)
				return
			}
			if tc.wantIncomplete {
				// H3 saw-terminal contract: EOF without metadata is an
				// incomplete run (typed error) but the client-facing wire
				// above is well-formed and terminated — assertions below
				// still hold ([DONE] tail, content deltas, usage none).
				require.Error(t, derr)
				require.ErrorIs(t, derr, provider.ErrStreamIncomplete)
			} else {
				require.NoError(t, derr)
			}

			// The stream always terminates with [DONE].
			out := strings.TrimSpace(buf.String())
			assert.True(t, strings.HasSuffix(out, "data: [DONE]"), "tail:\n%s", out)

			frames2 := strings.Split(out, "\n\n")
			var chunks []map[string]any
			for _, f := range frames2[:len(frames2)-1] {
				require.True(t, strings.HasPrefix(f, "data: "), "frame %q", f)
				var c map[string]any
				require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(f, "data: ")), &c))
				require.Equal(t, "chat.completion.chunk", c["object"])
				chunks = append(chunks, c)
			}

			// Collect content deltas and the finish reason.
			var gotContent []string
			var gotFinish *string
			sawUsageChunk := false
			for _, c := range chunks {
				choices, _ := c["choices"].([]any)
				if len(choices) == 0 {
					sawUsageChunk = true
					continue
				}
				choice := choices[0].(map[string]any)
				delta := choice["delta"].(map[string]any)
				if txt, ok := delta["content"].(string); ok {
					gotContent = append(gotContent, txt)
				}
				if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
					gotFinish = &fr
				}
			}
			assert.Equal(t, tc.wantContent, gotContent, "content deltas")
			if tc.wantFinish == "" {
				assert.Nil(t, gotFinish, "no finish chunk expected")
			} else {
				require.NotNil(t, gotFinish, "finish chunk expected")
				assert.Equal(t, tc.wantFinish, *gotFinish)
			}
			assert.Equal(t, tc.wantUsageChunk, sawUsageChunk, "usage-only chunk presence")

			require.NotNil(t, tc.wantUsage)
			assert.Equal(t, tc.wantUsage.Source, usage.Source)
			assert.Equal(t, tc.wantUsage.PromptTokens, usage.PromptTokens)
			assert.Equal(t, tc.wantUsage.CompletionTokens, usage.CompletionTokens)
			assert.Equal(t, tc.wantUsage.TotalTokens, usage.TotalTokens)
			assert.Equal(t, tc.wantUsage.CacheReadTokens, usage.CacheReadTokens)
		})
	}
}

// ————————————————————————————————————————————————————————————————
// Negative refusal matrix (card NEGATIVE packet).
// ————————————————————————————————————————————————————————————————

// TestBedrockContractMatrix_NegativeRefusals proves the card's negative
// packet end-to-end through the production pool/client: throttling,
// credential expiry, denied region (and the adjacent validation/model/5xx
// rows) surface as the TYPED *upstream.Error with the exact status and the
// provider's refusal body unrewritten (I51), and their STATUS-LEVEL
// retryability through both shared classifiers matches the pinned policy:
// 429 throttling retryable; 403 auth/region and 400/404 final by policy
// (500 final per-model, chain-advancing on fallback — the documented
// divergence between the two classifiers).
func TestBedrockContractMatrix_NegativeRefusals(t *testing.T) {
	bedrockStubEnv(t) // sequential: process-global env

	cases := []struct {
		name           string
		status         int
		body           string
		retryCandidate bool // retry.DefaultClassifier(429/503/529) status policy
		fallbackNext   bool // router.DefaultRetryable status policy
	}{
		{
			name:           "throttling 429 is retryable",
			status:         http.StatusTooManyRequests,
			body:           `{"__type":"ThrottlingException","message":"Rate exceeded for model ` + bedrockModelID + `"}`,
			retryCandidate: true,
			fallbackNext:   true,
		},
		{
			name:           "credential expiry 403 ExpiredTokenException is final",
			status:         http.StatusForbidden,
			body:           `{"__type":"ExpiredTokenException","message":"The security token included in the request is expired"}`,
			retryCandidate: false,
			fallbackNext:   false,
		},
		{
			name:           "invalid credentials 403 InvalidClientTokenException is final",
			status:         http.StatusForbidden,
			body:           `{"__type":"InvalidClientTokenException","message":"The security token included in the request is invalid"}`,
			retryCandidate: false,
			fallbackNext:   false,
		},
		{
			name:           "denied region 403 AccessDeniedException is final",
			status:         http.StatusForbidden,
			body:           `{"__type":"AccessDeniedException","message":"User: arn:aws:sts::111122223333:assumed-role/BedrockRole is not authorized to perform: bedrock:InvokeModel on resource: arn:aws:bedrock:ap-south-2:111122223333:foundation-model/` + bedrockModelID + ` with an explicit deny in a resource-based policy"}`,
			retryCandidate: false,
			fallbackNext:   false,
		},
		{
			name:           "validation 400 is final",
			status:         http.StatusBadRequest,
			body:           `{"__type":"ValidationException","message":"1 validation error detected: Value at 'inferenceConfig' failed to satisfy constraint"}`,
			retryCandidate: false,
			fallbackNext:   false,
		},
		{
			name:           "model not found 404 is final",
			status:         http.StatusNotFound,
			body:           `{"__type":"ResourceNotFoundException","message":"Could not detect a useable modelId: vendor.unknown-model:0"}`,
			retryCandidate: false,
			fallbackNext:   false,
		},
		{
			name:           "internal 500 is final per-model but chain-advancing on fallback",
			status:         http.StatusInternalServerError,
			body:           `{"__type":"InternalServerException","message":"An internal server error occurred"}`,
			retryCandidate: false,
			fallbackNext:   true,
		},
		{
			name:           "service unavailable 503 is retryable",
			status:         http.StatusServiceUnavailable,
			body:           `{"__type":"ServiceUnavailableException","message":"Bedrock is currently unavailable. An internal error occurred."}`,
			retryCandidate: true,
			fallbackNext:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var gotAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				gotAuth = r.Header.Get("Authorization")
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)

			client, err := newBedrockPool(t, srv.URL).Get(srv.URL, "bedrock")
			require.NoError(t, err)

			chat := []byte(`{"model":"` + bedrockModelID + `","messages":[{"role":"user","content":"ping"}]}`)
			_, _, ferr := client.ForwardJSONWithHeaders(context.Background(), chat, bedrockModelID, "", 2*time.Second)
			require.Error(t, ferr)

			// Typed error: exact status, provider body verbatim (I51).
			var upErr *upstream.Error
			require.ErrorAs(t, ferr, &upErr, "want *upstream.Error, got %T: %v", ferr, ferr)
			assert.Equal(t, tc.status, upErr.Status)
			assert.JSONEq(t, tc.body, upErr.Body)
			assert.Contains(t, ferr.Error(), "upstream error")

			// Identity invariant: the refusal happened on a SigV4 request —
			// never a static bearer/api key (I49 DefaultChain).
			mu.Lock()
			defer mu.Unlock()
			assert.True(t, strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256"), "got %q", gotAuth)

			// Outcome: an answered failure is a known-completed exchange —
			// never unknown — so the ordinary status policy governs.
			assert.Equal(t, retry.OutcomeExecuted, retry.Classify(tc.status, upErr))

			// Status-level retryability through BOTH shared classifiers
			// (nil error isolates the status policy from the transport-
			// error branch, mirroring the pinned retry decision table).
			assert.Equal(t, tc.retryCandidate, retry.DefaultClassifier(tc.status, nil), "retry.DefaultClassifier")
			assert.Equal(t, tc.fallbackNext, router.DefaultRetryable(tc.status, nil), "router.DefaultRetryable")
		})
	}
}

// ————————————————————————————————————————————————————————————————
// Preflight fail-closed matrix.
// ————————————————————————————————————————————————————————————————

// TestBedrockContractMatrix_PreflightFailuresClosed pins the request-
// construction phase of the negative packet: identity and region resolution
// failures (credential expiry at the chain, missing configuration) never
// fabricate an HTTP status, classify as unknown-outcome (terminal — no
// automatic repeat and no fallback advance), and produce deterministic
// adapter-owned diagnostics.
func TestBedrockContractMatrix_PreflightFailuresClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(bedrockConverseOutput))
	}))
	t.Cleanup(srv.Close)

	cases := []struct {
		name       string
		setup      func(t *testing.T)
		wantErrSub string
	}{
		{
			name: "no resolvable identity fails closed (credential failure, status-free)",
			setup: func(t *testing.T) {
				t.Helper()
				bedrockIsolateAWSIdentityExternal(t)
				t.Setenv("AWS_REGION", "us-east-1")
			},
			// The adapter-owned wrap prefix is the contract; the inner text
			// is SDK-version-dependent (with IMDS disabled the chain reports
			// the skipped IMDS probe, not a bare "no credentials").
			wantErrSub: "bedrock: resolve AWS credentials:",
		},
		{
			name: "no resolvable region fails closed (status-free)",
			setup: func(t *testing.T) {
				t.Helper()
				bedrockIsolateAWSIdentityExternal(t)
				t.Setenv("AWS_ACCESS_KEY_ID", "AKIDPREFLIGHT")
				t.Setenv("AWS_SECRET_ACCESS_KEY", "preflight-key")
			},
			wantErrSub: "region is not configured",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)

			client, err := newBedrockPool(t, srv.URL).Get(srv.URL, "bedrock")
			require.NoError(t, err)

			chat := []byte(`{"model":"` + bedrockModelID + `","messages":[{"role":"user","content":"ping"}]}`)
			_, _, ferr := client.ForwardJSONWithHeaders(context.Background(), chat, bedrockModelID, "", 2*time.Second)
			require.Error(t, ferr)

			// NOT an upstream error: nothing was sent, so no status exists.
			var upErr *upstream.Error
			assert.NotErrorAs(t, ferr, &upErr, "preflight failure must not fabricate an HTTP status: %v", ferr)
			assert.Contains(t, ferr.Error(), tc.wantErrSub)
			assert.Contains(t, ferr.Error(), "bedrock:")

			// Unknown outcome → terminal for the fallback chain (no
			// automatic advance without execution evidence).
			assert.Equal(t, retry.OutcomeUnknown, retry.Classify(0, ferr))
			assert.False(t, router.DefaultRetryable(0, ferr))

			// Deterministic: the same failure repeats identically.
			_, _, ferr2 := client.ForwardJSONWithHeaders(context.Background(), chat, bedrockModelID, "", 2*time.Second)
			require.Error(t, ferr2)
			assert.Equal(t, ferr.Error(), ferr2.Error())
		})
	}

	// Static API keys are neither required nor consumed end-to-end: a
	// non-empty upstream API key never reaches the wire on any header.
	t.Run("static api key ignored end-to-end", func(t *testing.T) {
		bedrockStubEnv(t)
		var mu sync.Mutex
		var gotAPIKey, gotAuth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			gotAPIKey = r.Header.Get("X-Api-Key")
			gotAuth = r.Header.Get("Authorization")
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(bedrockConverseOutput))
		}))
		t.Cleanup(srv.Close)

		client, err := newBedrockPool(t, srv.URL).Get(srv.URL, "bedrock")
		require.NoError(t, err)
		chat := []byte(`{"model":"` + bedrockModelID + `","messages":[{"role":"user","content":"ping"}]}`)
		_, respBody, ferr := client.ForwardJSONWithHeaders(context.Background(), chat, bedrockModelID, "operator-static-key-must-be-ignored", 2*time.Second)
		require.NoError(t, ferr)
		require.NotEmpty(t, respBody)
		mu.Lock()
		defer mu.Unlock()
		assert.Empty(t, gotAPIKey)
		assert.NotContains(t, gotAuth, "operator-static-key-must-be-ignored")
		assert.True(t, strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256"))
	})
}

// bedrockIsolateAWSIdentityExternal is the external-package twin of the
// internal bedrockIsolateAWSIdentity helper (same env contract, same empty
// shared-file fixtures): blanks every ambient AWS identity source and
// disables IMDS so the DefaultChain resolves only what a test installs.
func bedrockIsolateAWSIdentityExternal(t *testing.T) {
	t.Helper()
	for _, k := range bedrockMatrixAWSEnvVars {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	for _, name := range []string{"config", "credentials"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o600))
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// bedrockMatrixAWSEnvVars mirrors the internal bedrockAWSIdentityEnvVars
// list (external test packages cannot see internal identifiers).
var bedrockMatrixAWSEnvVars = []string{
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_REGION",
	"AWS_DEFAULT_REGION",
	"AWS_PROFILE",
	"AWS_CONFIG_FILE",
	"AWS_SHARED_CREDENTIALS_FILE",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
	"AWS_ROLE_ARN",
	"AWS_ROLE_SESSION_NAME",
	"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	"AWS_CONTAINER_CREDENTIALS_FULL_URI",
	"AWS_ENDPOINT_URL",
	"AWS_ENDPOINT_URL_STS",
	"AWS_ENDPOINT_URL_SSO",
}
