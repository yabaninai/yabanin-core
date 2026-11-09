package provider

// N08-P04-T02 (internal-delivery-program): vLLM / Ollama / llama.cpp capabilities walk.
//
// These tests pin the adapter-level capability contract the packet walks
// through, so later packet cards (T03 discovery/availability/health split,
// T05 "installed model without the needed endpoint is not shown working")
// consume a tested seam instead of re-deriving it:
//
//   - all three runtimes are OpenAI-compatible thin pass-through adapters:
//     one chat endpoint for stream and non-stream, identity translation in
//     both directions, optional Bearer, SSE Accept on the stream path;
//   - usage parsing follows each runtime's /v1 surface exactly: vLLM's
//     automatic prefix caching (prompt_tokens_details.cached_tokens) reaches
//     billing, Ollama's NATIVE /api shape is outside the adapter contract and
//     must yield zero usage (never fabricated numbers), llama.cpp's
//     OpenAI-compat usage parses like vLLM's;
//   - non-chat payloads (embeddings-shaped bodies, upstream error bodies)
//     pass through byte-identically, so a capability the endpoint does not
//     serve is refused by that endpoint with its precise reason (I51), never
//     rewritten or masked by the adapter.
//
// Wire-level streaming evidence through the local adapter names lives in
// pkg/upstream/local_endpoint_test.go (TestLocalEndpoint_StreamChatCapability).
// Provider-name-level include_usage injection for these runtimes is already
// pinned by config.defaultStreamUsageProviders (pkg/config/config.go, RM-03).

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// localCapabilityWalk lists the three runtimes named by N08-P04-T02. TGI is
// deliberately absent: its contract is stream-dependent (translating), not a
// thin pass-through, and the T02 card scopes vLLM/Ollama/llama.cpp.
var localCapabilityWalk = []string{"vllm", "ollama", "llamacpp"}

// TestLocalCapability_AdapterContractMatrix pins the walked capability
// contract at the adapter boundary: a single OpenAI-compatible chat endpoint
// for both stream modes, identity translation, optional Bearer auth and the
// SSE Accept header on the streaming path. A regression that quietly changed
// any of these (a second path for streaming, schema translation, a mandatory
// key, a missing Accept) must fail here before it can strand local traffic.
func TestLocalCapability_AdapterContractMatrix(t *testing.T) {
	t.Parallel()

	chatBody := []byte(`{"model":"qwen","messages":[{"role":"user","content":"ping"}]}`)

	for _, name := range localCapabilityWalk {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p, err := New(name)
			require.NoError(t, err)

			// One chat endpoint for both stream modes: the OpenAI-compatible
			// runtimes serve streaming and non-streaming chat on the same path.
			assert.Equal(t, "/v1/chat/completions", p.Path(false))
			assert.Equal(t, p.Path(false), p.Path(true),
				"%s: streaming and non-streaming chat must share the endpoint", name)

			// Identity translation in both directions: the runtimes speak the
			// OpenAI chat schema, so the adapter must not rewrite bodies.
			reqOut, err := p.TranslateRequest(chatBody)
			require.NoError(t, err)
			assert.Equal(t, string(chatBody), string(reqOut),
				"%s: TranslateRequest must be identity", name)
			respOut, err := p.TranslateResponse([]byte(`{"id":"c","choices":[]}`))
			require.NoError(t, err)
			assert.JSONEq(t, `{"id":"c","choices":[]}`, string(respOut),
				"%s: TranslateResponse must be identity", name)

			// Optional Bearer: local endpoints run keyless by default; a
			// configured key must map to Authorization: Bearer on both paths.
			for _, stream := range []bool{false, true} {
				req, perr := p.PrepareRequest(context.Background(), "http://ep", p.Path(stream), chatBody, "", stream)
				require.NoError(t, perr)
				assert.Equal(t, "POST", req.Method)
				assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
				assert.Empty(t, req.Header.Get("Authorization"),
					"%s: keyless row must not send credentials upstream", name)
				if stream {
					assert.Equal(t, "text/event-stream", req.Header.Get("Accept"),
						"%s: streaming hop must advertise SSE", name)
				} else {
					assert.Empty(t, req.Header.Get("Accept"))
				}

				req, perr = p.PrepareRequest(context.Background(), "http://ep", p.Path(stream), chatBody, "k", stream)
				require.NoError(t, perr)
				assert.Equal(t, "Bearer k", req.Header.Get("Authorization"),
					"%s: a configured key must reach the endpoint as Bearer", name)
			}

			// No model-name remap hook: these runtimes serve the name the
			// registry row carries (--served-model-name / Ollama tag /
			// llama.cpp --alias), so the adapter must not implement
			// ModelFinalizer to re-pin it.
			_, isFinalizer := p.(ModelFinalizer)
			assert.False(t, isFinalizer,
				"%s must not remap model names; the registry name IS the served name", name)
		})
	}
}

// TestLocalCapability_UsageParsingPerRuntime walks the usage capability per
// runtime with each one's realistic response shapes.
//
// The vLLM case is the billing-critical one: automatic prefix caching reports
// prompt_tokens_details.cached_tokens, and those cache reads must reach
// billing (the generic TestOpenAICompatAdapters_ParseCachedTokens covers the
// shared parser; this case documents WHY the field matters for vLLM).
//
// The Ollama native case is the limitation pin: the adapter serves Ollama's
// OpenAI-compatible /v1 surface only. Pointing the row at the native
// /api/chat shape must yield zero usage with Source "none" — never invented
// numbers — which makes the misconfiguration observable downstream instead of
// silently billing zeros (contract negative: a model without the needed
// endpoint surface is not shown working).
func TestLocalCapability_UsageParsingPerRuntime(t *testing.T) {
	t.Parallel()

	t.Run("vllm_prefix_cache_reaches_billing", func(t *testing.T) {
		t.Parallel()

		// vLLM with automatic prefix caching: cached prefix tokens are
		// reported as prompt_tokens_details.cached_tokens.
		body := []byte(`{"id":"cmpl-vllm","object":"chat.completion","model":"qwen",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":8000,"completion_tokens":50,"total_tokens":8050,` +
			`"prompt_tokens_details":{"cached_tokens":2000}}}`)
		u := (VLLM{}).ParseUsage(body)
		assert.Equal(t, int64(8000), u.PromptTokens)
		assert.Equal(t, int64(50), u.CompletionTokens)
		assert.Equal(t, int64(8050), u.TotalTokens)
		assert.Equal(t, int64(2000), u.CacheReadTokens,
			"vLLM APC cache reads must reach billing as CacheReadTokens")
		assert.Equal(t, UsageSourceProvider, u.Source)
	})

	t.Run("ollama_v1_surface_parses", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{"id":"chatcmpl-ollama","object":"chat.completion","model":"qwen2.5:7b",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":9,"completion_tokens":4,"total_tokens":13}}`)
		u := (Ollama{}).ParseUsage(body)
		assert.Equal(t, int64(9), u.PromptTokens)
		assert.Equal(t, int64(4), u.CompletionTokens)
		assert.Equal(t, int64(13), u.TotalTokens)
		assert.Equal(t, UsageSourceProvider, u.Source)
	})

	t.Run("ollama_native_api_shape_yields_zero_not_fabricated", func(t *testing.T) {
		t.Parallel()

		// Ollama's NATIVE /api/chat response: eval counts, no OpenAI usage
		// object. The adapter contract is the /v1 surface; the native shape
		// must produce zero usage classified as "none" so the gap is
		// observable, never fabricated tokens.
		body := []byte(`{"model":"qwen2.5:7b","created_at":"2026-10-28T00:00:00Z",` +
			`"message":{"role":"assistant","content":"pong"},"done":true,` +
			`"prompt_eval_count":9,"eval_count":4}`)
		u := (Ollama{}).ParseUsage(body)
		assert.Zero(t, u.PromptTokens)
		assert.Zero(t, u.CompletionTokens)
		assert.Zero(t, u.TotalTokens)
		assert.Equal(t, UsageSourceNone, u.Source,
			"native /api shape is outside the adapter contract: zero usage, not invented numbers")
	})

	t.Run("llamacpp_openai_compat_parses", func(t *testing.T) {
		t.Parallel()

		body := []byte(`{"id":"chatcmpl-llamacpp","object":"chat.completion","model":"qwen",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":11,"completion_tokens":5,"total_tokens":16}}`)
		u := (LlamaCPP{}).ParseUsage(body)
		assert.Equal(t, int64(11), u.PromptTokens)
		assert.Equal(t, int64(5), u.CompletionTokens)
		assert.Equal(t, int64(16), u.TotalTokens)
		assert.Equal(t, UsageSourceProvider, u.Source)
	})
}

// TestLocalCapability_PassthroughIsByteExact pins the refusal half of the
// capability contract (I51: unsupported capability → reject with the precise
// reason): bodies the chat endpoint cannot serve — an embeddings-shaped
// request, an upstream error object — cross TranslateRequest/TranslateResponse
// byte-identically. The adapter neither rewrites a non-chat payload into chat
// nor masks an upstream refusal: the endpoint's own error text reaches the
// client verbatim as the precise reason.
func TestLocalCapability_PassthroughIsByteExact(t *testing.T) {
	t.Parallel()

	embeddingsShaped := []byte(`{"model":"qwen","input":["text to embed"]}`)
	upstreamError := []byte(`{"error":{"message":"model does not support embeddings","type":"invalid_request_error"}}`)

	for _, name := range localCapabilityWalk {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p, err := New(name)
			require.NoError(t, err)

			for _, body := range [][]byte{embeddingsShaped, upstreamError} {
				reqOut, terr := p.TranslateRequest(body)
				require.NoError(t, terr)
				assert.Equal(t, string(body), string(reqOut),
					"%s: non-chat request payloads must pass through byte-identically", name)

				respOut, terr := p.TranslateResponse(body)
				require.NoError(t, terr)
				assert.Equal(t, string(body), string(respOut),
					"%s: upstream refusal bodies must not be rewritten — the precise reason reaches the client", name)
			}
		})
	}
}

// TestLocalCapability_PrepareRequestBodyVerbatim guards the transport half of
// the pass-through contract: the adapter must ship the translated body
// unmodified inside the outgoing request (no re-serialization drift) on both
// stream modes.
func TestLocalCapability_PrepareRequestBodyVerbatim(t *testing.T) {
	t.Parallel()

	chatBody := []byte(`{"model":"qwen:7b","messages":[{"role":"user","content":"ping"}]}`)

	for _, name := range localCapabilityWalk {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p, err := New(name)
			require.NoError(t, err)

			for _, stream := range []bool{false, true} {
				req, perr := p.PrepareRequest(context.Background(), "http://ep", p.Path(stream), chatBody, "", stream)
				require.NoError(t, perr)
				require.NotNil(t, req.Body)
				sent, rerr := io.ReadAll(req.Body)
				require.NoError(t, rerr)
				assert.Equal(t, string(chatBody), string(sent),
					"%s (stream=%v): outgoing body must be the client payload verbatim", name, stream)
			}
		})
	}
}
