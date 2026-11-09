// Package provider abstracts upstream LLM API providers (OpenAI, Anthropic,
// custom) behind a single interface so the gateway can route to any of them
// without hardcoded paths or auth schemes.
package provider

import (
	"context"
	"net/http"
)

// Provider abstracts a single upstream LLM API. Implementations must be safe
// for concurrent use — the same instance is shared across all goroutines via
// the upstream.Pool.
type Provider interface {
	// Name returns the canonical provider identifier ("openai", "anthropic",
	// "openai-compat", ...). Used as a Pool key alongside the base URL.
	Name() string

	// Path returns the upstream path for either streaming or non-streaming
	// chat-completion requests. Examples:
	//   - OpenAI:     /v1/chat/completions (same for both)
	//   - Anthropic:  /v1/messages
	Path(stream bool) string

	// PrepareRequest builds the outgoing *http.Request — URL, headers, body.
	// Implementations set provider-specific auth (Bearer vs x-api-key) and
	// required headers (e.g. anthropic-version). The body is passed through
	// unchanged; cross-schema translation is the job of TranslateRequest.
	PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error)

	// ParseUsage extracts token counts from a non-streaming upstream response.
	// Shape differs per provider; the gateway treats the result uniformly.
	ParseUsage(respBody []byte) Usage

	// TranslateRequest converts an OpenAI ChatCompletionRequest body into the
	// provider's native request schema. For openai-compat it is identity.
	TranslateRequest(openaiBody []byte) ([]byte, error)

	// TranslateResponse converts a provider's native non-streaming response
	// back into an OpenAI ChatCompletionResponse shape so the gateway can
	// serve a single response contract to clients. For openai-compat it is
	// identity.
	TranslateResponse(providerBody []byte) ([]byte, error)
}

// ModelFinalizer is the OPTIONAL adapter hook invoked by the upstream client
// AFTER its per-hop model override. The override writes the requested registry
// name into "model", which would clobber adapters whose upstream requires one
// canonical served-model name (e.g. jais). Implementations re-assert the name
// the upstream actually serves; the override argument is the name the gateway
// just wrote (ignore it when pinning).
type ModelFinalizer interface {
	FinalizeModel(body []byte, overridden string) []byte
}

// Usage is the cross-provider token usage representation.
//
// Canonical token semantics: PromptTokens counts every input token of the
// request, including cache reads and cache writes. CacheReadTokens and
// CacheCreationTokens are subsets of PromptTokens (both stay zero when the
// provider does not report them). TotalTokens = PromptTokens + CompletionTokens.
// Providers that omit a metric leave that field zero.
type Usage struct {
	PromptTokens        int64
	CompletionTokens    int64
	TotalTokens         int64
	CacheReadTokens     int64 // OpenAI: prompt_tokens_details.cached_tokens; Anthropic: cache_read_input_tokens
	CacheCreationTokens int64 // Anthropic: cache_creation_input_tokens
	// Source is provider, estimated, or none. Empty means the caller has not classified it yet.
	Source string
}
