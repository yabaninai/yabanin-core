package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// anthropicVersion is the required API version header for the Messages API.
const anthropicVersion = "2023-06-01"

// anthropicBetaPromptCaching is the beta header value that enables Anthropic's
// prompt caching feature. When present, Anthropic caches content blocks marked
// with cache_control and reuses them on subsequent requests — reducing latency
// and cost for repeated system prompts or long shared context.
const anthropicBetaPromptCaching = "prompt-caching-2024-07-31"

// Anthropic is the adapter for Anthropic's native Messages API
// (POST /v1/messages). Auth uses x-api-key + anthropic-version; request and
// response bodies differ from OpenAI and are translated on the fly.
type Anthropic struct{}

// NewAnthropic returns a stateless Anthropic adapter.
func NewAnthropic() Anthropic { return Anthropic{} }

// Name returns the provider identifier used in logs and metrics.
// Name.
func (Anthropic) Name() string { return "anthropic" }

// Path returns the upstream API path for this provider.
// Path.
func (Anthropic) Path(_ bool) string { return "/v1/messages" }

// PrepareRequest adapts the gateway request for this provider's upstream.
// PrepareRequest.
func (Anthropic) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("build anthropic request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	// Prompt-caching: forward the beta header whenever the body contains a
	// cache_control marker (e.g. {"cache_control":{"type":"ephemeral"}}).
	// The presence of this pattern is sufficient — Anthropic ignores the
	// header when no cache blocks are present, so it is safe to always add
	// here as well; but for clarity we gate on actual intent.
	if hasCacheControl(body) {
		req.Header.Set("anthropic-beta", anthropicBetaPromptCaching)
	}
	return req, nil
}

// hasCacheControl reports whether a JSON body contains any cache_control block.
// This is a lightweight scan: it looks for the literal key "cache_control" in
// the raw bytes so we don't need to fully parse the payload.
func hasCacheControl(body []byte) bool {
	return strings.Contains(string(body), "\"cache_control\"")
}

// TranslateRequest converts an OpenAI ChatCompletionRequest body to Anthropic
// Messages API shape. See chatToAnthropicRequest.
func (Anthropic) TranslateRequest(openaiBody []byte) ([]byte, error) {
	return chatToAnthropicRequest(openaiBody)
}

// TranslateResponse converts a non-streaming Anthropic Messages response into
// an OpenAI ChatCompletionResponse shape. See anthropicToChatResponse.
func (Anthropic) TranslateResponse(body []byte) ([]byte, error) {
	return anthropicToChatResponse(body)
}

// ParseUsage extracts token counts from an Anthropic Messages response,
// including cache-related fields (for P3.9 prompt-caching accounting).
//
// TranslateResponse normalized it to the OpenAI contract — for that shape
// (a usage block with prompt_tokens and no input_tokens) the OpenAI fields
// are read instead: prompt_tokens_details.cached_tokens maps to
// CacheReadTokens and prompt_tokens_details.cache_creation_input_tokens
// (emitted by anthropicToChatResponse) to CacheCreationTokens, so cache
// billing (D5) survives the translation round-trip. The native
// /v1/messages path keeps feeding provider-native bodies and is unchanged.
func (Anthropic) ParseUsage(body []byte) Usage {
	var resp struct {
		Usage *struct {
			InputTokens              *int64 `json:"input_tokens"`
			OutputTokens             *int64 `json:"output_tokens"`
			CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
			// OpenAI-contract fields, present only on translated bodies.
			PromptTokens     *int64 `json:"prompt_tokens"`
			CompletionTokens *int64 `json:"completion_tokens"`
			Details          *struct {
				CachedTokens             int64 `json:"cached_tokens"`
				CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(body, &resp)
	if resp.Usage == nil {
		return Usage{Source: UsageSourceNone}
	}
	u := resp.Usage
	if u.InputTokens == nil && u.PromptTokens != nil {
		// Translated (OpenAI-contract) shape: the canonical prompt_tokens
		// already includes the cache read and write portions.
		prompt := *u.PromptTokens
		completion := int64(0)
		if u.CompletionTokens != nil {
			completion = *u.CompletionTokens
		}
		usage := Usage{
			PromptTokens:     prompt,
			CompletionTokens: completion,
			TotalTokens:      prompt + completion,
			Source:           UsageSourceProvider,
		}
		if u.Details != nil {
			usage.CacheReadTokens = u.Details.CachedTokens
			usage.CacheCreationTokens = u.Details.CacheCreationInputTokens
		}
		return usage
	}
	if u.InputTokens == nil {
		return Usage{Source: UsageSourceNone}
	}
	// Anthropic input_tokens excludes cache read and cache creation.
	// Canonical PromptTokens includes both.
	prompt := *u.InputTokens +
		derefInt64(u.CacheReadInputTokens) +
		derefInt64(u.CacheCreationInputTokens)
	output := derefInt64(u.OutputTokens)
	return Usage{
		PromptTokens:        prompt,
		CompletionTokens:    output,
		TotalTokens:         prompt + output,
		CacheReadTokens:     derefInt64(u.CacheReadInputTokens),
		CacheCreationTokens: derefInt64(u.CacheCreationInputTokens),
		Source:              UsageSourceProvider,
	}
}

// derefInt64 returns *v, or 0 for nil (absent JSON fields carry no value).
func derefInt64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// mapAnthropicStop converts Anthropic stop_reason values to OpenAI
// finish_reason equivalents. Unknown reasons default to "stop". "refusal" is
// explicit: a refusal must never masquerade as a normally completed answer
// (the reverse direction maps content_filter back to refusal), N07-P01-T03.
func mapAnthropicStop(reason string) string {
	switch reason {
	case "end_turn", "stop_sequence", "":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "refusal":
		return "content_filter"
	default:
		return "stop"
	}
}
