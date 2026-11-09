package provider

import "encoding/json"

// openAIParseUsage extracts token counts from an OpenAI-shaped (or any
// OpenAI-compatible: Sakana/Sarvam/Mistral/...) non-streaming response body.
// Shared by all OpenAI-compat adapters — sovereign and local — so usage
// parsing stays in one place and every adapter parses back the same fields
// the provider actually sends (N03-P06-T04: billing must follow real usage).
//
// Cache-read sources, mirroring the SSE parser (stream.go RM-03):
//   - prompt_tokens_details.cached_tokens — OpenAI, DeepSeek (current),
//     GLM/Z.ai, vLLM automatic prefix caching;
//   - prompt_cache_hit_tokens — the legacy DeepSeek field, used only when
//     prompt_tokens_details is absent so a provider reporting both is never
//     double-counted.
func openAIParseUsage(respBody []byte) Usage {
	var resp struct {
		Usage *struct {
			PromptTokens        int64 `json:"prompt_tokens"`
			CompletionTokens    int64 `json:"completion_tokens"`
			TotalTokens         int64 `json:"total_tokens"`
			PromptTokensDetails *struct {
				CachedTokens int64 `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
			PromptCacheHitTokens int64 `json:"prompt_cache_hit_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(respBody, &resp)
	var u Usage
	if resp.Usage != nil {
		u.PromptTokens = resp.Usage.PromptTokens
		u.CompletionTokens = resp.Usage.CompletionTokens
		u.TotalTokens = resp.Usage.TotalTokens
		u.Source = UsageSourceProvider
		if resp.Usage.PromptTokensDetails != nil {
			u.CacheReadTokens = resp.Usage.PromptTokensDetails.CachedTokens
		} else if resp.Usage.PromptCacheHitTokens > 0 {
			u.CacheReadTokens = resp.Usage.PromptCacheHitTokens
		}
	} else {
		u.Source = UsageSourceNone
	}
	return u
}
