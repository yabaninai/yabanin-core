package cli

import (
	"net/http"

	"github.com/reireirei/yabanin/pkg/provider"
)

// PromptCacheHeader is the responses header reporting whether the upstream provider served the request's
// prompt (partially) from its NATIVE prompt cache — the cache the provider
// itself maintains (Anthropic cache_read_input_tokens, OpenAI
// prompt_tokens_details.cached_tokens), not the gateway's semantic response
// cache (that one surfaces as X-Cache).
const PromptCacheHeader = "X-Yabanin-Prompt-Cache"

// promptCacheOutcome maps provider-reported usage cache fields to the
// transparency header value (D4):
//
//   - "hit"  — the provider reported cached prompt tokens read
//     (Usage.CacheReadTokens > 0);
//   - "miss" — the provider reported usage, with no cached tokens read;
//   - ""     — no provider usage was parsed at all; there is nothing to
//     report and the header stays absent (never fabricate an outcome).
//
// The value derives exclusively from the upstream usage block (D5: the same
// fields that bill at CacheReadPerM/CacheWritePerM), so the header can never
// disagree with the accounting.
func promptCacheOutcome(u provider.Usage) string {
	if u.Source != provider.UsageSourceProvider {
		return ""
	}
	if u.CacheReadTokens > 0 {
		return "hit"
	}
	return "miss"
}

// setPromptCacheHeader reports the provider prompt-cache outcome on a
// buffered (non-streaming) JSON response. It MUST run before WriteHeader.
// Absent when no provider usage was parsed — never fabricate an outcome.
func setPromptCacheHeader(w http.ResponseWriter, u provider.Usage) {
	if outcome := promptCacheOutcome(u); outcome != "" {
		w.Header().Set(PromptCacheHeader, outcome)
	}
}

// setPromptCacheTrailer reports the provider prompt-cache outcome on a
// streaming response as an HTTP trailer (N03-P06-T02: SSE transparency).
//
// SSE headers are committed with the first relayed byte, but the outcome
// derives from usage that only arrives with the stream tail (OpenAI-compat
// trailing usage chunk, Anthropic message_delta) — the header channel cannot
// carry it without buffering the stream. http.TrailerPrefix delivers the
// value after the final chunk: HTTP/1.1 chunked (SSE has no Content-Length)
// and HTTP/2 both support it, and not a single SSE byte or event changes
// (the N03-P01 event contract is untouched). Clients that never read
// trailers see a byte-identical body.
//
// Absent when no provider usage was parsed — never fabricate an outcome.
// The apiformat AnthropicStreamWriter forwards http.TrailerPrefix entries to
// the client at Finish (N07-P01-T02: adapted /v1/messages SSE parity with
// the native relay). On a writer that snapshots headers at commit and never
// re-reads them this stays a silent no-op: transparency is best-effort on
// such wrapped shapes, authoritative accounting stays in the usage event.
func setPromptCacheTrailer(w http.ResponseWriter, u provider.Usage) {
	if outcome := promptCacheOutcome(u); outcome != "" {
		w.Header().Set(http.TrailerPrefix+PromptCacheHeader, outcome)
	}
}
