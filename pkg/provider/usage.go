// Package provider — usage & cost accounting (P3.11).
//
// ExtendedUsage augments the cross-provider Usage struct with the data
// required for billing and cost observability: an estimated USD cost and the
// provider/model context the cost was computed for.
//
// ComputeCost multiplies token counts by the per-model unit prices in
// pkg/pricing. Cache tokens are billed at their own (cheaper) rate when the
// provider reports them.

package provider

import (
	"github.com/reireirei/yabanin/pkg/pricing"
)

// ExtendedUsage is Usage + the accounting fields the event stream carries
// for downstream billing/analytics (P3.11, consumed by P11 billing). The
// shape is stable across providers — providers that don't report a given
// field leave it as zero.
type ExtendedUsage struct {
	Usage
	// EstimatedCostUSD is the dollar amount computed from Usage and the
	// pricing table. Zero when the model is unknown to pricing.Lookup.
	// PriceKnown is false in that case so callers do not treat the zero as a real price.
	EstimatedCostUSD float64
	PriceKnown       bool
	// ProviderName and ModelName record the context Cost was computed for.
	// Redundant with the surrounding request fields but useful when
	// ExtendedUsage is logged or shipped without its parent event.
	ProviderName string
	ModelName    string
}

// ComputeCost multiplies the supplied Usage by the per-model unit prices
// from pkg/pricing and returns an ExtendedUsage. Unknown (provider, model)
// combinations yield zero cost — see pricing.Lookup.
//
// Local runtime providers (vllm/ollama/llamacpp/tgi) are never priced: the
// pricing data is offline-only (embedded snapshot, no network) and a row
// under a local provider key could only be an invented cloud price for
// self-hosted serving. The lookup is skipped entirely and the result fails
// closed — PriceKnown=false (unknown, NOT free) with exactly-zero cost
// (N08-P04-T04 offline pricing semantics; predicate shared with discovery).
//
// Cache tokens are billed at their own rate:
//   - CacheReadTokens are charged at CacheReadPerM (typically 25-50% of input)
//   - CacheCreationTokens at CacheWritePerM (typically 1.25x input)
//
// Non-cache prompt tokens (PromptTokens - CacheReadTokens - CacheCreationTokens)
// are charged at InputPerM. OpenAI reports CacheCreationTokens = 0, so that
// path is unchanged. If a provider reports more cache tokens than
// PromptTokens the input portion is clamped to zero.
func ComputeCost(u Usage, providerName, modelName string) ExtendedUsage {
	if isLocalRuntimeProvider(providerName) {
		return ExtendedUsage{
			Usage:            u,
			EstimatedCostUSD: 0,
			PriceKnown:       false,
			ProviderName:     providerName,
			ModelName:        modelName,
		}
	}

	p, known := pricing.DefaultLookup(providerName, modelName)

	// Defensive: don't let a misreporting provider produce negative input cost.
	nonCacheInput := u.PromptTokens - u.CacheReadTokens - u.CacheCreationTokens
	if nonCacheInput < 0 {
		nonCacheInput = 0
	}

	cost := perM(p.InputPerM)*float64(nonCacheInput) +
		perM(p.OutputPerM)*float64(u.CompletionTokens) +
		perM(p.CacheWritePerM)*float64(u.CacheCreationTokens) +
		perM(p.CacheReadPerM)*float64(u.CacheReadTokens)

	return ExtendedUsage{
		Usage:            u,
		EstimatedCostUSD: cost,
		PriceKnown:       known,
		ProviderName:     providerName,
		ModelName:        modelName,
	}
}

// Usage source values stored on request_logs.usage_source.
const (
	UsageSourceProvider  = "provider"
	UsageSourceEstimated = "estimated"
	UsageSourceNone      = "none"
)

// perM scales a $/1M-tokens rate to $/token. Kept as a helper so the formula
// above stays readable.
func perM(rate float64) float64 { return rate / 1_000_000.0 }
