// Package pricing holds per-model unit prices used for estimated cost
// accounting (P3.11). Prices are USD per 1 million tokens at the rates
// published by each provider; cache prices apply only to providers that
// support prompt caching (Anthropic, OpenAI cached tokens).
//
// The static table here is intentionally minimal — it covers the models we
// seed in P3.16 and exists so the gateway can publish estimated_cost_usd on
// every routing event. P11 will replace this with a DB-backed lookup
// (`pricing_table` table) so operators can update prices without redeploys.
package pricing

// Price is the per-1M-token unit price for one model variant. All fields are
// USD per 1,000,000 tokens. A zero Price (the default for unknown models)
// yields zero cost in ComputeCost, so unknown models are silently reported
// as $0 rather than failing the request.
type Price struct {
	InputPerM      float64 // $ per 1M prompt tokens (non-cached).
	OutputPerM     float64 // $ per 1M completion tokens.
	CacheWritePerM float64 // $ per 1M prompt-cache-write tokens (Anthropic cache_creation_input_tokens).
	CacheReadPerM  float64 // $ per 1M prompt-cache-read tokens.
}

// table is keyed by "provider:model". Lookup falls back to Price{} (zero)
// for unknown combinations — see package docs for why.
//
// Rates are taken from each provider's public pricing page at the time of
// P3.16 seed-data authoring. When prices change, update this table (and the
// matching seed SQL) in the same commit.
var table = map[string]Price{
	// ---- OpenAI ----
	"openai:gpt-4o":        {InputPerM: 2.5, OutputPerM: 10.0, CacheWritePerM: 3.125, CacheReadPerM: 1.25},
	"openai:gpt-4o-mini":   {InputPerM: 0.15, OutputPerM: 0.6, CacheWritePerM: 0.1875, CacheReadPerM: 0.075},
	"openai:gpt-4-turbo":   {InputPerM: 10.0, OutputPerM: 30.0, CacheWritePerM: 0, CacheReadPerM: 5.0},
	"openai:gpt-4":         {InputPerM: 30.0, OutputPerM: 60.0},
	"openai:gpt-3.5-turbo": {InputPerM: 0.5, OutputPerM: 1.5},

	// ---- Anthropic ----
	"anthropic:claude-3-5-sonnet-20241022": {InputPerM: 3.0, OutputPerM: 15.0, CacheWritePerM: 3.75, CacheReadPerM: 0.3},
	"anthropic:claude-3-5-sonnet-latest":   {InputPerM: 3.0, OutputPerM: 15.0, CacheWritePerM: 3.75, CacheReadPerM: 0.3},
	"anthropic:claude-3-5-haiku-20241022":  {InputPerM: 0.8, OutputPerM: 4.0, CacheWritePerM: 1.0, CacheReadPerM: 0.08},
	"anthropic:claude-3-5-haiku-latest":    {InputPerM: 0.8, OutputPerM: 4.0, CacheWritePerM: 1.0, CacheReadPerM: 0.08},
	"anthropic:claude-3-opus-20240229":     {InputPerM: 15.0, OutputPerM: 75.0, CacheWritePerM: 18.75, CacheReadPerM: 1.5},
}

// Lookup returns the Price for the given (provider, model) pair. Returns the
// zero Price when the combination is unknown — callers SHOULD treat the
// resulting $0 cost as "unknown" rather than "free" in user-facing surfaces.
func Lookup(provider, model string) Price {
	if p, ok := table[provider+":"+model]; ok {
		return p
	}
	return Price{}
}
