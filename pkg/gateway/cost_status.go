package cli

import "github.com/reireirei/yabanin/pkg/provider"

// costStatus classifies a completed or failed request for request_logs.cost_status.
// A cache hit wins over token and price state. Missing usage is no_usage even
// when the dollar amount is zero. Unknown prices stay distinct from a real zero.
func usageSourceOrNone(source string) string {
	if source == "" {
		return provider.UsageSourceNone
	}
	return source
}

func costStatus(cacheHit bool, usageSource string, priceKnown bool) string {
	if cacheHit {
		return "cache_hit"
	}
	if usageSource == "" || usageSource == provider.UsageSourceNone {
		return "no_usage"
	}
	if !priceKnown {
		return "unknown_price"
	}
	return "priced"
}

// costStatusUnit lifts a no_usage classification to priced when the request
// was settled through a non-token unit rate (T02): the cost is real and
// catalog-priced even though the upstream reported no token usage (speech
// never reports tokens; transcriptions/images without a usage block).
// Any other base status is returned unchanged.
func costStatusUnit(base string, unitPriced bool) string {
	if unitPriced && base == "no_usage" {
		return "priced"
	}
	return base
}
