package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Regression: cache-hit events carried CounterfactualCostUSD = 0, so the
// cache never contributed savings and streaming events carried no
// counterfactual at all — SUM(counterfactual_cost_usd) collapsed toward 0
// and the savings percentage exploded negative on streaming-heavy traffic
// (observed −24,595% on the local stand).

func TestCachedUsageCounterfactual_PricesCachedUsage(t *testing.T) {
	doc := []byte(`{
		"id": "resp-1",
		"model": "glm-5.3-flash",
		"choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
		"usage": {"prompt_tokens": 2015, "completion_tokens": 10, "total_tokens": 2025}
	}`)

	got := cachedUsageCounterfactual(doc, "openai", "gpt-4o")
	assert.Greater(t, got, 0.0, "priced usage must yield a positive counterfactual")
}

func TestCachedUsageCounterfactual_UnknownUsageStaysZero(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"not json", []byte("garbage")},
		{"no usage", []byte(`{"id":"x","choices":[]}`)},
		{"empty usage", []byte(`{"usage":{"prompt_tokens":0,"completion_tokens":0}}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.InDelta(t, 0.0, cachedUsageCounterfactual(tc.data, "openai", "gpt-4o"), 1e-12,
				"unknown counterfactual must read as 0, never fabricated")
		})
	}
}
