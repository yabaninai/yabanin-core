package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BoundUpstreamHostLabel must return a value from a CLOSED set — the
// allowlist systems, the suffix-rule systems, and the fixed "other" /
// "unknown" buckets — for ANY input, including hostile free text. A raw host
// or URL must never surface as a label value (unbounded series cardinality).
func TestBoundUpstreamHostLabel_ClosedValueSet(t *testing.T) {
	known := map[string]struct{}{
		"openai": {}, "anthropic": {}, "gemini": {}, "vertex_ai": {},
		"deepseek": {}, "mistral_ai": {}, "x_ai": {}, "cohere": {},
		"openrouter": {}, "groq": {}, "together": {}, "fireworks": {},
		"perplexity":  {},
		"aws.bedrock": {}, "azure.ai.openai": {}, "sambanova": {},
		"other": {}, "unknown": {},
	}
	inputs := []string{
		"https://api.openai.com/v1",
		"https://api.anthropic.com/v1/messages",
		"https://generativelanguage.googleapis.com/v1",
		"https://abc123.bedrock-runtime.us-east-1.amazonaws.com",
		"https://tenant-x.openai.azure.com/openai/deployments/gpt",
		"https://host.api.sambanova.ai/v1",
		"https://self-hosted.tenant.example.com/v1",
		"http://10.0.0.7:8080/v1",
		"https://" + strings.Repeat("sub", 3000) + ".example.com", // huge unknown host
		strings.Repeat("garbage-", 500),                           // huge garbage, no scheme
		"://no-scheme",
		"",
	}
	seen := make(map[string]struct{}, len(inputs))
	for _, in := range inputs {
		v := BoundUpstreamHostLabel(in)
		_, ok := known[v]
		require.True(t, ok, "label value %q for input %.40q must be inside the closed set", v, in)
		require.LessOrEqual(t, len(v), 32, "bounded label values are short buckets, got %d bytes", len(v))
		seen[v] = struct{}{}
	}
	assert.Contains(t, seen, "openai", "known hosts map to their canonical bucket")
	assert.Contains(t, seen, "aws.bedrock", "suffix rules still resolve")
	assert.Contains(t, seen, "other", "unknown hosts bucket to the fixed value")
	assert.Contains(t, seen, "unknown", "unusable/empty input degrades to the unknown bucket")
}

// Exact-mapping pins at the three value classes: canonical allowlist bucket,
// fixed unknown-host bucket, unusable-input bucket.
func TestBoundUpstreamHostLabel_ExactBuckets(t *testing.T) {
	assert.Equal(t, "openai", BoundUpstreamHostLabel("https://api.openai.com/v1/chat/completions"))
	assert.Equal(t, "azure.ai.openai", BoundUpstreamHostLabel("https://dep-1.openai.azure.com"))
	assert.Equal(t, "other", BoundUpstreamHostLabel("https://tenant-gateway.internal:8443/v1"))
	assert.Equal(t, "unknown", BoundUpstreamHostLabel(""))
	assert.Equal(t, "unknown", BoundUpstreamHostLabel("://missing-host"))
}

// The renamed `host` label must actually exist on the gauge with the bounded
// contract: a write through the helper lands on exactly one series, and no
// `url` label series can exist anymore (never-fed metric, zero-breakage
// window — asserted here so a future emitter cannot silently regress).
func TestUpstreamHealthState_BoundedHostLabel(t *testing.T) {
	// The gauge is package-global: sibling tests (alert firing regression
	// drives, expr-metrics declaration probes) write host-label series into
	// it and leave them behind. Under -shuffle any of them may precede this
	// test, so the total-series assertion is only meaningful from a clean
	// registry — reset at entry and assert the single series this test owns.
	UpstreamHealthState.Reset()
	gauge := UpstreamHealthState.WithLabelValues(BoundUpstreamHostLabel("https://api.anthropic.com/v1"))
	gauge.Set(1)

	count := testutil.CollectAndCount(UpstreamHealthState, "gateway_upstream_health_state")
	assert.Equal(t, 1, count, "exactly one bounded-label series exists after one write")
}
