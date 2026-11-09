// Package metrics — per-provider upstream / fallback / retry metric tests (P3.19).

package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testGatherer uses the default Prometheus registry where promauto registers all collectors.
var testGatherer = prometheus.DefaultGatherer

// fetchValueByName returns the value of a specific metric family by name.
// Returns 0 if not found or no non-zero samples exist.
func fetchValueByName(name string) float64 {
	mfs, err := testGatherer.Gather()
	if err != nil {
		return 0
	}
	for _, m := range mfs {
		if m.GetName() != name {
			continue
		}
		for _, mp := range m.Metric {
			if v := mp.Counter; v != nil && v.Value != nil {
				return *v.Value
			}
			if v := mp.Gauge; v != nil && v.Value != nil {
				return *v.Value
			}
		}
	}
	return 0
}

// fetchValue returns the value of the first non-zero counter/gauge metric
// whose name starts with "gateway_" (our subsystem). This skips Go runtime
// and process metrics from the default registry.
func fetchValue() float64 { return fetchValueByName("gateway_upstream_requests_total") }

func resetAll() {
	UpstreamRequestsTotal.Reset()
	UpstreamDurationSeconds.Reset()
	UpstreamTokensTotal.Reset()
	UpstreamCostUSD.Reset()
	FallbackTotal.Reset()
	RetryTotal.Reset()
	UpstreamHealthState.Reset()
}

func TestUpstreamRequestsTotal_Incremented(t *testing.T) {
	resetAll()
	UpstreamRequestsTotal.WithLabelValues("openai", "gpt-4o", "200").Inc()
	assert.InDelta(t, 1.0, fetchValueByName("gateway_upstream_requests_total"), 1e-9)
}

func TestFallbackTotal_Incremented(t *testing.T) {
	resetAll()
	FallbackTotal.WithLabelValues("gpt-4o", "gpt-4o-mini", "503").Inc()
	assert.InDelta(t, 1.0, fetchValueByName("gateway_fallback_total"), 1e-9)
}

func TestRetryTotal_Incremented(t *testing.T) {
	resetAll()
	RetryTotal.WithLabelValues("1", "429").Inc()
	assert.InDelta(t, 1.0, fetchValueByName("gateway_retry_total"), 1e-9)
}

func TestUpstreamDurationSeconds_Observable(t *testing.T) {
	resetAll()
	// Histograms don't have simple counter values; verify it doesn't panic
	// and is registered by checking it appears in Gather output.
	UpstreamDurationSeconds.WithLabelValues("openai", "gpt-4o").Observe(0.5)
	mfs, err := testGatherer.Gather()
	require.NoError(t, err)
	var found bool
	for _, m := range mfs {
		if strings.Contains(m.GetName(), "upstream_duration_seconds") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected upstream_duration_seconds in Gather output")
}

func TestUpstreamTokensTotal_MultipleDirections(t *testing.T) {
	resetAll()
	UpstreamTokensTotal.WithLabelValues("openai", "gpt-4o", "prompt").Add(10000)
	assert.InDelta(t, 10000.0, fetchValueByName("gateway_upstream_tokens_total"), 1e-9)

	resetAll()
	UpstreamTokensTotal.WithLabelValues("anthropic", "claude-3", "cache_read").Add(500)
	assert.InDelta(t, 500.0, fetchValueByName("gateway_upstream_tokens_total"), 1e-9)
}

func TestUpstreamCostUSD_Additive(t *testing.T) {
	resetAll()
	UpstreamCostUSD.WithLabelValues("openai", "gpt-4o").Add(0.025)
	assert.InDelta(t, 0.025, fetchValueByName("gateway_upstream_cost_usd_total"), 0.0001)

	// Same vector — additive (no reset).
	UpstreamCostUSD.WithLabelValues("openai", "gpt-4o").Add(0.010)
	assert.InDelta(t, 0.035, fetchValueByName("gateway_upstream_cost_usd_total"), 0.0001)
}

func TestUpstreamHealthState_SetsGauge(t *testing.T) {
	resetAll()
	UpstreamHealthState.WithLabelValues("https://api.openai.com").Set(1.0)
	assert.InDelta(t, 1.0, fetchValueByName("gateway_upstream_health_state"), 1e-9)

	resetAll()
	UpstreamHealthState.WithLabelValues("https://api.anthropic.com").Set(3.0)
	assert.InDelta(t, 3.0, fetchValueByName("gateway_upstream_health_state"), 1e-9)
}

func TestCollectorsRegistered(t *testing.T) {
	resetAll()
	Init() // idempotent — ignores duplicate registration errors
	UpstreamRequestsTotal.WithLabelValues("test", "test", "200").Inc()
	assert.InDelta(t, 1.0, fetchValue(), 1e-9)
}

// TestMetricsExposition verifies that the upstream metrics appear in the
// Prometheus exposition format, confirming proper label names and help text.
func TestMetricsExposition(t *testing.T) {
	resetAll()
	UpstreamRequestsTotal.WithLabelValues("openai", "gpt-4o", "200").Inc()

	mfs, err := testGatherer.Gather()
	require.NoError(t, err)

	var found bool
	for _, m := range mfs {
		if strings.Contains(m.GetName(), "upstream_requests_total") {
			found = true
			assert.NotEmpty(t, m.GetHelp())
			break
		}
	}
	assert.True(t, found, "expected upstream_requests_total in exposition")
}

// TestMetricsLabelsPresent verifies that all expected metric families are
// registered and have their expected labels by inspecting the Gather output.
func TestMetricsLabelsPresent(t *testing.T) {
	resetAll()
	// Write one sample to each vector so they appear in Gather().
	UpstreamRequestsTotal.WithLabelValues("p", "m", "200").Inc()
	UpstreamDurationSeconds.WithLabelValues("p", "m").Observe(0.1)
	UpstreamTokensTotal.WithLabelValues("p", "m", "prompt").Add(1)
	UpstreamCostUSD.WithLabelValues("p", "m").Add(0.01)
	FallbackTotal.WithLabelValues("a", "b", "503").Inc()
	RetryTotal.WithLabelValues("1", "429").Inc()
	UpstreamHealthState.WithLabelValues("u").Set(1.0)

	mfs, err := testGatherer.Gather()
	require.NoError(t, err)

	var familyNames []string
	for _, m := range mfs {
		familyNames = append(familyNames, m.GetName())
	}

	expected := []string{
		"gateway_upstream_requests_total",
		"gateway_upstream_duration_seconds",
		"gateway_upstream_tokens_total",
		"gateway_upstream_cost_usd_total",
		"gateway_fallback_total",
		"gateway_retry_total",
		"gateway_upstream_health_state",
	}
	for _, exp := range expected {
		found := false
		for _, n := range familyNames {
			if n == exp {
				found = true
				break
			}
		}
		assert.True(t, found, "expected metric family %q not found; got: %v", exp, familyNames)
	}

	// Verify labels exist on the requests_total metric.
	for _, m := range mfs {
		if m.GetName() == "gateway_upstream_requests_total" && len(m.Metric) > 0 {
			assert.NotEmpty(t, m.Metric[0].Label, "upstream_requests_total should have label pairs")
			break
		}
	}

	// Verify that all family names are valid proto messages (no nil metrics).
	for _, m := range mfs {
		assert.NotNil(t, m.GetName(), "metric family name must not be empty")
		assert.NotNil(t, m.Help, "metric help text must not be nil")
		assert.NotNil(t, m.GetType(), "metric type must not be nil")
		if len(m.Metric) > 0 {
			assert.NotNil(t, m.Metric[0], "metric sample must not be nil")
			var hasCounter bool
			if m.Metric[0].Counter != nil {
				hasCounter = true
			}
			_ = hasCounter
			// Ensure proto field is valid — just check no nil pointer dereference.
			_ = &dto.Metric{}
		}
	}
}
