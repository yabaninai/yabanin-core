// Package metrics — per-provider / fallback / retry metrics (P3.19).
//
// These collectors give operators visibility into multi-provider routing:
// which providers are healthy, which models are failing, how often fallback
// chains engage, and where retry budget is being consumed.
//
// All collectors here are registered via metrics.Init (see metrics.go) and
// exposed on the /metrics admin endpoint alongside the HTTP/circuit ones.

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Per-provider upstream metrics. Labels:
//   - provider: "openai", "anthropic", "openai-compat", ...
//   - model:    the model name as resolved by the resolver
//   - status:   HTTP status code from the upstream (or "0" for transport errors)
var (
	UpstreamRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "upstream_requests_total",
			Help:      "Total upstream requests by provider/model/status. Status 0 = transport error.",
		},
		[]string{"provider", "model", "status"},
	)

	UpstreamDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "upstream_duration_seconds",
			Help:      "Upstream request duration by provider/model.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"provider", "model"},
	)

	UpstreamTokensTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "upstream_tokens_total",
			Help:      "Tokens exchanged with upstream, by provider/model/direction (prompt|completion|cache_read|cache_creation).",
		},
		[]string{"provider", "model", "direction"},
	)

	UpstreamCostUSD = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "upstream_cost_usd_total",
			Help:      "Estimated USD cost routed through each provider/model (sum over the lifetime of the process).",
		},
		[]string{"provider", "model"},
	)
)

// Fallback/retry metrics. Labels:
//   - from / to:  source and target model names when the chain advances
//   - reason:     the upstream status code (or "transport") that triggered fallback
//   - attempt:    retry attempt number ("0" = first try, "1" = first retry, ...)
//   - status:     HTTP status code of the retried attempt
var (
	FallbackTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "fallback_total",
			Help:      "Fallback events: chain advanced from one model to another. Reason is the triggering status code or 'transport'.",
		},
		[]string{"from", "to", "reason"},
	)

	RetryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "retry_total",
			Help:      "Retry attempts by attempt number and resulting status. Incremented once per retry (not per try).",
		},
		[]string{"attempt", "status"},
	)
)

// UpstreamHealthState tracks the latest health-check result per upstream.
// Values: 0 = unknown (no probe yet), 1 = healthy, 2 = degraded, 3 = unhealthy.
//
// Label contract (N13-P02-T03): the `host` label value MUST come from
// BoundUpstreamHostLabel — a bounded provider bucket, never the raw URL.
// Feeding a raw tenant-configurable URL into a Prometheus label would mint
// a permanent new time series per distinct base URL (unbounded series
// cardinality). The label was previously named `url` and has never
// been fed by any emitter (zero series exist), so the rename breaks nothing.
var UpstreamHealthState = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Subsystem: subsystem,
		Name:      "upstream_health_state",
		Help:      "Health-check state per upstream provider bucket (0 unknown, 1 healthy, 2 degraded, 3 unhealthy). Label `host` is a bounded value from BoundUpstreamHostLabel, never a raw URL.",
	},
	[]string{"host"},
)

// UpstreamFirstTokenSeconds is the time-to-first-token for streaming
// responses, measured from request start to the first upstream SSE byte
// (Bifrost parity: bifrost_stream_first_token_latency_seconds). Only
// observed for streams that produced at least one token.
var UpstreamFirstTokenSeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Subsystem: subsystem,
		Name:      "upstream_first_token_seconds",
		Help:      "Time to first streamed token by provider/model. Non-streaming requests are not observed.",
		Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	},
	[]string{"provider", "model"},
)

// upstreamCollectors is appended to allCollectors in metrics.go via init() so
// Init() registers them alongside the HTTP/circuit/loggerd collectors.
var upstreamCollectors = []prometheus.Collector{
	UpstreamRequestsTotal,
	UpstreamDurationSeconds,
	UpstreamTokensTotal,
	UpstreamCostUSD,
	FallbackTotal,
	RetryTotal,
	UpstreamHealthState,
	UpstreamFirstTokenSeconds,
}

// init merges upstream collectors into allCollectors at package load. This
// runs after the allCollectors slice is initialised in metrics.go.
func init() {
	allCollectors = append(allCollectors, upstreamCollectors...)
}
