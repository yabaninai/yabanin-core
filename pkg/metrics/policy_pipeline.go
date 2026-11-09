package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// OP-8 gateway policy pipeline: one run counter plus outcome counters and a
// per-run duration histogram. Labels:
//   - policy: the policy NAME from the YAML document (policystore pipelines
//     are named; uuids stay out of the metrics cardinality);
//   - endpoint: the gateway surface ("chat", "messages", ...);
//   - outcome (runs only): the composed verdict of that policy's run —
//     allow | flag | mask | deny.
//
// No payload content, category or severity is ever a label value.
var (
	GatewayPolicyLoadFailuresTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "policy_load_failures_total",
			Help:      "Policy store load failures by runtime mode and cache state.",
		},
		[]string{"mode", "cache_state"},
	)

	GatewayPolicyRunsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "policy_runs_total",
			Help:      "Policy pipeline runs by policy, endpoint and outcome (allow/flag/mask/deny).",
		},
		[]string{"policy", "endpoint", "outcome"},
	)

	GatewayPolicyEffectiveInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Subsystem: subsystem,
			Name:      "policy_effective_info",
			Help:      "Effective policy snapshot identity by policy and SHA-256 hash; value is 1 for every observed snapshot.",
		},
		[]string{"policy", "effective_hash"},
	)

	GatewayPolicyDeniesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "policy_denies_total",
			Help:      "Policy runs whose composed verdict was deny (enforce-effective policies only).",
		},
		[]string{"policy", "endpoint"},
	)

	GatewayPolicyMasksTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "policy_masks_total",
			Help:      "Policy runs that mutated the payload (mask verdict or any content change).",
		},
		[]string{"policy", "endpoint"},
	)

	GatewayPolicyShadowFlagsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "policy_shadow_flags_total",
			Help:      "Findings recorded by shadow-mode policy runs (what enforce would have done).",
		},
		[]string{"policy", "endpoint"},
	)

	GatewayPolicyDurationMs = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "policy_duration_ms",
			Help:      "Wall-clock duration of one policy pipeline run in milliseconds.",
			Buckets:   []float64{0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
		},
		[]string{"policy", "endpoint"},
	)
)

var policyCollectors = []prometheus.Collector{
	GatewayPolicyLoadFailuresTotal,
	GatewayPolicyRunsTotal,
	GatewayPolicyEffectiveInfo,
	GatewayPolicyDeniesTotal,
	GatewayPolicyMasksTotal,
	GatewayPolicyShadowFlagsTotal,
	GatewayPolicyDurationMs,
}

func init() {
	allCollectors = append(allCollectors, policyCollectors...)
}
