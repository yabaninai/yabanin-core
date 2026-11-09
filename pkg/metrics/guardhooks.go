package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// GuardHooksTotal counts pre-egress guard-hook detections, labelled by the
// active mode, the sensitive-data category, and the outcome (log/redact/deny).
// Card U1. It is only incremented when the hooks are enabled (mode != off).
var GuardHooksTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "",
		Subsystem: subsystem,
		Name:      "guard_hooks_total",
		Help:      "Total guard-hook detections by mode, category and outcome.",
	},
	[]string{"mode", "category", "outcome"},
)

// GuardFindingsTruncatedTotal counts guardrail findings dropped after the
// per-request cap (guardhooks.MaxFindingsPerDetection). It is incremented at
// least once per truncated evaluation, so operators can tell when a request
// produced more findings than the retained bound.
var GuardFindingsTruncatedTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "",
		Subsystem: subsystem,
		Name:      "guard_findings_truncated_total",
		Help:      "Guardrail findings dropped after the per-request findings cap.",
	},
)

var guardHooksCollectors = []prometheus.Collector{
	GuardHooksTotal,
	GuardFindingsTruncatedTotal,
}

func init() {
	allCollectors = append(allCollectors, guardHooksCollectors...)
}
