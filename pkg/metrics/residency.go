package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ResidencyEnforcementTotal counts residency decisions, labelled by region and
// decision ("allowed" / "denied").
var ResidencyEnforcementTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Subsystem: subsystem,
		Name:      "residency_enforcement_total",
		Help:      "Residency policy decisions per region (allowed/denied).",
	},
	[]string{"region", "decision"},
)

// ResidencyRemapTotal counts how often a denied model was remapped in-region.
var ResidencyRemapTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Subsystem: subsystem,
		Name:      "residency_remap_total",
		Help:      "Residency remaps (denied → in-region model) per region.",
	},
	[]string{"region"},
)

// ResidencyEvaluationSeconds times a single pack evaluation.
var ResidencyEvaluationSeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Subsystem: subsystem,
		Name:      "residency_evaluation_seconds",
		Help:      "Duration of a residency pack evaluation.",
		Buckets:   prometheus.DefBuckets,
	},
	[]string{"pack_id"},
)

// ResidencyEgressDeniedTotal counts per-egress-kind residency denials
// (N09-P05-T02), labelled by the data kind ("inference", "embeddings",
// "logs", "export", "tools"), the denied ISO country code and the matched
// rule ("kind_excluded", "kind_not_allowed", "org_excluded"). Labels are
// bounded: kinds and rules are closed sets, countries come from the
// deployment's configured regions.
var ResidencyEgressDeniedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Subsystem: subsystem,
		Name:      "residency_egress_denied_total",
		Help:      "Per-egress-kind residency denials by kind, country and rule.",
	},
	[]string{"kind", "country", "rule"},
)
