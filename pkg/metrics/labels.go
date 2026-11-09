package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// LabelsDroppedTotal counts labels discarded by reason.
	LabelsDroppedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "yabanin",
			Name:      "labels_dropped_total",
			Help:      "Labels dropped while resolving a request.",
		},
		[]string{"reason"},
	)
	// LabelsRequestsTotal counts requests by whether any label survived.
	LabelsRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "yabanin",
			Name:      "labels_requests_total",
			Help:      "Requests seen by the label middleware.",
		},
		[]string{"has_labels"},
	)
	// RollupRefreshSeconds is the duration of one rollup window rewrite.
	RollupRefreshSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "yabanin",
			Name:      "rollup_refresh_seconds",
			Help:      "Duration of an analytics rollup window refresh.",
		},
	)
	// RollupRefreshErrorsTotal counts failed rollup refreshes.
	RollupRefreshErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "yabanin",
			Name:      "rollup_refresh_errors_total",
			Help:      "Analytics rollup refreshes that returned an error.",
		},
	)
)
