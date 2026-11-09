package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// TokenBudgetTotal counts per-task / per-session token-budget outcomes,
// labelled by scope (task|session) and outcome (ok|warn|exceeded). Card G3.
// It is only incremented when the corresponding budget is enabled (> 0).
var TokenBudgetTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "",
		Subsystem: subsystem,
		Name:      "token_budget_total",
		Help:      "Total token-budget checks by scope and outcome.",
	},
	[]string{"scope", "outcome"},
)

var tokenBudgetCollectors = []prometheus.Collector{
	TokenBudgetTotal,
}

func init() {
	allCollectors = append(allCollectors, tokenBudgetCollectors...)
}
