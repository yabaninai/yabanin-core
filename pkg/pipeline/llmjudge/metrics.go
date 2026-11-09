package llmjudge

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Outcome label values recorded on both judge metrics. "error" covers
// transport failures and malformed verdicts alike (the step-level on_error
// mode decides what the run does with it; see pkg/pipeline OnError).
const (
	outcomeAllow = "allow"
	outcomeFlag  = "flag"
	outcomeMask  = "mask"
	outcomeDeny  = "deny"
	outcomeError = "error"
)

var judgeDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name: "pipeline_llmjudge_duration_seconds",
	Help: "Wall-clock duration of llm_judge step runs, including the judge " +
		"model round trip and verdict parsing. The judge adds directly to " +
		"request latency, so this is the budget surface for threshold tuning.",
	Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
}, []string{"model", "outcome"})

var judgeVerdicts = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "pipeline_llmjudge_verdicts_total",
	Help: "llm_judge step outcomes: allow | flag | deny | mask per finding " +
		"mapping, plus error for failed or malformed judge calls.",
}, []string{"model", "outcome"})

// recordJudgeOutcome writes one duration observation and one verdict-count
// increment. modelLabel is the resolved judge model name (or the raw policy
// reference when resolution failed) — bounded cardinality by construction,
// it comes from the model registry or the policy document, never from
// request content.
func recordJudgeOutcome(modelLabel, outcome string, d time.Duration) {
	if modelLabel == "" {
		modelLabel = "unknown"
	}
	judgeDuration.WithLabelValues(modelLabel, outcome).Observe(d.Seconds())
	judgeVerdicts.WithLabelValues(modelLabel, outcome).Inc()
}
