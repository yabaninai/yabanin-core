package handlers

import (
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/feedback"
)

// RetrainHandlers exposes on-demand data-flywheel retrain status.
type RetrainHandlers struct {
	exporter          *feedback.Exporter
	trigger           *classifier.FeedbackDrivenRetrainTrigger
	feedbackCollector *feedback.Collector
}

// NewRetrainHandlers creates retrain status handlers.
func NewRetrainHandlers(exporter *feedback.Exporter, trigger *classifier.FeedbackDrivenRetrainTrigger) *RetrainHandlers {
	return &RetrainHandlers{
		exporter: exporter,
		trigger:  trigger,
	}
}

// SetFeedbackCollector attaches the feedback collector for problematic class queries.
func (rh *RetrainHandlers) SetFeedbackCollector(fc *feedback.Collector) {
	rh.feedbackCollector = fc
}

type retrainStatusResponse struct {
	NeedsRetrain     bool               `json:"needs_retrain"`
	DegradedClasses  []string           `json:"degraded_classes,omitempty"`
	RecentFeedback   int                `json:"recent_feedback_count"`
	ProblemRates     map[string]float64 `json:"problem_rates,omitempty"`
	RetrainRecommend string             `json:"retrain_recommendation"`
}

// Status returns on-demand retrain recommendation based on feedback + drift.
func (rh *RetrainHandlers) Status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var resp retrainStatusResponse

	// 1. Get recent feedback count.
	samples, err := rh.exporter.ExportAllRecent(ctx, 7*24*time.Hour)
	if err == nil {
		resp.RecentFeedback = len(samples)
	}

	// 2. Get problematic class rates from feedback collector.
	var problemRates map[string]float64
	if rh.feedbackCollector != nil {
		rates, err := rh.feedbackCollector.GetProblematicClasses(ctx, "")
		if err == nil && len(rates) > 0 {
			problemRates = make(map[string]float64, len(rates))
			for c, rate := range rates {
				problemRates[string(c)] = rate
			}
			resp.ProblemRates = problemRates
		}
	}

	// 3. Update trigger with current problematic rates and check retrain signal.
	if rh.trigger != nil && len(problemRates) > 0 {
		classRates := make(map[classifier.Class]float64, len(problemRates))
		for c, rate := range problemRates {
			classRates[classifier.Class(c)] = rate
		}
		rh.trigger.Update(classRates)
		resp.NeedsRetrain = rh.trigger.NeedsRetrain(0.20)
	} else {
		resp.NeedsRetrain = false
	}

	// Collect degraded classes.
	var degraded []string
	for c, rate := range problemRates {
		if rate > 0.15 {
			degraded = append(degraded, c)
		}
	}
	resp.DegradedClasses = degraded

	// 4. Build recommendation text.
	if resp.NeedsRetrain {
		resp.RetrainRecommend = "RETRAIN: Degraded classes detected with problem rate >20%. " +
			"Review problematic samples and retrain the classifier."
	} else if len(degraded) > 0 {
		resp.RetrainRecommend = "MONITOR: Some classes show elevated negative feedback (>15%). " +
			"No immediate action required, but watch for drift."
	} else if resp.RecentFeedback == 0 {
		resp.RetrainRecommend = "OK: No recent feedback data available. Classifier status unknown."
	} else {
		resp.RetrainRecommend = "OK: Classifier performance within normal bounds."
	}

	writeJSON(w, http.StatusOK, resp)
}
