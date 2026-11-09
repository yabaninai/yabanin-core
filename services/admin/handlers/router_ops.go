package handlers

// global cache management, A/B experiments, region routing, vertical
// compliance packs, the policy-template marketplace, feedback export,
// retrain status, and the classifier feedback collector endpoint.

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// mountOps registers the root-only operational routes on the root CRUD
// group.
func (h *AdminHandlers) mountOps(r chi.Router) {
	// Global cache management (root-only)
	r.Post("/api/cache/flush", h.FlushCache())
	r.Get("/api/cache/analytics", h.CacheAnalytics())
	r.Post("/api/cache/warm", h.WarmCache())

	// P4.14: A/B experiment endpoints
	r.Post("/api/cache/experiments", h.CreateExperimentHandler())
	r.Get("/api/cache/experiments", h.ListExperimentsHandler())
	r.Get("/api/cache/experiments/{exp_id}/results", h.GetExperimentResultsHandler())

	// PB2.7: Region routing admin (root-only)
	if h.regionHandlers != nil {
		r.Get("/api/regions", h.regionHandlers.ListRegions)
		r.Get("/api/organizations/{id}/region", h.regionHandlers.GetOrgRegion)
		r.Put("/api/organizations/{id}/region", h.regionHandlers.UpdateOrgRegion)
	}

	// PC2: Vertical compliance packs admin (root-only)
	if h.verticalHandlers != nil {
		r.Get("/api/organizations/{orgID}/verticals", h.verticalHandlers.List)
		r.Post("/api/organizations/{orgID}/verticals/{vertical}", h.verticalHandlers.Enable)
		r.Delete("/api/organizations/{orgID}/verticals/{vertical}", h.verticalHandlers.Disable)
	}

	// PC3: Policy template marketplace (root-only)
	if h.templateHandlers != nil {
		r.Post("/api/organizations/{orgID}/templates/export", h.templateHandlers.Export)
		r.Get("/api/templates/marketplace", h.templateHandlers.ListAvailable)
		r.Put("/api/organizations/{orgID}/templates/{templateID}/subscribe", h.templateHandlers.Subscribe)
	}

	// PC3: Feedback export (root-only)
	if h.feedback.exporter != nil {
		r.Get("/api/feedback/export", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			samples, err := h.feedback.exporter.ExportAllRecent(ctx, 7*24*time.Hour)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, apiError{Error: "export failed: " + err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"count":   len(samples),
				"samples": samples,
				"window":  "7d",
			})
		})
	}

	// W-FEED: owner feedback list + CSV export (root-only; unmounted while
	// the lister is not wired, like the other DB-gated groups above).
	if h.feedback.lister != nil {
		r.Get("/api/feedback", h.ListFeedbackHandler())
		r.Get("/api/feedback/export", h.ExportFeedbackHandler())
	}

	// Data flywheel: retrain status (root-only)
	if h.retrainHandlers != nil {
		r.Get("/api/retrain/status", h.retrainHandlers.Status)
	}
}

// mountFeedback registers the classifier feedback endpoint on the
// top-level router (API-key auth, not admin-only). Mounted only when the
// collector is wired.
func (h *AdminHandlers) mountFeedback(r chi.Router) {
	// P5.13: Classifier feedback endpoint (API-key auth, not admin-only)
	if h.feedback.collector != nil {
		handler := NewSubmitFeedbackHandler(h.feedback.collector, h.feedback.resolver)
		r.Post("/v1/feedback", handler.ServeHTTP)
	}
}
