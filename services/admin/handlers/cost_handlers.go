package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// CostAnalyticsHandler returns per-org cost breakdown.
func (h *AdminHandlers) CostAnalyticsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}

		orgID := chi.URLParam(r, "org_id")
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id path parameter is required"), http.StatusBadRequest)
			return
		}

		days := 7 // default last 7 days
		if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 {
			days = d
		}

		to := time.Now()
		from := to.AddDate(0, 0, -days)

		report, err := h.store.GetCostAnalytics(r.Context(), orgID, from, to, r.URL.Query().Get("provider"))
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, report)
	}
}

// GlobalCostStatsHandler returns cost stats across all orgs.
func (h *AdminHandlers) GlobalCostStatsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}

		days := 30
		if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 {
			days = d
		}

		to := time.Now()
		from := to.AddDate(0, 0, -days)

		report, err := h.store.GetGlobalCostStats(r.Context(), from, to)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, report)
	}
}

// ShadowComparisonHandler returns the primary-vs-shadow cost comparison for
// mirror traffic (v9, S6). Query params: days (default 30), org_id (optional).
// A window with no shadow traffic returns a valid report with
// verdict="insufficient_data" and overlap=0 — not an error.
func (h *AdminHandlers) ShadowComparisonHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		days := 30
		if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 {
			days = d
		}
		report, err := h.store.GetShadowComparison(r.Context(), r.URL.Query().Get("org_id"), days)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, report)
	}
}

// QualityScoresHandler returns the ADL-04 quality closed-loop report:
// per-model / per-task-class quality scores aggregated from evalgate
// (LLM-as-judge) verdicts, plus a routing recommendation (data + window).
// Query params: days (default 30), org_id (optional). A window with no judged
// traffic returns a valid report with verdict="insufficient_data" — not an
// error.
func (h *AdminHandlers) QualityScoresHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		days := 30
		if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 {
			days = d
		}
		to := time.Now()
		from := to.AddDate(0, 0, -days)
		report, err := h.store.GetQualityScores(r.Context(), r.URL.Query().Get("org_id"), from, to)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, report)
	}
}

// SavingsReportHandler returns combined cache + routing savings analytics.
// Supports optional org_id query param for per-org filtering.
func (h *AdminHandlers) SavingsReportHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}

		days := 7
		if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 {
			days = d
		}

		orgID := r.URL.Query().Get("org_id")

		report, err := h.store.GetSavingsReport(r.Context(), orgID, days, r.URL.Query().Get("provider"))
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, report)
	}
}
