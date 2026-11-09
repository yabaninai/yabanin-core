package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// parseID converts a query string to *string, returning nil for empty strings.
func parseID(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// requireStore returns true if the store is non-nil; otherwise writes a 500 error and returns false.
func (h *AdminHandlers) requireStore(w http.ResponseWriter, r *http.Request) bool {
	if h.store == nil {
		h.respondError(w, r, fmt.Errorf("store not configured"), http.StatusInternalServerError)
		return false
	}
	return true
}

func (h *AdminHandlers) dashboard() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.store == nil {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"total_requests": int64(0),
				"success_rate":   float64(0),
				"avg_latency_ms": float64(0),
				"top_models":     []adminstore.TopModelCount{},
				"top_orgs":       []adminstore.TopOrgCount{},
			}); err != nil {
				h.logger.ErrorContext(r.Context(), "encode response", slog.String("error", err.Error()))
			}
			return
		}
		stats, err := h.store.GetRequestLogStats(r.Context(), nil, time.Time{})
		if err != nil {
			h.respondError(w, r, fmt.Errorf("db error"), http.StatusInternalServerError)
			return
		}

		topModels, err := h.store.TopModels(r.Context(), nil, 10)
		if err != nil {
			h.logger.ErrorContext(r.Context(), "analytics TopModels failed", slog.String("error", err.Error()))
		}
		topOrgs, err := h.store.TopOrgs(r.Context(), 10)
		if err != nil {
			h.logger.ErrorContext(r.Context(), "analytics TopOrgs failed", slog.String("error", err.Error()))
		}

		type dash struct {
			TotalRequests int64                      `json:"total_requests"`
			SuccessRate   float64                    `json:"success_rate"`
			AvgLatency    float64                    `json:"avg_latency_ms"`
			TopModels     []adminstore.TopModelCount `json:"top_models"`
			TopOrgs       []adminstore.TopOrgCount   `json:"top_orgs"`
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(dash{
			TotalRequests: stats.TotalRequests,
			SuccessRate:   stats.SuccessRate * 100,
			AvgLatency:    stats.AvgDurationMs,
			TopModels:     topModels,
			TopOrgs:       topOrgs,
		}); err != nil {
			h.logger.ErrorContext(r.Context(), "encode response", slog.String("error", err.Error()))
		}
	}
}

func (h *AdminHandlers) apiAnalyticsStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := parseID(r.URL.Query().Get("org_id"))
		sinceStr := r.URL.Query().Get("since")

		var since time.Time
		if sinceStr != "" {
			var err error
			since, err = time.Parse(time.RFC3339, sinceStr)
			if err != nil {
				h.respondError(w, r, fmt.Errorf("invalid since format, use RFC3339"), http.StatusBadRequest)
				return
			}
		}

		stats, err := h.store.GetRequestLogStats(r.Context(), orgID, since)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(stats); err != nil {
			h.logger.ErrorContext(r.Context(), "encode response", slog.String("error", err.Error()))
		}
	}
}

func (h *AdminHandlers) apiTopModels() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		limit := 10
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}
		items, err := h.store.TopModels(r.Context(), parseID(r.URL.Query().Get("org_id")), limit)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(items); err != nil {
			h.logger.ErrorContext(r.Context(), "encode response", slog.String("error", err.Error()))
		}
	}
}

func (h *AdminHandlers) apiTopOrgs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		limit := 10
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}
		items, err := h.store.TopOrgs(r.Context(), limit)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(items); err != nil {
			h.logger.ErrorContext(r.Context(), "encode response", slog.String("error", err.Error()))
		}
	}
}

func (h *AdminHandlers) apiTimeSeries() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		interval := r.URL.Query().Get("interval")
		if interval == "" {
			interval = "1h"
		}
		sinceStr := r.URL.Query().Get("since")

		var since time.Time
		if sinceStr != "" {
			var err error
			since, err = time.Parse(time.RFC3339, sinceStr)
			if err != nil {
				h.respondError(w, r, fmt.Errorf("invalid since format, use RFC3339"), http.StatusBadRequest)
				return
			}
		}

		points, err := h.store.RequestTimeSeries(r.Context(), parseID(r.URL.Query().Get("org_id")), since, interval)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(points); err != nil {
			h.logger.ErrorContext(r.Context(), "encode response", slog.String("error", err.Error()))
		}
	}
}

func (h *AdminHandlers) apiErrorBreakdown() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		sinceStr := r.URL.Query().Get("since")

		var since time.Time
		if sinceStr != "" {
			var err error
			since, err = time.Parse(time.RFC3339, sinceStr)
			if err != nil {
				h.respondError(w, r, fmt.Errorf("invalid since format, use RFC3339"), http.StatusBadRequest)
				return
			}
		}

		items, err := h.store.ErrorBreakdown(r.Context(), parseID(r.URL.Query().Get("org_id")), since)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(items); err != nil {
			h.logger.ErrorContext(r.Context(), "encode response", slog.String("error", err.Error()))
		}
	}
}

func (h *AdminHandlers) apiLatency() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		sinceStr := r.URL.Query().Get("since")

		var since time.Time
		if sinceStr != "" {
			var err error
			since, err = time.Parse(time.RFC3339, sinceStr)
			if err != nil {
				h.respondError(w, r, fmt.Errorf("invalid since format, use RFC3339"), http.StatusBadRequest)
				return
			}
		}

		pctls, err := h.store.LatencyPercentiles(r.Context(), parseID(r.URL.Query().Get("org_id")), since)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(pctls); err != nil {
			h.logger.ErrorContext(r.Context(), "encode response", slog.String("error", err.Error()))
		}
	}
}

func (h *AdminHandlers) apiRecentErrors() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		limit := 50
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}
		items, err := h.store.RecentErrors(r.Context(), parseID(r.URL.Query().Get("org_id")), limit)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(items); err != nil {
			h.logger.ErrorContext(r.Context(), "encode response", slog.String("error", err.Error()))
		}
	}
}

// apiTaskAnalytics handles GET /api/analytics/tasks?org_id=&from=&to=&group_by=&limit=.
// G4: CTOR/task cost analytics. group_by is task|session|agent|user (default task);
// from/to are RFC3339 (defaults: last 24h / now); limit ≤ 500 (default 100).
func (h *AdminHandlers) apiTaskAnalytics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		q := r.URL.Query()
		orgID := q.Get("org_id")
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id is required"), http.StatusBadRequest)
			return
		}
		groupBy := q.Get("group_by")
		if groupBy == "" {
			groupBy = "task"
		}
		limit := 100
		if l := q.Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}

		now := time.Now().UTC()
		from := now.Add(-24 * time.Hour)
		to := now
		if f := q.Get("from"); f != "" {
			parsed, err := time.Parse(time.RFC3339, f)
			if err != nil {
				h.respondError(w, r, fmt.Errorf("invalid from format, use RFC3339"), http.StatusBadRequest)
				return
			}
			from = parsed
		}
		if t := q.Get("to"); t != "" {
			parsed, err := time.Parse(time.RFC3339, t)
			if err != nil {
				h.respondError(w, r, fmt.Errorf("invalid to format, use RFC3339"), http.StatusBadRequest)
				return
			}
			to = parsed
		}

		report, err := h.store.GetTaskAnalytics(r.Context(), orgID, from, to, groupBy, limit)
		if err != nil {
			// An invalid group_by is a client error; everything else is a DB error.
			if strings.Contains(err.Error(), "group_by must be one of") {
				h.respondError(w, r, err, http.StatusBadRequest)
				return
			}
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(report); err != nil {
			h.logger.ErrorContext(r.Context(), "encode response", slog.String("error", err.Error()))
		}
	}
}
