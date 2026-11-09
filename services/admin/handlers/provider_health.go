package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// provider and model (requests, error share, p50/p95, last error with its
// timestamp) over a bounded period. Same handler-side org gate as the
// routing map: foreign org → 404 without leaking that it exists.

// providerHealthPeriodBounds caps how far back one health query may reach.
const maxProviderHealthPeriod = 90 * 24 * time.Hour

// ProviderHealthStore is the narrow capability the provider health handler
// needs.
type ProviderHealthStore interface {
	GetProviderHealth(ctx context.Context, orgID string, from, to time.Time) ([]adminstore.ProviderHealth, error)
}

// parseHealthPeriod resolves the `period` query value to a lookback window.
// Accepted: 1h, 24h, 7d, 30d, or a Go duration string; default 24h, capped
// at 90 days. The bool is false when the value cannot be parsed.
func parseHealthPeriod(period string, now time.Time) (time.Time, time.Time, bool) {
	if period == "" {
		period = "24h"
	}
	var d time.Duration
	switch period {
	case "1h":
		d = time.Hour
	case "24h", "1d":
		d = 24 * time.Hour
	case "7d":
		d = 7 * 24 * time.Hour
	case "30d":
		d = 30 * 24 * time.Hour
	default:
		parsed, err := time.ParseDuration(period)
		if err != nil || parsed <= 0 {
			return time.Time{}, time.Time{}, false
		}
		d = parsed
	}
	if d > maxProviderHealthPeriod {
		d = maxProviderHealthPeriod
	}
	to := now
	return to.Add(-d), to, true
}

// ProviderHealth handles GET /api/providers/health?org_id=&period=.
// Read-only; gated by analytics.read (the request_logs analytics family).
func (h *AdminHandlers) ProviderHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if !h.requireOrgRead(w, r, orgID, adminstore.PermAnalyticsRead) {
			return
		}
		period := r.URL.Query().Get("period")
		from, to, ok := parseHealthPeriod(period, time.Now().UTC())
		if !ok {
			h.respondError(w, r, fmt.Errorf("invalid period, use 1h, 24h, 7d, 30d or a duration"), http.StatusBadRequest)
			return
		}
		if period == "" {
			period = "24h"
		}
		store, ok := h.store.(ProviderHealthStore)
		if !ok {
			h.respondError(w, r, fmt.Errorf("store does not support provider health"), http.StatusNotImplemented)
			return
		}
		health, err := store.GetProviderHealth(r.Context(), orgID, from, to)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"org_id":    orgID,
			"period":    period,
			"from":      from.Format(time.RFC3339),
			"to":        to.Format(time.RFC3339),
			"providers": health,
		}); err != nil && h.logger != nil {
			h.logger.ErrorContext(r.Context(), "encode provider health", slog.String("error", err.Error()))
		}
	}
}
