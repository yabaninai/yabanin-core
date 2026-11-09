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

// model actually served the request (model_used — after alias resolution,
// rule overrides, tier fallback and failover), how often, and how much of
// the window's non-shadow traffic the edges explain (coverage). Same
// handler-side org gate as the routing map: foreign org → 404 without
// leaking that it exists.

// RoutingActualStore is the narrow capability the recorded-paths handler
// needs. The concrete *adminstore.Store implements it; capability
// interfaces keep the broad StoreInterface untouched.
type RoutingActualStore interface {
	GetActualRouting(ctx context.Context, orgID string, from, to time.Time) (*adminstore.RoutingActual, error)
}

// RoutingActual handles GET /api/routing/actual?org_id=&period= — the
// requested→used model paths recorded over the lookback window. Read-only;
// gated by analytics.read (the request_logs analytics family, same as
// provider health — traffic aggregation, not configuration). The period
// vocabulary is the shared view window: 1h, 24h, 7d, 30d, or a Go duration,
// default 24h, capped at 90 days (parseHealthPeriod).
func (h *AdminHandlers) RoutingActual() http.HandlerFunc {
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
		store, ok := h.store.(RoutingActualStore)
		if !ok {
			h.respondError(w, r, fmt.Errorf("store does not support routing actual"), http.StatusNotImplemented)
			return
		}
		actual, err := store.GetActualRouting(r.Context(), orgID, from, to)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"org_id":   orgID,
			"period":   period,
			"from":     from.Format(time.RFC3339),
			"to":       to.Format(time.RFC3339),
			"edges":    actual.Edges,
			"coverage": actual.Coverage,
		}); err != nil && h.logger != nil {
			h.logger.ErrorContext(r.Context(), "encode routing actual", slog.String("error", err.Error()))
		}
	}
}
