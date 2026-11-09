package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// GetOrgRoutingSettings handles GET /api/organizations/{id}/routing.
// Returns per-org routing_mode and threshold_confidence.
func (h *AdminHandlers) GetOrgRoutingSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		rs, err := h.store.GetOrgRoutingSettings(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("routing settings: %w", err), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, rs)
	}
}

// UpdateOrgRoutingSettings handles PATCH /api/organizations/{id}/routing.
// Body: {"routing_mode": "auto", "routing_threshold_confidence": 0.6}
func (h *AdminHandlers) UpdateOrgRoutingSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")

		var req struct {
			RoutingMode                string  `json:"routing_mode"`
			RoutingThresholdConfidence float64 `json:"routing_threshold_confidence"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}

		// Validate routing_mode.
		mode := strings.ToLower(req.RoutingMode)
		validModes := map[string]bool{
			strings.ToLower(adminstore.RoutingModeAuto):           true,
			strings.ToLower(adminstore.RoutingModeAggressiveCost): true,
			strings.ToLower(adminstore.RoutingModeAlwaysPremium):  true,
			strings.ToLower(adminstore.RoutingModeAlwaysCheap):    true,
			strings.ToLower(adminstore.RoutingModeClassifierOnly): true,
		}
		if mode == "" {
			mode = strings.ToLower(adminstore.RoutingModeAuto)
		}
		if !validModes[mode] {
			h.respondError(w, r, fmt.Errorf("invalid routing_mode: %q (valid: auto, aggressive_cost, always_premium, always_cheap, classifier_only)", req.RoutingMode), http.StatusBadRequest)
			return
		}

		// Validate threshold.
		threshold := req.RoutingThresholdConfidence
		if threshold < 0 || threshold > 1 {
			h.respondError(w, r, fmt.Errorf("routing_threshold_confidence must be between 0 and 1"), http.StatusBadRequest)
			return
		}

		if err := h.store.UpdateOrgRoutingSettings(r.Context(), orgID, mode, threshold); err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				h.respondError(w, r, fmt.Errorf("update routing settings: %w", err), http.StatusNotFound)
				return
			}
			h.respondError(w, r, fmt.Errorf("update routing settings: %w", err), http.StatusInternalServerError)
			return
		}

		h.auditLogActionWithCtx(r.Context(), r, "update", "org_routing_settings",
			fmt.Sprintf("id=%s mode=%s threshold=%.2f", orgID, mode, threshold))

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
