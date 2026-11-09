package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// GetOrgSpendAlertSettings handles GET /api/organizations/{id}/spend-alert.
// Returns per-org spend alert threshold, webhook, last alert time, and today's spend.
func (h *AdminHandlers) GetOrgSpendAlertSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		rs, err := h.store.GetOrgSpendAlertSettings(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("spend alert settings: %w", err), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, rs)
	}
}

// UpdateOrgSpendAlertSettings handles PATCH /api/organizations/{id}/spend-alert.
// Body: {"threshold_usd": 50.0, "webhook_url": "https://hooks.slack.com/..."}
// Set threshold_usd to null to disable alerts.
func (h *AdminHandlers) UpdateOrgSpendAlertSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")

		var req struct {
			ThresholdUSD *float64 `json:"threshold_usd"`
			WebhookURL   *string  `json:"webhook_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}

		// Validate threshold if set.
		if req.ThresholdUSD != nil && *req.ThresholdUSD <= 0 {
			h.respondError(w, r, fmt.Errorf("threshold_usd must be positive or null (to disable)"), http.StatusBadRequest)
			return
		}

		if err := h.store.UpdateOrgSpendAlertSettings(r.Context(), orgID, req.ThresholdUSD, req.WebhookURL); err != nil {
			h.respondError(w, r, fmt.Errorf("update spend alert settings: %w", err), http.StatusInternalServerError)
			return
		}

		h.auditLogActionWithCtx(r.Context(), r, "update", "org_spend_alert_settings",
			fmt.Sprintf("id=%s threshold=%v webhook_set=%v", orgID, req.ThresholdUSD, req.WebhookURL != nil))

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
