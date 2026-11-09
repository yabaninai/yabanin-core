package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

type orgOriginalRetentionStore interface {
	GetOrgOriginalRetention(ctx context.Context, orgID string) (*adminstore.OrgOriginalRetention, error)
	UpdateOrgOriginalRetention(ctx context.Context, orgID string, enabled *bool) error
}

// GetOrgOriginalRetention returns the explicit org value and its inherited
// effective setting. The inherited platform default is processed-only.
func (h *AdminHandlers) GetOrgOriginalRetention() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.store.(orgOriginalRetentionStore)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "original retention settings are unavailable"})
			return
		}
		setting, err := store.GetOrgOriginalRetention(r.Context(), chi.URLParam(r, "id"))
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, adminstore.ErrNotFound) {
				status = http.StatusNotFound
			}
			h.respondError(w, r, fmt.Errorf("org original retention: %w", err), status)
			return
		}
		writeJSON(w, http.StatusOK, setting)
	}
}

// UpdateOrgOriginalRetention sets enabled to true/false or null to inherit
// the platform default. An explicit org.update permission is required.
func (h *AdminHandlers) UpdateOrgOriginalRetention() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.store.(orgOriginalRetentionStore)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "original retention settings are unavailable"})
			return
		}
		orgID := chi.URLParam(r, "id")
		if h.requireOrgScope(w, r, orgID, adminstore.PermOrgUpdate) == "" {
			return
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body == nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
			return
		}
		rawEnabled, hasEnabled := body["enabled"]
		if !hasEnabled {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "enabled is required (boolean or null)"})
			return
		}
		var enabled *bool
		if string(rawEnabled) != "null" {
			var value bool
			if err := json.Unmarshal(rawEnabled, &value); err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "enabled must be a boolean or null"})
				return
			}
			enabled = &value
		}
		if err := store.UpdateOrgOriginalRetention(r.Context(), orgID, enabled); err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, adminstore.ErrNotFound) {
				status = http.StatusNotFound
			}
			h.respondError(w, r, fmt.Errorf("update org original retention: %w", err), status)
			return
		}
		value := "inherit"
		if enabled != nil {
			value = fmt.Sprint(*enabled)
		}
		h.auditLogActionWithCtx(r.Context(), r, "update", "org_original_retention", fmt.Sprintf("org_id=%s enabled=%s", orgID, value))
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
