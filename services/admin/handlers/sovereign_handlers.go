package handlers

// file keeps the HTTP surface and the policy-cache invalidation hook.

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// SovereignHandlers exposes CRUD over sovereign models + per-org policy.
type SovereignHandlers struct {
	store            *adminstore.Store
	PolicyInvalidate func(orgID string) // drops router policy cache
}

func NewSovereignHandlers(s *adminstore.Store, invalidate func(string)) *SovereignHandlers {
	return &SovereignHandlers{store: s, PolicyInvalidate: invalidate}
}

// ListModels returns sovereign model rows (country/jurisdiction/tier/cn_flagged).
func (h *SovereignHandlers) ListModels(w http.ResponseWriter, r *http.Request) {
	if h.store == nil || h.store.DB() == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "database not configured"})
		return
	}
	models, err := h.store.ListSovereignModels(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, models)
}

// ToggleModel enables or disables a sovereign model by name.
func (h *SovereignHandlers) ToggleModel(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid body"})
		return
	}
	if h.store == nil || h.store.DB() == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "database not configured"})
		return
	}
	if err := h.store.SetSovereignModelEnabled(r.Context(), name, body.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// GetPolicy retrieves the per-org sovereignty routing policy.
func (h *SovereignHandlers) GetPolicy(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org_id")
	if h.store == nil || h.store.DB() == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "database not configured"})
		return
	}
	p, err := h.store.GetOrgSovereigntyPolicy(r.Context(), orgID)
	if err != nil {
		p = &adminstore.OrgSovereigntyPolicy{
			RequiredTier:      "foreign",
			ExcludedCountries: []string{},
		}
	}
	writeJSON(w, http.StatusOK, p)
}

// UpdatePolicy upserts a per-org sovereignty routing policy and invalidates the cache.
func (h *SovereignHandlers) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org_id")
	var body adminstore.OrgSovereigntyPolicy
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid body"})
		return
	}
	if body.RequiredTier == "" {
		body.RequiredTier = "foreign"
	}
	if h.store == nil || h.store.DB() == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "database not configured"})
		return
	}
	if err := h.store.UpsertOrgSovereigntyPolicy(r.Context(), orgID, &body); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	if h.PolicyInvalidate != nil {
		h.PolicyInvalidate(orgID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
