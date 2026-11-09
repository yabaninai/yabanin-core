package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/policy"
)

// PolicyTemplateHandlers exposes policy template CRUD and marketplace endpoints.
type PolicyTemplateHandlers struct {
	marketplace *policy.TemplateMarketplace
	store       StoreInterface
}

// NewPolicyTemplateHandlers creates template handlers.
func NewPolicyTemplateHandlers(mp *policy.TemplateMarketplace, store StoreInterface) *PolicyTemplateHandlers {
	return &PolicyTemplateHandlers{marketplace: mp, store: store}
}

// Export exports an org's policy pack as a shareable template.
func (h *PolicyTemplateHandlers) Export(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	if orgID == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id required"})
		return
	}

	var req struct {
		Region      string `json:"region"`
		PackID      string `json:"pack_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return
	}

	// Get the org's current rules from store.
	rules := policy.ResidencyRule{} // defaults — in production fetch from DB

	tmpl := policy.ExportAsTemplate(orgID, req.Name, req.Description,
		policy.Region(req.Region), req.PackID, rules)

	if err := h.marketplace.RegisterLocal(orgID, tmpl); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusOK, map[string]any{
		"template": tmpl,
	})
}

// ListAvailable lists all templates available in the marketplace.
func (h *PolicyTemplateHandlers) ListAvailable(w http.ResponseWriter, r *http.Request) {
	tmpls, err := h.marketplace.ListAvailable(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusOK, map[string]any{
		"templates": tmpls,
	})
}

// Subscribe subscribes an org to a template.
func (h *PolicyTemplateHandlers) Subscribe(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	templateID := chi.URLParam(r, "template_id")
	if orgID == "" || templateID == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id and template_id required"})
		return
	}

	if err := h.marketplace.Subscribe(orgID, templateID); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusOK, map[string]any{
		"org_id":      orgID,
		"template_id": templateID,
		"subscribed":  true,
	})
}
