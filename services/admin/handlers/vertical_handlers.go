package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// VerticalHandlers holds state for vertical-pack admin endpoints.
type VerticalHandlers struct {
	store  StoreInterface // may be nil if DB not configured
	logger LoggerAdapter  // nil = no-op logging
}

// LoggerAdapter provides a minimal logging interface matching slog.Logger subset.
type LoggerAdapter interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// NewVerticalHandlers creates vertical pack admin handlers.
func NewVerticalHandlers(store StoreInterface, logger LoggerAdapter) *VerticalHandlers {
	return &VerticalHandlers{store: store, logger: logger}
}

// List returns enabled verticals for an org.
func (vh *VerticalHandlers) List(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	if orgID == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id required"})
		return
	}

	// In production this queries org_verticals table.
	// For now return empty list (DB query wired via StoreInterface).
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusOK, map[string]any{
		"org_id":    orgID,
		"verticals": []string{},
	})
}

// Enable enables a vertical for an org.
func (vh *VerticalHandlers) Enable(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	vertical := chi.URLParam(r, "vertical")
	if orgID == "" || vertical == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id and vertical required"})
		return
	}

	validVerticals := map[string]bool{
		"halal": true, "carbon": true, "healthcare": true,
		"finance": true, "defense": true, "education": true,
		"legal": true, "retail": true,
	}
	if !validVerticals[vertical] {
		writeJSON(w, http.StatusBadRequest, apiError{Error: fmt.Sprintf("invalid vertical %q", vertical)})
		return
	}

	body := struct {
		Config map[string]any `json:"config"`
	}{Config: make(map[string]any)}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return
	}

	// In production this INSERTs into org_verticals table.
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusOK, map[string]any{
		"org_id":   orgID,
		"vertical": vertical,
		"enabled":  true,
		"config":   body.Config,
	})
}

// Disable disables a vertical for an org.
func (vh *VerticalHandlers) Disable(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id")
	vertical := chi.URLParam(r, "vertical")
	if orgID == "" || vertical == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id and vertical required"})
		return
	}

	// In production this DELETEs from org_verticals table.
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusOK, map[string]any{
		"org_id":   orgID,
		"vertical": vertical,
		"enabled":  false,
	})
}

// ListMarketplace returns available vertical packs for admin marketplace.
func (vh *VerticalHandlers) ListMarketplace(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusOK, map[string]any{
		"verticals": []map[string]any{
			{
				"id":          "halal_bpjph",
				"name":        "Halal BPJPH Compliance",
				"description": "Indonesian Islamic finance compliance with lineage attestation.",
				"region":      "GLOBAL",
			},
			{
				"id":          "carbon_brsr",
				"name":        "Carbon Emissions Tracking",
				"description": "BRSR/CSRD carbon-aware routing and budget enforcement.",
				"region":      "GLOBAL",
			},
			{
				"id":          "healthcare_phi",
				"name":        "Healthcare PHI Redaction",
				"description": "PHI redaction for DPDP/PDPA/HIPAA compliance.",
				"region":      "GLOBAL",
			},
			{
				"id":          "finance_rbi",
				"name":        "Finance RBI Compliance",
				"description": "Model allow-listing + human-in-the-loop regulatory approval.",
				"region":      "IN",
			},
			{
				"id":          "defense_itar",
				"name":        "Defense ITAR Compliance",
				"description": "ITAR screening + sovereign-only pool enforcement.",
				"region":      "US",
			},
		},
	})
}
