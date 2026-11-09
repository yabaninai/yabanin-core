package handlers

// this file keeps the HTTP surface (statuses, bodies, validation order)
// and the programmatic helpers as thin delegating wrappers.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// ResalePricingHandlers handles CRUD for the reseller_pricing table.
type ResalePricingHandlers struct {
	store *adminstore.Store
	log   LoggerAdapter
}

// NewResalePricingHandlers creates handlers backed by a DB pool.
func NewResalePricingHandlers(pool *pgxpool.Pool, log LoggerAdapter) *ResalePricingHandlers {
	var store *adminstore.Store
	if pool != nil {
		store = adminstore.New(pool, nil, nil)
	}
	return &ResalePricingHandlers{store: store, log: log}
}

// CreateResalePricingRequest is the body for PUT /api/orgs/{id}/resale-pricing.
type CreateResalePricingRequest struct {
	OrgID           string   `json:"org_id"`
	ModelName       *string  `json:"model_name,omitempty"` // nil = all models
	MarkupPct       float64  `json:"markup_pct"`           // e.g. 15.00 = 15%
	FixedInputPerM  *float64 `json:"fixed_input_per_m,omitempty"`
	FixedOutputPerM *float64 `json:"fixed_output_per_m,omitempty"`
}

// effectiveResaleModelName mirrors the stored model name for the response
// echo: nil (or empty, which the store normalizes to SQL NULL) echoes "".
func effectiveResaleModelName(modelName *string) string {
	if modelName == nil {
		return ""
	}
	return *modelName
}

// HandleCreateOrUpdateResalePricing sets or updates a resale pricing rule.
func (h *ResalePricingHandlers) HandleCreateOrUpdateResalePricing(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "database not configured"})
		return
	}

	var req CreateResalePricingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
		return
	}

	if req.MarkupPct < 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "markup_pct must be >= 0"})
		return
	}

	orgID := r.PathValue("id")

	// The store normalizes an empty model name to SQL NULL so that
	// markup.go:getOverride can match org-wide rules via model_name IS NULL.
	id, err := h.store.UpsertResalePricing(r.Context(), orgID, req.ModelName, req.MarkupPct, req.FixedInputPerM, req.FixedOutputPerM)
	if err != nil {
		h.log.Error("resale pricing upsert failed", "org_id", orgID, "model", effectiveResaleModelName(req.ModelName), "error", err)
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "pricing_upsert_failed: " + err.Error()})
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"id":                 id,
		"org_id":             orgID,
		"model_name":         effectiveResaleModelName(req.ModelName),
		"markup_pct":         req.MarkupPct,
		"fixed_input_per_m":  req.FixedInputPerM,
		"fixed_output_per_m": req.FixedOutputPerM,
	})
}

// HandleListResalePricing returns all active resale pricing rules.
func (h *ResalePricingHandlers) HandleListResalePricing(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "database not configured"})
		return
	}

	items, err := h.store.ListResalePricing(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "pricing_list_failed: " + err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"count": len(items),
		"items": items,
	})
}

// HandleDeleteResalePricing deactivates a resale pricing rule.
func (h *ResalePricingHandlers) HandleDeleteResalePricing(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "database not configured"})
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "pricing ID must be a number"})
		return
	}

	found, err := h.store.DeactivateResalePricing(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "pricing_delete_failed: " + err.Error()})
		return
	}

	if !found {
		writeJSON(w, http.StatusNotFound, apiError{Error: "resale pricing rule not found or already inactive"})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{"status": "deactivated", "id": idStr})
}

// HandleGetResalePricing returns a single resale pricing rule by ID.
func (h *ResalePricingHandlers) HandleGetResalePricing(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "database not configured"})
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "pricing ID must be a number"})
		return
	}

	pr, err := h.store.GetResalePricing(r.Context(), id)
	if err != nil {
		if adminstore.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, apiError{Error: "resale pricing rule not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "pricing_query_failed: " + err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"id":                 id,
		"org_id":             pr.OrgID,
		"model_name":         pr.ModelName,
		"markup_pct":         pr.MarkupPct,
		"fixed_input_per_m":  pr.FixedInputPerM,
		"fixed_output_per_m": pr.FixedOutputPerM,
		"active":             pr.Active,
		"created_at":         pr.CreatedAt,
		"updated_at":         pr.UpdatedAt,
	})
}

// HandleGetOrgResalePricing returns all resale pricing rules for an org.
func (h *ResalePricingHandlers) HandleGetOrgResalePricing(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "database not configured"})
		return
	}

	orgID := r.PathValue("id")
	if orgID == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org ID is required"})
		return
	}

	items, err := h.store.ListOrgResalePricing(r.Context(), orgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "org_pricing_query_failed: " + err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"org_id": orgID,
		"count":  len(items),
		"items":  items,
	})
}

// CreateResalePricing is the programmatic version of HandleCreateOrUpdateResalePricing.
func (h *ResalePricingHandlers) CreateResalePricing(ctx context.Context, p CreateResalePricingRequest) (int64, error) {
	if h.store == nil {
		return 0, fmt.Errorf("database not configured")
	}
	return h.store.CreateResalePricing(ctx, p.OrgID, p.ModelName, p.MarkupPct, p.FixedInputPerM, p.FixedOutputPerM)
}

// ListAllResalePricing returns all active resale pricing rules.
func (h *ResalePricingHandlers) ListAllResalePricing(ctx context.Context) ([]interface{}, error) {
	if h.store == nil {
		return nil, fmt.Errorf("database not configured")
	}
	rows, err := h.store.ListActiveResalePricing(ctx)
	if err != nil {
		return nil, err
	}

	var items []interface{}
	for _, pr := range rows {
		items = append(items, map[string]interface{}{
			"id": pr.ID, "org_id": pr.OrgID, "model_name": pr.ModelName,
			"markup_pct": pr.MarkupPct, "fixed_input_per_m": pr.FixedInputPerM,
			"fixed_output_per_m": pr.FixedOutputPerM, "active": pr.Active,
		})
	}
	return items, nil
}

// DeleteResalePricing deactivates a pricing rule.
func (h *ResalePricingHandlers) DeleteResalePricing(ctx context.Context, id int64) (bool, error) {
	if h.store == nil {
		return false, fmt.Errorf("database not configured")
	}
	return h.store.DeactivateResalePricing(ctx, id)
}

// GetResalePricingByID returns a single pricing rule.
func (h *ResalePricingHandlers) GetResalePricingByID(ctx context.Context, id int64) (map[string]interface{}, bool, error) {
	if h.store == nil {
		return nil, false, fmt.Errorf("database not configured")
	}
	pr, found, err := h.store.GetResalePricingByID(ctx, id)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	return map[string]interface{}{
		"id": pr.ID, "org_id": pr.OrgID, "model_name": pr.ModelName,
		"markup_pct": pr.MarkupPct, "fixed_input_per_m": pr.FixedInputPerM,
		"fixed_output_per_m": pr.FixedOutputPerM, "active": pr.Active,
	}, true, nil
}

// GetOrgResalePricing returns all pricing rules for an org.
func (h *ResalePricingHandlers) GetOrgResalePricing(ctx context.Context, orgID string) ([]interface{}, error) {
	if h.store == nil {
		return nil, fmt.Errorf("database not configured")
	}
	rows, err := h.store.ListOrgResalePricingSummary(ctx, orgID)
	if err != nil {
		return nil, err
	}

	var items []interface{}
	for _, pr := range rows {
		items = append(items, map[string]interface{}{
			"id": pr.ID, "org_id": pr.OrgID, "model_name": pr.ModelName,
			"markup_pct": pr.MarkupPct, "fixed_input_per_m": pr.FixedInputPerM,
			"fixed_output_per_m": pr.FixedOutputPerM, "active": pr.Active,
		})
	}
	return items, nil
}
