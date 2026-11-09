package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminauth"
	adminstore "github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// ListPricingHandler returns all pricing entries with optional provider/model filters.
func (h *AdminHandlers) ListPricingHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}

		opts := adminstore.ListPricingOptions{Active: true}

		if provider := r.URL.Query().Get("provider"); provider != "" {
			opts.Provider = provider
		}
		if model := r.URL.Query().Get("model"); model != "" {
			opts.Model = model
		}

		entries, err := h.store.ListPricing(r.Context(), opts)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, entries)
	}
}

// CreatePricingHandler creates a new pricing entry.
func (h *AdminHandlers) CreatePricingHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}

		var req adminstore.CreatePricingParams
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body: %w", err), http.StatusBadRequest)
			return
		}

		if req.Provider == "" || req.Model == "" {
			h.respondError(w, r, fmt.Errorf("provider and model are required"), http.StatusBadRequest)
			return
		}

		entry, err := h.store.CreatePricing(r.Context(), req)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		if h.dbPricer != nil {
			h.dbPricer.ClearCache()
		}

		writeJSON(w, http.StatusCreated, entry)
	}
}

// UpdatePricingHandler updates an existing pricing entry.
func (h *AdminHandlers) UpdatePricingHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}

		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("invalid id: %s", idStr), http.StatusBadRequest)
			return
		}

		var req adminstore.UpdatePricingParams
		req.ID = id
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body: %w", err), http.StatusBadRequest)
			return
		}

		entry, err := h.store.UpdatePricing(r.Context(), req)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		if h.dbPricer != nil {
			h.dbPricer.ClearCache()
		}

		writeJSON(w, http.StatusOK, entry)
	}
}

// DeletePricingHandler permanently removes a pricing entry.
func (h *AdminHandlers) DeletePricingHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}

		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("invalid id: %s", idStr), http.StatusBadRequest)
			return
		}

		if err := h.store.DeletePricing(r.Context(), id); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		if h.dbPricer != nil {
			h.dbPricer.ClearCache()
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ImportPricingHandler previews or applies a catalog import. Prices are global,
// so only a root admin may call it. The route group also requires root.
func (h *AdminHandlers) ImportPricingHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		isRoot, _ := r.Context().Value(adminauth.ContextKeyIsRoot{}).(bool)
		if !isRoot {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mode := r.URL.Query().Get("mode")
		if mode == "" {
			mode = "dry_run"
		}
		if mode != "dry_run" && mode != "apply" {
			h.respondError(w, r, fmt.Errorf("mode must be dry_run or apply"), http.StatusBadRequest)
			return
		}
		var body struct {
			Catalog    pricing.PriceFile            `json:"catalog"`
			Map        []adminstore.CatalogPriceMap `json:"map"`
			OnlyMapped bool                         `json:"only_mapped"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body: %w", err), http.StatusBadRequest)
			return
		}
		result, err := h.store.ImportCatalogPricing(r.Context(), body.Catalog, body.Map, body.OnlyMapped, mode == "apply", adminNameFromContext(r))
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if mode == "apply" {
			if h.dbPricer != nil {
				h.dbPricer.ClearCache()
			}
			h.auditLogAction(r, "pricing_import", "models_pricing", fmt.Sprintf("created=%d unchanged=%d", result.Created, result.Unchanged))
		}
		writeJSON(w, http.StatusOK, result)
	}
}

// ExportPricingCSVHandler returns pricing data as CSV for finance/audit.
func (h *AdminHandlers) ExportPricingCSVHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}

		entries, err := h.store.ListPricing(r.Context(), adminstore.ListPricingOptions{Active: true})
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=pricing_%s.csv", time.Now().Format("2006-01-02")))

		cw := csv.NewWriter(w)
		defer cw.Flush()

		// Header row
		if err := cw.Write([]string{"id", "provider", "model", "input_per_m", "output_per_m", "cache_write_per_m", "cache_read_per_m", "effective_from"}); err != nil {
			return
		}

		for _, e := range entries {
			if err := cw.Write([]string{
				strconv.FormatInt(e.ID, 10),
				e.Provider,
				e.Model,
				fmt.Sprintf("%.6f", e.InputPerM),
				fmt.Sprintf("%.6f", e.OutputPerM),
				fmt.Sprintf("%.6f", e.CacheWritePerM),
				fmt.Sprintf("%.6f", e.CacheReadPerM),
				e.EffectiveFrom.Format("2006-01-02T15:04:05Z"),
			}); err != nil {
				return
			}
		}
	}
}
