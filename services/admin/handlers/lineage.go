package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/lineage"
)

// LineageStore is the subset of adminstore.Store used for lineage queries.
type LineageStore interface {
	GetLineageByRequestID(ctx context.Context, requestID string) (lineage.Attestation, error)
	ListLineageByOrg(ctx context.Context, orgID string, limit int) ([]lineage.Attestation, error)
	ListLineageByOrgFiltered(ctx context.Context, orgID, model string, from, to time.Time, limit int) ([]lineage.Attestation, error)
}

// LineageVerifier is the subset needed for verification.
type LineageVerifier interface {
	VerifyRequest(ctx context.Context, requestID string) (bool, error)
}

// SetLineageStore attaches the lineage query store.
func (h *AdminHandlers) SetLineageStore(s LineageStore) {
	h.lineage.store = s
}

// SetLineageVerifier attaches the lineage verifier.
func (h *AdminHandlers) SetLineageVerifier(v LineageVerifier) {
	h.lineage.verifier = v
}

// GetLineageByRequest handles GET /api/lineage/{request_id}.
func (h *AdminHandlers) GetLineageByRequest() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.lineage.store == nil {
			h.respondError(w, r, fmt.Errorf("lineage store not configured"), http.StatusServiceUnavailable)
			return
		}
		requestID := requestIDParam(r)
		att, err := h.lineage.store.GetLineageByRequestID(r.Context(), requestID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("get lineage: %w", err), http.StatusNotFound)
			return
		}
		if h.resourceHidden(w, r, att.OrgID) {
			return
		}
		writeJSON(w, http.StatusOK, att)
	}
}

// VerifyLineage handles POST /api/lineage/{request_id}/verify.
func (h *AdminHandlers) VerifyLineage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := requestIDParam(r)
		// Confirm the attestation's org before verify so org A cannot probe
		// org B's request id. Root keeps the previous verifier-only path.
		if !isRoot(r) {
			if h.lineage.store == nil {
				h.respondError(w, r, fmt.Errorf("lineage store not configured"), http.StatusServiceUnavailable)
				return
			}
			att, err := h.lineage.store.GetLineageByRequestID(r.Context(), requestID)
			if err != nil {
				h.respondError(w, r, fmt.Errorf("get lineage: %w", err), http.StatusNotFound)
				return
			}
			if h.resourceHidden(w, r, att.OrgID) {
				return
			}
		}
		if h.lineage.verifier == nil {
			h.respondError(w, r, fmt.Errorf("lineage verifier not configured"), http.StatusServiceUnavailable)
			return
		}
		valid, err := h.lineage.verifier.VerifyRequest(r.Context(), requestID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("verify lineage: %w", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"request_id": requestID,
			"valid":      valid,
		})
	}
}

// ListLineageByOrg handles GET /api/organizations/{id}/lineage.
func (h *AdminHandlers) ListLineageByOrg() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.lineage.store == nil {
			h.respondError(w, r, fmt.Errorf("lineage store not configured"), http.StatusServiceUnavailable)
			return
		}
		orgID := chi.URLParam(r, "id")
		if resolved := h.requireOrgScope(w, r, orgID, adminstore.PermLineageRead); resolved == "" {
			return
		}
		limit := 50 // default
		if v := r.URL.Query().Get("limit"); v != "" {
			n, err := fmt.Sscanf(v, "%d", &limit)
			if err != nil || n != 1 || limit <= 0 || limit > 1000 {
				limit = 50
			}
		}
		// Server-side filters (ASTR-09 debt): model and an RFC3339 [from, to]
		// window — the LIMIT now applies after filtering, not to a windowless
		// head that the client then filters again.
		q := r.URL.Query()
		var from, to time.Time
		if v := q.Get("from"); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				h.respondError(w, r, fmt.Errorf("invalid from format, use RFC3339"), http.StatusBadRequest)
				return
			}
			from = t
		}
		if v := q.Get("to"); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				h.respondError(w, r, fmt.Errorf("invalid to format, use RFC3339"), http.StatusBadRequest)
				return
			}
			to = t
		}
		records, err := h.lineage.store.ListLineageByOrgFiltered(r.Context(), orgID, q.Get("model"), from, to, limit)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("list lineage: %w", err), http.StatusInternalServerError)
			return
		}
		if records == nil {
			records = []lineage.Attestation{}
		}
		writeJSON(w, http.StatusOK, records)
	}
}
