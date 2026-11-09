package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

// SetInternalServiceKey enables the read-only /internal service API (used by
// trcli and local automation). The key is compared with constant-time equality
// (adminauth.AuthFromHeader). When never set, the group is not mounted at all.
func (h *AdminHandlers) SetInternalServiceKey(key string) {
	h.internalServiceKey = key
}

// mountInternalAPI registers the /internal group on the root router. It sits
// under the global timeout/body-size/security-header and rate-limit middlewares,
// outside the cookie session + CSRF chain: header auth is stateless by design.
func (h *AdminHandlers) mountInternalAPI(r chi.Router) {
	if h.internalServiceKey == "" {
		return
	}
	r.Route("/internal", func(ir chi.Router) {
		ir.Use(adminauth.AuthFromHeader(h.internalServiceKey))
		ir.Get("/api-keys", h.internalAPIKeys())
		ir.Get("/analytics/savings", h.internalSavingsReport())
		ir.Get("/analytics/cost", h.internalCostReport())
	})
}

// internalAPIKeys lists the API keys of exactly one org. Read-only service
// path: org_id is mandatory so a leaked key never yields a cross-org view
// (unlike the root UI endpoint, which may also list globally).
func (h *AdminHandlers) internalAPIKeys() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id query parameter is required"})
			return
		}
		ptr := orgID
		f := parsePage(r)
		keys, total, err := h.store.ListAPIKeys(r.Context(), &ptr, f)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writePaginated(w, f, keys, total)
	}
}

// internalSavingsReport returns the org savings analytics for a bounded window.
// Read-only service path: org_id is mandatory.
func (h *AdminHandlers) internalSavingsReport() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id query parameter is required"})
			return
		}
		days := 7
		if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 {
			days = d
		}
		report, err := h.store.GetSavingsReport(r.Context(), orgID, days, "")
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, report)
	}
}

// internalCostReport returns the org cost analytics for a bounded window.
// Read-only service path mirroring the dashboard CostAnalyticsHandler, but
// stateless (X-Admin-Key) for machine callers such as the MCP bridge; org_id
// is mandatory so a leaked service key never yields a cross-org view.
func (h *AdminHandlers) internalCostReport() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id query parameter is required"})
			return
		}
		days := 7
		if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d > 0 {
			days = d
		}
		to := time.Now()
		from := to.AddDate(0, 0, -days)
		report, err := h.store.GetCostAnalytics(r.Context(), orgID, from, to, "")
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, report)
	}
}
