package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/cache"
)

// GetOrgCacheSettings handles GET /api/organizations/{id}/cache-settings.
// Returns per-org cache mode and enabled flag.
func (h *AdminHandlers) GetOrgCacheSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		cs, err := h.store.GetOrgCacheSettings(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("cache settings: %w", err), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, cs)
	}
}

// UpdateOrgCacheSettings handles PATCH /api/organizations/{id}/cache-settings.
// Updates per-org cache mode and enabled flag.
func (h *AdminHandlers) UpdateOrgCacheSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")

		var req struct {
			CacheEnabled bool   `json:"cache_enabled"`
			CacheMode    string `json:"cache_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}

		// Validate mode.
		mode := strings.ToLower(req.CacheMode)
		if mode != "" && mode != "off" && mode != "exact" && mode != "semantic" {
			h.respondError(w, r, fmt.Errorf("invalid cache_mode: %q (valid: off, exact, semantic)", req.CacheMode), http.StatusBadRequest)
			return
		}
		if mode == "" {
			mode = "semantic" // default
		}

		if err := h.store.UpdateOrgCacheSettings(r.Context(), orgID, req.CacheEnabled, mode); err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				h.respondError(w, r, fmt.Errorf("update cache settings: %w", err), http.StatusNotFound)
				return
			}
			h.respondError(w, r, fmt.Errorf("update cache settings: %w", err), http.StatusInternalServerError)
			return
		}

		h.auditLogActionWithCtx(r.Context(), r, "update", "org_cache_settings",
			fmt.Sprintf("id=%s enabled=%v mode=%s", orgID, req.CacheEnabled, mode))

		if h.policyLoader != nil {
			h.policyLoader.Invalidate(orgID)
		}

		// If cache was disabled, flush all entries for this org. The
		// settings mutation is the contract of this endpoint and stays 200
		// even when the flush fails (best-effort cleanup, bounded by the
		// remaining entry TTL) — but the failure is never silent: the warn
		// log carries the error and its retryability class (FIX-04).
		if !req.CacheEnabled && h.inv != nil {
			if err := h.inv.InvalidateOrgAll(r.Context(), orgID); err != nil {
				h.logger.Warn("org cache flush failed after disable; stale entries remain until TTL",
					"org_id", orgID, "error", err,
					"retryable", cache.IsRetryable(r.Context(), err), "canceled", cache.IsCancellation(err))
			}
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// FlushCache handles POST /api/cache/flush to flush cache for an org or model tier.
func (h *AdminHandlers) FlushCache() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		modelTier := r.URL.Query().Get("model_tier")
		reason := r.URL.Query().Get("reason")
		if reason == "" {
			reason = "manual"
		}

		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id query parameter is required"), http.StatusBadRequest)
			return
		}

		var err error
		if h.inv == nil {
			h.respondError(w, r, fmt.Errorf("cache invalidator not configured"), http.StatusServiceUnavailable)
			return
		}
		if modelTier != "" {
			// RT-05: flush the current route namespace's version, not the
			// legacy "1" — new entries are written under cache.RouteVersion.
			err = h.inv.InvalidateModelVersion(r.Context(), modelTier, cache.RouteVersion)
		} else {
			err = h.inv.InvalidateOrgAll(r.Context(), orgID)
		}
		// FIX-04: InvalidateModelVersion/InvalidateOrgAll report SCAN/DEL
		// failures honestly now, so an error here means stale keys may
		// remain. The failure is answered 5xx (never "flushed") and the
		// full partial-state error is in the error log written by
		// respondError — the 5xx body itself stays generic per S01.
		if err != nil {
			h.respondError(w, r, fmt.Errorf("cache flush: %w", err), http.StatusInternalServerError)
			return
		}

		h.auditLogActionWithCtx(r.Context(), r, "flush", "cache",
			fmt.Sprintf("org_id=%s model_tier=%s reason=%s", orgID, modelTier, reason))

		writeJSON(w, http.StatusOK, map[string]string{"status": "flushed"})
	}
}

// CacheAnalytics handles GET /api/cache/analytics.
// Returns aggregate cache analytics data.
func (h *AdminHandlers) CacheAnalytics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}

		snapshot := cache.GetAnalyticsSnapshot()
		if snapshot == nil {
			snapshot = map[string]interface{}{"error": "no analytics data"}
		}
		writeJSON(w, http.StatusOK, snapshot)
	}
}

// The deprecated cache-warm route announces its lifecycle on the wire: the
// dates mirror the x-deprecated-since / x-sunset metadata of
// POST /api/cache/warm in docs/api/admin.openapi.yaml, and the lifecycle
// test keeps the two in lock-step (docs/api/CONTRACT.md §9). A constant
// misparse fails at init, not at request time.
const (
	cacheWarmDeprecationSince = "2026-10-31"
	cacheWarmSunset           = "2027-04-29"
)

var (
	cacheWarmDeprecationHeader = imfFixdate(cacheWarmDeprecationSince)
	cacheWarmSunsetHeader      = imfFixdate(cacheWarmSunset)
)

// imfFixdate renders an RFC3339 date as the IMF-fixdate form HTTP date
// headers use.
func imfFixdate(day string) string {
	t, err := time.Parse(time.DateOnly, day)
	if err != nil {
		panic(fmt.Sprintf("invalid lifecycle date %q: %v", day, err))
	}
	return t.UTC().Format(http.TimeFormat)
}

// WarmCache handles POST /api/cache/warm.
//
// Deprecated (W-CACHE): the history warmer wrote unsigned entries that the
// RT-05 lookup always rejected, so it had no production value and was removed.
// The route is kept mounted but answers 410 Gone, with Deprecation/Sunset
// headers so the notice reaches clients that never read the spec.
func (h *AdminHandlers) WarmCache() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Deprecation", cacheWarmDeprecationHeader)
		w.Header().Set("Sunset", cacheWarmSunsetHeader)
		if !h.requireStore(w, r) {
			return
		}
		writeJSON(w, http.StatusGone, map[string]string{
			"status":  "gone",
			"message": "cache warming is deprecated and removed; the semantic cache learns from live traffic only",
		})
	}
}

// BumpModelVersion handles POST /api/models/{name}/bump-version.
// Manually bumps the model version to invalidate stale cache entries.
func (h *AdminHandlers) BumpModelVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		name := chi.URLParam(r, "name")

		if err := h.store.BumpModelVersion(r.Context(), name); err != nil {
			h.respondError(w, r, fmt.Errorf("bump model version: %w", err), http.StatusNotFound)
			return
		}

		h.auditLogActionWithCtx(r.Context(), r, "bump_version", "model", fmt.Sprintf("name=%s", name))
		writeJSON(w, http.StatusOK, map[string]string{"status": "version bumped"})
	}
}

// CacheAnalyticsHandler returns cache hit-rate and savings analytics for an org.
func (h *AdminHandlers) CacheAnalyticsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "org_id")

		fromStr := r.URL.Query().Get("from")
		toStr := r.URL.Query().Get("to")

		from := time.Now().Add(-24 * time.Hour)
		to := time.Now()
		if fromStr != "" {
			if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
				from = t
			}
		}
		if toStr != "" {
			if t, err := time.Parse(time.RFC3339, toStr); err == nil {
				to = t
			}
		}

		analytics, err := h.store.GetCacheAnalytics(r.Context(), orgID, from, to)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("get cache analytics: %w", err), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, analytics)
	}
}

// experimentStore returns the wired A/B experiment store, or nil when the
// deployment did not configure one (in which case the experiment endpoints
// respond 501 instead of pretending to work).
func (h *AdminHandlers) experimentStore() *cache.ExperimentStore {
	return h.experiments
}

// SetExperimentStore wires the DB-backed A/B experiment store (pkg/cache).
func (h *AdminHandlers) SetExperimentStore(s *cache.ExperimentStore) {
	h.experiments = s
}

// CreateExperimentHandler creates a new A/B experiment.
func (h *AdminHandlers) CreateExperimentHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		es := h.experimentStore()
		if es == nil {
			h.respondError(w, r, fmt.Errorf("experiment store not configured"), http.StatusNotImplemented)
			return
		}

		var req struct {
			Name       string `json:"name"`
			OrgID      string `json:"org_id"`
			TrafficPct int    `json:"traffic_pct"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.TrafficPct <= 0 || req.TrafficPct > 100 {
			h.respondError(w, r, fmt.Errorf("traffic_pct must be 1-100"), http.StatusBadRequest)
			return
		}

		exp, err := es.CreateExperiment(r.Context(), req.Name, req.OrgID, req.TrafficPct)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("create experiment: %w", err), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusCreated, exp)
	}
}

// ListExperimentsHandler lists A/B experiments.
func (h *AdminHandlers) ListExperimentsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		es := h.experimentStore()
		if es == nil {
			h.respondError(w, r, fmt.Errorf("experiment store not configured"), http.StatusNotImplemented)
			return
		}
		orgID := r.URL.Query().Get("org_id")
		enabled := r.URL.Query().Get("enabled") == "true"

		experiments, err := es.ListExperiments(r.Context(), orgID, enabled)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("list experiments: %w", err), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, experiments)
	}
}

// GetExperimentResultsHandler returns savings per variant.
func (h *AdminHandlers) GetExperimentResultsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		es := h.experimentStore()
		if es == nil {
			h.respondError(w, r, fmt.Errorf("experiment store not configured"), http.StatusNotImplemented)
			return
		}
		expID := chi.URLParam(r, "exp_id")

		results, err := es.GetResults(r.Context(), expID)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("get results: %w", err), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, results)
	}
}
