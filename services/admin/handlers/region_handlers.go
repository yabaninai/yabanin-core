package handlers

// file keeps the HTTP surface (including the "sg" default read answer).

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RegionStore is the storage seam of the region-routing handlers (the
// FeedbackLister precedent): the HTTP layer depends on the two read/write
// operations plus the wired-DB probe, so the path-parameter plumbing is
// unit-testable without a live Postgres pool. *adminstore.Store satisfies it.
type RegionStore interface {
	DB() *pgxpool.Pool
	GetOrgHomeRegion(ctx context.Context, orgID string) (string, bool, error)
	UpsertOrgHomeRegion(ctx context.Context, orgID, homeRegion string, pinned bool) error
}

// RegionHandlers exposes admin endpoints for region routing management.
type RegionHandlers struct {
	store            RegionStore
	PolicyInvalidate func(orgID string)
}

// NewRegionHandlers creates admin HTTP handlers for region routing management.
func NewRegionHandlers(s RegionStore, invalidate func(string)) *RegionHandlers {
	return &RegionHandlers{store: s, PolicyInvalidate: invalidate}
}

// GetOrgRegion returns the home region assignment for an org.
func (h *RegionHandlers) GetOrgRegion(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id") // the route registers {id} (router_ops.go)
	if h.store == nil || h.store.DB() == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "database not configured"})
		return
	}
	region, pinned, err := h.store.GetOrgHomeRegion(r.Context(), orgID)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{
			"home_region":      region,
			"residency_pinned": pinned,
		})
	case errors.Is(err, pgx.ErrNoRows):
		// No assignment row yet — the org was never pinned. This is the
		// documented default answer, not an outage.
		writeJSON(w, http.StatusOK, map[string]any{"home_region": "sg", "residency_pinned": false})
	default:
		// Store outage/timeout: answer honestly instead of papering it over
		// with the "sg" default — the API must never state a residency the
		// database did not answer (A04: 200 masquerade made UIs render a
		// false residency). The typed no-row sentinel stays the only path
		// to the default; everything else is a 5xx.
		slog.Error("get org home region: region store unavailable", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "region store unavailable"})
	}
}

// UpdateOrgRegion upserts the org home-region assignment.
func (h *RegionHandlers) UpdateOrgRegion(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "id") // the route registers {id} (router_ops.go)
	var body struct {
		HomeRegion string `json:"home_region"`
		Pinned     bool   `json:"residency_pinned"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid body"})
		return
	}
	if h.store == nil || h.store.DB() == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "database not configured"})
		return
	}
	if err := h.store.UpsertOrgHomeRegion(r.Context(), orgID, body.HomeRegion, body.Pinned); err != nil {
		// Same honesty as the read path: a failed residency write is a 5xx,
		// never a silent success, and the internal store error detail stays
		// server-side (the client gets the generic apiError shape).
		slog.Error("update org home region: region store unavailable", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "region store unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ListRegions returns the known regions from config.
func (h *RegionHandlers) ListRegions(w http.ResponseWriter, r *http.Request) {
	// Regions are loaded from config; exposed here for admin visibility.
	writeJSON(w, http.StatusOK, map[string]any{
		"regions": []string{"sg", "in", "eu"},
	})
}
