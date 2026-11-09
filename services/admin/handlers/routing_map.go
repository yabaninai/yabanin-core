package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// org member vs foreign org) is enforced in the handler, not middleware, so
// a foreign org_id is answered 404 (no leak that the org exists) instead of
// the middleware's 403 — the acceptance matrix for these endpoints.

// RoutingMapStore is the narrow capability the routing map handler needs.
// The concrete *adminstore.Store implements it; capability interfaces keep
// the broad StoreInterface untouched.
type RoutingMapStore interface {
	GetRoutingMap(ctx context.Context, orgID string) (*adminstore.RoutingMap, error)
}

// requireOrgRead gates a read-only org-scoped view: root (the platform
// operator) passes for any org; a non-root caller must hold perm on the
// requested org. Anything else — a foreign org, or a membership without the
// permission — is answered 404 with a bare "not found", indistinguishable
// from a missing org (no tenant existence leak).
func (h *AdminHandlers) requireOrgRead(w http.ResponseWriter, r *http.Request, orgID string, perm adminstore.Permission) bool {
	if orgID == "" {
		h.respondError(w, r, fmt.Errorf("org_id is required"), http.StatusBadRequest)
		return false
	}
	if isRoot(r) {
		return true
	}
	role, ok := h.callerRoleOnOrg(r, orgID)
	if !ok || !adminstore.RoleHas(string(role), perm) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "not found"})
		return false
	}
	return true
}

// RoutingMap handles GET /api/routing/map?org_id= — models with provider,
// failover chains and tier pools, aliases → targets, rules → targets, plus
// the computed warnings (chain to a disabled/nonexistent model, cycle in a
// chain, rule on a disabled model). Read-only; gated by routing.manage.
func (h *AdminHandlers) RoutingMap() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if !h.requireOrgRead(w, r, orgID, adminstore.PermRoutingManage) {
			return
		}
		store, ok := h.store.(RoutingMapStore)
		if !ok {
			h.respondError(w, r, fmt.Errorf("store does not support the routing map"), http.StatusNotImplemented)
			return
		}
		mapping, err := store.GetRoutingMap(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(mapping); err != nil && h.logger != nil {
			h.logger.ErrorContext(r.Context(), "encode routing map", slog.String("error", err.Error()))
		}
	}
}
