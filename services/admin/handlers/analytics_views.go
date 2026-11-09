package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

const analyticsViewLimit = 100

// AnalyticsViewStore is the saved-view table.
type AnalyticsViewStore interface {
	ListAnalyticsViews(ctx context.Context, orgID, ownerID string) ([]adminstore.AnalyticsView, error)
	CountAnalyticsViews(ctx context.Context, orgID, ownerID string) (int, error)
	CreateAnalyticsView(ctx context.Context, view adminstore.AnalyticsView) (adminstore.AnalyticsView, error)
	GetAnalyticsView(ctx context.Context, id string) (adminstore.AnalyticsView, error)
	UpdateAnalyticsView(ctx context.Context, view adminstore.AnalyticsView) error
	DeleteAnalyticsView(ctx context.Context, id string) error
}

// SetAnalyticsViewStore wires the views table. Nil answers 503.
func (h *AdminHandlers) SetAnalyticsViewStore(s AnalyticsViewStore) { h.analytics.views = s }

func (h *AdminHandlers) requireViews(w http.ResponseWriter, r *http.Request) bool {
	if h.analytics.views == nil {
		h.respondError(w, r, fmt.Errorf("analytics views are not configured"), http.StatusServiceUnavailable)
		return false
	}
	return true
}

type analyticsViewBody struct {
	Name   string            `json:"name"`
	Query  map[string]string `json:"query"`
	Shared bool              `json:"shared"`
}

// ListAnalyticsViews — GET /api/analytics/views?org_id= (analytics.read).
func (h *AdminHandlers) ListAnalyticsViews() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireViews(w, r) {
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id is required"), http.StatusBadRequest)
			return
		}
		views, err := h.analytics.views.ListAnalyticsViews(r.Context(), orgID, adminIDFromContext(r))
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, views)
	}
}

// CreateAnalyticsView — POST /api/analytics/views?org_id= (analytics.read).
func (h *AdminHandlers) CreateAnalyticsView() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireViews(w, r) {
			return
		}
		// AT-22: the created view's org comes from the request identity only —
		// the ?org_id query (the target RequireOrgPermission membership-checks)
		// or the out-of-band org header. The body never supplies the org: with
		// an empty ?org_id the middleware validated membership against the
		// header org, so honoring a body org_id would let an admin of org-A
		// write a shared view into org-B without any role there.
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			orgID = r.Header.Get(OrgHeader)
		}
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id is required"), http.StatusBadRequest)
			return
		}
		body, ok := decodeViewBody(w, r)
		if !ok {
			return
		}
		if body.Query == nil {
			body.Query = map[string]string{}
		}
		if body.Query["org_id"] != "" && body.Query["org_id"] != orgID {
			h.respondError(w, r, fmt.Errorf("query org_id does not match the request"), http.StatusBadRequest)
			return
		}
		body.Query["org_id"] = orgID
		name, query, ok := h.normalizeView(w, r, body)
		if !ok {
			return
		}
		owner := adminIDFromContext(r)
		n, err := h.analytics.views.CountAnalyticsViews(r.Context(), orgID, owner)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if n >= analyticsViewLimit {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "view_limit", "code": "view_limit"})
			return
		}
		created, err := h.analytics.views.CreateAnalyticsView(r.Context(), adminstore.AnalyticsView{
			OrgID: orgID, OwnerID: owner, Name: name, Query: query, Shared: body.Shared,
		})
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if body.Shared {
			h.auditLogAction(r, "analytics_view.create", "analytics_view:"+created.ID, "shared=true")
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

// UpdateAnalyticsView — PUT /api/analytics/views/{id} (owner or org.update).
func (h *AdminHandlers) UpdateAnalyticsView() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireViews(w, r) {
			return
		}
		current, ok := h.loadEditableView(w, r)
		if !ok {
			return
		}
		body, ok := decodeViewBody(w, r)
		if !ok {
			return
		}
		if body.Query == nil {
			body.Query = map[string]string{}
		}
		if body.Query["org_id"] == "" {
			body.Query["org_id"] = current.OrgID
		}
		if body.Query["org_id"] != current.OrgID {
			h.respondError(w, r, fmt.Errorf("query org_id does not match the view"), http.StatusBadRequest)
			return
		}
		name, query, ok := h.normalizeView(w, r, body)
		if !ok {
			return
		}
		current.Name = name
		current.Query = query
		current.Shared = body.Shared
		if err := h.analytics.views.UpdateAnalyticsView(r.Context(), current); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, current)
	}
}

// DeleteAnalyticsView — DELETE /api/analytics/views/{id} (owner or org.update).
func (h *AdminHandlers) DeleteAnalyticsView() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireViews(w, r) {
			return
		}
		current, ok := h.loadEditableView(w, r)
		if !ok {
			return
		}
		if err := h.analytics.views.DeleteAnalyticsView(r.Context(), current.ID); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if current.Shared {
			h.auditLogAction(r, "analytics_view.delete", "analytics_view:"+current.ID, "shared=true")
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *AdminHandlers) loadEditableView(w http.ResponseWriter, r *http.Request) (adminstore.AnalyticsView, bool) {
	view, err := h.analytics.views.GetAnalyticsView(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, adminstore.ErrNotFound) {
			status = http.StatusNotFound
		}
		h.respondError(w, r, err, status)
		return adminstore.AnalyticsView{}, false
	}
	if isRoot(r) {
		return view, true
	}
	// AT-22: a non-root caller only reaches views that belong to the org the
	// request targets (query ?org_id or the org header — the same target
	// RequireOrgPermission validated). Ownership alone does not cross the org
	// boundary, and a foreign view is 404 so its existence stays hidden.
	if h.resourceHidden(w, r, view.OrgID) {
		return adminstore.AnalyticsView{}, false
	}
	caller := adminIDFromContext(r)
	if view.OwnerID == caller {
		return view, true
	}
	if !view.Shared {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return adminstore.AnalyticsView{}, false
	}
	role, ok := h.callerRoleOnOrg(r, view.OrgID)
	if !ok {
		// No membership in the view's org: answer 404 like the private branch —
		// a 403 would reveal that the shared view exists (AT-22).
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return adminstore.AnalyticsView{}, false
	}
	if !adminstore.RoleHas(string(role), adminstore.PermOrgUpdate) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient permission for this organization"})
		return adminstore.AnalyticsView{}, false
	}
	return view, true
}

func decodeViewBody(w http.ResponseWriter, r *http.Request) (analyticsViewBody, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return analyticsViewBody{}, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var body analyticsViewBody
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return analyticsViewBody{}, false
	}
	return body, true
}

func (h *AdminHandlers) normalizeView(w http.ResponseWriter, r *http.Request, body analyticsViewBody) (string, map[string]string, bool) {
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 80 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_name", "code": "invalid_name"})
		return "", nil, false
	}
	query, err := adminstore.NormalizeAnalyticsViewQuery(body.Query, time.Now())
	if err != nil {
		if ae, ok := err.(*adminstore.AnalyticsQueryError); ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": ae.Error(), "code": ae.Code})
			return "", nil, false
		}
		h.respondError(w, r, err, http.StatusBadRequest)
		return "", nil, false
	}
	return name, query, true
}
