package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	chi "github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// ENT-02: RBAC — org membership (role) management.
//
// members.manage (org-admin, and root) may grant a role that is not higher
// than their own. A non-root caller cannot change their own role, and is_root
// is not a membership field — a body that carries it is rejected.

// ListOrgMembers — GET /api/organizations/{id}/members.
func (h *AdminHandlers) ListOrgMembers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		if resolved := h.requireOrgScope(w, r, id, adminstore.PermMembersManage); resolved == "" {
			return
		}
		members, err := h.store.ListOrgMembers(r.Context(), id)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": members})
	}
}

// CreateOrgMember — POST /api/organizations/{id}/members.
func (h *AdminHandlers) CreateOrgMember() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		if resolved := h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage); resolved == "" {
			return
		}
		var req struct {
			UserID string             `json:"user_id"`
			Role   adminstore.OrgRole `json:"role"`
			IsRoot *bool              `json:"is_root"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.IsRoot != nil {
			h.respondError(w, r, fmt.Errorf("is_root cannot be set on a membership"), http.StatusBadRequest)
			return
		}
		if req.UserID == "" {
			h.respondError(w, r, fmt.Errorf("user_id is required"), http.StatusBadRequest)
			return
		}
		if !adminstore.ValidOrgRole(req.Role) {
			h.respondError(w, r, fmt.Errorf("role must be one of: org-admin, operator, reader, security_auditor, partner"), http.StatusBadRequest)
			return
		}
		if h.rejectMemberChange(w, r, orgID, req.UserID, &req.Role) {
			return
		}
		m, err := h.store.CreateOrgMembership(r.Context(), adminstore.OrgMembership{UserID: req.UserID, OrgID: orgID, Role: req.Role})
		if err != nil {
			status := http.StatusInternalServerError
			if containsText(err.Error(), "already exists") {
				status = http.StatusConflict
			}
			h.respondError(w, r, err, status)
			return
		}
		h.auditLogAction(r, "create", "org_member", "org="+orgID+",user="+req.UserID+",role="+string(req.Role))
		writeJSON(w, http.StatusCreated, m)
	}
}

// UpdateOrgMember — PUT /api/organizations/{id}/members/{userID} (change role).
func (h *AdminHandlers) UpdateOrgMember() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		if resolved := h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage); resolved == "" {
			return
		}
		userID := chi.URLParam(r, "userID")
		var req struct {
			Role   adminstore.OrgRole `json:"role"`
			IsRoot *bool              `json:"is_root"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.IsRoot != nil {
			h.respondError(w, r, fmt.Errorf("is_root cannot be set on a membership"), http.StatusBadRequest)
			return
		}
		if !adminstore.ValidOrgRole(req.Role) {
			h.respondError(w, r, fmt.Errorf("role must be one of: org-admin, operator, reader, security_auditor, partner"), http.StatusBadRequest)
			return
		}
		if h.rejectMemberChange(w, r, orgID, userID, &req.Role) {
			return
		}
		m, err := h.store.SetOrgMembership(r.Context(), userID, orgID, req.Role)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "update", "org_member", "org="+orgID+",user="+userID+",role="+string(req.Role))
		writeJSON(w, http.StatusOK, m)
	}
}

// DeleteOrgMember — DELETE /api/organizations/{id}/members/{userID}.
func (h *AdminHandlers) DeleteOrgMember() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		if resolved := h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage); resolved == "" {
			return
		}
		userID := chi.URLParam(r, "userID")
		if h.rejectMemberChange(w, r, orgID, userID, nil) {
			return
		}
		if err := h.store.DeleteOrgMembership(r.Context(), userID, orgID); err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		h.auditLogAction(r, "delete", "org_member", "org="+orgID+",user="+userID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// containsText reports whether s contains sub (used to map the unique-violation
// error to a 409 without importing the store's internals here).
func containsText(s, sub string) bool {
	return strings.Contains(s, sub)
}

// rejectMemberChange blocks a non-root caller from editing their own role and
// from granting a role ranked above their own. Root is not subject to either
// rule. newRole is nil for a delete, which only checks the self-edit rule.
func (h *AdminHandlers) rejectMemberChange(w http.ResponseWriter, r *http.Request, orgID, targetUser string, newRole *adminstore.OrgRole) bool {
	if isRoot(r) {
		return false
	}
	if self := requestUserID(r); self != "" && self == targetUser {
		writeJSON(w, http.StatusForbidden, apiError{Error: "cannot change your own role"})
		return true
	}
	if newRole == nil {
		return false
	}
	role, ok := h.callerRoleOnOrg(r, orgID)
	if !ok || adminstore.OrgRoleRank(*newRole) > adminstore.OrgRoleRank(role) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "cannot grant a role above your own"})
		return true
	}
	return false
}
