package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// AUX-13: console GET /api/me — who the caller is and what they may do.
//
// The payload mirrors the exact model RequireOrgPermission enforces
// (roles_authz.go): GetUserOrgRoles + adminstore.RoleHas, with the root flag
// from the same session revalidation source (TP-02). No new authorization
// logic lives here, and the response names only organizations the caller
// holds a membership on — a foreign org is never listed. Root bypasses
// membership (platform operator), so its org list is empty and clients treat
// is_root as "all capabilities". The server remains the sole arbiter; this
// endpoint only feeds UI hints.

// meOrganization is the caller's effective rights on one organization.
type meOrganization struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Role        adminstore.OrgRole      `json:"role"`
	Permissions []adminstore.Permission `json:"permissions"`
}

// meResponse is the console /api/me payload. The portal /api/me (portal.go)
// is a separate contract for developer-portal sessions; this one serves the
// admin console session.
type meResponse struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Email         string           `json:"email"`
	IsRoot        bool             `json:"is_root"`
	Organizations []meOrganization `json:"organizations"`
}

// Me answers GET /api/me for an authenticated console admin.
func (h *AdminHandlers) Me() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := adminauth.AdminUserFromContext(r)
		if !ok || user.ID == "" {
			// ChiAuthMiddleware always sets the session context; reaching the
			// handler without it means the route left the protected group —
			// fail closed.
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "unauthorized"})
			return
		}

		resp := meResponse{
			ID:            user.ID,
			Email:         user.Email,
			IsRoot:        user.IsRoot,
			Organizations: []meOrganization{},
		}

		// The display name is not part of the signed session; read the same
		// admin record the session revalidator uses (TP-02).
		record, err := h.store.GetAdminUserByID(r.Context(), user.ID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		resp.Name = record.DisplayName

		if user.IsRoot {
			writeJSON(w, http.StatusOK, resp)
			return
		}

		roles, err := h.store.GetUserOrgRoles(r.Context(), user.ID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		orgIDs := make([]string, 0, len(roles))
		for id := range roles {
			orgIDs = append(orgIDs, id)
		}
		sort.Strings(orgIDs) // deterministic payload (map iteration is random)

		for _, id := range orgIDs {
			role := roles[id]
			perms := make([]adminstore.Permission, 0, len(adminstore.AllPermissions()))
			for _, p := range adminstore.AllPermissions() {
				if adminstore.RoleHas(string(role), p) {
					perms = append(perms, p)
				}
			}
			org, err := h.store.GetOrganizationByID(r.Context(), id)
			if err != nil {
				if errors.Is(err, adminstore.ErrNotFound) {
					continue // orphaned membership — the org is gone
				}
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
			resp.Organizations = append(resp.Organizations, meOrganization{
				ID:          id,
				Name:        org.Name,
				Role:        role,
				Permissions: perms,
			})
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// onboardingStore is the W-WELCOME capability interface for the per-org
// onboarding progress flag (GET/POST /api/me/onboarding). Stores without it
// keep the endpoints at 501 — the same opt-in pattern as passwordChangeStore
// below; the dashboard degrades to an unpersisted flow instead of failing.
type onboardingStore interface {
	GetOrgOnboarding(ctx context.Context, orgID string) (*adminstore.OrgOnboarding, error)
	UpsertOrgOnboarding(ctx context.Context, orgID string, completed, skipped bool) error
}

// MyOnboarding answers GET /api/me/onboarding?org_id={org} (W-WELCOME): the
// caller's org onboarding flag. The route middleware (RequireOrgRole reader+)
// already proved membership on the target org, so the handler only needs the
// session context (fail closed, same contract as Me) and the org id.
func (h *AdminHandlers) MyOnboarding() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := adminauth.AdminUserFromContext(r)
		if !ok || user.ID == "" {
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "unauthorized"})
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id query parameter is required"), http.StatusBadRequest)
			return
		}
		store, ok := h.store.(onboardingStore)
		if !ok {
			h.respondError(w, r, fmt.Errorf("onboarding persistence not supported"), http.StatusNotImplemented)
			return
		}
		state, err := store.GetOrgOnboarding(r.Context(), orgID)
		if err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				h.respondError(w, r, err, http.StatusNotFound)
				return
			}
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, state)
	}
}

// MarkMyOnboarding answers POST /api/me/onboarding?org_id={org} (W-WELCOME):
// advance the org's onboarding flag — completed (flow finished / every step
// detected) or skipped (dismissed); body {completed|skipped}, exactly one
// true. The org target rides the QUERY STRING on purpose: the route
// middleware (RequireOrgRole) resolves the target org from the path, query or
// OrgHeader — never the body — so a body-carried org would 400 before the
// handler ever ran. The flags only ever advance; both/neither is a caller bug
// (400). Every mark is audit-logged: it changes what the operators see on
// their next login.
func (h *AdminHandlers) MarkMyOnboarding() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := adminauth.AdminUserFromContext(r)
		if !ok || user.ID == "" || user.Email == "" {
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "unauthorized"})
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			h.respondError(w, r, fmt.Errorf("org_id query parameter is required"), http.StatusBadRequest)
			return
		}

		var req struct {
			Completed bool `json:"completed"`
			Skipped   bool `json:"skipped"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.Completed == req.Skipped {
			h.respondError(w, r, fmt.Errorf("exactly one of completed/skipped must be true"), http.StatusBadRequest)
			return
		}

		store, ok := h.store.(onboardingStore)
		if !ok {
			h.respondError(w, r, fmt.Errorf("onboarding persistence not supported"), http.StatusNotImplemented)
			return
		}
		if err := store.UpsertOrgOnboarding(r.Context(), orgID, req.Completed, req.Skipped); err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				h.respondError(w, r, err, http.StatusNotFound)
				return
			}
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}

		mark := "completed"
		if req.Skipped {
			mark = "skipped"
		}
		h.auditLogAction(r, "update", "org_onboarding",
			fmt.Sprintf("org=%s,state=%s", orgID, mark))

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// passwordChangeStore is the W-SECADM capability interface for self-service
// password changes. Stores without it keep the endpoint at 501 — the session
// middleware's watermark accessor (GetAdminUserSessionsInvalidatedAt) is the
// same opt-in pattern.
type passwordChangeStore interface {
	UpdateAdminUserPasswordHash(ctx context.Context, id, passwordHash string) error
}

// ChangeMyPassword answers POST /api/me/password for the authenticated
// console admin (W-SECADM): verify the current password, store the new
// bcrypt hash through the store's UpdateAdminUserPasswordHash — which bumps
// admin_users.sessions_changed_at, so EVERY session issued before the change
// with a fresh issued-at so the caller survives their own change while all
// other sessions die.
func (h *AdminHandlers) ChangeMyPassword() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := adminauth.AdminUserFromContext(r)
		if !ok || user.ID == "" || user.Email == "" {
			// Same fail-closed contract as Me: the route sits in the protected
			// group, so a missing session context means a wiring bug.
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "unauthorized"})
			return
		}

		var req struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if err := validateAdminPassword(req.NewPassword); err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}

		// The current password must verify against the live record. The email
		// comes from the signed session (already revalidated against the
		// store by TP-02), never from the request body.
		record, err := h.store.GetAdminUserByEmailWithHash(r.Context(), user.Email)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if adminauth.VerifyPassword(req.CurrentPassword, record.PasswordHash) != nil {
			h.respondError(w, r, fmt.Errorf("current password is incorrect"), http.StatusBadRequest)
			return
		}

		hashed, err := adminauth.HashPassword(req.NewPassword)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		pw, ok := h.store.(passwordChangeStore)
		if !ok {
			h.respondError(w, r, fmt.Errorf("password changes not supported"), http.StatusNotImplemented)
			return
		}
		if err := pw.UpdateAdminUserPasswordHash(r.Context(), user.ID, hashed); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "update", "admin_user", "id="+user.ID+",action=password_change")

		// Re-issue the caller's session. The fresh issued-at must be
		// strictly AFTER the just-written watermark — including across the
		// watermark's millisecond truncation in the guard (a cookie issued
		// in the same truncated millisecond counts as pre-change and would
		// log this very client out; see adminauth.sessionInvalidated).
		issuedAt := time.Now()
		if watermark, err := h.adminSessionsInvalidatedAt(r.Context(), user.ID); err == nil && !watermark.IsZero() {
			if at := watermark.Truncate(time.Millisecond).Add(time.Millisecond); at.After(issuedAt) {
				issuedAt = at
			}
		}
		session := adminauth.AdminSession{
			UserID:    user.ID,
			Email:     user.Email,
			IsRoot:    user.IsRoot,
			SessionID: generateSessionID(),
			IssuedAt:  issuedAt,
			ExpiresAt: issuedAt.Add(adminauth.SessionDuration),
		}
		cookie, err := adminauth.CreateAdminSessionCookie(session, h.sessionSecret)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("session error"), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
