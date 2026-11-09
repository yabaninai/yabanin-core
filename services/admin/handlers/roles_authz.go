package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// ENT-02: RBAC — server-side role checks for org-scoped admin access.
//
// S01 enforced a binary matrix (root operator vs everyone-else 403). This adds
// the membership dimension: a NON-root admin may act on an org only if they hold
// a role on it (admin_org_memberships) that is at least the route's required
// role. Root (is_root) remains the platform operator and bypasses membership.
//
// Role order (adminstore.OrgRoleRank): org-admin > operator > reader > partner.
// Enforcement points:
//   - requireOrgScope (authz.go) resolves a non-root caller's role on the
//     target org and 403s when they hold none — the org-scoped MUTATION gate.
//   - RequireOrgRole (below) is the middleware for org-scoped READ/aggregate
//     routes that must be scoped to a specific org + minimum role.

// ctxKeyOrgRole carries the caller's role for the resolved org (cached per
// request so a handler + middleware that each resolve the role issue one read).
type ctxKeyOrgRole struct{}

// WithOrgRole stores the caller's role for an org in the request context.
func WithOrgRole(ctx context.Context, orgID string, role adminstore.OrgRole) context.Context {
	m := map[string]adminstore.OrgRole{}
	if prev, ok := ctx.Value(ctxKeyOrgRole{}).(map[string]adminstore.OrgRole); ok {
		m = prev
	}
	m[orgID] = role
	return context.WithValue(ctx, ctxKeyOrgRole{}, m)
}

// orgRoleFromContext returns a previously-resolved role for an org.
func orgRoleFromContext(ctx context.Context, orgID string) (adminstore.OrgRole, bool) {
	m, ok := ctx.Value(ctxKeyOrgRole{}).(map[string]adminstore.OrgRole)
	if !ok {
		return "", false
	}
	r, ok := m[orgID]
	return r, ok
}

// callerRoleOnOrg resolves the caller's role on an org via the store, with a
// per-request cache. (zero, false) on lookup failure or no membership.
func (h *AdminHandlers) callerRoleOnOrg(r *http.Request, orgID string) (adminstore.OrgRole, bool) {
	if role, ok := orgRoleFromContext(r.Context(), orgID); ok {
		return role, true
	}
	user, ok := adminauth.AdminUserFromContext(r)
	if !ok || user.ID == "" {
		return "", false
	}
	roles, err := h.store.GetUserOrgRoles(r.Context(), user.ID)
	if err != nil {
		return "", false
	}
	role, present := roles[orgID]
	if !present {
		return "", false
	}
	// NOTE: WithOrgRole would need a request replacement to take effect;
	// *http.Request is a value here, so the per-request role cache is
	// currently inert (the store lookup above is the source of truth).
	_ = WithOrgRole
	return role, true
}

// targetOrgID resolves the org a request targets for RBAC, most-explicit
// first: the path param, then the org_id query param (the analytics group
// targets its org via ?org_id= — that query IS the data target and must win
// over the ambient OrgHeader scope hint), then the out-of-band OrgHeader.
// (Reads no body — role checks run for reads too, where there is no body.)
func targetOrgID(r *http.Request) string {
	// {id} is the org only on /api/organizations and /api/orgs. Other routes
	// (api-keys, teams, agent-keys) use {id} for the resource, so a bare
	// PathValue("id") would treat the key id as the org and 403 the owner.
	if strings.HasPrefix(r.URL.Path, "/api/organizations/") || strings.HasPrefix(r.URL.Path, "/api/orgs/") {
		if v := r.PathValue("id"); v != "" {
			return v
		}
		if v := r.PathValue("orgID"); v != "" {
			return v
		}
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/api/organizations/"); ok {
		if id, _, _ := strings.Cut(rest, "/"); id != "" {
			return id
		}
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/api/orgs/"); ok {
		if id, _, _ := strings.Cut(rest, "/"); id != "" {
			return id
		}
	}
	if v := r.URL.Query().Get("org_id"); v != "" {
		return v
	}
	return r.Header.Get(OrgHeader)
}

// RequireOrgRole is the RBAC middleware for org-scoped routes: it resolves the
// target org and requires the caller to hold at least minRole on it. Root
// always passes (the platform operator). A non-root caller with no role on the
// target org is 403'd — including for reads (a reader may read their own org,
// not an org they have no role on).
func (h *AdminHandlers) RequireOrgRole(minRole adminstore.OrgRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isRoot(r) {
				next.ServeHTTP(w, r)
				return
			}
			orgID := targetOrgID(r)
			if orgID == "" {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "org target required"})
				return
			}
			role, ok := h.callerRoleOnOrg(r, orgID)
			if !ok || adminstore.OrgRoleRank(role) < adminstore.OrgRoleRank(minRole) {
				writeJSON(w, http.StatusForbidden, apiError{Error: "insufficient role for this organization"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireOrgPermission allows the request when the caller holds p on the
// target org. Root passes. No membership, an unknown role, or a role without
// p is 403. The org is resolved the same way as RequireOrgRole.
func (h *AdminHandlers) RequireOrgPermission(p adminstore.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isRoot(r) {
				next.ServeHTTP(w, r)
				return
			}
			orgID := targetOrgID(r)
			if orgID == "" {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "org target required"})
				return
			}
			role, ok := h.callerRoleOnOrg(r, orgID)
			if !ok || !adminstore.RoleHas(string(role), p) {
				writeJSON(w, http.StatusForbidden, apiError{Error: "insufficient permission for this organization"})
				return
			}
			// Handlers still call requireOrgScope, which reads the scope set by
			// OrgScopeMiddleware. These routes no longer sit in that group, so
			// the resolved target becomes the scope for the rest of the request.
			ctx := context.WithValue(r.Context(), ctxKeyOrgScope{}, orgID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GlobalRoleStore is the capability for reading a platform-level admin
// global role (admin_users.global_role), type-asserted from StoreInterface
// like CASStore. Only the real adminstore.Store provides it.
type GlobalRoleStore interface {
	GetAdminUserGlobalRole(ctx context.Context, userID string) (string, error)
}

// globalRoleStore returns the store's global-role capability, or nil when the
// backend does not provide it (fail-closed at the call site).
func (h *AdminHandlers) globalRoleStore() GlobalRoleStore {
	gs, _ := h.store.(GlobalRoleStore)
	return gs
}

// RequireGlobalAuditRead is the RBAC middleware for the platform-wide audit
// journal. AUTH-01: admission comes ONLY from admin_users.global_role
// (operator-provisioned security_auditor) or root. Org memberships are
// deliberately NOT consulted — org admins can grant the org security_auditor
// role inside their own org (member create/update, invite accept, SCIM), so
// membership-sourced admission would hand every org admin a reader of every
// org's journal. Unknown user, a missing capability, or any store error is
// 403 (fail-closed).
func (h *AdminHandlers) RequireGlobalAuditRead() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isRoot(r) {
				next.ServeHTTP(w, r)
				return
			}
			denied := true
			user, ok := adminauth.AdminUserFromContext(r)
			if ok && user.ID != "" {
				if gs := h.globalRoleStore(); gs != nil {
					role, err := gs.GetAdminUserGlobalRole(r.Context(), user.ID)
					if err == nil && adminstore.CanReadGlobalAudit(false, role) {
						denied = false
					}
				}
			}
			if denied {
				writeJSON(w, http.StatusForbidden, apiError{Error: "insufficient role for the platform audit"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
