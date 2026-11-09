package handlers

// exist only when SetPortal enabled it. The static portal /api/me is
// registered on the top-level router before the dashboard subrouter is
// mounted, so it wins over the console's session-authed /api/me.

import (
	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

// mountPortal registers the developer-portal login/callback pages and the
// portal-scoped API (portal session + portal CSRF).
func (h *AdminHandlers) mountPortal(r chi.Router) {
	if h.portal.enabled {
		r.Get("/portal/login", h.PortalLogin())
		r.Get("/portal/callback", h.PortalCallback())
		r.Get("/portal", h.PortalHome())
		r.Post("/portal/keys", h.PortalCreateKeyPage())
		r.Post("/portal/keys/{id}/revoke", h.PortalRevokeKeyPage())
		portalAuthed := r.With(adminauth.PortalAuthMiddleware(h.sessionSecret), adminauth.PortalCSRFValidation())
		portalAuthed.Post("/portal/logout", h.PortalLogout())
		portalAuthed.Get("/api/me", h.PortalMe())
		portalAuthed.Get("/api/me/keys", h.PortalListKeys())
		portalAuthed.Post("/api/me/keys", h.PortalCreateKey())
		portalAuthed.Delete("/api/me/keys/{id}", h.PortalDeleteKey())
	}
}
