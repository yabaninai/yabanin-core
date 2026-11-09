package handlers

// dashboard-aggregate endpoints every admin sees after login.

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// mountConsole registers /api/me, /api/version and the root dashboard
// aggregate on the protected (session-authed) subrouter.
func (h *AdminHandlers) mountConsole(protected chi.Router) {
	// AUX-13: console identity + per-org rights for UI hints (disabled
	// buttons, hidden nav). UI-only convenience — the server keeps arbitrating
	// every route. Portal deployments keep serving the portal /api/me above
	// (static route wins over this mount); the dashboard then fails open via
	// the hook's error path.
	protected.Get("/api/me", h.Me())
	// W-SECADM: self-service password change (session + CSRF as every
	// protected mutation; the handler re-issues the caller's session and the
	// store's watermark revokes all older ones).
	protected.Post("/api/me/password", h.ChangeMyPassword())
	// Version handshake for the dashboard (the client compares
	// api_level after login). Same session gate as /api/me — the protected
	// group's ChiAuthMiddleware + CSRFValidation (GET exempt); the handler
	// itself additionally fails closed without a session context. Build
	// facts only: version/commit/api_level/migration, no secrets, no paths.
	protected.Get("/api/version", h.Version())
	protected.With(adminauth.MustBeRoot()).Method(http.MethodPost, "/api/root/payload-grants", h.apiRootRequestPayloadGrant())

	// Server-side coding-agent config render
	// over pkg/clientconfig — the dashboard's TS mirror is retired in favor
	// of this endpoint. Plain session gate: the render is caller-supplied
	// params over stateless templates (no DB read, no secret can enter or
	// leave), so an org-permission gate would gate nothing real. GET is
	// CSRF-exempt like every read.
	protected.Get("/api/client-config/{agent}", h.ClientConfig())

	// W-WELCOME: per-org onboarding progress (read + advance). Org-scoped
	// under RequireOrgRole(reader+): any member manages their org's flow
	// state, root bypasses, a foreign org 403s — the onboarding flag is
	// operator-visible state, not a platform setting, so MustBeRoot would be
	// the wrong gate. GET is CSRF-exempt; POST carries CSRF like every
	// protected mutation. Stores without the capability answer 501 (the
	// dashboard degrades to an unpersisted flow).
	onboarding := protected.With(h.RequireOrgRole(adminstore.RoleReader))
	onboarding.Get("/api/me/onboarding", h.MyOnboarding())
	onboarding.Post("/api/me/onboarding", h.MarkMyOnboarding())

	// The legacy dashboard aggregate (stats/models/top-orgs without an org
	// scope) is a cross-org view: root-only, same principle as audit-logs and
	// top-orgs (TP-01). Org-scoped analytics stay under RequireOrgPermission.
	protected.With(adminauth.MustBeRoot()).Get("/", h.dashboard())
}
