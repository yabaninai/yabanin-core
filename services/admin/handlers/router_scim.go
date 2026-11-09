package handlers

//
//   - /scim/v2/** — the RFC 7644 provisioning server, authenticated by the
//     org-scoped SCIM bearer token (scimAuthMiddleware). Mounted on the
//     PUBLIC router deliberately: it must NOT sit behind the admin cookie
//     session — the IdP authenticates with its issued token only.
//   - /api/organizations/{id}/scim/tokens — the admin console surface that
//     issues/revokes those tokens, under the org:members.manage gate (root
//     or the org's owners), exactly like member invitations.

import (
	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// mountSCIM registers the /scim/v2 bearer-authenticated provisioning server.
func (h *AdminHandlers) mountSCIM(r chi.Router) {
	r.Route(scimBasePath, func(sr chi.Router) {
		sr.Use(h.scimAuthMiddleware)
		sr.Use(h.scimAuditMiddleware)
		sr.Get("/ServiceProviderConfig", h.SCIMServiceProviderConfig())
		// RFC 7644 §4 discovery trio — /Schemas and
		// /ResourceTypes serve static documents of the supported subset.
		sr.Get("/Schemas", h.SCIMSchemas())
		sr.Get("/ResourceTypes", h.SCIMResourceTypes())

		sr.Get("/Users", h.SCIMListUsers())
		sr.Post("/Users", h.SCIMCreateUser())
		sr.Get("/Users/{id}", h.SCIMGetUser())
		sr.Put("/Users/{id}", h.SCIMPutUser())
		sr.Patch("/Users/{id}", h.SCIMPatchUser())
		sr.Delete("/Users/{id}", h.SCIMDeleteUser())

		sr.Get("/Groups", h.SCIMListGroups())
		sr.Post("/Groups", h.SCIMCreateGroup())
		sr.Get("/Groups/{id}", h.SCIMGetGroup())
		sr.Patch("/Groups/{id}", h.SCIMPatchGroup())
		sr.Delete("/Groups/{id}", h.SCIMDeleteGroup())
	})
}

// mountSCIMAdmin registers the org-scoped token management routes under the
// members.manage permission group.
func (h *AdminHandlers) mountSCIMAdmin(protected chi.Router) {
	tokens := protected.With(h.RequireOrgPermission(adminstore.PermMembersManage))
	tokens.Get("/api/organizations/{id}/scim/tokens", h.ListScimTokens())
	tokens.Post("/api/organizations/{id}/scim/tokens", h.CreateScimToken())
	tokens.Delete("/api/organizations/{id}/scim/tokens/{tokenID}", h.RevokeScimToken())
}
