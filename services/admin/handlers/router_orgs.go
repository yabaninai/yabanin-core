package handlers

// org-permission group, plus the root-only org/team/admin-user CRUD and the
// per-organization settings (cache, routing mode, residency packs).

import (
	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// mountOrgs registers the org-permission-gated member management routes
// and, when the portal store is wired, the developer management routes.
func (h *AdminHandlers) mountOrgs(protected chi.Router) {
	members := protected.With(h.RequireOrgPermission(adminstore.PermMembersManage))
	members.Get("/api/organizations/{id}/members", h.ListOrgMembers())
	members.Post("/api/organizations/{id}/members", h.CreateOrgMember())
	members.Put("/api/organizations/{id}/members/{userID}", h.UpdateOrgMember())
	members.Delete("/api/organizations/{id}/members/{userID}", h.DeleteOrgMember())
	// W-INV: member invitations under the same members.manage gate; the
	// public acceptance page mounts in router_public.go (/invite/{token}).
	members.Get("/api/organizations/{id}/members/invites", h.ListInvites())
	members.Post("/api/organizations/{id}/members/invite", h.CreateInvite())
	members.Post("/api/organizations/{id}/members/invites/{inviteID}/resend", h.ResendInvite())
	members.Post("/api/organizations/{id}/members/invites/{inviteID}/revoke", h.RevokeInvite())
	if h.portal.store != nil {
		members.Get("/api/organizations/{id}/developers", h.ListDevelopers())
		members.Post("/api/organizations/{id}/developers", h.CreateDeveloper())
		members.Put("/api/organizations/{id}/developers/{userID}", h.UpdateDeveloper())
		members.Delete("/api/organizations/{id}/developers/{userID}", h.DeleteDeveloper())
	}
	retention := protected.With(h.RequireOrgPermission(adminstore.PermOrgUpdate))
	retention.Get("/api/organizations/{id}/original-retention", h.GetOrgOriginalRetention())
	retention.Patch("/api/organizations/{id}/original-retention", h.UpdateOrgOriginalRetention())
}

// mountOrgsRoot registers the root-only organization surface on the root
// CRUD group: organizations, teams, admin users and the per-org settings.
func (h *AdminHandlers) mountOrgsRoot(r chi.Router) {
	// Organizations
	r.Get("/api/organizations", h.ListOrganizations())
	r.Post("/api/organizations", h.CreateOrganization())
	r.Get("/api/organizations/{id}", h.GetOrganization())
	r.Put("/api/organizations/{id}", h.UpdateOrganization())
	r.Delete("/api/organizations/{id}", h.DeleteOrganization())

	// Teams
	r.Get("/api/teams", h.ListTeams())
	r.Post("/api/teams", h.CreateTeam())
	r.Get("/api/teams/{id}", h.GetTeam())
	r.Put("/api/teams/{id}", h.UpdateTeam())
	r.Delete("/api/teams/{id}", h.DeleteTeam())

	// Admin Users
	r.Get("/api/admin-users", h.ListAdminUsers())
	r.Post("/api/admin-users", h.CreateAdminUser())
	r.Get("/api/admin-users/{id}", h.GetAdminUser())
	r.Put("/api/admin-users/{id}", h.UpdateAdminUser())
	r.Delete("/api/admin-users/{id}", h.DeleteAdminUser())

	// Cache settings per organization (root-only)
	r.Get("/api/organizations/{id}/cache-settings", h.GetOrgCacheSettings())
	r.Patch("/api/organizations/{id}/cache-settings", h.UpdateOrgCacheSettings())

	// Routing mode per organization (root-only) — P5.5
	r.Get("/api/organizations/{id}/routing", h.GetOrgRoutingSettings())
	r.Patch("/api/organizations/{id}/routing", h.UpdateOrgRoutingSettings())

	// PA.6: residency policy-pack CRUD + org residency-region (root-only)
	r.Get("/api/organizations/{id}/policy-packs", h.ListPolicyPacks())
	r.Put("/api/organizations/{id}/policy-packs/{region}", h.UpsertPolicyPack())
	r.Delete("/api/organizations/{id}/policy-packs/{packID}", h.DeletePolicyPack())
	r.Get("/api/organizations/{id}/residency", h.GetOrgResidency())
	r.Put("/api/organizations/{id}/residency", h.UpdateOrgResidency())
}
