package handlers

// groups (RM-42), plus the root-only agent-profile and whitelist CRUD.

import (
	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// mountKeys registers the org-permission-gated API-key and agent-key
// routes.
func (h *AdminHandlers) mountKeys(protected chi.Router) {
	// RM-42: these routes leave MustBeRoot. Each group is one permission.
	// Ownership checks live in the handlers (a foreign id is 404).
	keys := protected.With(h.RequireOrgPermission(adminstore.PermKeysManage))
	keys.Get("/api/api-keys", h.ListAPIKeys())
	keys.Post("/api/api-keys", h.CreateAPIKey())
	keys.Get("/api/api-keys/{id}", h.GetAPIKey())
	keys.Put("/api/api-keys/{id}", h.UpdateAPIKeyActive())
	keys.Put("/api/api-keys/{id}/labels", h.UpdateAPIKeyLabels())
	keys.Post("/api/api-keys/{id}/rotate", h.RotateAPIKey())
	keys.Delete("/api/api-keys/{id}", h.DeleteAPIKey())

	agentKeys := protected.With(h.RequireOrgPermission(adminstore.PermAgentKeysManage))
	agentKeys.Get("/api/agent-keys", h.ListAgentKeys())
	agentKeys.Post("/api/agent-keys", h.CreateAgentKey())
	// Literal "delegate" before /{id} so it is not captured as an id.
	agentKeys.Post("/api/agent-keys/delegate", h.CreateDelegatedAgentKey())
	agentKeys.Get("/api/agent-keys/{id}", h.GetAgentKey())
	agentKeys.Post("/api/agent-keys/{id}/revoke", h.RevokeAgentKey())
	agentKeys.Get("/api/agent-keys/{id}/budget", h.GetAgentBudget())
	agentKeys.Put("/api/agent-keys/{id}/budget", h.UpsertAgentBudget())
	agentKeys.Delete("/api/agent-keys/{id}/budget", h.DeleteAgentBudget())
	// N04-P05 T03: scoped delegation chain (human → agent/CI subject). A key
	// authenticates but grants nothing; these routes issue/list/revoke the
	// bounded permission subset that opens scoped access.
	agentKeys.Post("/api/agent-keys/{id}/delegations", h.IssuePrincipalDelegation())
	agentKeys.Get("/api/agent-keys/{id}/delegations", h.ListPrincipalDelegations())
	agentKeys.Post("/api/agent-keys/{id}/delegations/{delegationID}/revoke", h.RevokePrincipalDelegation())
}

// mountKeysRoot registers the root-only key-issuance surface: agent role
// profiles and the per-key/per-team model whitelists.
func (h *AdminHandlers) mountKeysRoot(r chi.Router) {
	// ADL-06: agent role profiles (reusable yag_ key-issuance templates).
	r.Get("/api/agent-profiles", h.ListAgentProfiles())
	r.Post("/api/agent-profiles", h.CreateAgentProfile())
	r.Get("/api/agent-profiles/{id}", h.GetAgentProfile())
	r.Put("/api/agent-profiles/{id}", h.UpdateAgentProfile())
	r.Delete("/api/agent-profiles/{id}", h.DeleteAgentProfile())

	// Whitelists
	r.Get("/api/whitelist/api-keys/{target_id}", h.listKeyWhitelist())
	r.Post("/api/whitelist/api-keys/{target_id}", h.addKeyWhitelist())
	r.Delete("/api/whitelist/api-keys/{target_id}/{model_name}", h.removeKeyWhitelist())
	r.Get("/api/whitelist/teams/{target_id}", h.listTeamWhitelist())
	r.Post("/api/whitelist/teams/{target_id}", h.addTeamWhitelist())
	r.Delete("/api/whitelist/teams/{target_id}/{model_name}", h.removeTeamWhitelist())
}
