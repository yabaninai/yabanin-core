package handlers

// CRUD group: MCP servers (MCP-02), per-agent MCP grants (MCP-03), tool
// policies (TOOL-01) and A2A agents (A2A-01). All root-only and org-scoped
// (S01); every store is nil without a DB and its routes answer 503.

import (
	"github.com/go-chi/chi/v5"
)

// mountMCP registers the MCP/tool-policy/A2A registry CRUD routes.
func (h *AdminHandlers) mountMCP(r chi.Router) {
	// MCP servers (MCP-02): external MCP server registry + invoke proxy
	// allow-list. Root-only; org-scoped (S01). The store is nil when no
	// DB is configured — the routes answer 503 (requireMCPStore).
	r.Post("/api/organizations/{id}/mcp/servers", h.CreateMCPServer())
	r.Get("/api/organizations/{id}/mcp/servers", h.ListMCPServers())
	r.Get("/api/organizations/{id}/mcp/servers/{name}", h.GetMCPServer())
	r.Patch("/api/organizations/{id}/mcp/servers/{name}", h.UpdateMCPServer())
	r.Delete("/api/organizations/{id}/mcp/servers/{name}", h.DeleteMCPServer())
	// Tool policies (TOOL-01): per-org tool-call governance. Root-only;
	// org-scoped (S01). Store nil without DB → 503.
	// POST /api/tool-policies is the dashboard-facing alias of the
	// org-scoped create (N07-P07-T06): the console's create posts this
	// path and addresses the org via the body org_id, which the handler's
	// requireOrgScope consumes for the root operator. Same group → the
	// identical guard chain (session+csrf+root+orgscope); the drift gate
	// and the fully-wired golden walk keep the alias from ever drifting
	// weaker than the scoped surface.
	r.Post("/api/tool-policies", h.CreateToolPolicy())
	r.Post("/api/organizations/{id}/tool-policies", h.CreateToolPolicy())
	r.Get("/api/organizations/{id}/tool-policies", h.ListToolPolicies())
	r.Get("/api/organizations/{id}/tool-policies/presets", h.ListToolPolicyPresets())
	r.Post("/api/organizations/{id}/tool-policies/presets/{preset}", h.ApplyToolPolicyPreset())
	r.Get("/api/organizations/{id}/tool-policies/{name}", h.GetToolPolicy())
	r.Patch("/api/organizations/{id}/tool-policies/{name}", h.UpdateToolPolicy())
	r.Delete("/api/organizations/{id}/tool-policies/{name}", h.DeleteToolPolicy())
	// A2A agents (A2A-01): external A2A agent registry. Root-only;
	// org-scoped (S01). The store is nil when no DB is configured — the
	// routes answer 503 (requireA2AStore).
	r.Post("/api/organizations/{id}/a2a/agents", h.CreateA2AAgent())
	r.Get("/api/organizations/{id}/a2a/agents", h.ListA2AAgents())
	r.Get("/api/organizations/{id}/a2a/agents/{name}", h.GetA2AAgent())
	r.Patch("/api/organizations/{id}/a2a/agents/{name}", h.UpdateA2AAgent())
	r.Delete("/api/organizations/{id}/a2a/agents/{name}", h.DeleteA2AAgent())
	// MCP-03: per-agent grants (a yag_ agent may invoke a server's tools).
	r.Get("/api/organizations/{id}/mcp/servers/{name}/grants", h.ListMCPGrants())
	r.Post("/api/organizations/{id}/mcp/servers/{name}/grants", h.CreateMCPGrant())
	r.Patch("/api/organizations/{id}/mcp/servers/{name}/grants/{agent_id}", h.UpdateMCPGrant())
	r.Delete("/api/organizations/{id}/mcp/servers/{name}/grants/{agent_id}", h.DeleteMCPGrant())
	// MC-1: the server-level MCP credential (one per server, encrypted at
	// rest, masked reads). Root-only; org-scoped (S01). Store nil without a
	// DB → 503 (requireMCPCredStore).
	r.Put("/api/organizations/{id}/mcp/servers/{name}/credential", h.PutMCPServerCredential())
	r.Get("/api/organizations/{id}/mcp/servers/{name}/credential", h.GetMCPServerCredential())
	r.Delete("/api/organizations/{id}/mcp/servers/{name}/credential", h.DeleteMCPServerCredential())
}
