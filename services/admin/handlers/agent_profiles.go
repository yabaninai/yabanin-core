package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	chi "github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// --- Agent role profiles (ADL-06) ---
//
// A profile is a reusable template for issuing a yag_ agent key. CRUD lives
// here (Control Plane → "Agent profiles"); inheritance at key issuance is in
// CreateAgentKey (agentkeys.go). The single invariant enforced everywhere:
// a profile's grant set must be ⊆ the servers available to the org
// (the mcp_servers registry is the ceiling) — so a key issued on the profile
// can never inherit a grant the org has not registered.

// orgServerNames returns the set of MCP server names available to an org —
// the ceiling a profile's (or a key's) grant set may not exceed. It returns
// nil when the MCP registry is not wired (no DB) or on a read error; callers
// treat a nil ceiling as "unknown" and apply grants best-effort at issue time.
func (h *AdminHandlers) orgServerNames(ctx context.Context, orgID string) map[string]bool {
	if h.mcp.store == nil {
		return nil
	}
	servers, err := h.mcp.store.List(ctx, orgID)
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for _, s := range servers {
		set[s.Name] = true
	}
	return set
}

// orgInScope reports whether orgID is within the caller's scope, writing the
// 403 when it is not. For root (an operator) any org is in scope; for an
// org-scoped admin the middleware has pinned the scope and a mismatch is
// rejected. Returns false (and has written the response) when not allowed.
func (h *AdminHandlers) orgInScope(w http.ResponseWriter, r *http.Request, orgID string) bool {
	if isRoot(r) {
		return true
	}
	scope := OrgScopeFromRequest(r)
	if scope == "" || orgID != scope {
		writeJSON(w, http.StatusForbidden, apiError{Error: "org scope does not match the request target"})
		return false
	}
	return true
}

// assertGrantsWithinOrg enforces the ADL-06 invariant: the grant set (server
// names) must be ⊆ the servers available to the org. When the ceiling is
// unknown (no MCP registry) the check is skipped — the grants are then applied
// best-effort at issue time (a key can only use what the proxy has).
func (h *AdminHandlers) assertGrantsWithinOrg(ctx context.Context, orgID string, grants []string) error {
	ceiling := h.orgServerNames(ctx, orgID)
	if ceiling == nil {
		return nil // unknown ceiling (no MCP registry) — apply best-effort at issue
	}
	for _, g := range grants {
		if !ceiling[g] {
			return fmt.Errorf("grant %q is not an MCP server available to this organization", g)
		}
	}
	return nil
}

// CreateAgentProfile — POST /api/agent-profiles.
func (h *AdminHandlers) CreateAgentProfile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		var req struct {
			OrgID          string   `json:"org_id"`
			Name           string   `json:"name"`
			TierHint       string   `json:"tier_hint"`
			MCPGrants      []string `json:"mcp_grants"`
			BudgetCapCents *int64   `json:"budget_cap_cents"`
			GuardMode      string   `json:"guard_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			h.respondError(w, r, fmt.Errorf("name is required"), http.StatusBadRequest)
			return
		}
		orgID := h.requireOrgScope(w, r, req.OrgID)
		if orgID == "" {
			return
		}
		if req.BudgetCapCents != nil && *req.BudgetCapCents <= 0 {
			h.respondError(w, r, fmt.Errorf("budget_cap_cents must be positive when set"), http.StatusBadRequest)
			return
		}
		if err := h.assertGrantsWithinOrg(r.Context(), orgID, req.MCPGrants); err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		prof, err := h.store.CreateAgentProfile(r.Context(), adminstore.AgentProfileCreateParams{
			OrgID:          orgID,
			Name:           req.Name,
			TierHint:       req.TierHint,
			MCPGrants:      req.MCPGrants,
			BudgetCapCents: req.BudgetCapCents,
			GuardMode:      req.GuardMode,
		})
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "create", "agent_profile", "id="+prof.ID+",name="+req.Name+",org="+orgID)
		writeJSON(w, http.StatusCreated, prof)
	}
}

// ListAgentProfiles — GET /api/agent-profiles?org_id=.
func (h *AdminHandlers) ListAgentProfiles() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := h.requireOrgScope(w, r, r.URL.Query().Get("org_id"))
		if orgID == "" {
			return
		}
		profs, err := h.store.ListAgentProfiles(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": profs})
	}
}

// GetAgentProfile — GET /api/agent-profiles/{id}.
func (h *AdminHandlers) GetAgentProfile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		prof, err := h.store.GetAgentProfile(r.Context(), id)
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		if !h.orgInScope(w, r, prof.OrgID) {
			return
		}
		writeJSON(w, http.StatusOK, prof)
	}
}

// UpdateAgentProfile — PUT /api/agent-profiles/{id}.
func (h *AdminHandlers) UpdateAgentProfile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		existing, err := h.store.GetAgentProfile(r.Context(), id)
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		if !h.orgInScope(w, r, existing.OrgID) {
			return
		}
		var req struct {
			Name           *string   `json:"name"`
			TierHint       *string   `json:"tier_hint"`
			MCPGrants      *[]string `json:"mcp_grants"`
			BudgetCapCents **int64   `json:"budget_cap_cents"`
			GuardMode      *string   `json:"guard_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.MCPGrants != nil {
			if err := h.assertGrantsWithinOrg(r.Context(), existing.OrgID, *req.MCPGrants); err != nil {
				h.respondError(w, r, err, http.StatusBadRequest)
				return
			}
		}
		if req.BudgetCapCents != nil && *req.BudgetCapCents != nil && **req.BudgetCapCents <= 0 {
			h.respondError(w, r, fmt.Errorf("budget_cap_cents must be positive when set"), http.StatusBadRequest)
			return
		}
		prof, err := h.store.UpdateAgentProfile(r.Context(), id, adminstore.AgentProfileUpdateParams{
			Name:           req.Name,
			TierHint:       req.TierHint,
			MCPGrants:      req.MCPGrants,
			BudgetCapCents: req.BudgetCapCents,
			GuardMode:      req.GuardMode,
		})
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "update", "agent_profile", "id="+id+",org="+existing.OrgID)
		writeJSON(w, http.StatusOK, prof)
	}
}

// DeleteAgentProfile — DELETE /api/agent-profiles/{id}.
func (h *AdminHandlers) DeleteAgentProfile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		existing, err := h.store.GetAgentProfile(r.Context(), id)
		if err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		if !h.orgInScope(w, r, existing.OrgID) {
			return
		}
		if err := h.store.DeleteAgentProfile(r.Context(), id); err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		h.auditLogAction(r, "delete", "agent_profile", "id="+id+",org="+existing.OrgID)
		w.WriteHeader(http.StatusNoContent)
	}
}
