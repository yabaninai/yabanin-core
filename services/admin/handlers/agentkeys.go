package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	chi "github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/mcpagg"
)

// --- Agent keys (G1) ---

// CreateAgentKey creates a new agent-principal key. It generates the yag_
// plaintext (shown once), stores only its sha256, and returns the plaintext in
// the response. The org must come from the authenticated admin's scope.
func (h *AdminHandlers) CreateAgentKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		var req struct {
			Name      string `json:"name"`
			OrgID     string `json:"org_id"`
			ProfileID string `json:"profile_id"` // ADL-06: issue on a role profile (inherit its settings)
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			h.respondError(w, r, fmt.Errorf("name is required"), http.StatusBadRequest)
			return
		}
		orgID := h.requireOrgScope(w, r, req.OrgID, adminstore.PermAgentKeysManage)
		if orgID == "" {
			return
		}

		// ADL-06: when issued on a profile, the key inherits the profile's
		// budget cap + MCP grants (already ⊆ the org's servers by construction).
		var profile *adminstore.AgentProfile
		if req.ProfileID != "" {
			prof, perr := h.store.GetAgentProfile(r.Context(), req.ProfileID)
			if perr != nil || prof == nil {
				h.respondError(w, r, fmt.Errorf("profile not found"), http.StatusNotFound)
				return
			}
			if !h.orgInScope(w, r, prof.OrgID) {
				return
			}
			if prof.OrgID != orgID {
				h.respondError(w, r, fmt.Errorf("profile is not in this organization"), http.StatusForbidden)
				return
			}
			profile = prof
		}

		plaintext, err := auth.GenerateAgentKey()
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		keyHash := auth.HashKey(plaintext)
		var dailyCap *int64
		var inheritedGrants []string
		if profile != nil {
			dailyCap = profile.BudgetCapCents
			inheritedGrants = []string{}
			if h.mcp.store != nil {
				// Inherit the profile's grant template, intersected with the
				// org's available servers (defensive — the profile already
				// enforces the ceiling at create/update time).
				ceiling := h.orgServerNames(r.Context(), orgID)
				seen := map[string]bool{}
				for _, g := range profile.MCPGrants {
					if (ceiling == nil || ceiling[g]) && !seen[g] {
						inheritedGrants = append(inheritedGrants, g)
						seen[g] = true
					}
				}
			} else {
				inheritedGrants = append(inheritedGrants, profile.MCPGrants...)
			}
		}
		key, err := h.store.CreateAgentKeyDelegated(r.Context(), adminstore.AgentKeyCreateParams{
			KeyHash:         keyHash,
			Name:            req.Name,
			OrgID:           orgID,
			DailyLimitCents: dailyCap,
		})
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		// Inherit the budget cap as a normal agent_budgets row (the per-agent
		// enforcer blocks the key on overspend, fail-closed).
		if profile != nil && profile.BudgetCapCents != nil {
			if _, err := h.store.UpsertAgentBudget(r.Context(), key.ID, *profile.BudgetCapCents); err != nil {
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
		}
		// Apply the inherited MCP grants (a grant conflict is logged, not fatal).
		for _, server := range inheritedGrants {
			if h.mcp.store == nil {
				break
			}
			if _, err := h.mcp.store.CreateGrant(r.Context(), mcpagg.GrantCreateParams{
				OrgID: orgID, AgentID: key.ID, ServerName: server,
				AllowedTools: []string{}, Enabled: true,
			}); err != nil {
				h.logger.WarnContext(r.Context(), "profile grant apply failed",
					"key", key.ID, "server", server, "error", err.Error())
			}
		}
		h.auditLogAction(r, "create", "agent_key", "id="+key.ID+",name="+req.Name+",org="+orgID+profileRef(profile))
		// Return the plaintext once; the stored row only has the hash.
		resp := map[string]any{
			"key":    plaintext,
			"key_id": key.ID,
			"name":   key.Name,
			"org_id": key.OrgID,
			"active": key.Active,
		}
		if profile != nil {
			resp["profile_id"] = profile.ID
			resp["profile_name"] = profile.Name
			resp["tier_hint"] = profile.TierHint
			resp["guard_mode"] = profile.GuardMode
			resp["inherited_mcp_grants"] = inheritedGrants
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

// profileRef renders the ",profile=<id>" audit suffix only when a profile was
// used to issue the key.
func profileRef(p *adminstore.AgentProfile) string {
	if p == nil {
		return ""
	}
	return ",profile=" + p.ID
}

// ListAgentKeys lists agent keys for an org.
func (h *AdminHandlers) ListAgentKeys() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := h.requireOrgScope(w, r, r.URL.Query().Get("org_id"), adminstore.PermAgentKeysManage)
		if orgID == "" {
			return
		}
		keys, err := h.store.ListAgentKeys(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": keys})
	}
}

// GetAgentKey returns a single agent key by ID.
func (h *AdminHandlers) GetAgentKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		key, ok := h.agentKeyVisible(w, r, id)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, key)
	}
}

// RevokeAgentKey revokes (deactivates) an agent key.
func (h *AdminHandlers) RevokeAgentKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		// S02: fetch the hash first so the revoke can purge the resolver cache.
		// A foreign id is 404 and is not revoked.
		key, ok := h.agentKeyVisible(w, r, id)
		if !ok {
			return
		}
		if err := h.store.RevokeAgentKey(r.Context(), id); err != nil {
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		h.purgeResolverKeys(r.Context(), key.KeyHash)
		h.auditLogAction(r, "revoke", "agent_key", "id="+id)
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	}
}

// --- Agent key delegation (ADL-03) ---

// CreateDelegatedAgentKey — POST /api/agent-keys/delegate.
//
// Issues a CHILD agent key under a parent agent key. The delegation invariants
// (enforced here, so escalation is impossible by construction):
//   - the parent exists, is active, is a ROOT (parent_id IS NULL), and is in
//     the caller's org scope (a child cannot delegate further);
//   - the child's MCP grants = the requested set INTERSECTED with the parent's
//     enabled grants (a child can never hold a grant the parent lacks);
//   - the child's daily budget cap, if set, must be positive (the per-agent
//     budget enforcer then blocks the child on overspend, fail-closed);
//   - the TTL is required and bounded (must be in the future); the auth
//     resolver rejects the child once past it.
//
// Spend is attributed to the child (agent_id = child key id); the child reports
// back to the parent through the existing CTOR analytics grouped by task tag.
func (h *AdminHandlers) CreateDelegatedAgentKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		var req struct {
			ParentAgent string   `json:"parent_agent"`
			Name        string   `json:"name"`
			TTLSeconds  int64    `json:"ttl"` // seconds (raw number, not a Go duration string)
			BudgetCents *int64   `json:"budget_caps"`
			MCPGrants   []string `json:"mcp_grants"`
			OrgID       string   `json:"org_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			h.respondError(w, r, fmt.Errorf("name is required"), http.StatusBadRequest)
			return
		}
		if req.ParentAgent == "" {
			h.respondError(w, r, fmt.Errorf("parent_agent is required"), http.StatusBadRequest)
			return
		}
		if req.TTLSeconds <= 0 {
			h.respondError(w, r, fmt.Errorf("ttl must be positive"), http.StatusBadRequest)
			return
		}
		const maxTTLSeconds = int64(90 * 24 * 3600)
		if req.TTLSeconds > maxTTLSeconds {
			h.respondError(w, r, fmt.Errorf("ttl must be at most 90d"), http.StatusBadRequest)
			return
		}
		if req.BudgetCents != nil && *req.BudgetCents <= 0 {
			h.respondError(w, r, fmt.Errorf("budget_caps must be positive when set"), http.StatusBadRequest)
			return
		}
		orgID := h.requireOrgScope(w, r, req.OrgID, adminstore.PermAgentKeysManage)
		if orgID == "" {
			return
		}

		// 1) Parent must exist, be active, be a root, and be in this org.
		parent, err := h.store.GetAgentKeyByID(r.Context(), req.ParentAgent)
		if err != nil || parent == nil {
			h.respondError(w, r, fmt.Errorf("parent agent not found"), http.StatusNotFound)
			return
		}
		if !parent.Active {
			h.respondError(w, r, fmt.Errorf("parent agent is revoked"), http.StatusConflict)
			return
		}
		if parent.ParentID != nil {
			h.respondError(w, r, fmt.Errorf("parent agent is itself a child and cannot delegate"), http.StatusConflict)
			return
		}
		if h.resourceHidden(w, r, parent.OrgID) {
			return
		}
		if parent.OrgID != orgID {
			h.respondError(w, r, fmt.Errorf("parent agent is not in this organization"), http.StatusForbidden)
			return
		}

		// 2) Grants = requested ∩ parent's enabled grants (escalation is
		//    impossible). When the MCP registry is not wired (no DB for grants)
		//    the intersection is empty — the child simply gets no MCP grants.
		//    AUTH-02: the child grant also inherits the parent grant's tool
		//    scope (copy, so later parent edits cannot silently widen the
		//    child) — an unrestricted parent grant yields an unrestricted
		//    child grant, a restricted one restricts the child to the same
		//    tool set.
		effective := []string{}
		parentSet := map[string]bool{}
		parentTools := map[string][]string{}
		if h.mcp.store != nil {
			parentGrants, gerr := h.mcp.store.ListGrantsForAgent(r.Context(), orgID, parent.ID)
			if gerr != nil {
				h.respondError(w, r, fmt.Errorf("could not read parent grants"), http.StatusInternalServerError)
				return
			}
			for _, g := range parentGrants {
				parentSet[g.ServerName] = true
				parentTools[g.ServerName] = append([]string(nil), g.AllowedTools...)
			}
			seen := map[string]bool{}
			for _, server := range req.MCPGrants {
				if parentSet[server] && !seen[server] {
					effective = append(effective, server)
					seen[server] = true
				}
			}
		}

		// 3) Issue the child key (hash-only) with the delegation fields.
		//    AUDIT-P1-03: when the delegation carries a budget cap, the cap is
		//    validated against the parent's remaining headroom and the child
		//    key + its agent_budgets enforcement row are written in ONE
		//    advisory-locked transaction — the audit finding (a cap wider
		//    than what the parent can still fund) cannot reproduce, not even
		//    under concurrent delegations on the same parent. A cap-less
		//    delegation keeps the legacy single-insert path (a cap-less child
		//    has no budget row and is denied at spend time anyway).
		plaintext, err := auth.GenerateAgentKey()
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		keyHash := auth.HashKey(plaintext)
		expiresAt := time.Now().UTC().Add(time.Duration(req.TTLSeconds) * time.Second)
		params := adminstore.AgentKeyCreateParams{
			KeyHash:         keyHash,
			Name:            req.Name,
			OrgID:           orgID,
			ParentID:        &parent.ID,
			ExpiresAt:       &expiresAt,
			DailyLimitCents: req.BudgetCents,
		}
		var child *adminstore.AgentKey
		if req.BudgetCents != nil {
			ds := h.delegationBudget()
			if ds == nil {
				h.respondError(w, r, fmt.Errorf("delegation budget enforcement not supported"), http.StatusNotImplemented)
				return
			}
			child, err = ds.CreateAgentKeyDelegatedChecked(r.Context(), params)
			if err != nil {
				switch {
				case errors.Is(err, adminstore.ErrParentBudgetMissing),
					errors.Is(err, adminstore.ErrDelegationHeadroomExceeded),
					errors.Is(err, adminstore.ErrParentNotDelegable):
					h.respondError(w, r, err, http.StatusConflict)
				default:
					h.respondError(w, r, err, http.StatusInternalServerError)
				}
				return
			}
		} else {
			child, err = h.store.CreateAgentKeyDelegated(r.Context(), params)
			if err != nil {
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
		}

		// 4) The budget cap is already applied for capped delegations (same
		//    transaction as the key insert); nothing to do here.

		// 5) Apply the MCP grants (already the parent∩requested intersection,
		//    with the parent's tool scope carried over — AUTH-02).
		for _, server := range effective {
			if _, err := h.mcp.store.CreateGrant(r.Context(), mcpagg.GrantCreateParams{
				OrgID:        orgID,
				AgentID:      child.ID,
				ServerName:   server,
				AllowedTools: parentTools[server], // nil/[] = unrestricted, like the parent
				Enabled:      true,
			}); err != nil {
				// A grant conflict (child already has it) is not fatal — the
				// key was issued; surface it but keep the key.
				h.logger.WarnContext(r.Context(), "delegation grant apply failed",
					"child", child.ID, "server", server, "error", err.Error())
			}
		}

		h.auditLogAction(r, "create", "delegated_agent_key",
			"id="+child.ID+",parent="+parent.ID+",name="+req.Name+",org="+orgID)
		// Return the plaintext ONCE; the stored row only has the hash.
		writeJSON(w, http.StatusCreated, map[string]any{
			"key":               plaintext,
			"key_id":            child.ID,
			"name":              child.Name,
			"org_id":            child.OrgID,
			"parent_agent":      parent.ID,
			"active":            child.Active,
			"expires_at":        expiresAt,
			"daily_limit_cents": req.BudgetCents,
			"mcp_grants":        effective,
		})
	}
}

// agentKeyVisible loads an agent key and hides it when it belongs to another
// org. Missing and foreign ids both answer 404.
func (h *AdminHandlers) agentKeyVisible(w http.ResponseWriter, r *http.Request, id string) (*adminstore.AgentKey, bool) {
	key, err := h.store.GetAgentKeyByID(r.Context(), id)
	if err != nil || key == nil {
		if err == nil {
			err = fmt.Errorf("agent key not found")
		}
		h.respondError(w, r, err, http.StatusNotFound)
		return nil, false
	}
	if h.resourceHidden(w, r, key.OrgID) {
		return nil, false
	}
	return key, true
}
