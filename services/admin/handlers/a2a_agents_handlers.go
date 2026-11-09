package handlers

// A2A agent registry CRUD (A2A-01) — the agent-to-agent counterpart of the
// MCP server registry (mcp_servers_handlers.go). Same discipline: root-only,
// org-scoped (S01 matrix), SSRF-guarded URLs at registration, and a
// registered agent stays inert until an operator enables it explicitly.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/reireirei/yabanin/pkg/a2aagg"
)

// requireA2AStore writes 503 when the registry is not wired (no DB) and
// returns false; the handler must return immediately.
func (h *AdminHandlers) requireA2AStore(w http.ResponseWriter) bool {
	if h.mcp.a2a == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "a2a agent registry not configured (no database)"})
		return false
	}
	return true
}

type a2aAgentCreateRequest struct {
	OrgID       string  `json:"org_id"`
	Name        string  `json:"name"`
	DisplayName *string `json:"display_name,omitempty"`
	URL         string  `json:"url"`
	Enabled     bool    `json:"enabled"`
}

type a2aAgentUpdateRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	URL         *string `json:"url,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

// CreateA2AAgent — POST /api/organizations/{id}/a2a/agents
func (h *AdminHandlers) CreateA2AAgent() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireA2AStore(w) {
			return
		}
		var req a2aAgentCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		orgID := h.requireOrgScope(w, r, req.OrgID)
		if orgID == "" {
			return
		}
		if err := a2aagg.ValidateAgentName(req.Name); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		al, err := h.mcpAllowList()
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
			return
		}
		if err := a2aagg.ValidateAgentURL(req.URL, al); err != nil { //nolint:contextcheck // SSRF guard runs on a bounded background ctx (QG2-D3 threads request ctx)
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		store := h.mcp.a2a
		agent, err := store.Create(r.Context(), a2aagg.CreateParams{
			OrgID:       orgID,
			Name:        req.Name,
			DisplayName: req.DisplayName,
			URL:         req.URL,
			Enabled:     req.Enabled,
		})
		if err != nil {
			writeA2AAgentErr(w, err)
			return
		}
		h.auditLogAction(r, "create", "a2a_agent",
			"id="+agent.ID+",name="+agent.Name+",org="+orgID+",enabled="+boolStr(agent.Enabled))
		writeJSON(w, http.StatusCreated, agent)
	}
}

// ListA2AAgents — GET /api/organizations/{id}/a2a/agents
func (h *AdminHandlers) ListA2AAgents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireA2AStore(w) {
			return
		}
		orgID := r.PathValue("id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id is required"})
			return
		}
		agents, err := h.mcp.a2a.List(r.Context(), orgID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, agents)
	}
}

// GetA2AAgent — GET /api/organizations/{id}/a2a/agents/{name}
func (h *AdminHandlers) GetA2AAgent() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireA2AStore(w) {
			return
		}
		orgID := r.PathValue("id")
		name := r.PathValue("name")
		if orgID == "" || name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and agent name are required"})
			return
		}
		agent, err := h.mcp.a2a.Get(r.Context(), orgID, name)
		if err != nil {
			writeA2AAgentErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, agent)
	}
}

// UpdateA2AAgent — PATCH /api/organizations/{id}/a2a/agents/{name}
func (h *AdminHandlers) UpdateA2AAgent() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireA2AStore(w) {
			return
		}
		orgID := r.PathValue("id")
		name := r.PathValue("name")
		if orgID == "" || name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and agent name are required"})
			return
		}
		var req a2aAgentUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		// A URL change re-runs the registration-time SSRF guard.
		if req.URL != nil {
			al, err := h.mcpAllowList()
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
				return
			}
			if err := a2aagg.ValidateAgentURL(*req.URL, al); err != nil { //nolint:contextcheck // SSRF guard runs on a bounded background ctx (QG2-D3 threads request ctx)
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		agent, err := h.mcp.a2a.Update(r.Context(), orgID, name, a2aagg.UpdateParams{
			DisplayName: req.DisplayName,
			URL:         req.URL,
			Enabled:     req.Enabled,
		})
		if err != nil {
			writeA2AAgentErr(w, err)
			return
		}
		h.auditLogAction(r, "update", "a2a_agent",
			"name="+name+",org="+orgID+",enabled="+boolStr(agent.Enabled))
		writeJSON(w, http.StatusOK, agent)
	}
}

// DeleteA2AAgent — DELETE /api/organizations/{id}/a2a/agents/{name}
func (h *AdminHandlers) DeleteA2AAgent() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireA2AStore(w) {
			return
		}
		orgID := r.PathValue("id")
		name := r.PathValue("name")
		if orgID == "" || name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and agent name are required"})
			return
		}
		if err := h.mcp.a2a.Delete(r.Context(), orgID, name); err != nil {
			writeA2AAgentErr(w, err)
			return
		}
		h.auditLogAction(r, "delete", "a2a_agent", "name="+name+",org="+orgID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

// writeA2AAgentErr renders a2aagg store errors (ErrNotFound → 404, duplicate
// create → 409, anything else → 500).
func writeA2AAgentErr(w http.ResponseWriter, err error) {
	if errors.Is(err, a2aagg.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "a2a agent not found"})
		return
	}
	if err != nil && strings.Contains(err.Error(), "already exists") {
		writeJSON(w, http.StatusConflict, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
