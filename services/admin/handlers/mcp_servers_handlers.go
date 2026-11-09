package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// MCP server registry CRUD (MCP-02, Phase 5).
//
// All routes are root-only and org-scoped (S01 matrix): the org ID comes
// from the path and is checked against the X-Yabanin-Org-Id scope by
// OrgScopeMiddleware / requireOrgScope. The SSRF domain allow-list for
// server URLs is the deployment-level gateway AllowedUpstreams list — the
// same list that governs provider URLs (one operator-managed list, no
// per-org secret material).
//
// Enabling a server is a deliberate operator action (root, explicit
// enabled=true) — the availability-honesty posture of models_registry
// (I18N-14): a registered server is inert until enabled.

const mcpAllowListSource = "gateway allowed_upstreams (SetMCPStore)"

// mcpAllowList builds the SSRF allow-list for MCP server URLs from the
// deployment config (SetMCPStore). An empty list means "no domains allowed"
// (fail-closed) — ValidateServerURL then rejects every host, which is the
// safe default for a feature that dials operator-registered external URLs.
func (h *AdminHandlers) mcpAllowList() (ssrf.AllowList, error) {
	entries := h.mcp.allowedUpstreams
	if entries == nil {
		entries = []string{}
	}
	var al ssrf.AllowList
	var err error
	if h.mcp.dnsResolver != nil {
		// Same-package test seam (QG2-D3): deterministic DNS answers.
		al, err = ssrf.NewAllowListWithResolver(entries, h.mcp.dnsResolver)
	} else {
		al, err = ssrf.NewAllowList(entries)
	}
	if err != nil {
		return ssrf.AllowList{}, fmt.Errorf("mcp servers: bad %s: %w", mcpAllowListSource, err)
	}
	return al, nil
}

// requireMCPStore writes 503 when the registry is not wired (no DB) and
// returns false; the handler must return immediately.
func (h *AdminHandlers) requireMCPStore(w http.ResponseWriter) bool {
	if h.mcp.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "mcp server registry not configured (no database)"})
		return false
	}
	return true
}

type mcpServerCreateRequest struct {
	OrgID          string   `json:"org_id"`
	Name           string   `json:"name"`
	DisplayName    *string  `json:"display_name,omitempty"`
	URL            string   `json:"url"`
	Transport      string   `json:"transport,omitempty"`
	AllowedTools   []string `json:"allowed_tools,omitempty"`
	Enabled        bool     `json:"enabled"`
	CredentialMode string   `json:"credential_mode,omitempty"`
}

type mcpServerUpdateRequest struct {
	DisplayName    *string   `json:"display_name,omitempty"`
	URL            *string   `json:"url,omitempty"`
	Transport      *string   `json:"transport,omitempty"`
	AllowedTools   *[]string `json:"allowed_tools,omitempty"`
	Enabled        *bool     `json:"enabled,omitempty"`
	CredentialMode *string   `json:"credential_mode,omitempty"`
}

// CreateMCPServer — POST /api/organizations/{id}/mcp/servers
func (h *AdminHandlers) CreateMCPServer() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPStore(w) {
			return
		}
		var req mcpServerCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		orgID := h.requireOrgScope(w, r, req.OrgID)
		if orgID == "" {
			return
		}
		if err := mcpagg.ValidateServerName(req.Name); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		transport := req.Transport
		if transport == "" {
			transport = mcpagg.TransportHTTP
		}
		if err := mcpagg.ValidateTransport(transport); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		if err := mcpagg.ValidateAllowedTools(req.AllowedTools); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		// An omitted credential_mode stores 'auto' (the legacy chain) — the
		// pre-0016 default keeps old API callers byte-compatible (I54: the
		// mode is the connection configuration's selection).
		if err := mcpagg.ValidateCredentialMode(req.CredentialMode); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		al, err := h.mcpAllowList()
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
			return
		}
		if err := mcpagg.ValidateServerURL(req.URL, al); err != nil { //nolint:contextcheck // SSRF guard runs on a bounded background ctx (QG2-D3 threads request ctx)
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		store := h.mcp.store
		srv, err := store.Create(r.Context(), mcpagg.CreateParams{
			OrgID:          orgID,
			Name:           req.Name,
			DisplayName:    req.DisplayName,
			URL:            req.URL,
			Transport:      transport,
			AllowedTools:   req.AllowedTools,
			Enabled:        req.Enabled,
			CredentialMode: req.CredentialMode,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		h.auditLogAction(r, "create", "mcp_server",
			fmt.Sprintf("id=%s,name=%s,org=%s,enabled=%v", srv.ID, srv.Name, orgID, srv.Enabled))
		writeJSON(w, http.StatusCreated, srv)
	}
}

// ListMCPServers — GET /api/organizations/{id}/mcp/servers
func (h *AdminHandlers) ListMCPServers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPStore(w) {
			return
		}
		orgID := r.PathValue("id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id is required"})
			return
		}
		store := h.mcp.store
		servers, err := store.List(r.Context(), orgID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		if servers == nil {
			servers = []*mcpagg.Server{}
		}
		writeJSON(w, http.StatusOK, servers)
	}
}

// GetMCPServer — GET /api/organizations/{id}/mcp/servers/{name}
func (h *AdminHandlers) GetMCPServer() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPStore(w) {
			return
		}
		orgID := r.PathValue("id")
		name := r.PathValue("name")
		if orgID == "" || name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and server name are required"})
			return
		}
		store := h.mcp.store
		srv, err := store.Get(r.Context(), orgID, name)
		if err != nil {
			writeMCPServerErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, srv)
	}
}

// UpdateMCPServer — PATCH /api/organizations/{id}/mcp/servers/{name}
func (h *AdminHandlers) UpdateMCPServer() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPStore(w) {
			return
		}
		orgID := r.PathValue("id")
		name := r.PathValue("name")
		if orgID == "" || name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and server name are required"})
			return
		}
		var req mcpServerUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		if req.Transport != nil {
			if err := mcpagg.ValidateTransport(*req.Transport); err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		if req.AllowedTools != nil {
			if err := mcpagg.ValidateAllowedTools(*req.AllowedTools); err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		if req.CredentialMode != nil {
			if err := mcpagg.ValidateCredentialMode(*req.CredentialMode); err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		if req.URL != nil {
			al, err := h.mcpAllowList()
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
				return
			}
			if err := mcpagg.ValidateServerURL(*req.URL, al); err != nil { //nolint:contextcheck // SSRF guard runs on a bounded background ctx (QG2-D3 threads request ctx)
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		store := h.mcp.store
		srv, err := store.Update(r.Context(), orgID, name, mcpagg.UpdateParams{
			DisplayName:    req.DisplayName,
			URL:            req.URL,
			Transport:      req.Transport,
			AllowedTools:   req.AllowedTools,
			Enabled:        req.Enabled,
			CredentialMode: req.CredentialMode,
		})
		if err != nil {
			writeMCPServerErr(w, err)
			return
		}
		// Any applied update changes the connection configuration (mode,
		// URL, tool ceiling...) and bumps config_version; the gateway's
		// cached credential decisions must re-resolve under the new
		// configuration immediately (positives are version-guarded;
		// negatives stay TTL-bounded, the documented probe polarity).
		h.bumpMCPCredsVersion(r, orgID)
		h.auditLogAction(r, "update", "mcp_server",
			fmt.Sprintf("id=%s,name=%s,org=%s,enabled=%v,mode=%s,config_version=%d",
				srv.ID, srv.Name, orgID, srv.Enabled, srv.CredentialMode, srv.ConfigVersion))
		writeJSON(w, http.StatusOK, srv)
	}
}

// DeleteMCPServer — DELETE /api/organizations/{id}/mcp/servers/{name}
func (h *AdminHandlers) DeleteMCPServer() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPStore(w) {
			return
		}
		orgID := r.PathValue("id")
		name := r.PathValue("name")
		if orgID == "" || name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and server name are required"})
			return
		}
		store := h.mcp.store
		if err := store.Delete(r.Context(), orgID, name); err != nil {
			writeMCPServerErr(w, err)
			return
		}
		h.auditLogAction(r, "delete", "mcp_server",
			fmt.Sprintf("name=%s,org=%s", name, orgID))
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

// writeMCPServerErr renders mcpagg store errors (ErrNotFound → 404).
func writeMCPServerErr(w http.ResponseWriter, err error) {
	if err == mcpagg.ErrNotFound {
		writeJSON(w, http.StatusNotFound, apiError{Error: "mcp server not found"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
}

// ---------------------------------------------------------------------------
// MCP-03: per-agent grants. A grant authorizes one yag_ agent to invoke one
// server's tools. Routes nest under the server (the grant names both the agent
// and the server). Root-only; org-scoped (S01), same as the server CRUD.
// ---------------------------------------------------------------------------

type mcpGrantCreateRequest struct {
	AgentID      string   `json:"agent_id"`
	AllowedTools []string `json:"allowed_tools,omitempty"`
	Enabled      bool     `json:"enabled"`
}

type mcpGrantUpdateRequest struct {
	AllowedTools *[]string `json:"allowed_tools,omitempty"`
	Enabled      *bool     `json:"enabled,omitempty"`
}

// ListMCPGrants — GET /api/organizations/{id}/mcp/servers/{name}/grants
func (h *AdminHandlers) ListMCPGrants() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPStore(w) {
			return
		}
		orgID := r.PathValue("id")
		name := r.PathValue("name")
		if orgID == "" || name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and server name are required"})
			return
		}
		grants, err := h.mcp.store.ListGrantsForServer(r.Context(), orgID, name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		if grants == nil {
			grants = []*mcpagg.Grant{}
		}
		writeJSON(w, http.StatusOK, grants)
	}
}

// CreateMCPGrant — POST /api/organizations/{id}/mcp/servers/{name}/grants
func (h *AdminHandlers) CreateMCPGrant() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPStore(w) {
			return
		}
		orgID := r.PathValue("id")
		name := r.PathValue("name")
		if orgID == "" || name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and server name are required"})
			return
		}
		var req mcpGrantCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		if req.AgentID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "agent_id is required"})
			return
		}
		if err := mcpagg.ValidateAllowedTools(req.AllowedTools); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		// The grant references a server that must exist for the org (otherwise
		// the grant is inert and confusing). The FK is on (org_id, agent_id),
		// so a server-existence check is the only way to reject a dangling grant.
		if _, err := h.mcp.store.Get(r.Context(), orgID, name); err != nil {
			writeMCPServerErr(w, err)
			return
		}
		g, err := h.mcp.store.CreateGrant(r.Context(), mcpagg.GrantCreateParams{
			OrgID:        orgID,
			AgentID:      req.AgentID,
			ServerName:   name,
			AllowedTools: req.AllowedTools,
			Enabled:      req.Enabled,
		})
		if err != nil {
			writeMCPGrantErr(w, err)
			return
		}
		// MC-3: a (re)created grant may return previously orphaned per-user
		// credentials to service (restore). A failed restore is logged and
		// audited, never a failed grant response — the runtime enforces the
		// grant on every invoke regardless.
		h.mcpUserCredLifecycleHook(r, "restore", orgID, name, req.AgentID)
		h.auditLogAction(r, "create", "mcp_server_grant",
			fmt.Sprintf("server=%s,agent=%s,org=%s,enabled=%v", name, req.AgentID, orgID, g.Enabled))
		writeJSON(w, http.StatusCreated, g)
	}
}

// UpdateMCPGrant — PATCH /api/organizations/{id}/mcp/servers/{name}/grants/{agent_id}
func (h *AdminHandlers) UpdateMCPGrant() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPStore(w) {
			return
		}
		orgID := r.PathValue("id")
		name := r.PathValue("name")
		agentID := r.PathValue("agent_id")
		if orgID == "" || name == "" || agentID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id, server name and agent id are required"})
			return
		}
		var req mcpGrantUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		if req.AllowedTools != nil {
			if err := mcpagg.ValidateAllowedTools(*req.AllowedTools); err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		g, err := h.mcp.store.UpdateGrant(r.Context(), orgID, agentID, name, mcpagg.GrantUpdateParams{
			AllowedTools: req.AllowedTools,
			Enabled:      req.Enabled,
		})
		if err != nil {
			writeMCPGrantErr(w, err)
			return
		}
		// MC-3: disabling the grant orphans the per-user credentials;
		// re-enabling restores them.
		if g.Enabled {
			h.mcpUserCredLifecycleHook(r, "restore", orgID, name, agentID)
		} else {
			h.mcpUserCredLifecycleHook(r, "orphan", orgID, name, agentID)
		}
		h.auditLogAction(r, "update", "mcp_server_grant",
			fmt.Sprintf("server=%s,agent=%s,org=%s,enabled=%v", name, agentID, orgID, g.Enabled))
		writeJSON(w, http.StatusOK, g)
	}
}

// DeleteMCPGrant — DELETE /api/organizations/{id}/mcp/servers/{name}/grants/{agent_id}
func (h *AdminHandlers) DeleteMCPGrant() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireMCPStore(w) {
			return
		}
		orgID := r.PathValue("id")
		name := r.PathValue("name")
		agentID := r.PathValue("agent_id")
		if orgID == "" || name == "" || agentID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id, server name and agent id are required"})
			return
		}
		if err := h.mcp.store.DeleteGrant(r.Context(), orgID, agentID, name); err != nil {
			writeMCPGrantErr(w, err)
			return
		}
		// MC-3: the revoked grant orphans the per-user credentials (runtime
		// stops seeing them; the rows persist for the restore path).
		h.mcpUserCredLifecycleHook(r, "orphan", orgID, name, agentID)
		h.auditLogAction(r, "delete", "mcp_server_grant",
			fmt.Sprintf("server=%s,agent=%s,org=%s", name, agentID, orgID))
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

// mcpUserCredLifecycleHook runs the MC-3 orphan/restore transition after a
// grant mutation. action is "orphan" or "restore". The hook never fails the
// grant response: the runtime enforces the grant on every invoke, so a
// missed bookkeeping flip only affects the lifecycle UI, and it is both
// logged and audited.
func (h *AdminHandlers) mcpUserCredLifecycleHook(r *http.Request, action, orgID, serverName, agentID string) {
	if h.mcp.userCredLifecycle == nil {
		return
	}
	var err error
	if action == "orphan" {
		err = h.mcp.userCredLifecycle.OrphanMCPUserCredentials(r.Context(), orgID, serverName, agentID)
	} else {
		err = h.mcp.userCredLifecycle.RestoreMCPUserCredentials(r.Context(), orgID, serverName, agentID)
	}
	details := fmt.Sprintf("server=%s,agent=%s,org=%s", serverName, agentID, orgID)
	if err != nil {
		if h.store != nil && h.store.Log() != nil {
			h.store.Log().Warn("mcp user credential lifecycle hook failed", "action", action, "error", err.Error())
		}
		h.auditLogAction(r, "mcp_user_credential_lifecycle_failed", "mcp_user_credential", "action="+action+","+details)
		return
	}
	h.auditLogAction(r, "mcp_user_credential_"+action, "mcp_user_credential", details)
}

// writeMCPGrantErr renders mcpagg grant store errors.
func writeMCPGrantErr(w http.ResponseWriter, err error) {
	if err == mcpagg.ErrNotFound {
		writeJSON(w, http.StatusNotFound, apiError{Error: "mcp grant not found"})
		return
	}
	// A duplicate grant (unique constraint) is a 409.
	if strings.Contains(err.Error(), "already exists") {
		writeJSON(w, http.StatusConflict, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
}
