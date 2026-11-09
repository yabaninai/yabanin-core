package handlers

// TOOL-01/04: tool-policy registry CRUD + preset application (root-only,
// org-scoped, S01 matrix — same discipline as the MCP server registry).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// requireToolPolicyStore writes 503 when the registry is not wired.
func (h *AdminHandlers) requireToolPolicyStore(w http.ResponseWriter) bool {
	if h.mcp.toolPolicies == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "tool policy registry not configured (no database)"})
		return false
	}
	return true
}

type toolPolicyCreateRequest struct {
	OrgID    string          `json:"org_id"`
	Name     string          `json:"name"`
	Subject  string          `json:"subject"`
	Server   string          `json:"server"`
	Tool     string          `json:"tool"`
	Action   string          `json:"action"`
	Rules    json.RawMessage `json:"rules,omitempty"`
	Priority int             `json:"priority"`
	Enabled  bool            `json:"enabled"`
}

type toolPolicyUpdateRequest struct {
	Subject  *string          `json:"subject,omitempty"`
	Server   *string          `json:"server,omitempty"`
	Tool     *string          `json:"tool,omitempty"`
	Action   *string          `json:"action,omitempty"`
	Rules    *json.RawMessage `json:"rules,omitempty"`
	Priority *int             `json:"priority,omitempty"`
	Enabled  *bool            `json:"enabled,omitempty"`
}

func validatePolicyPayload(name, subject, server, tool, action string, rules json.RawMessage, priority int) error {
	if err := toolpolicy.ValidateName(name); err != nil {
		return err
	}
	if err := toolpolicy.ValidatePattern(subject); err != nil {
		return err
	}
	if server != "" {
		if err := toolpolicy.ValidatePattern(server); err != nil {
			return err
		}
	}
	if err := toolpolicy.ValidatePattern(tool); err != nil {
		return err
	}
	if err := toolpolicy.ValidateAction(action); err != nil {
		return err
	}
	if err := toolpolicy.ValidateRulesJSON(rules); err != nil {
		return err
	}
	if priority < 0 || priority > 1000 {
		return errors.New("toolpolicy: priority must be 0..1000")
	}
	return nil
}

// CreateToolPolicy — POST /api/organizations/{id}/tool-policies
func (h *AdminHandlers) CreateToolPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireToolPolicyStore(w) {
			return
		}
		var req toolPolicyCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		orgID := h.requireOrgScope(w, r, req.OrgID)
		if orgID == "" {
			return
		}
		if err := validatePolicyPayload(req.Name, req.Subject, req.Server, req.Tool, req.Action, req.Rules, req.Priority); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		p, err := h.mcp.toolPolicies.Create(r.Context(), toolpolicy.CreateParams{
			OrgID: orgID, Name: req.Name, Subject: req.Subject, Server: req.Server,
			Tool: req.Tool, Action: req.Action, Rules: req.Rules,
			Priority: req.Priority, Enabled: req.Enabled,
		})
		if err != nil {
			writeToolPolicyErr(w, err)
			return
		}
		h.invalidateToolPolicies(orgID)
		h.auditLogAction(r, "create", "tool_policy",
			"name="+p.Name+",org="+orgID+",tool="+p.Tool+",action="+p.Action)
		writeJSON(w, http.StatusCreated, p)
	}
}

// ListToolPolicies — GET /api/organizations/{id}/tool-policies
func (h *AdminHandlers) ListToolPolicies() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireToolPolicyStore(w) {
			return
		}
		orgID := r.PathValue("id")
		if orgID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id is required"})
			return
		}
		policies, err := h.mcp.toolPolicies.List(r.Context(), orgID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, policies)
	}
}

// GetToolPolicy — GET /api/organizations/{id}/tool-policies/{name}
func (h *AdminHandlers) GetToolPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireToolPolicyStore(w) {
			return
		}
		orgID, name := r.PathValue("id"), r.PathValue("name")
		if orgID == "" || name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and policy name are required"})
			return
		}
		p, err := h.mcp.toolPolicies.Get(r.Context(), orgID, name)
		if err != nil {
			writeToolPolicyErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, p)
	}
}

// UpdateToolPolicy — PATCH /api/organizations/{id}/tool-policies/{name}
func (h *AdminHandlers) UpdateToolPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireToolPolicyStore(w) {
			return
		}
		orgID, name := r.PathValue("id"), r.PathValue("name")
		if orgID == "" || name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and policy name are required"})
			return
		}
		var req toolPolicyUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed JSON body"})
			return
		}
		if req.Subject != nil {
			if err := toolpolicy.ValidatePattern(*req.Subject); err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		if req.Server != nil {
			if err := toolpolicy.ValidatePattern(*req.Server); err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		if req.Tool != nil {
			if err := toolpolicy.ValidatePattern(*req.Tool); err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		if req.Action != nil {
			if err := toolpolicy.ValidateAction(*req.Action); err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		if req.Rules != nil {
			if err := toolpolicy.ValidateRulesJSON(*req.Rules); err != nil {
				writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
				return
			}
		}
		p, err := h.mcp.toolPolicies.Update(r.Context(), orgID, name, toolpolicy.UpdateParams{
			Subject: req.Subject, Server: req.Server, Tool: req.Tool, Action: req.Action,
			Rules: req.Rules, Priority: req.Priority, Enabled: req.Enabled,
		})
		if err != nil {
			writeToolPolicyErr(w, err)
			return
		}
		h.invalidateToolPolicies(orgID)
		h.auditLogAction(r, "update", "tool_policy", "name="+name+",org="+orgID)
		writeJSON(w, http.StatusOK, p)
	}
}

// DeleteToolPolicy — DELETE /api/organizations/{id}/tool-policies/{name}
func (h *AdminHandlers) DeleteToolPolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireToolPolicyStore(w) {
			return
		}
		orgID, name := r.PathValue("id"), r.PathValue("name")
		if orgID == "" || name == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and policy name are required"})
			return
		}
		if err := h.mcp.toolPolicies.Delete(r.Context(), orgID, name); err != nil {
			writeToolPolicyErr(w, err)
			return
		}
		h.invalidateToolPolicies(orgID)
		h.auditLogAction(r, "delete", "tool_policy", "name="+name+",org="+orgID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	}
}

// ListToolPolicyPresets — GET /api/organizations/{id}/tool-policies/presets
func (h *AdminHandlers) ListToolPolicyPresets() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, toolpolicy.Presets())
	}
}

// ApplyToolPolicyPreset — POST /api/organizations/{id}/tool-policies/presets/{preset}
// creates the preset's policy rows (idempotent per row name: existing rows
// are kept, the preset skips name collisions).
func (h *AdminHandlers) ApplyToolPolicyPreset() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireToolPolicyStore(w) {
			return
		}
		orgID, presetID := r.PathValue("id"), r.PathValue("preset")
		if orgID == "" || presetID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org id and preset id are required"})
			return
		}
		if h.requireOrgScope(w, r, orgID) == "" {
			return
		}
		preset, ok := toolpolicy.LookupPreset(presetID)
		if !ok {
			writeJSON(w, http.StatusNotFound, apiError{Error: "unknown preset " + presetID})
			return
		}
		var created, skipped int
		for i, tpl := range preset.Policies {
			name := preset.ID + "-" + strings.ToLower(tpl.Tool) + "-" + string(rune('a'+i%26))
			if err := toolpolicy.ValidateName(name); err != nil {
				// sanitize pattern chars the name constraint rejects
				name = preset.ID + "-" + fmt.Sprint(i)
			}
			if _, err := h.mcp.toolPolicies.Get(r.Context(), orgID, name); err == nil {
				skipped++
				continue
			}
			if _, err := h.mcp.toolPolicies.Create(r.Context(), toolpolicy.CreateParams{
				OrgID: orgID, Name: name, Subject: tpl.Subject, Tool: tpl.Tool,
				Action: tpl.Action, Priority: tpl.Priority, Enabled: true,
			}); err != nil {
				writeToolPolicyErr(w, err)
				return
			}
			created++
		}
		h.invalidateToolPolicies(orgID)
		h.auditLogAction(r, "apply_preset", "tool_policy", "preset="+preset.ID+",org="+orgID+",created="+fmt.Sprint(created))
		writeJSON(w, http.StatusOK, map[string]any{"preset": preset.ID, "created": created, "skipped_existing": skipped})
	}
}

// invalidateToolPolicies drops the engine cache for the org so edits land
// immediately (the engine reference is nil in tests without wiring).
func (h *AdminHandlers) invalidateToolPolicies(orgID string) {
	if h.mcp.toolEngine != nil {
		h.mcp.toolEngine.Invalidate(orgID)
	}
}

func writeToolPolicyErr(w http.ResponseWriter, err error) {
	if errors.Is(err, toolpolicy.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "tool policy not found"})
		return
	}
	if strings.Contains(err.Error(), "already exists") {
		writeJSON(w, http.StatusConflict, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
}
