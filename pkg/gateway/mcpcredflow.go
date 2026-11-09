package cli

// MC-3 (MCP-CREDENTIALS-PLAN-2026-10-05): the per-user lazy-authorization
// endpoints on the gateway data plane (agent-authenticated, yag_ keys):
//
//	POST /api/mcp/credentials/{server}   headers submit/rotate (grant ceiling)
//	POST /api/mcp/auth/{server}/begin    oauth: consent URL + pending row
//	GET  /api/mcp/auth/{server}/callback oauth: code exchange (PUBLIC — the
//	                                     IdP redirects the human's browser
//	                                     here; the state nonce is the
//	                                     capability, the org rides as a
//	                                     routing hint)
//
// The grant on the server stays the ceiling for every flow step (the store
// enforces it on submit/begin/token-write). Secrets never appear in any
// response: masked rows (last4/has_secret) only. Every CRUD/status step
// lands in the hash-chained audit journal with X-Audit-Reason.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	apierrors "github.com/reireirei/yabanin/pkg/errors"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// mcpCredFlowBodyLimit bounds the credential-submit body (a headers JSON
// object; the store additionally caps the plaintext at 8 KiB).
const mcpCredFlowBodyLimit = 16 * 1024

// mcpFlowReasonHeader is the operator/agent motive for a mutating flow step
// (X-Audit-Reason parity with the admin surface).
const mcpFlowReasonHeader = "X-Audit-Reason"

// auditReasonHeader extracts (trimmed, length-capped) the reason header.
func auditReasonHeader(r *http.Request) string {
	const maxRunes = 512
	reason := strings.TrimSpace(r.Header.Get(mcpFlowReasonHeader))
	if reason == "" {
		return ""
	}
	runes := []rune(reason)
	if len(runes) > maxRunes {
		reason = string(runes[:maxRunes])
	}
	return reason
}

// mcpUserCredSubmitBody is the submit payload; unknown fields are rejected.
type mcpUserCredSubmitBody struct {
	Headers map[string]any `json:"headers"`
}

// requireMCPAgent writes the same 401/403 the invoke endpoint uses and
// returns ("", "", false) when the caller is not an agent-principal on an
// org.
func (gw *gateway) requireMCPAgent(w http.ResponseWriter, r *http.Request) (orgID, agentID string, ok bool) {
	orgID = r.Header.Get("X-Org-Id")
	if orgID == "" {
		apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication, "org resolution failed")
		return "", "", false
	}
	agentID = r.Header.Get("X-Agent-Id")
	if agentID == "" {
		apierrors.Write(w, http.StatusForbidden, "agent_only",
			"mcp credentials require an agent-principal (yag_) key")
		return "", "", false
	}
	return orgID, agentID, true
}

// mcpSubmitUserCredential — POST /api/mcp/credentials/{server}
func (gw *gateway) mcpSubmitUserCredential(w http.ResponseWriter, r *http.Request) {
	if gw.mcpCredsSrc == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	orgID, agentID, ok := gw.requireMCPAgent(w, r)
	if !ok {
		return
	}
	serverName := r.PathValue("server")
	if serverName == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "server name is required")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, mcpCredFlowBodyLimit+1))
	if err != nil || len(raw) > mcpCredFlowBodyLimit {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "invalid request body")
		return
	}
	var body mcpUserCredSubmitBody
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || len(body.Headers) == 0 {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			`body must be {"headers":{...}} with at least one header`)
		return
	}
	payload, err := json.Marshal(body.Headers)
	if err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "headers must be a JSON object")
		return
	}
	row, err := gw.mcpCredsSrc.SubmitUserHeaders(r.Context(), orgID, serverName, agentID, string(payload), auditReasonHeader(r))
	if err != nil {
		gw.writeMCPUserCredErr(w, err)
		return
	}
	// The masked row only — no secret material on the wire.
	writeMCPJSON(w, http.StatusOK, row)
}

// mcpOAuthBegin — POST /api/mcp/auth/{server}/begin
func (gw *gateway) mcpOAuthBegin(w http.ResponseWriter, r *http.Request) {
	if gw.mcpCredsSrc == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	orgID, agentID, ok := gw.requireMCPAgent(w, r)
	if !ok {
		return
	}
	serverName := r.PathValue("server")
	if serverName == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "server name is required")
		return
	}
	redirectURI := gw.mcpCallbackURL(r, serverName)
	authorizeURL, state, err := gw.mcpCredsSrc.BeginUserOAuth(r.Context(), orgID, serverName, agentID, redirectURI)
	if err != nil {
		if errors.Is(err, errMCPNoOAuthConfig) {
			apierrors.Write(w, http.StatusConflict, apierrors.ErrorCodeInvalidRequest,
				"the server has no enabled oauth credential to start the flow from")
			return
		}
		gw.writeMCPUserCredErr(w, err)
		return
	}
	writeMCPJSON(w, http.StatusOK, map[string]string{
		"url":      authorizeURL,
		"state":    state,
		"redirect": redirectURI,
	})
}

// mcpOAuthCallback — GET /api/mcp/auth/{server}/callback (public: the IdP
// redirects the human's browser here; no agent key is present). The state
// nonce is the capability; org is a routing hint (a wrong org just misses —
// the state random part is the secret).
func (gw *gateway) mcpOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if gw.mcpCredsSrc == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	serverName := r.PathValue("server")
	orgID := strings.TrimSpace(r.URL.Query().Get("org"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if orgID == "" || state == "" || code == "" || serverName == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "org, state and code are required")
		return
	}
	row, err := gw.mcpCredsSrc.CompleteUserOAuth(r.Context(), orgID, serverName, code, state)
	if err != nil {
		// Browser-facing: a terse generic failure — never driver or IdP text.
		gw.log.Warn("mcp oauth callback failed", "org", orgID, "server", serverName, "error", err.Error())
		apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication, "the authorization flow could not be completed")
		return
	}
	writeMCPJSON(w, http.StatusOK, map[string]any{
		"status":     "authorized",
		"server":     serverName,
		"agent_id":   row.AgentKeyID,
		"expires_at": row.ExpiresAt,
	})
}

// mcpCallbackURL derives the oauth redirect_uri from the request origin
// (best-effort: deployments behind a proxy set X-Forwarded-Proto; an
// operator override lives in the server-level oauth credential).
func (gw *gateway) mcpCallbackURL(r *http.Request, serverName string) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme != "http" && scheme != "https" {
		scheme = "https"
		if host := r.Host; strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
			scheme = "http"
		}
	}
	return scheme + "://" + r.Host + "/api/mcp/auth/" + url.PathEscape(serverName) + "/callback"
}

// writeMCPJSON renders one JSON value (the gateway has no shared helper for
// success bodies; the invoke handler writes its JSON inline).
func writeMCPJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeMCPUserCredErr maps the flow store errors: not-found (missing grant
// or server) → 404, anything else → generic 500 (driver text to the log).
func (gw *gateway) writeMCPUserCredErr(w http.ResponseWriter, err error) {
	if errors.Is(err, adminstore.ErrNotFound) {
		apierrors.Write(w, http.StatusNotFound, "not_found",
			"mcp server not available or no grant for this agent")
		return
	}
	gw.log.Error("mcp credential flow failed", "error", err.Error())
	apierrors.Write(w, http.StatusInternalServerError, "internal", "internal error")
}
