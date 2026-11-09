package cli

// A2A-01: the gateway-side /api/a2a/send endpoint — one message/send against
// an org-registered external A2A agent (pkg/a2aagg). Mirrors mcpInvoke:
// agent-principal (yag_) only, the org from the resolved key, identity
// headers set by the auth middleware (client copies stripped on ingress).

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/reireirei/yabanin/pkg/a2aagg"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/logctx"
)

// a2aSend handles POST /api/a2a/send.
func (gw *gateway) a2aSend(w http.ResponseWriter, r *http.Request) {
	if gw.a2aProxy == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	orgID := r.Header.Get("X-Org-Id")
	if orgID == "" {
		apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication,
			"org resolution failed")
		return
	}
	// Agent-principal only: the middleware sets X-Agent-Id from the resolved
	// yag_ principal; an empty value means a regular api_key — rejected.
	agentID := r.Header.Get("X-Agent-Id")
	if agentID == "" {
		apierrors.Write(w, http.StatusForbidden, "agent_only",
			"a2a sends require an agent-principal (yag_) key")
		return
	}
	var req a2aagg.SendRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"malformed JSON body")
		return
	}
	// TOOL-01: org tool policy gates the send (tool name "a2a:<agent>").
	if gw.policyDeniesTool(w, r, orgID, agentID, "a2a:"+req.Agent) {
		return
	}
	id := a2aagg.Identity{
		AgentID:   agentID,
		TeamID:    r.Header.Get("X-Team-Id"),
		RequestID: logctx.RequestID(r.Context()),
		TaskID:    r.Header.Get("X-Yabanin-Task"),
	}
	// The agent display name rides upstream as X-Yabanin-Agent-Name
	// (attribution aid, same contract as MCP-04); a lookup failure simply
	// omits the header.
	if gw.mcpAgentName != nil {
		id.AgentName = gw.mcpAgentName(r.Context(), agentID)
	}
	result, err := gw.a2aProxy.Send(r.Context(), orgID, id, req)
	if err != nil {
		var iErr *a2aagg.InvokeError
		if errors.As(err, &iErr) {
			status := http.StatusBadGateway
			switch iErr.Code {
			case a2aagg.ErrCodeAgentOnly:
				status = http.StatusForbidden
			case a2aagg.ErrCodeNotFound:
				status = http.StatusNotFound
			case a2aagg.ErrCodeSSRF, a2aagg.ErrCodeMethod:
				status = http.StatusBadRequest
			case a2aagg.ErrCodeDenied:
				status = http.StatusConflict
			case a2aagg.ErrCodeTimeout:
				status = http.StatusGatewayTimeout
			}
			apierrors.Write(w, status, iErr.Code, iErr.Message)
			return
		}
		gw.log.Error("a2a send failed", "org", orgID, "agent", req.Agent, "error", err)
		apierrors.Write(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	// The body is the upstream JSON-RPC result (application/json). gosec
	// G705's taint analysis flags w.Write(result) as a potential reflected
	// XSS; it is a false positive here: the response is JSON (not HTML), the
	// Content-Type is fixed, and the browser does not execute it as a script.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(result); err != nil { //nolint:gosec // G705: JSON body, not HTML
		gw.log.Warn("a2a send: writing response failed", "org", orgID, "error", err)
	}
}
