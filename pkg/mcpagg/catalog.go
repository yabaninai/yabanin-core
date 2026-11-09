package mcpagg

// (pkg/mcpserver) needs the tools each granted upstream advertises so
// tools/list can return real descriptors (name/description/inputSchema)
// instead of bare allow-list names. The discovery read lives HERE because it
// must reuse the exact invoke plumbing — SSRF re-check, credential
// resolution (MC-2), bounded client, SSE-aware decoding — and the card
// forbids duplicating that chain in a second package.
//
// It is a discovery read, not a tool call: no args guards run (there are no
// args), no AuditEvent is recorded (the mcpserver endpoint counts it in its
// own request metrics), and nothing egresses org data — the request is an
// empty JSON-RPC tools/list to an already-granted, allow-listed upstream.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ToolDescriptor is one tool advertised by an upstream MCP server (the
// tools/list catalog entry). InputSchema is the upstream's JSON schema for
// the arguments object, passed through verbatim.
type ToolDescriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ListServerTools returns the tools one registered server advertises, for an
// agent that holds an enabled grant on it. The guard posture mirrors Invoke:
// the N05-P02-T04 four-dimension grant check (subject / server / action /
// — tool is not checked: discovery is not tool-scoped; the caller
// intersects allow-lists), SSRF re-check on the upstream URL, credential
// resolution under the policy-selected credential mode with exactly one
// force-refresh + retry on a 401/403. Failures surface as *InvokeError
// (same code vocabulary) or *AuthRequiredError; unknown infrastructure
// errors are wrapped plain errors.
func (p *Proxy) ListServerTools(ctx context.Context, orgID string, id Identity, server string) ([]ToolDescriptor, error) {
	// N05-P02-T04: the same four-dimension grant check as Invoke, with
	// action=list and tool="" (dimension 4 skipped — tools/list is not
	// tool-scoped). Grant revocation stops discovery the same way it stops
	// calls.
	srv, _, refusal, err := p.authorizeGrant(ctx, orgID, id, server, "", GrantActionList)
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		return nil, refusal.err
	}

	// AUTH-02: the agent AND every ancestor in its delegation chain must
	// hold an enabled grant on this server — the existence check is the
	// authorization fact (the caller intersects allow-lists).
	allowance, err := p.store.DelegationChainAllowance(ctx, orgID, id.AgentID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, &InvokeError{Code: ErrCodeNotFound,
				Message: fmt.Sprintf("mcp server %q is not available for this org", server)}
		}
		return nil, fmt.Errorf("mcpagg: lookup delegation chain allowance: %w", err)
	}
	if _, ok := allowance[server]; !ok {
		return nil, &InvokeError{Code: ErrCodeNotFound,
			Message: fmt.Sprintf("mcp server %q is not available for this org", server)}
	}

	// SSRF re-check (rebind window) — before any credential work, the same
	// order and the same test seam as Invoke.
	if !p.testAllowHTTP {
		if err := ValidateURLAtInvoke(srv.URL, p.allow, false); err != nil { //nolint:contextcheck // SSRF guard runs on a bounded background ctx (QG2-D3 threads request ctx)
			return nil, &InvokeError{Code: ErrCodeSSRF, Message: err.Error()}
		}
	}

	// N05-P02-T04: policy-selected credential mode for DISCOVERY — tool "*"
	// (any tool on this server; a mode row pinned to one exact tool does not
	// govern discovery of the catalog). Same fail-closed semantics as
	// Invoke step 4b.
	credMode := ""
	if p.modePolicy != nil && p.creds != nil {
		m, err := p.modePolicy.SelectCredentialMode(ctx, orgID, srv.Name, "*", id.AgentID)
		if err != nil {
			return nil, &InvokeError{Code: ErrCodeDenied,
				Message: fmt.Sprintf("credential mode policy is unavailable; refusing the call: %v", err)}
		}
		if m, err = normalizeCredMode(m); err != nil {
			return nil, &InvokeError{Code: ErrCodeDenied,
				Message: fmt.Sprintf("credential mode policy returned an invalid mode; refusing the call: %v", err)}
		}
		credMode = m
	}

	// MC-2 credential resolution under the selected mode (fail-closed on
	// infrastructure errors; a layer/pin mismatch refuses BEFORE egress —
	// the same no-silent-switch invariant as Invoke step 5).
	var credHeaders map[string][]string
	credKind := CredKindNone
	if p.creds != nil {
		if credModeConstrained(credMode) {
			ls, levelAware := p.creds.(LevelAwareCredSource)
			if !levelAware {
				p.metricCredMode(srv.Name, credMode, "error")
				return nil, &InvokeError{Code: ErrCodeDenied,
					Message: "credential mode policy requires a credential source that reports which layer resolved the credential; refusing the call"}
			}
			headers, kind, level, err := ls.AuthHeadersLevel(ctx, orgID, server, id.AgentID)
			if err != nil {
				p.metricCreds(server, kind, CredOutcomeError)
				return nil, fmt.Errorf("mcpagg: resolve credential: %w", err)
			}
			credHeaders, credKind = headers, kind
			if credModeViolation(credMode, level) {
				p.metricCredMode(srv.Name, credMode, "deny")
				return nil, &InvokeError{Code: ErrCodeDenied,
					Message: fmt.Sprintf("credential mode policy pins %q for this call; the resolved credential is the %s credential — refusing",
						credMode, level)}
			}
			p.metricCredMode(srv.Name, credMode, "allow")
		} else {
			headers, kind, err := p.creds.AuthHeaders(ctx, orgID, server, id.AgentID)
			if err != nil {
				p.metricCreds(server, kind, CredOutcomeError)
				return nil, fmt.Errorf("mcpagg: resolve credential: %w", err)
			}
			credHeaders, credKind = headers, kind
		}
		if credHeaders != nil {
			p.metricCreds(server, credKind, CredOutcomeHit)
		} else {
			p.metricCreds(server, CredKindNone, CredOutcomeMiss)
		}
	}

	result, status, callErr := p.postRPC(ctx, srv, "tools/list", map[string]any{}, id, credHeaders)
	if callErr != nil && isAuthRejection(status) && p.creds != nil {
		// The retry's status is not consulted — the structured errors carry
		// everything the caller needs.
		result, _, callErr = p.retryToolsListAfterUnauthorized(ctx, orgID, id, srv, credKind, credMode)
	}
	if callErr != nil {
		var authErr *AuthRequiredError
		if errors.As(callErr, &authErr) {
			return nil, authErr
		}
		var iErr *InvokeError
		if errors.As(callErr, &iErr) {
			return nil, iErr
		}
		return nil, callErr
	}

	var parsed struct {
		Tools []ToolDescriptor `json:"tools"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return nil, &InvokeError{Code: ErrCodeUpstream,
			Message: "upstream tools/list: malformed result"}
	}
	if parsed.Tools == nil {
		parsed.Tools = []ToolDescriptor{}
	}
	return parsed.Tools, nil
}

// retryToolsListAfterUnauthorized is the tools/list counterpart of
// retryAfterUnauthorized: one force-refresh + retry; without a credential
// the org simply lacks one → mcp_auth_required (kind: headers). Under a
// constrained credMode the refresh is level-aware and the refreshed
// credential is held to the same pin (credModeRefusal parity with the
// invoke retry).
func (p *Proxy) retryToolsListAfterUnauthorized(ctx context.Context, orgID string, id Identity, srv *Server, credKind, credMode string) (json.RawMessage, int, error) {
	if credKind == CredKindNone {
		return nil, http.StatusUnauthorized, newAuthRequiredError(CredKindHeaders, srv.Name,
			"the mcp server requires authorization; no usable credential is stored for this agent")
	}
	if credModeConstrained(credMode) {
		ls, levelAware := p.creds.(LevelAwareCredSource)
		if !levelAware {
			p.metricCredMode(srv.Name, credMode, "error")
			return nil, 0, &credModeRefusal{&InvokeError{Code: ErrCodeDenied,
				Message: "credential mode policy requires a credential source that reports which layer resolved the credential; refusing the call"}}
		}
		refreshed, kind, level, retry, err := ls.OnUpstreamUnauthorizedLevel(ctx, orgID, srv.Name, id.AgentID, credKind)
		if err != nil {
			p.metricCreds(srv.Name, credKind, CredOutcomeError)
			return nil, 0, fmt.Errorf("mcpagg: credential refresh: %w", err)
		}
		if !retry {
			return nil, http.StatusUnauthorized, newAuthRequiredError(credKind, srv.Name,
				"the stored mcp credential was rejected by the server; re-authorization is required")
		}
		p.metricCreds(srv.Name, kind, CredOutcomeRefresh)
		if credModeViolation(credMode, level) {
			p.metricCredMode(srv.Name, credMode, "deny")
			return nil, 0, &credModeRefusal{&InvokeError{Code: ErrCodeDenied,
				Message: fmt.Sprintf("credential mode policy pins %q for this call; the refreshed credential is the %s credential — refusing",
					credMode, level)}}
		}
		p.metricCredMode(srv.Name, credMode, "allow")
		return p.postRPC(ctx, srv, "tools/list", map[string]any{}, id, refreshed)
	}
	refreshed, retry, err := p.creds.OnUpstreamUnauthorized(ctx, orgID, srv.Name, id.AgentID, credKind)
	if err != nil {
		p.metricCreds(srv.Name, credKind, CredOutcomeError)
		return nil, 0, fmt.Errorf("mcpagg: credential refresh: %w", err)
	}
	if !retry {
		return nil, http.StatusUnauthorized, newAuthRequiredError(credKind, srv.Name,
			"the stored mcp credential was rejected by the server; re-authorization is required")
	}
	p.metricCreds(srv.Name, credKind, CredOutcomeRefresh)
	return p.postRPC(ctx, srv, "tools/list", map[string]any{}, id, refreshed)
}
