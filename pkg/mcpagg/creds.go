package mcpagg

// MC-2 (MCP-CREDENTIALS-PLAN-2026-10-05): upstream credential injection on
// the invoke path. The proxy resolves outbound auth headers through the
// CredSource the gateway implements (per-user active → server-level enabled
// → none), applies them to the JSON-RPC request, retries ONCE after a
// force-refresh when the upstream rejects with 401/403, and surfaces the
// lazy-authorization error (mcp_auth_required) with the human URL.
//
// Security invariants (docs/mcp-gateway.md §7): a credential NEVER extends
// the egress surface — the SSRF allow-list check on the server URL runs
// BEFORE any credential resolution, so a registered-but-disallowed host
// stays blocked with or without a credential. Plaintext secret material
// lives only inside the CredSource for the duration of one attempt; the
// proxy never logs or serializes it.

import (
	"context"
	"fmt"
	"net/http"
)

// Credential kinds (migration 0007 vocabulary, "-" when absent).
const (
	CredKindHeaders = "headers"
	CredKindOAuth   = "oauth"
	CredKindNone    = "-"
)

// CredOutcome labels for the gateway_mcp_creds_total metric.
const (
	CredOutcomeHit     = "hit"
	CredOutcomeMiss    = "miss"
	CredOutcomeRefresh = "refresh"
	CredOutcomeError   = "error"
)

// ErrCodeAuthRequired is the 401 error code the caller sees when no usable
// credential exists (or the stored one is dead): the response body carries
// {"error":{"code":"mcp_auth_required","kind":...,"url":...}} so an agent
// (or its human) can complete the lazy authorization flow (MC-3).
const ErrCodeAuthRequired = "mcp_auth_required"

// Credential-surface paths the AuthRequiredError URL points at (mounted by
// the MC-3 route group on the same gateway origin).
const (
	credSubmitPathFmt = "/api/mcp/credentials/%s" //nolint:gosec // G101: a route path, not a credential
	credBeginPathFmt  = "/api/mcp/auth/%s/begin"  //nolint:gosec // G101: a route path, not a credential
)

// AuthRequiredError is the structured lazy-authorization error: kind is the
// credential kind that would satisfy the server (headers → the submit
// endpoint, oauth → the begin endpoint) and URL is the human-readable
// relative path to start that flow.
type AuthRequiredError struct {
	Kind    string `json:"kind"`
	URL     string `json:"url"`
	Message string `json:"message"`
}

// Error implements error.
func (e *AuthRequiredError) Error() string {
	return ErrCodeAuthRequired + ": " + e.Message
}

// newAuthRequiredError builds the error for the kind that would satisfy the
// server (serverName empty on pre-lookup failures keeps the URL stable).
func newAuthRequiredError(kind, serverName, message string) *AuthRequiredError {
	pathFmt := credSubmitPathFmt
	if kind == CredKindOAuth {
		pathFmt = credBeginPathFmt
	}
	return &AuthRequiredError{
		Kind:    kind,
		URL:     fmt.Sprintf(pathFmt, serverName),
		Message: message,
	}
}

// CredSource is the credential resolution surface the gateway implements
// over the adminstore + version cache. The proxy depends only on this
// interface; a nil source keeps the pre-credential behavior bit-for-bit.
type CredSource interface {
	// AuthHeaders resolves the outbound auth headers for one invoke:
	// per-user (active) → server-level (enabled). (nil, nil) means the org
	// holds no usable credential — the call proceeds unauthenticated, the
	// legacy posture, and the upstream verdict decides the outcome.
	AuthHeaders(ctx context.Context, orgID, serverName, agentID string) (headers map[string][]string, kind string, err error)

	// OnUpstreamUnauthorized runs when the upstream answered 401/403 with a
	// credential of the given kind applied. For oauth it force-refreshes the
	// token once; (headers, true) returns the refreshed headers for exactly
	// one retry. retry=false ends the attempt; a terminally dead token is
	// marked needs_reauth inside the source (sticky).
	OnUpstreamUnauthorized(ctx context.Context, orgID, serverName, agentID, kind string) (headers map[string][]string, retry bool, err error)
}

// maxCredHeaderNameBytes/Values guard the header application (defense in
// depth; the store validates the payload at write time).
const maxCredHeaderCount = 32

// applyCredHeaders copies the resolved credential headers onto the request.
// The payload is store-validated (token names, no CR/LF/NUL) at write time;
// this copy is fail-closed on malformed input rather than sending it.
func applyCredHeaders(req *http.Request, headers map[string][]string) error {
	if len(headers) == 0 {
		return nil
	}
	if len(headers) > maxCredHeaderCount {
		return fmt.Errorf("mcpagg: credential header set too large (%d)", len(headers))
	}
	for name, values := range headers {
		for i, v := range values {
			if i == 0 {
				req.Header.Set(name, v)
				continue
			}
			req.Header.Add(name, v)
		}
	}
	return nil
}
