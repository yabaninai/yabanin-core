package mcpagg

// N05-P02-T04: the four-dimension grant check — subject (the agent grant
// row), server, tool (the effective allow-list intersection) and action
// (invoke vs list) — consolidated from the two call sites that used to
// duplicate it (Invoke and ListServerTools). The ACTION dimension is new
// with that card: the vocabulary is explicit and enforced at both call
// sites, so the per-grant action column lands in the check that already
// consults it. The column EXISTS since migration 0020 (N05-P06-T02, owner
// decision 2026-11-05: per-grant action column EARLY, FIX-21 item):
// grantAllowsAction now reads Grant.AllowedActions. Rows created before 0020
// carry the column default ["invoke","list"] — today's behavior preserved;
// an explicitly empty list denies both actions (fail-closed), and unknown
// actions are refused, never silently granted.
//
// Refusals keep the exact pre-refactor wire behavior: every
// authorization-shaped refusal is not_found (an agent cannot enumerate
// grant-blocked vs server-blocked vs tool-blocked servers by probing),
// agent-principal violations are agent_only, and infrastructure errors stay
// plain wrapped errors (the call sites decide audit/span treatment).

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// Grant actions (N05-P02-T04 vocabulary).
const (
	GrantActionInvoke = "invoke" // tools/call on the aggregated server
	GrantActionList   = "list"   // tools/list discovery on the server
)

// grantAllowsAction reports whether the grant row authorizes the action.
// Since migration 0020 this is column-backed: the grant's AllowedActions
// must explicitly contain the action. The column default ["invoke","list"]
// keeps pre-0020 rows working unchanged; an empty list denies every action
// (the action dimension is fail-closed, unlike the tool dimension where an
// empty allow-list means "unrestricted" — documented on Grant). Unknown
// actions are refused — fail-closed, not silently granted.
func grantAllowsAction(g *Grant, action string) bool {
	if g == nil || !g.Enabled {
		return false
	}
	if _, known := validGrantActions[action]; !known {
		return false
	}
	return slices.Contains(g.AllowedActions, action)
}

// grantRefusal is a typed pre-egress authorization refusal with its audit
// context: the InvokeError the caller renders, the audit/span outcome label,
// and the server name + upstream URL the audit trail records (both empty on
// the earliest refusals, where the server was never resolved).
type grantRefusal struct {
	err        *InvokeError
	outcome    string
	serverName string
	serverURL  string
}

// Error implements error.
func (r *grantRefusal) Error() string { return r.err.Error() }

// authorizeGrant runs the four-dimension grant check for one call:
//
//  1. agent-principal only (MCP-03): id.AgentID must be set;
//  2. subject: the agent holds an enabled grant on the server — revoking
//     the grant (enabled=false / deleted) stops ALL dependent access
//     immediately, including the delegated credential path (the credential
//     resolution below step 5 never runs without a grant);
//  3. action: the grant authorizes the requested action (invoke/list);
//  4. tool (when tool != ""): the tool passes BOTH the server ceiling and
//     the grant allow-list (either side empty = all of that side).
//
// Returns the resolved server + grant rows, or a *grantRefusal on any
// authorization-shaped refusal, or a plain error on store/infrastructure
// failure. tool == "" (tools/list) skips dimension 4.
func (p *Proxy) authorizeGrant(ctx context.Context, orgID string, id Identity, server, tool, action string) (*Server, *Grant, *grantRefusal, error) {
	// MCP-03: tool surfaces are agent-key-only. The identity comes from the
	// gateway auth middleware (the resolved yag_ principal); a regular
	// api_key has an empty AgentID and is rejected before anything else.
	if id.AgentID == "" {
		return nil, nil, &grantRefusal{
			err: &InvokeError{Code: ErrCodeAgentOnly,
				Message: "mcp tool-calls require an agent-principal (yag_) key"},
			outcome: OutcomeDenied,
		}, nil
	}

	// The server must exist, be enabled, and belong to the org.
	srv, err := p.store.GetEnabled(ctx, orgID, server)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil, &grantRefusal{
				err: &InvokeError{Code: ErrCodeNotFound,
					Message: fmt.Sprintf("mcp server %q is not available for this org", server)},
				outcome: OutcomeNotFound,
			}, nil
		}
		return nil, nil, nil, fmt.Errorf("mcpagg: lookup server: %w", err)
	}

	// Subject dimension: the agent's grant on this server. A missing or
	// disabled grant is indistinguishable from a missing server (not_found)
	// — the agent cannot enumerate which of its requests are grant-blocked.
	// THIS is the revocation acceptance (N05-P02-T04): flipping the grant's
	// enabled flag (or deleting it) stops the dependent access — the
	// credential path below never runs, so neither the user's delegated
	// credential nor the org service credential is consulted.
	grant, err := p.store.GetEnabledGrant(ctx, orgID, id.AgentID, server)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil, &grantRefusal{
				err: &InvokeError{Code: ErrCodeNotFound,
					Message: fmt.Sprintf("mcp server %q is not available for this org", server)},
				outcome:    OutcomeNotFound,
				serverName: srv.Name,
				serverURL:  srv.URL,
			}, nil
		}
		return nil, nil, nil, fmt.Errorf("mcpagg: lookup agent grant: %w", err)
	}

	// Action dimension: the grant authorizes this operation. Refusal keeps
	// the grant-miss posture (not_found, same indistinguishability).
	if !grantAllowsAction(grant, action) {
		return nil, nil, &grantRefusal{
			err: &InvokeError{Code: ErrCodeNotFound,
				Message: fmt.Sprintf("mcp server %q is not available for this org", server)},
			outcome:    OutcomeNotFound,
			serverName: srv.Name,
			serverURL:  srv.URL,
		}, nil
	}

	// Tool dimension: the effective allow-list intersection (invoke only —
	// tools/list is not tool-scoped; the caller intersects the catalog).
	if tool != "" && (!toolAllowed(srv.AllowedTools, tool) || !toolAllowed(grant.AllowedTools, tool)) {
		return nil, nil, &grantRefusal{
			err: &InvokeError{Code: ErrCodeNotFound,
				Message: fmt.Sprintf("tool %q is not allowed on mcp server %q", tool, server)},
			outcome:    OutcomeNotFound,
			serverName: srv.Name,
			serverURL:  srv.URL,
		}, nil
	}

	return srv, grant, nil, nil
}
