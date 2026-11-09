package cli

// (pkg/mcpserver). Tools reuses the mcpagg store (enabled grants + enabled
// servers) plus the mcpagg upstream tools/list discovery; Call re-enters
// the EXISTING invoke path — the same mcpagg.Proxy.Invoke the
// /api/mcp/invoke endpoint uses — so the full guard chain runs once, here:
// agent-only gate, server+grant lookup, tool allow-list intersection,
// OP-6 toolpolicy args/result guards, SSRF re-check, MC-2 credentials,
// metrics and audit. The org deny-policy pre-check mirrors mcpInvoke.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/mcpserver"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// mcpServerBackend implements mcpserver.Backend over the gateway's
// aggregator wiring. The function fields are test seams — the defaults call
// the live store/proxy.
type mcpServerBackend struct {
	gw *gateway

	// listGrants / getServer / listUpstreamTools / invoke / chainAllowance
	// are the narrow seams tests substitute; nil selects the production
	// default.
	listGrants        func(ctx context.Context, orgID, agentID string) ([]*mcpagg.Grant, error)
	getServer         func(ctx context.Context, orgID, name string) (*mcpagg.Server, error)
	listUpstreamTools func(ctx context.Context, orgID string, id mcpagg.Identity, server string) ([]mcpagg.ToolDescriptor, error)
	invoke            func(ctx context.Context, orgID string, id mcpagg.Identity, req mcpagg.InvokeRequest) (json.RawMessage, error)
	// chainAllowance exposes the delegation-chain ceiling (AUTH-02) the
	// invoke path enforces; nil selects the live store.
	chainAllowance func(ctx context.Context, orgID, agentID string) (mcpagg.ChainAllowance, error)
	// the (server, tool) pair decides (DecideTool), so server-qualified
	// policy rows apply to the native MCP endpoint exactly like they do on
	// the inner invoke path (chat-path rows keep applying: they carry
	// Server='*'). The default resolves through gw.toolPolicies.
	decide func(ctx context.Context, orgID, subject, server, tool string) toolpolicy.Decision
}

func (b mcpServerBackend) grants() func(context.Context, string, string) ([]*mcpagg.Grant, error) {
	if b.listGrants != nil {
		return b.listGrants
	}
	return b.gw.mcpStore.ListGrantsForAgent
}

// chainAllowanceFn resolves the AUTH-02 delegation-chain ceiling. In
// production the backend is only constructed with a wired mcpStore, so the
// nil fallback (test wiring without a store) simply skips the chain filter —
// the invoke path enforces the same ceiling independently.
func (b mcpServerBackend) chainAllowanceFn() func(context.Context, string, string) (mcpagg.ChainAllowance, error) {
	if b.chainAllowance != nil {
		return b.chainAllowance
	}
	if b.gw.mcpStore == nil {
		return nil
	}
	return b.gw.mcpStore.DelegationChainAllowance
}

func (b mcpServerBackend) server() func(context.Context, string, string) (*mcpagg.Server, error) {
	if b.getServer != nil {
		return b.getServer
	}
	return b.gw.mcpStore.GetEnabled
}

func (b mcpServerBackend) upstreamTools() func(context.Context, string, mcpagg.Identity, string) ([]mcpagg.ToolDescriptor, error) {
	if b.listUpstreamTools != nil {
		return b.listUpstreamTools
	}
	return b.gw.mcpProxy.ListServerTools
}

func (b mcpServerBackend) invoker() func(context.Context, string, mcpagg.Identity, mcpagg.InvokeRequest) (json.RawMessage, error) {
	if b.invoke != nil {
		return b.invoke
	}
	return b.gw.mcpProxy.Invoke
}

func (b mcpServerBackend) decider() func(context.Context, string, string, string, string) toolpolicy.Decision {
	if b.decide != nil {
		return b.decide
	}
	if b.gw.toolPolicies == nil {
		return func(context.Context, string, string, string, string) toolpolicy.Decision {
			return toolpolicy.Decision{}
		}
	}
	return func(ctx context.Context, orgID, subject, server, tool string) toolpolicy.Decision {
		return b.gw.toolPolicies.DecideTool(ctx, orgID, subject, server, tool)
	}
}

// catalogEntry is one effective catalog row: the server that owns the tool
// plus the descriptor advertised on the wire. The server field never goes
// out over the protocol — it exists so a bare advertised name can be
// resolved back to the (server, tool) pair the invoke path needs, and so
// same-name tools from different servers disambiguate deterministically.
type catalogEntry struct {
	server string
	desc   mcpserver.ToolDesc
}

// Tools assembles the aggregate catalog: for every enabled grant of the
// agent, the granted server's advertised tools filtered to the effective
// allow-list (server ceiling ∩ delegation-chain allowance ∩ grant) and the
// org deny policies. A server whose discovery fails is skipped (a dead
// upstream hides its own tools but never breaks the whole catalog).
//
// The wire name of an entry is the bare upstream tool name (e.g. "search"),
// exactly what discovery returned. The offered protocol matrix is
// 2025-06-18/2025-03-26 (pkg/mcpserver/version.go); those revisions put no
// charset constraint on Tool.name — bare advertising is chosen because the
// protocol layer promises exact-catalog-name calls (pkg/mcpserver/server.go
// tools/list), so every name listed here is callable via Call, and
// conservative names (letters/digits/_/-) match the 2025-11-25 SHOULD
// guidance strict clients follow. The colon form is deliberately NOT
// advertised; Call also accepts the documented "server:tool" form for
// unambiguous addressing (see Call).
func (b mcpServerBackend) Tools(ctx context.Context, p mcpserver.Principal) ([]mcpserver.ToolDesc, error) {
	entries, err := b.catalog(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]mcpserver.ToolDesc, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.desc)
	}
	return out, nil
}

// catalog builds the effective per-principal catalog — the single pipeline
// both tools/list and bare-name resolution run, so "advertised" and
// "callable" can never drift apart (AUDIT-P1-02): resolution sees exactly
// what the listing saw, under the same grants/chain/allow-lists/policies.
// Entries are sorted by (name, owning server) so cursor pagination and
// ambiguity listings stay stable regardless of grant iteration order.
func (b mcpServerBackend) catalog(ctx context.Context, p mcpserver.Principal) ([]catalogEntry, error) {
	grants, err := b.grants()(ctx, p.OrgID, p.AgentID)
	if err != nil {
		return nil, fmt.Errorf("mcp backend: list grants: %w", err)
	}
	// AUTH-02: the catalog must not advertise servers or tools the agent's
	// delegation chain does not allow — the same fact the invoke path
	// enforces, so discovery cannot leak a parent-restricted tool that a
	// call would reject. Absent chain access to a server hides it entirely.
	var allowance mcpagg.ChainAllowance
	if fn := b.chainAllowanceFn(); fn != nil {
		if allowance, err = fn(ctx, p.OrgID, p.AgentID); err != nil {
			return nil, fmt.Errorf("mcp backend: delegation chain allowance: %w", err)
		}
	}
	id := mcpIdentity(p, b.gw)
	out := make([]catalogEntry, 0, len(grants))
	for _, g := range grants {
		if allowance != nil {
			if _, ok := allowance[g.ServerName]; !ok {
				continue // the delegation chain has no access to this server
			}
		}
		srv, err := b.server()(ctx, p.OrgID, g.ServerName)
		if err != nil {
			if errors.Is(err, mcpagg.ErrNotFound) {
				continue // disabled/removed server: nothing to show
			}
			return nil, fmt.Errorf("mcp backend: lookup server %q: %w", g.ServerName, err)
		}
		tools, err := b.upstreamTools()(ctx, p.OrgID, id, g.ServerName)
		if err != nil {
			// Auth-required on discovery is actionable only through the
			// tools/call error path; here the server simply contributes no
			// tools (it would fail the call the same way).
			b.gw.log.Debug("mcp backend: upstream tools/list skipped",
				"org", p.OrgID, "server", g.ServerName, "error", err)
			continue
		}
		for _, t := range tools {
			if !toolOnBothAllowLists(srv.AllowedTools, g.AllowedTools, t.Name) {
				continue
			}
			if allowance != nil && !allowance.Allows(g.ServerName, t.Name) {
				continue // the chain's tool scope hides this tool (AUTH-02)
			}
			if b.decider()(ctx, p.OrgID, p.AgentID, g.ServerName, t.Name).Action == toolpolicy.ActionDeny {
				metrics.ToolPolicyDeniedTotal.WithLabelValues(p.OrgID, t.Name).Inc()
				continue
			}
			out = append(out, catalogEntry{
				server: g.ServerName,
				desc: mcpserver.ToolDesc{
					Name:        t.Name,
					Description: t.Description,
					InputSchema: t.InputSchema,
				},
			})
		}
	}
	sortCatalogEntries(out)
	return out, nil
}

// Call re-enters the invoke path. Two wire forms are accepted (AUDIT-P1-02):
//
//   - the bare catalog name exactly as tools/list advertised it (e.g.
//     "search") — resolved by rebuilding the same catalog the listing
//     served (grants ∩ chain ∩ allow-lists ∩ org deny policies), so every
//     advertised name is callable and nothing unadvertised resolves. If two
//     granted servers advertise the same bare name, the bare form is
//     ambiguous: it fails with not_found naming the namespaced candidates
//     (sorted, taken from the caller's own catalog — no cross-principal
//     leak); no silent pick. The bare form costs one extra upstream
//     discovery pass (the catalog rebuild); discovery failing here yields
//     the same not_found a listing would have shown.
//   - the namespaced "server:tool" form (e.g. "knowledge:search") — the
//     documented flat catalog name (the same separator the audit trail's
//     mcp:<server>:<tool> label uses), the direct fast path and the
//     disambiguator. A name containing ':' is ALWAYS parsed as namespaced:
//     the namespaced form wins, which keeps resolution deterministic — also
//     for an upstream that advertises a colon-containing tool name (such a
//     name stays reachable only as "server:a:b"; the MCP spec forbids colons
//     in advertised tool names, so spec-compliant upstreams never hit this).
//
// The org deny-policy pre-check runs on the resolved (server, tool) pair,
// mirroring mcpInvoke's pre-proxy gate (a bare form of a policy-hidden tool
// resolves to zero catalog matches first: not_found — hidden, not denied).
func (b mcpServerBackend) Call(ctx context.Context, p mcpserver.Principal, name string, args json.RawMessage) (json.RawMessage, error) {
	var server, tool string
	if strings.ContainsRune(name, ':') {
		s, t, err := splitToolName(name)
		if err != nil {
			return nil, &mcpserver.ToolCallError{Code: mcpagg.ErrCodeNotFound, Message: err.Error()}
		}
		server, tool = s, t
	} else {
		s, t, err := b.resolveBareName(ctx, p, name)
		if err != nil {
			return nil, err
		}
		server, tool = s, t
	}
	if b.decider()(ctx, p.OrgID, p.AgentID, server, tool).Action == toolpolicy.ActionDeny {
		metrics.ToolPolicyDeniedTotal.WithLabelValues(p.OrgID, tool).Inc()
		b.gw.log.Warn("tool policy denied mcp.streamable invoke",
			"org", p.OrgID, "subject", p.AgentID, "tool", tool)
		return nil, &mcpserver.ToolCallError{Code: "policy_denied",
			Message: fmt.Sprintf("tool %q is denied by org policy", tool)}
	}
	result, err := b.invoker()(ctx, p.OrgID, mcpIdentity(p, b.gw), mcpagg.InvokeRequest{
		Server: server,
		Tool:   tool,
		Params: args,
	})
	if err != nil {
		return nil, mapInvokeError(err)
	}
	return result, nil
}

// resolveBareName maps an advertised catalog name to its owning
// (server, tool) pair by rebuilding the exact catalog tools/list served.
// Zero matches → not_found (never advertised, or filtered since — deny
// policies hide the tool rather than naming it); more than one match (two
// granted servers advertise the same name) → deterministic not_found
// ambiguity listing the namespaced candidates in catalog order.
func (b mcpServerBackend) resolveBareName(ctx context.Context, p mcpserver.Principal, name string) (string, string, error) {
	entries, err := b.catalog(ctx, p)
	if err != nil {
		return "", "", err
	}
	var hits []catalogEntry
	for _, e := range entries {
		if e.desc.Name == name {
			hits = append(hits, e)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0].server, hits[0].desc.Name, nil
	case 0:
		return "", "", &mcpserver.ToolCallError{
			Code:    mcpagg.ErrCodeNotFound,
			Message: fmt.Sprintf("tool %q not found (see tools/list)", name),
		}
	default:
		cands := make([]string, 0, len(hits))
		for _, e := range hits {
			cands = append(cands, e.server+":"+e.desc.Name)
		}
		return "", "", &mcpserver.ToolCallError{
			Code: mcpagg.ErrCodeNotFound,
			Message: fmt.Sprintf(
				"tool %q is ambiguous across servers; use the namespaced \"server:tool\" form: %s",
				name, strings.Join(cands, ", ")),
		}
	}
}

// mcpIdentity converts the verified principal into the mcpagg identity the
// proxy/audit trail expects (same fields as the invoke endpoint assembles;
// the agent display name is resolved once at principal time).
func mcpIdentity(p mcpserver.Principal, _ *gateway) mcpagg.Identity {
	return mcpagg.Identity{
		AgentID:   p.AgentID,
		AgentName: p.AgentName,
		TeamID:    p.TeamID,
		RequestID: p.RequestID,
		TaskID:    p.TaskID,
	}
}

// mapInvokeError converts the invoke path's structured errors into the
// protocol layer's ToolCallError (codes pass through unchanged so agents
// see the documented invoke vocabulary).
func mapInvokeError(err error) error {
	var authErr *mcpagg.AuthRequiredError
	if errors.As(err, &authErr) {
		return &mcpserver.ToolCallError{
			Code:    mcpagg.ErrCodeAuthRequired,
			Message: authErr.Message,
			Kind:    authErr.Kind,
			URL:     authErr.URL,
		}
	}
	var iErr *mcpagg.InvokeError
	if errors.As(err, &iErr) {
		return &mcpserver.ToolCallError{Code: iErr.Code, Message: iErr.Message}
	}
	return err
}

// toolOnBothAllowLists reports whether tool passes the server ceiling AND
// the grant list (empty on either side means "all of that side").
func toolOnBothAllowLists(serverAllow, grantAllow []string, tool string) bool {
	return toolOnAllowList(serverAllow, tool) && toolOnAllowList(grantAllow, tool)
}

func toolOnAllowList(allow []string, tool string) bool {
	if len(allow) == 0 {
		return true
	}
	for _, t := range allow {
		if t == tool {
			return true
		}
	}
	return false
}

// sortCatalogEntries orders the catalog by advertised name, then owning
// server, so cursor pagination and bare-name ambiguity listings are stable
// regardless of grant/store iteration order.
func sortCatalogEntries(entries []catalogEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].desc.Name != entries[j].desc.Name {
			return entries[i].desc.Name < entries[j].desc.Name
		}
		return entries[i].server < entries[j].server
	})
}

// splitToolName splits the namespaced "server:tool" wire form. Exactly two
// non-empty segments are accepted (a tool name may itself contain colons:
// the first colon is the separator, matching the audit trail's
// mcp:<server>:<tool> label). This form always wins over bare-name
// resolution — see Call.
func splitToolName(name string) (server, tool string, err error) {
	i := strings.IndexByte(name, ':')
	if i <= 0 || i == len(name)-1 {
		return "", "", fmt.Errorf("tool %q not found: names are \"server:tool\" (see tools/list)", name)
	}
	return name[:i], name[i+1:], nil
}

// mcpStreamablePrincipal extracts the verified principal from the gateway
// identity headers (set by the auth middleware from the resolved yag_
// principal; client copies are stripped at ingress) — the same reads the
// invoke handler performs.
func mcpStreamablePrincipal(gw *gateway) func(*http.Request) (mcpserver.Principal, error) {
	return func(r *http.Request) (mcpserver.Principal, error) {
		orgID := r.Header.Get("X-Org-Id")
		if orgID == "" {
			return mcpserver.Principal{}, &mcpserver.PrincipalError{
				Status:  http.StatusUnauthorized,
				Code:    "authentication",
				Message: "org resolution failed",
			}
		}
		agentID := r.Header.Get("X-Agent-Id")
		if agentID == "" {
			return mcpserver.Principal{}, &mcpserver.PrincipalError{
				Status:  http.StatusForbidden,
				Code:    "agent_only",
				Message: "mcp tool-calls require an agent-principal (yag_) key",
			}
		}
		p := mcpserver.Principal{
			OrgID:     orgID,
			AgentID:   agentID,
			TeamID:    r.Header.Get("X-Team-Id"),
			RequestID: logctx.RequestID(r.Context()),
			TaskID:    r.Header.Get("X-Yabanin-Task"),
		}
		if gw.mcpAgentName != nil {
			p.AgentName = gw.mcpAgentName(r.Context(), agentID)
		}
		return p, nil
	}
}
