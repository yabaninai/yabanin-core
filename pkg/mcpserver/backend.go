// Package mcpserver implements the native MCP endpoint on the gateway
// so MCP clients (Claude Desktop, Cursor, agents) connect to the gateway the
// same way they connect to any MCP server — POST /mcp with a yag_ agent key.
//
// Protocol surface (minimal set): initialize (protocolVersion negotiation +
// stateless signed session), tools/list (grant- and policy-filtered catalog
// from the mcpagg aggregator, cursor pagination), tools/call (proxied into
// the existing mcpagg invoke path with its FULL guard chain via Backend),
// ping, and the notifications/initialized + notifications/cancelled
// notifications. Responses are application/json, or text/event-stream when
// the client accepts only SSE (the spec allows either).
//
// Security posture is inherited, not re-implemented: auth and rate limiting
// are gateway middleware in front of the handler; tools/call re-enters
// mcpagg.Proxy.Invoke (toolpolicy guards, MC-2 credentials, SSRF re-check,
// audit); upstream egress stays bound to the registered allow-listed
// servers. The handler adds only transport-level defenses: bounded body
// size, bounded JSON depth, HMAC-signed expiring session ids, and strict
// JSON-RPC error handling (-32700/-32600/-32601/-32602).
package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Principal is the verified caller identity the gateway resolved from the
// agent key. It mirrors mcpagg.Identity — values come from gateway-set
// headers (client copies are stripped at ingress), never from the request
// body or client-controlled fields.
type Principal struct {
	OrgID     string
	AgentID   string
	TeamID    string
	AgentName string
	RequestID string
	TaskID    string
}

// ToolDesc is one catalog entry of tools/list (an MCP Tool object). The
// InputSchema is the upstream's JSON Schema for the arguments object.
type ToolDesc struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ToolPage is one page of the tools/list catalog.
type ToolPage struct {
	Tools      []ToolDesc `json:"tools"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

// ToolCallError is a structured tools/call failure that must surface as a
// JSON-RPC error object. Code uses the gateway error-code vocabulary
// (mcpagg.ErrCode* plus mcp_auth_required) so agents can branch on the same
// codes the invoke API documents; Kind/URL carry the MC-3 lazy-authorization
// flow pointer for mcp_auth_required.
type ToolCallError struct {
	Code    string
	Message string
	Kind    string
	URL     string
}

// Error implements error.
func (e *ToolCallError) Error() string { return e.Code + ": " + e.Message }

// Backend is the gateway-provided surface behind the protocol server. The
// gateway wires it to the mcpagg aggregator (grants + policy + proxy); the
// protocol layer depends only on this interface.
type Backend interface {
	// Tools returns the full grant- and policy-filtered tool catalog for the
	// principal, in a stable order (the protocol layer paginates it). A
	// per-server discovery failure is absorbed inside the backend (that
	// server is skipped) — a total failure returns an error.
	Tools(ctx context.Context, p Principal) ([]ToolDesc, error)

	// Call invokes one tool by its flat catalog name ("server:tool")
	// through the full invoke guard chain. A *ToolCallError surfaces as the
	// JSON-RPC error data; other errors are internal (-32603).
	Call(ctx context.Context, p Principal, name string, args json.RawMessage) (json.RawMessage, error)
}

// PrincipalError is an auth-layer rejection: the handler renders it as a
// plain HTTP error BEFORE any JSON-RPC parsing (auth is transport-level,
// mirroring the invoke endpoint's 401/403 behavior).
type PrincipalError struct {
	Status  int
	Code    string
	Message string
}

// Error implements error.
func (e *PrincipalError) Error() string { return e.Code + ": " + e.Message }

// Config holds the protocol server settings. Zero values mean the defaults
// documented per field.
type Config struct {
	// ServerName is serverInfo.name in the initialize result (default
	// "yabanin-mcp-gateway").
	ServerName string
	// ServerVersion is serverInfo.version (default "1.0.0").
	ServerVersion string
	// MaxBodyBytes caps the JSON-RPC request body (default 1 MiB).
	MaxBodyBytes int64
	// MaxJSONDepth caps JSON nesting depth (default 64; 0 = default).
	MaxJSONDepth int
	// SessionTTL is the lifetime of the Mcp-Session-Id issued at initialize
	// (default 12h).
	SessionTTL time.Duration
	// PageSize is the tools/list page size (default 100).
	PageSize int
	// Principal resolves the verified caller from the request. When nil the
	// default gateway header reader is used (X-Org-Id / X-Agent-Id, as set
	// by the auth middleware). A *PrincipalError return aborts with its
	// HTTP status before parsing.
	Principal func(*http.Request) (Principal, error)
}
