package mcp

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// httpServeMux is a dedicated ServeMux for the MCP SSE endpoints.
// Using a dedicated mux (instead of the global DefaultServeMux) prevents
// duplicate-pattern panics on re-init and keeps handlers isolated from
// any other code that registers on the process-global mux.
var httpServeMux = http.NewServeMux()

// NewMCPHandler creates an MCP server with the partner tools:
//   - tr_route: route a prompt through the gateway
//   - tr_spend_report: fetch cost analytics for an org
//   - tr_set_policy: update routing policy for an org
//   - tr_lineage_verify: verify lineage attestation for a request ID
//   - tr_delegate / tr_delegation_status: optional, only when enabled
func NewMCPHandler(client *GatewayClient) *server.MCPServer {
	return NewMCPHandlerWithDelegation(client, DelegationFromEnv())
}

// NewMCPHandlerWithDelegation is the testable constructor. When dep is nil or
// disabled, tr_delegate is not registered and no orchestrator is constructed
// by this function.
func NewMCPHandlerWithDelegation(client *GatewayClient, dep *DelegationOptions) *server.MCPServer {
	s := server.NewMCPServer("yabanin-mcp", "0.1.0")

	s.AddTool(mcp.Tool{
		Name:        "tr_route",
		Description: "Route a prompt through the Yabanin gateway with cost-aware model selection.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]any{
				"model":  map[string]string{"type": "string", "description": "Model name to route"},
				"prompt": map[string]string{"type": "string", "description": "The user prompt to send"},
			},
			Required: []string{"model", "prompt"},
		},
	}, handleRoute(client))

	s.AddTool(mcp.Tool{
		Name:        "tr_spend_report",
		Description: "Fetch cost analytics for an organization over the last N days.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]any{
				"org_id": map[string]string{"type": "string"},
				"days":   map[string]any{"type": "number", "default": 7},
			},
			Required: []string{"org_id"},
		},
	}, handleSpendReport(client))

	s.AddTool(mcp.Tool{
		Name:        "tr_set_policy",
		Description: "Update the routing policy for an organization.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]any{
				"org_id":    map[string]string{"type": "string"},
				"mode":      map[string]string{"type": "string"},
				"threshold": map[string]any{"type": "number", "default": 0.5},
			},
			Required: []string{"org_id", "mode"},
		},
	}, handleSetPolicy(client))

	s.AddTool(mcp.Tool{
		Name:        "tr_lineage_verify",
		Description: "Verify the jurisdictional lineage attestation for a request ID.",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]any{
				"request_id": map[string]string{"type": "string"},
			},
			Required: []string{"request_id"},
		},
	}, handleLineageVerify(client))

	if dep != nil && dep.Enabled && dep.Orchestrator != nil {
		s.AddTool(mcp.Tool{
			Name:        "tr_delegate",
			Description: "Delegate a coding task to a Yabanin-managed Codex or Cursor agent. Use analyze for read-only review and implement for workspace writes. provider is auto, codex, or cursor.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"task":     map[string]string{"type": "string", "description": "Task for the delegated agent"},
					"mode":     map[string]string{"type": "string", "description": "analyze or implement"},
					"provider": map[string]string{"type": "string", "description": "auto, codex, or cursor"},
				},
				Required: []string{"task"},
			},
		}, handleDelegate(dep.Orchestrator))
		s.AddTool(mcp.Tool{
			Name:        "tr_delegation_status",
			Description: "Show whether Codex and Cursor subscription executors are available. Does not return credentials.",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]any{},
			},
		}, handleDelegationStatus(dep.Orchestrator))
	}

	return s
}

// ServeStdio starts the MCP server over stdio (Claude Code).
func ServeStdio(client *GatewayClient) error {
	s := NewMCPHandler(client)
	return server.ServeStdio(s)
}

// HandlerSSE returns the MCP server for HTTP-SSE transport.
// Callers should wrap it with an appropriate SSE handler (e.g., from mcp-go).
func HandlerSSE(client *GatewayClient) *server.MCPServer {
	return NewMCPHandler(client)
}

// ServeHTTP creates an SSE MCP server and serves it on the given address.
// It blocks until the server is shut down (or a context timeout, if provided).
func ServeHTTP(client *GatewayClient, addr string) error {
	mcpServer := NewMCPHandler(client)
	sseSrv := server.NewSSEServer(mcpServer,
		server.WithBaseURL("http://"+addr),
		server.WithSSEDisableLocalhostProtection(true),
	)

	httpServeMux.HandleFunc(sseSrv.CompleteSsePath(), sseSrv.SSEHandler().ServeHTTP)
	httpServeMux.HandleFunc(sseSrv.CompleteMessagePath(), sseSrv.MessageHandler().ServeHTTP)

	srv, err := newMCPSSEHTTPServer(addr, httpServeMux)
	if err != nil {
		return err
	}
	return srv.ListenAndServe()
}

// Default/ceiling for the aggregate request-header cap — mirrors
// services/run's adminMaxHeaderBytes and pkg/gateway's gatewayMaxHeaderBytes
// (both helpers are unexported; keep the semantics identical so a future
// consolidation stays behavior-neutral). Invalid overrides fail startup
// rather than silently weakening configuration.
const (
	defaultMCPMaxHeaderBytes = 1 << 20
	maxMCPMaxHeaderBytes     = 16 << 20
)

// mcpMaxHeaderBytes resolves the YABANIN_HTTP_MAX_HEADER_BYTES aggregate
// request-header override shared across every HTTP listener.
func mcpMaxHeaderBytes() (int, error) {
	if raw := strings.TrimSpace(os.Getenv("YABANIN_HTTP_MAX_HEADER_BYTES")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("YABANIN_HTTP_MAX_HEADER_BYTES must be an integer: %w", err)
		}
		if n <= 0 || n > maxMCPMaxHeaderBytes {
			return 0, fmt.Errorf("YABANIN_HTTP_MAX_HEADER_BYTES must be between 1 and %d bytes", maxMCPMaxHeaderBytes)
		}
		return n, nil
	}
	return defaultMCPMaxHeaderBytes, nil
}

// newMCPSSEHTTPServer builds the MCP SSE listener with the gateway deadline
// posture (N01-P06 remainder closure: this listener previously carried
// ReadHeaderTimeout only):
//   - ReadHeaderTimeout 10s / ReadTimeout 15s: the SSE GET and the JSON-RPC
//     POST /messages both have bounded request reads (small bodies). ReadTimeout
//     does NOT truncate the long-lived SSE response — net/http clears the
//     connection read deadline once the (empty) request body is consumed, so
//     the deadline only bounds reading the request, never the stream
//     (pinned empirically on go1.27.3 and by TestSSEStreamSurvivesReadTimeout);
//   - WriteTimeout 0 (no deadline): the SSE endpoint streams indefinitely
//     until the client disconnects — a write deadline would truncate streams,
//     exactly as documented on the gateway main listener (gateway precedent:
//     streaming surfaces keep WriteTimeout disabled; per-request deadlines
//     are the streaming contract's bound);
//   - IdleTimeout 60s: keep-alive connections idle no longer than the
//     gateway/admin posture; in-use SSE connections are unaffected;
//   - MaxHeaderBytes: the shared YABANIN_HTTP_MAX_HEADER_BYTES aggregate cap,
//     failing construction on invalid overrides (fail-closed).
func newMCPSSEHTTPServer(addr string, handler http.Handler) (*http.Server, error) {
	maxHeaderBytes, err := mcpMaxHeaderBytes()
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		// WriteTimeout=0 — SSE streams must not be truncated (see above).
		WriteTimeout:   0,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: maxHeaderBytes,
	}, nil
}
