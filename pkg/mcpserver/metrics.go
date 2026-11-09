package mcpserver

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Tool-call outcomes are already counted by the shared invoke path
// (gateway_mcp_calls_total + audit trail); these counters cover the
// protocol surface itself (initialize/tools/list/notifications), which the
// invoke path never sees.

// mcpSessionsTotal counts session lifecycle events: created (an initialize
// handshake completed), cancelled (a client DELETE terminated a live
// session) and rejected (a presented Mcp-Session-Id failed validation —
// forged, stale after a restart, expired, or already cancelled).
var mcpSessionsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gateway_mcpserver_sessions_total",
		Help: "Native MCP endpoint session events by outcome (created/cancelled/rejected).",
	},
	[]string{"outcome"},
)

// mcpRequestsTotal counts protocol requests by JSON-RPC method (or the
// pseudo-methods "auth", "parse_error", "unknown") and outcome: ok,
// protocol_error, unauthorized, internal.
var mcpRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gateway_mcpserver_requests_total",
		Help: "Native MCP endpoint JSON-RPC requests by method and outcome.",
	},
	[]string{"method", "outcome"},
)

func countSession(outcome string) { mcpSessionsTotal.WithLabelValues(outcome).Inc() }
func countRequest(method, outcome string) {
	mcpRequestsTotal.WithLabelValues(method, outcome).Inc()
}
