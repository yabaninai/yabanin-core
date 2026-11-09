package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MCP-05 observability: counters for the MCP aggregator proxy's tool calls.

// MCPCallsTotal counts every tool invocation the proxy handles, labelled by
// the server, the tool, and the outcome. Outcome is one of the mcpagg.Outcome*
// constants: ok, denied, upstream_error, timeout, ssrf_blocked, not_found,
// disabled, auth_required. It is incremented by the proxy after each call
// (success or failure), so operators can see per-server/tool error rates
// without the audit trail. Label cardinality is bounded: server/tool are
// org-registered names (small, operator-controlled) and outcome is a fixed
// enum.
var MCPCallsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "",
		Subsystem: subsystem,
		Name:      "mcp_calls_total",
		Help:      "Total MCP tool invocations by server, tool and outcome.",
	},
	[]string{"server", "tool", "outcome"},
)

// MCPCredsTotal counts MCP credential resolver decisions (MC-2), labelled by
// the server, the credential kind (headers/oauth, "-" when no credential
// exists) and the outcome: hit (a credential resolved and was applied),
// miss (no usable credential — the caller gets mcp_auth_required when the
// upstream rejects), refresh (a force-refresh produced a retry) and error
// (resolution or refresh infrastructure failure). Label cardinality is
// bounded: server is an org-registered name, kind and outcome are fixed
// enums. No secret material is ever a label.
var MCPCredsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "",
		Subsystem: subsystem,
		Name:      "mcp_creds_total",
		Help:      "MCP credential resolver decisions by server, kind and outcome (hit/miss/refresh/error).",
	},
	[]string{"server", "kind", "outcome"},
)

// MCPCredModeTotal counts N05-P02-T04 credential-mode policy enforcement
// decisions, labelled by the server, the policy-selected mode
// (service/delegated; "-" when the selector failed before producing a valid
// mode) and the outcome: allow (the resolved credential layer satisfied the
// pin), deny (the resolved or refreshed credential layer violated the pin —
// the call refused BEFORE egress, no silent layer switch) and error
// (fail-closed refusal on an unverifiable state: selector failure, unknown
// mode, or a credential source that cannot report its layer). Label
// cardinality is bounded: server is an org-registered name, mode and
// outcome are fixed enums. No secret material is ever a label.
var MCPCredModeTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "",
		Subsystem: subsystem,
		Name:      "mcp_credmode_total",
		Help:      "MCP credential-mode policy enforcement decisions by server, mode and outcome (allow/deny/error).",
	},
	[]string{"server", "mode", "outcome"},
)

var mcpCollectors = []prometheus.Collector{
	MCPCallsTotal,
	MCPCredsTotal,
	MCPCredModeTotal,
}

func init() {
	allCollectors = append(allCollectors, mcpCollectors...)
}
