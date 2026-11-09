package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// OP-6 tool-call guardrails: one decision counter for the toolpolicy
// guard evaluation on the MCP invoke path (pre-egress args guards and
// post-egress result checks). The allow/deny winner decisions of the
// chat-path tool gate keep their dedicated ToolPolicyDeniedTotal.

// ToolpolicyDecisionsTotal counts one toolpolicy guard decision, labelled
// by the org, the MCP server, the tool and the outcome: allow (no rule
// matched / all passed), deny (blocked, the call or the result), mask
// (proceeded with a redacted result), flag (proceeded, observation
// recorded) and error (the policy loader was unavailable and the org
// posture is fail-open — the call ran UNGUARDED). Org is a uuid: one
// series per org, bounded by the org count; server/tool are
// org-registered names (small, operator-controlled); outcome is a fixed
// enum. No secret material or payload content is ever a label.
var ToolpolicyDecisionsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "",
		Subsystem: subsystem,
		Name:      "toolpolicy_decisions_total",
		Help:      "Toolpolicy guard decisions by org, server, tool and outcome (allow/deny/mask/flag/error).",
	},
	[]string{"org", "server", "tool", "outcome"},
)

var toolpolicyCollectors = []prometheus.Collector{
	ToolpolicyDecisionsTotal,
}

func init() {
	allCollectors = append(allCollectors, toolpolicyCollectors...)
}
