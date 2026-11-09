// OP-6: invoke-path guardrails on the Engine. GuardArgs is the pre-egress
// check (deny decision + args rules: schema / max-size / deny_regex) and
// GuardResult the post-egress check (secrets + deny_regex per the rule's
// flag/mask/deny mode). Both compose UNION + MOST-RESTRICTIVE across every
// matching enabled policy (see the rules.go composition decisions) and are
// value-free in every finding and reason (security invariant: no matched
// secret material ever leaves this package).
//
// The deny DECISION (Engine.DecideTool winner) is evaluated as part of
// GuardArgs so the MCP invoke path pays ONE cached lookup for both.
package toolpolicy

import (
	"context"
	"encoding/json"
	"fmt"
)

// GuardArgs is the pre-egress args guard for one MCP tool call. Evaluation
// order: the deny winner (DecideTool), then every matching policy's args
// rules in stable name order — findings accumulate, the first deny
// short-circuits (pipeline-engine parity). Loader outages follow the org's
// sticky posture: any fail-closed rule ⇒ deny; otherwise the call proceeds
// unguarded with Degraded set (count it as an error, never as an allow).
func (e *Engine) GuardArgs(ctx context.Context, orgID, subject, server, tool string, args json.RawMessage) ArgsReport {
	cached, degraded := e.guardLoad(ctx, orgID)
	if degraded {
		if e.guardPosture(orgID) {
			return ArgsReport{Denied: true,
				Reason: "tool policy unavailable; org guard posture is fail-closed",
				Findings: []Finding{{Source: "posture", Category: "policy_unavailable",
					Span: "", Action: "deny"}}}
		}
		return ArgsReport{Degraded: true}
	}
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	// The deny winner first: a plain deny row (no rules) blocks with its
	// policy name before any args check runs.
	if d := e.decideWinner(cached, subject, server, tool); d.Action == ActionDeny {
		return ArgsReport{Denied: true,
			Reason: fmt.Sprintf("tool %q denied by policy %q", tool, d.Policy.Name),
			Findings: []Finding{{Source: "decision", Category: "policy_deny",
				Span: d.Matched, Action: "deny"}}}
	}
	var rep ArgsReport
	for i := range cached.policies {
		p := &cached.policies[i]
		if !p.Enabled || len(p.Rules) == 0 {
			continue
		}
		if p.Subject != "*" && p.Subject != subject {
			continue
		}
		if !matches(p.Server, server) || !matches(p.Tool, tool) {
			continue
		}
		cr := cached.compiled[i]
		if cr.rules == nil {
			if cr.err != nil {
				// A rule row that failed to compile is unenforceable —
				// fail closed on that row (admin writes are validated;
				// this is defense in depth for out-of-band edits).
				rep.Denied = true
				rep.Reason = fmt.Sprintf("policy %q has uncompilable guard rules; failing closed", p.Name)
				rep.Findings = append(rep.Findings, Finding{Source: "posture",
					Category: "rules_uncompilable", Span: "", Action: "deny"})
				return rep
			}
			continue
		}
		arg := cr.rules.CheckArgs(args)
		if arg.Denied {
			rep.Denied = true
			rep.Reason = fmt.Sprintf("policy %q: %s", p.Name, arg.Reason)
			rep.Findings = append(rep.Findings, arg.Findings...)
			return rep
		}
	}
	return rep
}

// GuardDeclaredArgs is the CHAT-surface args guard for a model-declared
// (server = "*" — server-qualified rows are MCP-invoke-scoped, Decide
// parity). The deny winner and the union args rules apply; a deny means the
// declared call must not reach the client-side executor. Loader outages
// follow the org's sticky posture: fail-closed ⇒ deny, fail-open ⇒ Degraded
// (the response surface treats Degraded as pass-through — its pinned
// fail-open outage posture — and counts it as an error, never an allow).
func (e *Engine) GuardDeclaredArgs(ctx context.Context, orgID, subject, tool string, args json.RawMessage) ArgsReport {
	return e.GuardArgs(ctx, orgID, subject, "*", tool, args)
}

// GuardResult post-checks the serialized upstream tool result. Matching
// policies' result rules apply in stable name order; each observes the
// previous rule's output (mask composes), the first deny short-circuits,
// and the verdict is the most restrictive action seen (flag < mask < deny).
// A loader outage follows GuardArgs posture semantics (deny when the org
// posture is fail-closed, else Degraded with no action).
func (e *Engine) GuardResult(ctx context.Context, orgID, subject, server, tool string, result json.RawMessage) ResultReport {
	cached, degraded := e.guardLoad(ctx, orgID)
	if degraded {
		if e.guardPosture(orgID) {
			return ResultReport{Action: ResultDeny,
				Reason: "tool policy unavailable; org guard posture is fail-closed",
				Findings: []Finding{{Source: "posture", Category: "policy_unavailable",
					Span: "", Action: "deny"}}}
		}
		return ResultReport{Degraded: true}
	}
	composed := ResultReport{}
	for i := range cached.policies {
		p := &cached.policies[i]
		if !p.Enabled || len(p.Rules) == 0 {
			continue
		}
		if p.Subject != "*" && p.Subject != subject {
			continue
		}
		if !matches(p.Server, server) || !matches(p.Tool, tool) {
			continue
		}
		cr := cached.compiled[i]
		if cr.rules == nil {
			if cr.err != nil {
				composed.Action = ResultDeny
				composed.Reason = fmt.Sprintf("policy %q has uncompilable guard rules; failing closed", p.Name)
				composed.Findings = append(composed.Findings, Finding{Source: "posture",
					Category: "rules_uncompilable", Span: "", Action: "deny"})
				return composed
			}
			continue
		}
		// Sequential fold: a masking rule rewrites the text the next rule
		// observes (spans of later rules refer to the latest text).
		input := result
		if composed.Action == ResultMask && composed.Masked != nil {
			input = composed.Masked
		}
		rep := cr.rules.CheckResult(input)
		if rep.Action == "" {
			continue
		}
		if rep.Action.Rank() >= composed.Action.Rank() {
			composed.Action = rep.Action
			composed.Reason = fmt.Sprintf("policy %q: %s", p.Name, rep.Reason)
			if rep.Masked != nil {
				composed.Masked = rep.Masked
			}
		}
		composed.Findings = append(composed.Findings, rep.Findings...)
		if composed.Action == ResultDeny {
			return composed
		}
	}
	return composed
}

// decideWinner resolves the deny/allow winner over already-loaded rows
// (GuardArgs parity with DecideTool, without a second cache pass).
func (e *Engine) decideWinner(cached *cachedPolicies, subject, server, tool string) Decision {
	best := Decision{Action: ActionAllow}
	ranked := false
	for i := range cached.policies {
		p := cached.policies[i]
		if !p.Enabled {
			continue
		}
		if p.Subject != "*" && p.Subject != subject {
			continue
		}
		if !matches(p.Server, server) || !matches(p.Tool, tool) {
			continue
		}
		if !ranked || betterThan(&p, best.Policy, subject, server, tool) {
			best = Decision{Action: p.Action, Policy: &p, Matched: p.Tool}
			ranked = true
		}
	}
	return best
}

// guardLoad fetches the cached rows and reports whether the load failed
// (degraded — the caller applies the org posture).
func (e *Engine) guardLoad(ctx context.Context, orgID string) (*cachedPolicies, bool) {
	cached, err := e.load(ctx, orgID)
	if err != nil {
		return nil, true
	}
	return cached, false
}
