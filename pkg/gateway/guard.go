package cli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// guardHook resolves the CURRENT enforce hook for one request (audit CA-02 /
// card FIX-03): the hook must never be captured once at startup, or an
// already-running replica keeps enforcing a superseded version after an
// activation. Resolution order:
//  1. the runtime watcher's atomic snapshot when durable-version adoption is
//     wired (one atomic load; the watcher is the single runtime writer);
//  2. the startup lifecycle read live — ActiveHook is RLock-guarded and the
//     lifecycle supports concurrent readers, so a same-process
//     Activate/Rollback is visible to the next request (C1);
//  3. the construction-time built-in hook (mode off / no packs configured —
//     immutable after startup).
//
// Hook values are immutable and safe for concurrent Apply, so every request
// enforces exactly one valid version — never torn state between versions.
func (gw *gateway) guardHook() *guardhooks.Hook {
	if gw.guardWatch != nil {
		if h := gw.guardWatch.currentHook(); h != nil {
			return h
		}
	}
	if gw.guardLifecycle != nil {
		return gw.guardLifecycle.ActiveHook()
	}
	return gw.guardHooks
}

// applyEgressGuards runs the pre-egress guard hooks over the request body that
// is about to be forwarded upstream (card U1). It is a no-op when the hooks are
// disabled (mode off) or unset.
//
// Returns the (possibly redacted) body to forward and a non-nil error when the
// active mode is deny and a sensitive category was detected — the caller writes
// a 400 and does not forward. Metrics (GuardHooksTotal) are recorded for every
// detection in log/redact/deny modes. The hook is resolved per request via
// guardHook so runtime activations are enforced without a restart.
func (gw *gateway) applyEgressGuards(body []byte) ([]byte, error) {
	h := gw.guardHook()
	if h == nil || !h.Enabled() {
		return body, nil
	}
	text := string(body)
	// The policy runtime is the authority on shadow vs enforce. In shadow the
	// gateway downgrades every guard verdict — detection or failure — to an
	// audit-only event and forwards the body unchanged; the hook's own mode
	// stays a construction detail, never a second source of truth.
	if gw.guardPolicyIsShadow() {
		_, hits, applyErr := h.Apply(text)
		detectorFailure := hasDetectorFailure(hits)
		if len(hits) > 0 && !detectorFailure && (applyErr == nil || errors.Is(applyErr, guardhooks.ErrDenied)) {
			gw.guardDetectionAudit("egress", hits)
		}
		// Every detector failure must audit even when the hook's mode converts
		// the failure into a non-error result (log mode returns err == nil with
		// a detector-failure hit), otherwise a shadow + log-mode hook would
		// evaluate and stay silent.
		if detectorFailure || (applyErr != nil && !errors.Is(applyErr, guardhooks.ErrDenied)) {
			gw.guardFailureAudit("egress", guardhooks.VerdictAuditOnly)
		}
		return body, nil
	}
	mutated, hits, applyErr := h.Apply(text)
	if applyErr != nil && !errors.Is(applyErr, guardhooks.ErrDenied) {
		verdict, blocked := guardhooks.FailureOutcome(gw.guardFailureMode(), applyErr)
		gw.guardFailureAudit("egress", verdict)
		if !blocked {
			return body, nil
		}
		return nil, applyErr
	}
	if len(hits) == 0 {
		return body, nil
	}
	for _, hit := range hits {
		metrics.GuardHooksTotal.WithLabelValues(
			string(h.Mode()),
			string(hit.Category),
			string(hit.Outcome),
		).Inc()
	}
	gw.log.Info("guard hook detection",
		"mode", string(h.Mode()),
		"categories", categoryList(hits),
	)
	if applyErr != nil {
		return nil, applyErr
	}
	if mutated != nil {
		return mutated, nil
	}
	return body, nil
}

// categoryList renders hits as "cat(outcome), ..." for the log line.
func categoryList(hits []guardhooks.Hit) string {
	out := make([]string, 0, len(hits))
	for _, hit := range hits {
		out = append(out, string(hit.Category)+":"+string(hit.Outcome))
	}
	return joinStrings(out, ", ")
}

// joinStrings is a tiny local join to avoid importing strings for one line.
func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	var b bytes.Buffer
	for i, p := range parts {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(p)
	}
	return b.String()
}

// mcpParamGuard is the MCP-06 pre-egress guard for tool-call params. It
// adapts the gateway's guard hooks (the same mode/metrics/logging used on the
// chat path) to the mcpagg.Hook interface the proxy calls before forwarding.
//
// It resolves the hook per Scan via gw.guardHook — the same live resolution
// as the chat egress path — so runtime pack activations apply to MCP tool
// params too, regardless of the init order in buildGateway. When the hooks
// are disabled (mode off / nil) it passes params through untouched (mode
// "off") — the proxy then sends them as-is.
type mcpParamGuard struct {
	gw *gateway
}

// Scan implements mcpagg.Hook. params is the raw tool arguments (JSON). It
// returns the (possibly redacted) params to forward, a non-empty denyReason
// when the active mode is deny and a category was detected (the proxy drops the
// call with a 409 denied), and the mode that applied.
func (g *mcpParamGuard) Scan(_ context.Context, params []byte) ([]byte, string, string) {
	h := g.gw.guardHook()
	if h == nil || !h.Enabled() {
		// off / unset: pass through untouched.
		return params, "", string(guardhooks.ModeOff)
	}
	text := string(params)
	if g.gw.guardPolicyIsShadow() {
		_, hits, err := h.Apply(text)
		detectorFailure := hasDetectorFailure(hits)
		if len(hits) > 0 && !detectorFailure && (err == nil || errors.Is(err, guardhooks.ErrDenied)) {
			g.gw.guardDetectionAudit("mcp_tool_params", hits)
		}
		// Same rule as the egress shadow path: detector failures audit even in
		// hook modes that report them without an error (log mode).
		if detectorFailure || (err != nil && !errors.Is(err, guardhooks.ErrDenied)) {
			g.gw.guardFailureAudit("mcp_tool_params", guardhooks.VerdictAuditOnly)
		}
		return params, "", string(guardhooks.ModeLog)
	}
	mutated, hits, applyErr := h.Apply(text)
	mode := string(h.Mode())
	if applyErr != nil && !errors.Is(applyErr, guardhooks.ErrDenied) {
		verdict, blocked := guardhooks.FailureOutcome(g.gw.guardFailureMode(), applyErr)
		g.gw.guardFailureAudit("mcp_tool_params", verdict)
		if blocked {
			return params, "mcp tool params guard evaluation failed", mode
		}
		return params, "", mode
	}
	if len(hits) == 0 {
		return params, "", mode
	}
	// Same detection metric as the chat path (shared counter, mode/category/
	// outcome) — operators see MCP param detections alongside chat ones.
	for _, hit := range hits {
		metrics.GuardHooksTotal.WithLabelValues(
			string(h.Mode()),
			string(hit.Category),
			string(hit.Outcome),
		).Inc()
	}
	g.gw.log.Info("mcp guard hook detection",
		"mode", string(h.Mode()),
		"categories", categoryList(hits),
	)
	if errors.Is(applyErr, guardhooks.ErrDenied) {
		return params, "mcp tool params denied by guard hooks (" + string(h.Mode()) + ")", mode
	}
	if applyErr != nil {
		return params, "mcp tool params guard evaluation failed", mode
	}
	if mutated != nil {
		return mutated, "", mode
	}
	return params, "", mode
}

func hasDetectorFailure(hits []guardhooks.Hit) bool {
	for _, hit := range hits {
		if hit.Category == guardhooks.CatDetectorFailure {
			return true
		}
	}
	return false
}

// guardFailureMode shares the gateway's existing shadow/enforce policy mode
// with guardhook detector failures. Unwired/unknown policy state fails closed.
// guardPolicyIsShadow reports whether the active policy runtime pins the
// shadow (audit-only) posture for guard evaluation.
func (gw *gateway) guardPolicyIsShadow() bool {
	return gw.policyRuntime != nil && gw.policyRuntime.mode == PolicyModeShadow
}

func (gw *gateway) guardFailureMode() guardhooks.FailureMode {
	if gw.policyRuntime != nil && gw.policyRuntime.mode == PolicyModeShadow {
		return guardhooks.FailureModeShadow
	}
	return guardhooks.FailureModeEnforce
}

// guardFailureAudit records only the operation and failure class, never the
// inspected content. Shadow failures are auditable but do not block traffic.
func (gw *gateway) guardFailureAudit(operation string, verdict guardhooks.Verdict) {
	l := slog.Default()
	if gw != nil && gw.log != nil {
		l = gw.log
	}
	l.Warn("guard evaluation failed", "operation", operation, "verdict", string(verdict), "failure_class", "detector_error")
}

func (gw *gateway) guardDetectionAudit(operation string, hits []guardhooks.Hit) {
	l := slog.Default()
	if gw != nil && gw.log != nil {
		l = gw.log
	}
	l.Info("guard detection (shadow)", "operation", operation, "categories", categoryList(hits))
}
