package mcpagg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/ssrf"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
	"github.com/reireirei/yabanin/pkg/tracing"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Identity is the verified agent principal the proxy forwards upstream
// (MCP-04). It comes from the gateway auth middleware (X-Agent-Id et al.,
// set from the resolved yag_ principal) — never from client-supplied values
// (those headers are stripped on ingress, docs/mcp-gateway.md §6 R6).
//
// RequestID/TaskID carry the per-request observability context so the audit
// trail (MCP-03) can join a tool call to its request_logs row and tag spend
// by task. They are set by the gateway handler, not the client.
type Identity struct {
	AgentID   string
	AgentName string
	TeamID    string
	RequestID string
	TaskID    string
}

// Hook is the pre-egress parameter guard (MCP-06). Scan receives the raw
// tool params and returns the (possibly redacted) params to send, a deny
// reason (non-empty = drop the call), and the mode that applied. When nil
// the proxy sends params untouched (mode "off").
type Hook interface {
	Scan(ctx context.Context, params []byte) (out []byte, denyReason string, mode string)
}

// ToolGuard is the OP-6 tool-call guardrail surface: pre-egress args
// guards (deny decision + schema / max-size / deny_regex) and post-egress
// result checks (secrets / regex, flag|mask|deny). Satisfied by the shared
// *toolpolicy.Engine the gateway builds once over the real policy store
// (toolpolicy.NewEngine(toolpolicy.NewStore(pool))) and attaches here via
// WithToolGuard (gateway.go); nil keeps the pre-guardrail behavior
// bit-for-bit.
//
// Implementations are VALUE-FREE: every finding and reason names the rule
// and the span/category — matched secret material never crosses this
// interface (OP-6 invariant, pinned by tests on both sides).
type ToolGuard interface {
	GuardArgs(ctx context.Context, orgID, subject, server, tool string, args json.RawMessage) toolpolicy.ArgsReport
	GuardResult(ctx context.Context, orgID, subject, server, tool string, result json.RawMessage) toolpolicy.ResultReport
}

// AuditLogger records one tool invocation (MCP-03). Called after the
// upstream response is complete (or the call was dropped pre-egress), with
// the redacted params. Implementations must not block the response path for
// long; the proxy treats a returning error as "audit dropped" and counts it.
type AuditLogger interface {
	Log(ctx context.Context, e AuditEvent) error
}

// AuditEvent is one tool invocation as recorded by the audit trail.
// ParamsRedacted carries the post-guard params (secrets/PII already
// redacted by the Hook). Outcome is one of: ok, denied, upstream_error,
// timeout, ssrf_blocked, not_found, disabled.
type AuditEvent struct {
	OrgID          string
	AgentID        string
	ServerName     string
	Tool           string
	ParamsRedacted json.RawMessage
	LatencyMS      int64
	Outcome        string
	UpstreamStatus int
	// MCP-03: per-request context for the audit trail (request_logs join +
	// task tagging) and the upstream target (logged, not the params).
	RequestID    string
	TaskID       string
	TeamID       string
	UpstreamURL  string
	ErrorMessage string
}

// Outcome labels for AuditEvent.Outcome.
const (
	OutcomeOK            = "ok"
	OutcomeDenied        = "denied"
	OutcomeUpstreamError = "upstream_error"
	OutcomeTimeout       = "timeout"
	OutcomeSSRFBlocked   = "ssrf_blocked"
	OutcomeNotFound      = "not_found"
	OutcomeDisabled      = "disabled"
	// MC-2: the call ended in the lazy-authorization error (no usable
	// credential, or the stored one was terminally rejected).
	OutcomeAuthRequired = "auth_required"
	// OP-6: the call (or its result) was blocked by the toolpolicy
	// guardrails (deny policy, args rules or a result post-check).
	OutcomeToolBlocked = "tool_blocked"
	// N05-P02-T04: the call was refused by the credential-mode policy —
	// the policy-selected mode conflicts with the resolved credential
	// layer, or the mode could not be verified (fail-closed).
	//nolint:gosec // G101 false positive: this is an audit outcome label, not a credential
	OutcomeCredMode = "cred_mode_denied"
)

// Proxy invokes tools on registered external MCP servers.
type Proxy struct {
	store *Store
	cfg   Config
	allow ssrf.AllowList
	hook  Hook
	audit AuditLogger
	// creds is the optional MC-2 credential source (nil = the legacy
	// unauthenticated posture, bit-for-bit). Wired via WithCredsSource.
	creds CredSource
	// guard is the optional OP-6 toolpolicy guardrail (nil = no guardrails,
	// the pre-guardrail behavior). Wired via WithToolGuard.
	guard ToolGuard
	// modePolicy is the optional N05-P02-T04 credential-mode selector (nil
	// = no policy, the connection-config mode governs bit-for-bit). Wired
	// via WithCredModePolicy.
	modePolicy CredModePolicy
	nowFn      func() time.Time
	// testAllowHTTP is a unit-test seam (Config.testAllowHTTP), copied at build
	testAllowHTTP bool // unit-test seam (Config.testAllowHTTP), copied at build
	// MCP-05: OTel tracer for per-tool-call spans. Sourced from the global
	// tracer provider (tracing.Tracer) so it is a no-op when tracing is not
	// initialized; overridable in tests via testTracer.
	tracer trace.Tracer
}

// WithCredsSource attaches the credential resolver (MC-2). Nil (default)
// keeps the pre-credential behavior: calls go out unauthenticated.
func (p *Proxy) WithCredsSource(cs CredSource) *Proxy {
	p.creds = cs
	return p
}

// WithToolGuard attaches the OP-6 guardrails (toolpolicy engine). Nil
// (default) keeps the pre-guardrail behavior: no deny decisions, no args
// guards, no result post-checks.
func (p *Proxy) WithToolGuard(g ToolGuard) *Proxy {
	p.guard = g
	return p
}

// WithCredModePolicy attaches the N05-P02-T04 credential-mode selector
// (the toolpolicy engine via NewToolpolicyCredModes). Nil (default) keeps
// the connection-config credential mode bit-for-bit. With a selector wired,
// every constrained call also requires a LevelAwareCredSource — a source
// that cannot report the resolved credential's layer refuses constrained
// calls fail-closed (the layer constraint must be verifiable, never
// assumed).
func (p *Proxy) WithCredModePolicy(sel CredModePolicy) *Proxy {
	p.modePolicy = sel
	return p
}

// NewProxy builds a Proxy. allow is the SSRF domain allow-list; hook and
// audit may be nil (no guarding / no audit). cfg.Client() provides the HTTP
// client. The Config value is copied, so testAllowHTTP is frozen at build.
// The OTel tracer comes from the global provider (no-op until tracing.Init).
func NewProxy(store *Store, cfg Config, allow ssrf.AllowList, hook Hook, audit AuditLogger) *Proxy {
	nowFn := time.Now
	return &Proxy{
		store: store, cfg: cfg, allow: allow, hook: hook, audit: audit,
		nowFn: nowFn, testAllowHTTP: cfg.testAllowHTTP,
		tracer: tracing.Tracer("yabanin/mcpagg"),
	}
}

// InvokeRequest is one tool invocation request (gateway API body).
type InvokeRequest struct {
	Server string          `json:"server"`
	Tool   string          `json:"tool"`
	Params json.RawMessage `json:"params"`
}

// InvokeError is the structured error the gateway handler renders as a JSON
// error response. Code maps to an HTTP status in the handler layer.
type InvokeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements error.
func (e *InvokeError) Error() string { return e.Code + ": " + e.Message }

// ErrCode labels (the handler maps them to HTTP statuses):
//   - agent_only    → 403 (the caller is not an agent-principal yag_ key;
//     MCP-03 restricts tool-calls to agent keys)
//   - not_found     → 404 (server missing/disabled, no agent grant, or tool
//     not on the effective allow-list)
//   - ssrf_blocked  → 400 (URL failed the per-invoke SSRF guard)
//   - denied        → 409 (guard hook denied the params, or the
//     N05-P02-T04 credential-mode policy refused the call: the selected
//     mode conflicts with the resolved credential layer, or the mode could
//     not be verified — fail-closed, never a silent layer switch)
//   - tool_blocked  → 400 (OP-6 toolpolicy guardrails blocked the call or
//     its result: deny policy, args rules or a result post-check)
//   - upstream      → 502 (upstream returned non-2xx or a malformed body)
//   - timeout       → 504 (upstream exceeded the read/connect timeout)
const (
	ErrCodeAgentOnly   = "agent_only"
	ErrCodeNotFound    = "not_found"
	ErrCodeSSRF        = "ssrf_blocked"
	ErrCodeDenied      = "denied"
	ErrCodeToolBlocked = "mcp_tool_blocked"
	ErrCodeUpstream    = "upstream"
	ErrCodeTimeout     = "timeout"
)

// Invoke runs one tool call against the org's registered server:
// SSRF re-check → tool allow-list → param guard → upstream JSON-RPC POST →
// audit. It returns the upstream tool result (MCP CallToolResult JSON) on
// success, or a *InvokeError on the documented failure paths.
//
// The body is a pipeline over the invokeCall stage helpers (authorize →
// chain ceiling → args guard → SSRF → hook → credential → upstream →
// result guard); each helper performs its own metrics/audit and returns
// the span outcome label alongside the error, so every path — including
// pre-egress denials — is audited and traced exactly once.
func (p *Proxy) Invoke(ctx context.Context, orgID string, id Identity, req InvokeRequest) (json.RawMessage, error) {
	start := p.nowFn()

	// MCP-05: one span per tool call. The outcome attribute is set on the
	// way out (each stage returns its outcome label); the span ends when
	// Invoke returns (defer), so every path — including pre-egress denials —
	// is traced. When tracing is not initialized the tracer is a no-op
	// (tracing.Tracer), so this costs nothing in dev / test.
	ctx, span := p.tracer.Start(ctx, "mcp.tools/call",
		trace.WithAttributes(
			attribute.String("mcp.server", req.Server),
			attribute.String("mcp.tool", req.Tool),
			attribute.String("mcp.org", orgID),
			attribute.String("mcp.agent_id", id.AgentID),
		))
	spanOutcome := OutcomeOK
	defer func() {
		span.SetAttributes(attribute.String("mcp.outcome", spanOutcome))
		span.End()
	}()

	c := &invokeCall{orgID: orgID, id: id, req: req, params: req.Params, start: start}
	if outcome, err := p.invokeAuthorize(ctx, c); err != nil {
		spanOutcome = outcome
		return nil, err
	}
	if outcome, err := p.invokeChainCheck(ctx, c); err != nil {
		spanOutcome = outcome
		return nil, err
	}
	if outcome, err := p.invokeGuardArgs(ctx, c); err != nil {
		spanOutcome = outcome
		return nil, err
	}
	if outcome, err := p.invokeSSRFCheck(ctx, c); err != nil {
		spanOutcome = outcome
		return nil, err
	}
	if outcome, err := p.invokeHookScan(ctx, c); err != nil {
		spanOutcome = outcome
		return nil, err
	}
	if outcome, err := p.invokePrepareCredential(ctx, c); err != nil {
		spanOutcome = outcome
		return nil, err
	}

	// 401/403 with a credential applied gets exactly ONE force-refresh +
	// retry round inside invokeUpstream (oauth); a terminally rejected
	// credential surfaces as mcp_auth_required (MC-3 flows).
	result, status, callErr := p.invokeUpstream(ctx, c)
	latency := p.nowFn().Sub(start).Milliseconds()
	if callErr != nil {
		var err error
		spanOutcome, err = p.invokeCallFailure(ctx, c, callErr, status, latency)
		return nil, err
	}

	result, outcome, err := p.invokeGuardResult(ctx, c, result, status, latency)
	if err != nil {
		spanOutcome = outcome
		return nil, err
	}

	p.auditDone(ctx, orgID, id, c.srv.Name, req.Tool, c.params, OutcomeOK, status, latency, start, c.srv.URL)
	return result, nil
}

// invokeCall carries one tool call's state through the Invoke stage
// helpers. Invariants: params starts as the raw request params and is
// defaulted to {} at the args-guard stage (before that the chain audits
// carry the raw value — auditDone normalizes empty to {} itself); the hook
// stage REPLACES it with the redacted value, which is then what egresses
// AND what every later audit records. Credential lookups key on the
// REQUESTED server name (c.req.Server, the legacy contract); audit and
// metrics label on the resolved row (c.srv).
type invokeCall struct {
	orgID  string
	id     Identity
	req    InvokeRequest
	srv    *Server
	params json.RawMessage
	start  time.Time

	credHeaders map[string][]string
	credKind    string
	credMode    string
}

// invokeAuthorize runs the four-dimension grant check (subject / server /
// action / tool). MCP-03: tool-calls are agent-key-only (the identity comes
// from the gateway auth middleware; the inbound header is stripped on
// ingress, auth.go, so it cannot be client-spoofed). Revoking the grant
// stops ALL dependent access here — the credential stages never run
// without it. A refusal audits with the refusal's own server coordinates
// (both empty on the earliest denials, where the server was never
// resolved); a store error stays a plain wrapped error with no audit.
func (p *Proxy) invokeAuthorize(ctx context.Context, c *invokeCall) (string, error) {
	srv, _, refusal, err := p.authorizeGrant(ctx, c.orgID, c.id, c.req.Server, c.req.Tool, GrantActionInvoke)
	if err != nil {
		return OutcomeUpstreamError, err // store/DB error, not a documented InvokeError
	}
	if refusal != nil {
		p.auditDone(ctx, c.orgID, c.id, refusal.serverName, c.req.Tool, c.req.Params,
			refusal.outcome, 0, 0, c.start, refusal.serverURL)
		return refusal.outcome, refusal.err
	}
	c.srv = srv
	return "", nil
}

// invokeChainCheck enforces the AUTH-02 chain-wide tool ceiling: the agent
// AND every ancestor in its delegation chain must hold an enabled grant on
// this server, and the requested tool must pass the chain-wide allowance —
// the parent's scope applies at invoke time even if the child's stored
// grant predates a parent narrowing. No chain access is indistinguishable
// from "server unavailable" to the caller (not_found) — an agent cannot
// enumerate which of its requests are grant-blocked vs. server-blocked.
func (p *Proxy) invokeChainCheck(ctx context.Context, c *invokeCall) (string, error) {
	allowance, err := p.store.DelegationChainAllowance(ctx, c.orgID, c.id.AgentID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			p.auditDone(ctx, c.orgID, c.id, c.srv.Name, c.req.Tool, c.req.Params,
				OutcomeNotFound, 0, 0, c.start, c.srv.URL)
			return OutcomeNotFound, &InvokeError{Code: ErrCodeNotFound,
				Message: fmt.Sprintf("mcp server %q is not available for this org", c.req.Server)}
		}
		return OutcomeUpstreamError, fmt.Errorf("mcpagg: lookup delegation chain allowance: %w", err)
	}
	// Either side of the allowance empty means "all of that side".
	if !allowance.Allows(c.req.Server, c.req.Tool) {
		p.auditDone(ctx, c.orgID, c.id, c.srv.Name, c.req.Tool, c.req.Params,
			OutcomeNotFound, 0, 0, c.start, c.srv.URL)
		return OutcomeNotFound, &InvokeError{Code: ErrCodeNotFound,
			Message: fmt.Sprintf("tool %q is not allowed on mcp server %q", c.req.Tool, c.req.Server)}
	}
	return "", nil
}

// invokeGuardArgs runs the OP-6 toolpolicy guardrails, pre-egress: the
// server-aware deny decision plus the org's args rules (JSON-schema /
// max-size / deny_regex) over the params (defaulted to {} first). It runs
// BEFORE any network work — the SSRF re-check then saves its DNS work when
// the call is policy-blocked anyway. A deny surfaces as mcp_tool_blocked
// (400); a loader outage follows the org posture inside the guard
// (fail-closed ⇒ deny, fail-open ⇒ Degraded, counted as an error decision,
// never as an allow).
func (p *Proxy) invokeGuardArgs(ctx context.Context, c *invokeCall) (string, error) {
	if len(c.params) == 0 {
		c.params = json.RawMessage(`{}`)
	}
	if p.guard == nil {
		return "", nil
	}
	rep := p.guard.GuardArgs(ctx, c.orgID, c.id.AgentID, c.srv.Name, c.req.Tool, c.params)
	switch {
	case rep.Degraded:
		p.metricToolPolicy(c.orgID, c.srv.Name, c.req.Tool, "error")
	case rep.Denied:
		p.metricToolPolicy(c.orgID, c.srv.Name, c.req.Tool, "deny")
		p.auditDone(ctx, c.orgID, c.id, c.srv.Name, c.req.Tool, c.params,
			OutcomeToolBlocked, 0, 0, c.start, c.srv.URL)
		return OutcomeToolBlocked, &InvokeError{Code: ErrCodeToolBlocked, Message: rep.Reason}
	default:
		p.metricToolPolicy(c.orgID, c.srv.Name, c.req.Tool, "allow")
	}
	return "", nil
}

// invokeSSRFCheck is the SSRF guard, second layer (rebind window —
// docs/mcp-gateway.md R1).
func (p *Proxy) invokeSSRFCheck(ctx context.Context, c *invokeCall) (string, error) {
	// p.testAllowHTTP is the unit-test seam for httptest loopback upstreams
	// (production never sets it — see Config.testAllowHTTP). The full guard
	// is pinned in validate_test.go; the proxy logic is the subject of the
	// proxy tests.
	if p.testAllowHTTP {
		return "", nil
	}
	if err := ValidateURLAtInvoke(c.srv.URL, p.allow, false); err != nil { //nolint:contextcheck // SSRF guard runs on a bounded background ctx (QG2-D3 threads request ctx)
		p.auditDone(ctx, c.orgID, c.id, c.srv.Name, c.req.Tool, c.params,
			OutcomeSSRFBlocked, 0, 0, c.start, c.srv.URL)
		return OutcomeSSRFBlocked, &InvokeError{Code: ErrCodeSSRF, Message: err.Error()}
	}
	return "", nil
}

// invokeHookScan runs the pre-egress param guard (MCP-06). The guard may
// redact params (they are then what egress AND what the audit records) or
// deny the call with a reason.
func (p *Proxy) invokeHookScan(ctx context.Context, c *invokeCall) (string, error) {
	denyReason := ""
	if p.hook != nil {
		c.params, denyReason, _ = p.hook.Scan(ctx, c.params)
	}
	if denyReason != "" {
		p.auditDone(ctx, c.orgID, c.id, c.srv.Name, c.req.Tool, c.params,
			OutcomeDenied, 0, 0, c.start, c.srv.URL)
		return OutcomeDenied, &InvokeError{Code: ErrCodeDenied, Message: denyReason}
	}
	return "", nil
}

// invokePrepareCredential selects the policy credential mode (N05-P02-T04)
// and resolves the outbound credential (MC-2). Under a constrained mode the
// source must be level-aware and the resolved layer must match the pin — a
// mismatch refuses BEFORE egress: a delegated pin never silently runs on
// the org's (stronger) service credential and a service pin never leaks
// the org credential under a user identity. Miss (no credential) = the
// legacy unauthenticated posture; the upstream verdict decides
// (mcp_auth_required on 401/403). An infrastructure failure here is
// fail-closed: the org plausibly holds a credential and silently egressing
// unauthenticated is the exact leak the BYOK resolver policy refuses.
func (p *Proxy) invokePrepareCredential(ctx context.Context, c *invokeCall) (string, error) {
	if outcome, err := p.selectCredMode(ctx, c); err != nil {
		return outcome, err
	}
	if p.creds == nil {
		return "", nil
	}
	var err error
	if credModeConstrained(c.credMode) {
		err = p.resolveCredConstrained(ctx, c)
	} else {
		err = p.resolveCredPlain(ctx, c)
	}
	if err == nil {
		return "", nil
	}
	var refusal *InvokeError
	if errors.As(err, &refusal) {
		return OutcomeCredMode, refusal // refuseCredMode already metric'd + audited it
	}
	p.metricCreds(c.srv.Name, c.credKind, CredOutcomeError)
	p.auditDone(ctx, c.orgID, c.id, c.srv.Name, c.req.Tool, c.params,
		OutcomeUpstreamError, 0, 0, c.start, c.srv.URL)
	return OutcomeUpstreamError, fmt.Errorf("mcpagg: resolve credential: %w", err)
}

// selectCredMode resolves the policy-selected credential mode for this
// call (subject, server, tool). "" or "auto" = no constraint (the
// connection-config credential mode governs); "service"/"delegated" pin
// the layer the resolver must match. A selector failure or an unknown
// mode value is fail-closed: the call refuses rather than running under
// the config mode with the constraint unverified (a broken policy store
// must never silently upgrade a delegated pin to the service layer).
func (p *Proxy) selectCredMode(ctx context.Context, c *invokeCall) (string, error) {
	if p.modePolicy == nil || p.creds == nil {
		return "", nil
	}
	m, err := p.modePolicy.SelectCredentialMode(ctx, c.orgID, c.srv.Name, c.req.Tool, c.id.AgentID)
	if err != nil {
		return OutcomeCredMode, p.refuseCredMode(ctx, c.orgID, c.id, c.srv, c.req.Tool, c.params, "-", "error",
			fmt.Sprintf("credential mode policy is unavailable; refusing the call: %v", err), c.start)
	}
	m, err = normalizeCredMode(m)
	if err != nil {
		return OutcomeCredMode, p.refuseCredMode(ctx, c.orgID, c.id, c.srv, c.req.Tool, c.params, "-", "error",
			fmt.Sprintf("credential mode policy returned an invalid mode; refusing the call: %v", err), c.start)
	}
	c.credMode = m
	return "", nil
}

// resolveCredConstrained resolves under a pinned mode: the source must be
// level-aware (it refuses fail-closed otherwise — the layer constraint
// must be verifiable, never assumed) and the resolved layer must match the
// pin. A refusal returns as *InvokeError (already metric'd and audited by
// refuseCredMode); a plain error is an infrastructure failure the caller
// wraps fail-closed.
func (p *Proxy) resolveCredConstrained(ctx context.Context, c *invokeCall) error {
	ls, levelAware := p.creds.(LevelAwareCredSource)
	if !levelAware {
		return p.refuseCredMode(ctx, c.orgID, c.id, c.srv, c.req.Tool, c.params, c.credMode, "error",
			"credential mode policy requires a credential source that reports which layer resolved the credential; refusing the call", c.start)
	}
	headers, kind, level, err := ls.AuthHeadersLevel(ctx, c.orgID, c.req.Server, c.id.AgentID)
	c.credHeaders, c.credKind = headers, kind
	if err != nil {
		return err
	}
	if credModeViolation(c.credMode, level) {
		return p.refuseCredMode(ctx, c.orgID, c.id, c.srv, c.req.Tool, c.params, c.credMode, "deny",
			fmt.Sprintf("credential mode policy pins %q for this call; the resolved credential is the %s credential — refusing",
				c.credMode, level), c.start)
	}
	p.metricCredMode(c.srv.Name, c.credMode, "allow")
	p.countCredResolution(c.srv.Name, c.credKind, c.credHeaders)
	return nil
}

// resolveCredPlain is the unconstrained legacy resolution: per-user active
// → server-level enabled. Errors are infrastructure failures the caller
// wraps fail-closed.
func (p *Proxy) resolveCredPlain(ctx context.Context, c *invokeCall) error {
	headers, kind, err := p.creds.AuthHeaders(ctx, c.orgID, c.req.Server, c.id.AgentID)
	c.credHeaders, c.credKind = headers, kind
	if err != nil {
		return err
	}
	p.countCredResolution(c.srv.Name, c.credKind, c.credHeaders)
	return nil
}

// countCredResolution counts the hit/miss gateway_mcp_creds_total decision
// for a resolved credential (miss normalizes the kind label to "-").
func (p *Proxy) countCredResolution(serverName, kind string, headers map[string][]string) {
	if headers != nil {
		p.metricCreds(serverName, kind, CredOutcomeHit)
	} else {
		p.metricCreds(serverName, CredKindNone, CredOutcomeMiss)
	}
}

// invokeUpstream posts the tools/call and, when the upstream rejected an
// applied credential (401/403), runs the single force-refresh + retry
// round.
func (p *Proxy) invokeUpstream(ctx context.Context, c *invokeCall) (json.RawMessage, int, error) {
	result, status, callErr := p.callUpstream(ctx, c.srv, c.req.Tool, c.params, c.id, c.credHeaders)
	if callErr != nil && isAuthRejection(status) && p.creds != nil {
		return p.retryAfterUnauthorized(ctx, c.orgID, c.id, c.srv, c.req.Tool, c.params,
			c.credKind, c.credMode, c.start)
	}
	return result, status, callErr
}

// invokeCallFailure translates an upstream/refresh failure into the caller
// error and its audit/span outcome. The lazy-authorization error (MC-2)
// rides its own outcome — it is not a generic upstream failure (the
// handler renders mcp_auth_required with kind + url from it); a
// credential-mode refusal from the retry round gets the same loud
// OutcomeCredMode label as the pre-egress refusal; everything else maps
// through the InvokeError code (the audit outcome carries that code, e.g.
// "upstream"/"timeout").
func (p *Proxy) invokeCallFailure(ctx context.Context, c *invokeCall, callErr error, status int, latencyMS int64) (string, error) {
	var authErr *AuthRequiredError
	if errors.As(callErr, &authErr) {
		p.auditDone(ctx, c.orgID, c.id, c.srv.Name, c.req.Tool, c.params,
			OutcomeAuthRequired, status, latencyMS, c.start, c.srv.URL)
		return OutcomeAuthRequired, authErr
	}
	var cmErr *credModeRefusal
	if errors.As(callErr, &cmErr) {
		p.auditDone(ctx, c.orgID, c.id, c.srv.Name, c.req.Tool, c.params,
			OutcomeCredMode, status, latencyMS, c.start, c.srv.URL)
		return OutcomeCredMode, cmErr.InvokeError
	}
	outcome := OutcomeUpstreamError
	code := ErrCodeUpstream
	var iErr *InvokeError
	if errors.As(callErr, &iErr) {
		outcome = iErr.Code
		code = iErr.Code
	}
	p.auditDone(ctx, c.orgID, c.id, c.srv.Name, c.req.Tool, c.params,
		outcome, status, latencyMS, c.start, c.srv.URL)
	if code == ErrCodeTimeout {
		return outcome, &InvokeError{Code: ErrCodeTimeout, Message: callErr.Error()}
	}
	return outcome, &InvokeError{Code: ErrCodeUpstream, Message: callErr.Error()}
}

// invokeGuardResult runs the OP-6 result post-check: the org's result
// rules (secrets / deny_regex via pkg/guardhooks detectors) over the
// SERIALIZED upstream result. deny drops the result (the call already ran
// — the agent never sees it); mask returns the redacted result; flag
// passes it unchanged with the observation counted.
func (p *Proxy) invokeGuardResult(ctx context.Context, c *invokeCall, result json.RawMessage, status int, latencyMS int64) (json.RawMessage, string, error) {
	if p.guard == nil {
		return result, "", nil
	}
	rep := p.guard.GuardResult(ctx, c.orgID, c.id.AgentID, c.srv.Name, c.req.Tool, result)
	switch rep.Action {
	case toolpolicy.ResultDeny:
		p.metricToolPolicy(c.orgID, c.srv.Name, c.req.Tool, "deny")
		p.auditDone(ctx, c.orgID, c.id, c.srv.Name, c.req.Tool, c.params,
			OutcomeToolBlocked, status, latencyMS, c.start, c.srv.URL)
		return nil, OutcomeToolBlocked, &InvokeError{Code: ErrCodeToolBlocked, Message: rep.Reason}
	case toolpolicy.ResultMask:
		p.metricToolPolicy(c.orgID, c.srv.Name, c.req.Tool, "mask")
		result = json.RawMessage(rep.Masked)
	case toolpolicy.ResultFlag:
		p.metricToolPolicy(c.orgID, c.srv.Name, c.req.Tool, "flag")
	default:
		if rep.Degraded {
			p.metricToolPolicy(c.orgID, c.srv.Name, c.req.Tool, "error")
		}
	}
	return result, "", nil
}

// isAuthRejection reports whether the upstream status means the credential
// (or its absence) was rejected.
func isAuthRejection(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// retryAfterUnauthorized runs the single force-refresh + retry round:
// upstream rejected the attempt with 401/403. With no credential attached
// the org simply lacks one → mcp_auth_required (headers kind: the submit
// endpoint is the actionable default for Bearer-protected MCP servers). With
// a credential attached the source decides: oauth force-refreshes once
// (refresh metric + retry), otherwise the credential is terminally dead
// (needs_reauth marking happens inside the source) and the error surfaces.
// N05-P02-T04: under a constrained credMode the refresh goes through the
// level-aware surface and the refreshed credential is held to the SAME pin
// — a delegated pin must not gain the org's service credential through the
// retry window (and vice versa). credMode == "" (unconstrained) keeps the
// legacy path bit-for-bit.
func (p *Proxy) retryAfterUnauthorized(ctx context.Context, orgID string, id Identity, srv *Server, tool string, params json.RawMessage, credKind, credMode string, start time.Time) (json.RawMessage, int, error) {
	if credKind == CredKindNone {
		return nil, http.StatusUnauthorized, newAuthRequiredError(CredKindHeaders, srv.Name,
			"the mcp server requires authorization; no usable credential is stored for this agent")
	}
	if credModeConstrained(credMode) {
		// Invariant: step 5 only passes a constrained mode when the source
		// is level-aware (it refuses otherwise), so this assertion always
		// holds; if a future caller breaks it, fail closed.
		ls, levelAware := p.creds.(LevelAwareCredSource)
		if !levelAware {
			p.metricCredMode(srv.Name, credMode, "error")
			return nil, 0, &credModeRefusal{&InvokeError{Code: ErrCodeDenied,
				Message: "credential mode policy requires a credential source that reports which layer resolved the credential; refusing the call"}}
		}
		refreshed, kind, level, retry, err := ls.OnUpstreamUnauthorizedLevel(ctx, orgID, srv.Name, id.AgentID, credKind)
		if err != nil {
			p.metricCreds(srv.Name, credKind, CredOutcomeError)
			return nil, 0, fmt.Errorf("mcpagg: credential refresh: %w", err)
		}
		if !retry {
			return nil, http.StatusUnauthorized, newAuthRequiredError(credKind, srv.Name,
				"the stored mcp credential was rejected by the server; re-authorization is required")
		}
		p.metricCreds(srv.Name, kind, CredOutcomeRefresh)
		if credModeViolation(credMode, level) {
			p.metricCredMode(srv.Name, credMode, "deny")
			return nil, 0, &credModeRefusal{&InvokeError{Code: ErrCodeDenied,
				Message: fmt.Sprintf("credential mode policy pins %q for this call; the refreshed credential is the %s credential — refusing",
					credMode, level)}}
		}
		p.metricCredMode(srv.Name, credMode, "allow")
		return p.callUpstream(ctx, srv, tool, params, id, refreshed)
	}
	refreshed, retry, err := p.creds.OnUpstreamUnauthorized(ctx, orgID, srv.Name, id.AgentID, credKind)
	if err != nil {
		p.metricCreds(srv.Name, credKind, CredOutcomeError)
		return nil, 0, fmt.Errorf("mcpagg: credential refresh: %w", err)
	}
	if !retry {
		return nil, http.StatusUnauthorized, newAuthRequiredError(credKind, srv.Name,
			"the stored mcp credential was rejected by the server; re-authorization is required")
	}
	p.metricCreds(srv.Name, credKind, CredOutcomeRefresh)
	return p.callUpstream(ctx, srv, tool, params, id, refreshed)
}

// credModeRefusal marks a credential-mode policy refusal that surfaced from
// the retry round so Invoke records the OutcomeCredMode audit/span label
// (errors.As on *InvokeError does not match this wrapper, so Invoke checks
// it FIRST).
type credModeRefusal struct {
	*InvokeError
}

// refuseCredMode counts the credential-mode metric, records the pre-egress
// audit event under OutcomeCredMode and returns the InvokeError the caller
// surfaces (ErrCodeDenied → 409 on the REST surface: a loud policy denial,
// never a silent layer switch).
func (p *Proxy) refuseCredMode(ctx context.Context, orgID string, id Identity, srv *Server, tool string, params json.RawMessage, mode, metricOutcome, message string, start time.Time) *InvokeError {
	p.metricCredMode(srv.Name, mode, metricOutcome)
	p.auditDone(ctx, orgID, id, srv.Name, tool, params, OutcomeCredMode, 0, 0, start, srv.URL)
	return &InvokeError{Code: ErrCodeDenied, Message: message}
}

// metricCreds counts one gateway_mcp_creds_total decision. serverName may be
// empty on the earliest failures; "-" keeps the series stable (auditDone
// parity). An unknown kind normalizes to "-" the same way.
func (p *Proxy) metricCreds(serverName, kind, outcome string) {
	if serverName == "" {
		serverName = "-"
	}
	if kind == "" {
		kind = CredKindNone
	}
	metrics.MCPCredsTotal.WithLabelValues(serverName, kind, outcome).Inc()
}

// metricToolPolicy counts one OP-6 guard decision
// (gateway_toolpolicy_decisions_total{org,server,tool,outcome}).
func (p *Proxy) metricToolPolicy(orgID, serverName, tool, outcome string) {
	if serverName == "" {
		serverName = "-"
	}
	metrics.ToolpolicyDecisionsTotal.WithLabelValues(orgID, serverName, tool, outcome).Inc()
}

// metricCredMode counts one N05-P02-T04 credential-mode enforcement outcome
// (gateway_mcp_credmode_total{server, mode, outcome}): outcome is allow,
// deny or error; mode is the policy-selected pin (service/delegated) or "-"
// when the selector failed before producing a valid one. serverName may be
// empty on the earliest failures; "-" keeps the series stable (auditDone
// parity).
func (p *Proxy) metricCredMode(serverName, mode, outcome string) {
	if serverName == "" {
		serverName = "-"
	}
	if mode == "" {
		mode = "-"
	}
	metrics.MCPCredModeTotal.WithLabelValues(serverName, mode, outcome).Inc()
}

// callUpstream posts a JSON-RPC tools/call to the MCP server and returns the
// result content. MCP streamable HTTP: POST JSON-RPC; the response is either
// application/json (single result) or text/event-stream (the result as the
// last data frame). Both are handled. credHeaders (MC-2) carries the
// resolved credential headers — nil sends the legacy identity-only request.
func (p *Proxy) callUpstream(ctx context.Context, srv *Server, tool string, params json.RawMessage, id Identity, credHeaders map[string][]string) (json.RawMessage, int, error) {
	rpcParams := map[string]any{
		"name":      tool,
		"arguments": json.RawMessage(params),
	}
	return p.postRPC(ctx, srv, "tools/call", rpcParams, id, credHeaders)
}

// postRPC posts one JSON-RPC 2.0 request (tools/call, tools/list) to the
// upstream MCP server and returns the decoded "result" member plus the HTTP
// status. MCP streamable HTTP: the response is either application/json
// (single result) or text/event-stream (the result as the last data frame);
// both are handled. credHeaders (MC-2) carries the resolved credential
// headers — nil sends the legacy identity-only request.
func (p *Proxy) postRPC(ctx context.Context, srv *Server, rpcMethod string, rpcParams any, id Identity, credHeaders map[string][]string) (json.RawMessage, int, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  rpcMethod,
		"params":  rpcParams,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("mcpagg: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, &InvokeError{Code: ErrCodeUpstream, Message: "invalid upstream request"}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	// MC-2: the resolved credential headers. The payload is store-validated
	// at write time; the copy is fail-closed on malformed input and never
	// logged.
	if err := applyCredHeaders(httpReq, credHeaders); err != nil {
		return nil, 0, err
	}
	// MCP-04: identity headers from the verified principal (never from the
	// client — the gateway strips inbound copies).
	if id.AgentID != "" {
		httpReq.Header.Set("X-Yabanin-Agent-Id", id.AgentID)
	}
	if id.AgentName != "" {
		httpReq.Header.Set("X-Yabanin-Agent-Name", id.AgentName)
	}
	if id.TeamID != "" {
		httpReq.Header.Set("X-Yabanin-Team-Id", id.TeamID)
	}

	resp, err := p.cfg.Client().Do(httpReq)
	if err != nil {
		if isTimeout(err) {
			return nil, 0, &InvokeError{Code: ErrCodeTimeout, Message: "upstream timeout"}
		}
		return nil, 0, &InvokeError{Code: ErrCodeUpstream, Message: "upstream unreachable"}
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, p.cfg.MaxResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, &InvokeError{Code: ErrCodeUpstream, Message: "read upstream response failed"}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, resp.StatusCode, &InvokeError{Code: ErrCodeUpstream,
			Message: fmt.Sprintf("upstream status %d", resp.StatusCode)}
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "text/event-stream") {
		result, err := extractSSEResult(raw)
		if err != nil {
			return nil, resp.StatusCode, &InvokeError{Code: ErrCodeUpstream, Message: err.Error()}
		}
		return result, resp.StatusCode, nil
	}
	// application/json (or default): the body is the JSON-RPC response.
	result, err := extractJSONRPCResult(raw)
	if err != nil {
		return nil, resp.StatusCode, &InvokeError{Code: ErrCodeUpstream, Message: err.Error()}
	}
	return result, resp.StatusCode, nil
}

// extractJSONRPCResult parses a JSON-RPC response and returns the tool result
// (the "result" member). A JSON-RPC "error" member is an upstream error.
func extractJSONRPCResult(raw []byte) (json.RawMessage, error) {
	var rpc struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &rpc); err != nil {
		return nil, errors.New("mcpagg: invalid upstream json-rpc response")
	}
	if rpc.Error != nil {
		return nil, upstreamJSONRPCError(rpc.Error.Code)
	}
	if len(rpc.Result) == 0 {
		return nil, fmt.Errorf("mcpagg: upstream json-rpc response has no result")
	}
	return rpc.Result, nil
}

// extractSSEResult scans an SSE body for the JSON-RPC response frame (the
// "data:" line carrying a JSON-RPC object with a "result" or "error").
// MCP streamable HTTP sends the response as SSE; keep-alive pings and
// notification frames are skipped.
func extractSSEResult(raw []byte) (json.RawMessage, error) {
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(payload) == 0 || payload[0] != '{' {
			continue
		}
		var probe struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(payload, &probe); err != nil {
			continue // not a JSON-RPC frame (e.g. an event: meta line payload)
		}
		if len(probe.Error) > 0 {
			var e struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			_ = json.Unmarshal(probe.Error, &e)
			return nil, upstreamJSONRPCError(e.Code)
		}
		if len(probe.Result) > 0 {
			return probe.Result, nil
		}
	}
	return nil, fmt.Errorf("mcpagg: no json-rpc result frame in upstream sse stream")
}

func upstreamJSONRPCError(code int) error {
	return fmt.Errorf("mcpagg: upstream json-rpc error %d", code)
}

// toolAllowed reports whether tool passes the server's allow-list.
// An empty allow-list means all tools are allowed.
func toolAllowed(allow []string, tool string) bool {
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

// isTimeout reports whether err is a context/http deadline timeout.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr interface{ Timeout() bool }
	return errors.As(err, &netErr) && netErr.Timeout()
}

// auditDone records the audit event; a failing audit is swallowed (the call
// result is already determined — availability over audit, the gateway
// counts drops via its own metric, MCP-05). params is the POST-guard value
// (redacted when the hook redacted) — the original client params never reach
// the audit trail.
func (p *Proxy) auditDone(ctx context.Context, orgID string, id Identity, serverName, tool string, params json.RawMessage, outcome string, status int, latencyMS int64, start time.Time, upstreamURL string) {
	// MCP-05: count every tool call by server/tool/outcome — this is
	// observability and must be recorded even when no audit logger is wired
	// (p.audit == nil), so it runs BEFORE the nil-audit early return.
	// serverName is empty on the pre-lookup denials (agent_only); label it "-"
	// so the metric keeps a stable series.
	serverLabel := serverName
	if serverLabel == "" {
		serverLabel = "-"
	}
	metrics.MCPCallsTotal.WithLabelValues(serverLabel, tool, outcome).Inc()

	if p.audit == nil {
		return
	}
	if latencyMS == 0 {
		latencyMS = p.nowFn().Sub(start).Milliseconds()
	}
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	// The error message is derived from the outcome for the audit trail so a
	// reader can see WHY a call failed without re-deriving it from the status.
	errMsg := ""
	if outcome != OutcomeOK {
		errMsg = outcome
	}
	if err := p.audit.Log(ctx, AuditEvent{
		OrgID:          orgID,
		AgentID:        id.AgentID,
		ServerName:     serverName,
		Tool:           tool,
		ParamsRedacted: params,
		LatencyMS:      latencyMS,
		Outcome:        outcome,
		UpstreamStatus: status,
		RequestID:      id.RequestID,
		TaskID:         id.TaskID,
		TeamID:         id.TeamID,
		UpstreamURL:    upstreamURL,
		ErrorMessage:   errMsg,
	}); err != nil {
		// Swallowed by contract (availability over audit) but counted —
		metrics.SilentFailure("mcp_audit_write", "log_failed")
	}
}
