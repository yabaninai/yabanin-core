package a2aagg

// The gateway-side A2A proxy: one message/send against an org-registered
// external agent. Mirrors pkg/mcpagg's invoke discipline: agent-principal
// only, org-scoped registry lookup, per-send SSRF re-validation, pre-egress
// param guard, bounded upstream call, audit trail.

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

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/ssrf"
	"github.com/reireirei/yabanin/pkg/tracing"
)

// MethodSend is the one A2A JSON-RPC method the proxy carries in v1
// (docs/a2a-gateway.md): message/send, request/response. Streaming and
// push notifications are a later increment.
const MethodSend = "message/send"

// Identity is the verified caller principal, set by the gateway auth
// middleware (never by the client).
type Identity struct {
	AgentID   string
	AgentName string
	TeamID    string
	RequestID string
	TaskID    string
}

// Hook is the pre-egress param guard (same contract as mcpagg.Hook). Scan
// receives the raw message params and returns the (possibly redacted)
// params to send, a deny reason (non-empty = drop), and the mode that
// applied. When nil the proxy sends params untouched (mode "off").
type Hook interface {
	Scan(ctx context.Context, params []byte) (out []byte, denyReason string, mode string)
}

// AuditLogger records one message send. Called after the upstream response
// is complete (or the call was dropped pre-egress), with the redacted
// params. Errors are "audit dropped", never a response-path failure.
type AuditLogger interface {
	Log(ctx context.Context, e AuditEvent) error
}

// AuditEvent is one message send as recorded by the audit trail. Outcome is
// one of the Outcome* labels below.
type AuditEvent struct {
	OrgID          string
	AgentID        string
	AgentName      string
	TeamID         string
	RequestID      string
	TaskID         string
	TargetName     string
	Method         string
	ParamsRedacted json.RawMessage
	LatencyMS      int64
	Outcome        string
	UpstreamStatus int
	UpstreamURL    string
	ErrorMessage   string
}

// Outcome labels for AuditEvent.Outcome.
const (
	OutcomeOK            = "ok"
	OutcomeDenied        = "denied"
	OutcomeUpstreamError = "upstream_error"
	OutcomeTimeout       = "timeout"
	OutcomeSSRFBlocked   = "ssrf_blocked"
	OutcomeNotFound      = "not_found"
	OutcomeMethod        = "method_not_allowed"
)

// Proxy sends messages to registered external A2A agents.
type Proxy struct {
	store         *Store
	cfg           Config
	allow         ssrf.AllowList
	hook          Hook
	audit         AuditLogger
	nowFn         func() time.Time
	testAllowHTTP bool
	tracer        trace.Tracer
}

// NewProxy builds a Proxy. allow is the SSRF domain allow-list; hook and
// audit may be nil (no guarding / no audit).
func NewProxy(store *Store, cfg Config, allow ssrf.AllowList, hook Hook, audit AuditLogger) *Proxy {
	return &Proxy{
		store: store, cfg: cfg, allow: allow, hook: hook, audit: audit,
		nowFn: time.Now, testAllowHTTP: cfg.testAllowHTTP,
		tracer: tracing.Tracer("yabanin/a2aagg"),
	}
}

// SendRequest is one message send (gateway API body): the target agent name
// and the A2A message params (the `params` object of the JSON-RPC call —
// for message/send, {"message": {...}}).
type SendRequest struct {
	Agent  string          `json:"agent"`
	Params json.RawMessage `json:"params"`
}

// InvokeError is the structured error the gateway handler renders as JSON.
type InvokeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *InvokeError) Error() string { return e.Code + ": " + e.Message }

// ErrCode labels (the handler maps them to HTTP statuses):
//   - agent_only → 403 (caller is not a yag_ agent principal)
//   - not_found  → 404 (agent missing/disabled for this org)
//   - ssrf_blocked → 400 (URL failed the per-send SSRF guard)
//   - denied     → 409 (guard hook denied the params)
//   - method     → 400 (not a message/send envelope — v1 scope)
//   - upstream   → 502 (non-2xx or malformed body)
//   - timeout    → 504 (upstream exceeded the read/connect timeout)
const (
	ErrCodeAgentOnly = "agent_only"
	ErrCodeNotFound  = "not_found"
	ErrCodeSSRF      = "ssrf_blocked"
	ErrCodeDenied    = "denied"
	ErrCodeMethod    = "method_not_allowed"
	ErrCodeUpstream  = "upstream"
	ErrCodeTimeout   = "timeout"
)

// Send runs one message/send against the org's registered agent:
// agent-principal check → registry lookup → SSRF re-check → param guard →
// upstream JSON-RPC POST → audit.
func (p *Proxy) Send(ctx context.Context, orgID string, id Identity, req SendRequest) (json.RawMessage, error) {
	start := p.nowFn()

	ctx, span := p.tracer.Start(ctx, "a2a.message/send",
		trace.WithAttributes(
			attribute.String("a2a.agent", req.Agent),
			attribute.String("a2a.org", orgID),
			attribute.String("a2a.caller_agent_id", id.AgentID),
		))
	spanOutcome := OutcomeOK
	defer func() {
		span.SetAttributes(attribute.String("a2a.outcome", spanOutcome))
		span.End()
	}()

	// 0. A2A sends are agent-key-only: the identity comes from the gateway
	// auth middleware (the resolved yag_ principal); a regular api_key has
	// an empty AgentID. The inbound header is stripped on ingress, so this
	// value cannot be client-spoofed.
	if id.AgentID == "" {
		spanOutcome = OutcomeDenied
		p.auditDone(ctx, orgID, id, "", req.Params, OutcomeDenied, 0, 0, start, "")
		return nil, &InvokeError{Code: ErrCodeAgentOnly,
			Message: "a2a sends require an agent-principal (yag_) key"}
	}

	// 1. Agent must exist, be enabled, and belong to the org. A disabled or
	// missing row is indistinguishable to the caller (no enumeration).
	agent, err := p.store.GetEnabled(ctx, orgID, req.Agent)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			spanOutcome = OutcomeNotFound
			p.auditDone(ctx, orgID, id, req.Agent, req.Params, OutcomeNotFound, 0, 0, start, "")
			return nil, &InvokeError{Code: ErrCodeNotFound,
				Message: fmt.Sprintf("a2a agent %q is not available for this org", req.Agent)}
		}
		spanOutcome = OutcomeUpstreamError // store/DB error, not a documented InvokeError
		return nil, fmt.Errorf("a2aagg: lookup agent: %w", err)
	}

	// 2. SSRF guard, second layer (the rebind window — same invariant as
	// mcpagg: registration-time validation does not cache DNS).
	if p.testAllowHTTP {
		// Test seam: skip the guard for httptest loopback upstreams. The
		// full guard is pinned in validate_test.go.
	} else if err := ValidateURLAtSend(agent.URL, p.allow, false); err != nil { //nolint:contextcheck // SSRF guard runs on a bounded background ctx (QG2-D3 pattern)
		spanOutcome = OutcomeSSRFBlocked
		p.auditDone(ctx, orgID, id, agent.Name, req.Params, OutcomeSSRFBlocked, 0, 0, start, agent.URL)
		return nil, &InvokeError{Code: ErrCodeSSRF, Message: err.Error()}
	}

	// 3. Pre-egress param guard (same hook contract as MCP-06).
	params := req.Params
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	denyReason := ""
	if p.hook != nil {
		params, denyReason, _ = p.hook.Scan(ctx, params)
	}
	if denyReason != "" {
		spanOutcome = OutcomeDenied
		p.auditDone(ctx, orgID, id, agent.Name, params, OutcomeDenied, 0, 0, start, agent.URL)
		return nil, &InvokeError{Code: ErrCodeDenied, Message: denyReason}
	}

	// 4. Upstream JSON-RPC message/send.
	result, status, callErr := p.callUpstream(ctx, agent, params, id)
	latency := p.nowFn().Sub(start).Milliseconds()
	if callErr != nil {
		outcome := OutcomeUpstreamError
		code := ErrCodeUpstream
		var iErr *InvokeError
		if errors.As(callErr, &iErr) {
			outcome = iErr.Code
			code = iErr.Code
		}
		spanOutcome = outcome
		p.auditDone(ctx, orgID, id, agent.Name, params, outcome, status, latency, start, agent.URL)
		if code == ErrCodeTimeout {
			return nil, &InvokeError{Code: ErrCodeTimeout, Message: callErr.Error()}
		}
		return nil, &InvokeError{Code: ErrCodeUpstream, Message: callErr.Error()}
	}

	p.auditDone(ctx, orgID, id, agent.Name, params, OutcomeOK, status, latency, start, agent.URL)
	return result, nil
}

// callUpstream posts the JSON-RPC message/send envelope to the agent URL
// and returns the raw JSON-RPC result.
func (p *Proxy) callUpstream(ctx context.Context, agent *Agent, params json.RawMessage, id Identity) (json.RawMessage, int, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  MethodSend,
		"params":  json.RawMessage(params),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("a2aagg: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, agent.URL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("a2aagg: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	// Identity headers from the verified principal (never from the client —
	// the gateway strips inbound copies), same contract as MCP-04.
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
			return nil, 0, &InvokeError{Code: ErrCodeTimeout, Message: "upstream timeout: " + err.Error()}
		}
		return nil, 0, &InvokeError{Code: ErrCodeUpstream, Message: "upstream unreachable: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, p.cfg.MaxResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, &InvokeError{Code: ErrCodeUpstream, Message: "read upstream response: " + err.Error()}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet := strings.TrimSpace(string(raw))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return nil, resp.StatusCode, &InvokeError{Code: ErrCodeUpstream,
			Message: fmt.Sprintf("upstream status %d: %s", resp.StatusCode, snippet)}
	}
	result, err := extractJSONRPCResult(raw)
	if err != nil {
		return nil, resp.StatusCode, &InvokeError{Code: ErrCodeUpstream, Message: err.Error()}
	}
	return result, resp.StatusCode, nil
}

// extractJSONRPCResult returns the `result` member of a JSON-RPC 2.0
// response body; a JSON-RPC error object is surfaced as an upstream error.
func extractJSONRPCResult(raw []byte) (json.RawMessage, error) {
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("a2aagg: upstream response is not a JSON-RPC envelope: %w", err)
	}
	if env.Error != nil {
		msg := env.Error.Message
		if msg == "" {
			msg = "unknown upstream error"
		}
		return nil, fmt.Errorf("a2aagg: upstream JSON-RPC error: %s", msg)
	}
	if len(env.Result) == 0 {
		return nil, fmt.Errorf("a2aagg: upstream response carries no result")
	}
	return env.Result, nil
}

func isTimeout(err error) bool {
	var netErr interface{ Timeout() bool }
	return errors.As(err, &netErr) && netErr.Timeout()
}

// auditDone records the send outcome; an audit failure is logged-by-counter
// upstream (the interface contract), never a response-path error.
func (p *Proxy) auditDone(ctx context.Context, orgID string, id Identity, target string, params json.RawMessage, outcome string, status int, latencyMS int64, start time.Time, upstreamURL string) {
	if p.audit == nil {
		return
	}
	if err := p.audit.Log(ctx, AuditEvent{
		OrgID:          orgID,
		AgentID:        id.AgentID,
		AgentName:      id.AgentName,
		TeamID:         id.TeamID,
		RequestID:      id.RequestID,
		TaskID:         id.TaskID,
		TargetName:     target,
		Method:         MethodSend,
		ParamsRedacted: params,
		LatencyMS:      latencyMS,
		Outcome:        outcome,
		UpstreamStatus: status,
		UpstreamURL:    upstreamURL,
	}); err != nil {
		// Swallowed by contract (availability over audit) but counted —
		// exposed through the silent-failure metric.
		metrics.SilentFailure("a2a_audit_write", "log_failed")
	}
}
