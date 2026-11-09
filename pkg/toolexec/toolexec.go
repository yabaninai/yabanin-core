// Package toolexec implements TOOL-03: server-side tool executors — tools
// that run IN the Yabanin gateway process, so egress happens from the
// gateway's network position and jurisdiction, not from the developer's
// machine. v1 ships web_fetch; the discipline mirrors mcpagg: SSRF
// validation of the target (reserved-IP + allow-list), pre-egress guard
// hooks on the URL, bounded timeouts, response caps and an audit trail.
package toolexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// BuiltinServerName is the virtual registry name the gateway routes to
// this package ("yabanin"); tools are addressed as yabanin:<tool>.
const BuiltinServerName = "yabanin"

// Tool names.
const (
	ToolWebFetch    = "web_fetch"
	ToolHTTPRequest = "http_request"
	ToolHTTPHead    = "http_head"
	ToolDNSLookup   = "dns_lookup"
	ToolTimeNow     = "time_now"
)

// Config bounds the executors.
type Config struct {
	// ConnectTimeout bounds the TCP+TLS handshake.
	ConnectTimeout time.Duration
	// ReadTimeout bounds the full response.
	ReadTimeout time.Duration
	// MaxResponseBytes caps the fetched body.
	MaxResponseBytes int64
	// AllowedContentTypes: text-ish types are served; anything else is
	// reported as unsupported (a binary blob is useless to a model and a
	// liability to store).
	AllowedContentTypes []string

	httpClient *http.Client
}

// NewDefaultConfig returns safe defaults.
func NewDefaultConfig() Config {
	return Config{
		ConnectTimeout:   10 * time.Second,
		ReadTimeout:      20 * time.Second,
		MaxResponseBytes: 2 * 1024 * 1024,
		AllowedContentTypes: []string{
			"text/", "application/json", "application/xml", "application/yaml",
			"application/x-yaml", "application/javascript", "application/xhtml",
		},
	}
}

// Hook is the pre-egress guard (same contract as mcpagg.Hook): Scan gets
// the raw params (here: the URL), returns possibly redacted ones and a deny
// reason.
type Hook interface {
	Scan(ctx context.Context, params []byte) (out []byte, denyReason string, mode string)
}

// ToolGuard is the OP-6 toolpolicy guardrail surface (mcpagg.ToolGuard
// plus schema / max-size / deny_regex rules) and post-egress result checks
// (secrets / regex, flag|mask|deny). Satisfied by *toolpolicy.Engine and
// wired via WithToolGuard; nil keeps the pre-guardrail behavior bit-for-bit.
// Implementations are VALUE-FREE: findings and reasons name the rule and
// the span/category, never the matched material.
type ToolGuard interface {
	GuardArgs(ctx context.Context, orgID, subject, server, tool string, args json.RawMessage) toolpolicy.ArgsReport
	GuardResult(ctx context.Context, orgID, subject, server, tool string, result json.RawMessage) toolpolicy.ResultReport
}

// ValidateURL validates a fetch target. Implementation is injected so the
// gateway reuses its deployment SSRF allow-list (single dial-out surface).
type ValidateURL func(urlStr string) error

// Executor runs built-in tools.
type Executor struct {
	cfg      Config
	hook     Hook
	validate ValidateURL
	now      func() time.Time
	// guard is the optional OP-6 guardrail (nil = no guardrails). Wired via
	// WithToolGuard; enforced by ExecuteGuarded.
	guard ToolGuard

	clientOnce sync.Once
	httpClient *http.Client
}

// NewExecutor builds an Executor. validate must be the deployment's SSRF
// check (https/http allowed — intranet targets are legitimate for fetch,
// but reserved-IP + allow-list rules still apply).
func NewExecutor(cfg Config, validate ValidateURL, hook Hook) *Executor {
	return &Executor{cfg: cfg, hook: hook, validate: validate, now: time.Now}
}

// WithToolGuard attaches the OP-6 guardrails (toolpolicy engine). Nil
// (default) keeps the pre-guardrail behavior: no deny decisions, no args
// guards, no result post-checks.
func (x *Executor) WithToolGuard(g ToolGuard) *Executor {
	x.guard = g
	return x
}

// ExecError is the structured error (mcpagg.InvokeError parity).
type ExecError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *ExecError) Error() string { return e.Code + ": " + e.Message }

// Error codes (the gateway maps them to HTTP statuses).
const (
	ErrCodeNotFound    = "not_found"    // unknown builtin tool → 404
	ErrCodeDenied      = "denied"       // guard hook deny → 409
	ErrCodeSSRF        = "ssrf_blocked" // target failed the guard → 400
	ErrCodeUpstream    = "upstream"     // fetch failed / bad status → 502
	ErrCodeTimeout     = "timeout"      // 504
	ErrCodeBadReq      = "bad_request"  // malformed params → 400
	ErrCodeToolBlocked = "tool_blocked" // OP-6 toolpolicy guard deny → 400
)

// Result is the successful execution outcome returned to the caller.
type Result struct {
	Tool        string
	UpstreamURL string
	Status      int
	LatencyMS   int64
	Body        json.RawMessage
	// ParamsRedacted carries the guard-redacted params so the caller's
	// audit trail records WHAT was asked without secrets/PII (the hook
	// already redacted them before egress).
	ParamsRedacted json.RawMessage
}

// Execute runs one built-in tool call (catalog dispatch).
func (x *Executor) Execute(ctx context.Context, tool string, params json.RawMessage) (*Result, error) {
	for _, b := range builtins {
		if b.descriptor.Name == tool {
			return b.handler(ctx, x, params)
		}
	}
	return nil, unknownToolErr(tool)
}

// ExecuteGuarded runs one built-in tool call under the attached OP-6
// the EFFECTIVE tool name (http_request composes http_<method>), so a deny
// decision or an args rule (schema / max_bytes / deny_regex) blocks the call
// with tool_blocked and it never reaches the tool — and the post-egress
// GuardResult folds over the serialized body (mask rewrites it, deny drops
// the result; the call itself already ran, the mcpagg parity). Decision
// outcomes are counted on the shared toolpolicy decision counter
// (server = "yabanin", tool = the effective name). The identity comes from
// the caller (the gateway's verified principal); the raw Execute stays the
// unguarded dispatch for callers that enforce policy upstream.
func (x *Executor) ExecuteGuarded(ctx context.Context, orgID, subject, tool string, params json.RawMessage) (*Result, error) {
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	effective := EffectiveToolName(tool, params)
	if x.guard == nil {
		return x.Execute(ctx, tool, params)
	}
	rep := x.guard.GuardArgs(ctx, orgID, subject, BuiltinServerName, effective, params)
	switch {
	case rep.Degraded:
		metricToolPolicy(orgID, effective, "error")
	case rep.Denied:
		metricToolPolicy(orgID, effective, "deny")
		return nil, &ExecError{Code: ErrCodeToolBlocked, Message: rep.Reason}
	default:
		metricToolPolicy(orgID, effective, "allow")
	}
	res, err := x.Execute(ctx, tool, params)
	if err != nil {
		return nil, err
	}
	resRep := x.guard.GuardResult(ctx, orgID, subject, BuiltinServerName, effective, res.Body)
	switch resRep.Action {
	case toolpolicy.ResultDeny:
		metricToolPolicy(orgID, effective, "deny")
		return nil, &ExecError{Code: ErrCodeToolBlocked, Message: resRep.Reason}
	case toolpolicy.ResultMask:
		metricToolPolicy(orgID, effective, "mask")
		res.Body = json.RawMessage(resRep.Masked)
	case toolpolicy.ResultFlag:
		metricToolPolicy(orgID, effective, "flag")
	default:
		if resRep.Degraded {
			metricToolPolicy(orgID, effective, "error")
		}
	}
	return res, nil
}

// metricToolPolicy counts one guard decision (the mcpagg invoke-path label
// contract: org, server, tool, outcome — no payload content ever a label).
func metricToolPolicy(orgID, tool, outcome string) {
	metrics.ToolpolicyDecisionsTotal.WithLabelValues(orgID, BuiltinServerName, tool, outcome).Inc()
}

type webFetchParams struct {
	URL string `json:"url"`
}

type webFetchResult struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Content     string `json:"content"`
	Truncated   bool   `json:"truncated"`
}

func (x *Executor) webFetch(ctx context.Context, params json.RawMessage) (*Result, error) {
	start := x.now()
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	// Pre-egress guard on the params (the URL rides them).
	if x.hook != nil {
		var deny string
		params, deny, _ = x.hook.Scan(ctx, params)
		if deny != "" {
			return nil, &ExecError{Code: ErrCodeDenied, Message: deny}
		}
	}
	var p webFetchParams
	if err := json.Unmarshal(params, &p); err != nil || p.URL == "" {
		return nil, &ExecError{Code: ErrCodeBadReq, Message: "web_fetch requires {\"url\": \"...\"}"}
	}
	// SSRF: the deployment allow-list + reserved-IP resolution.
	if x.validate != nil {
		if err := x.validate(p.URL); err != nil {
			return nil, &ExecError{Code: ErrCodeSSRF, Message: err.Error()}
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return nil, &ExecError{Code: ErrCodeBadReq, Message: "invalid url: " + err.Error()}
	}
	req.Header.Set("User-Agent", "yabanin-webfetch/1")
	req.Header.Set("Accept", strings.Join(x.cfg.AllowedContentTypes, ", "))

	resp, err := x.client().Do(req)
	if err != nil {
		if isTimeout(err) {
			return nil, &ExecError{Code: ErrCodeTimeout, Message: "fetch timeout: " + err.Error()}
		}
		return nil, &ExecError{Code: ErrCodeUpstream, Message: "fetch failed: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	latency := x.now().Sub(start).Milliseconds()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &ExecError{Code: ErrCodeUpstream,
			Message: fmt.Sprintf("fetch status %d for %s", resp.StatusCode, p.URL)}
	}
	ct := resp.Header.Get("Content-Type")
	if !contentTypeAllowed(x.cfg.AllowedContentTypes, ct) {
		return nil, &ExecError{Code: ErrCodeUpstream,
			Message: fmt.Sprintf("content type %q not supported (text-like only)", ct)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, x.cfg.MaxResponseBytes+1))
	if err != nil {
		return nil, &ExecError{Code: ErrCodeUpstream, Message: "read body: " + err.Error()}
	}
	truncated := int64(len(body)) > x.cfg.MaxResponseBytes
	if truncated {
		body = body[:x.cfg.MaxResponseBytes]
	}
	out, err := json.Marshal(webFetchResult{
		URL: p.URL, Status: resp.StatusCode, ContentType: ct,
		Content: string(body), Truncated: truncated,
	})
	if err != nil {
		return nil, &ExecError{Code: ErrCodeUpstream, Message: "encode result: " + err.Error()}
	}
	return &Result{
		Tool: ToolWebFetch, UpstreamURL: p.URL, Status: resp.StatusCode,
		LatencyMS: latency, Body: out, ParamsRedacted: params,
	}, nil
}

// client returns the shared HTTP client, built lazily under sync.Once (the
// executors run on concurrent request goroutines). Redirects are never
// followed: every hop would need its own SSRF validation, and a 302 must
// not smuggle the gateway to an otherwise-blocked target — the non-2xx
// redirect response surfaces as an upstream error instead (same posture as
// mcpagg/a2aagg).
func (x *Executor) client() *http.Client {
	x.clientOnce.Do(func() {
		c := &http.Client{Timeout: x.cfg.ReadTimeout}
		if x.cfg.httpClient != nil {
			if t := x.cfg.httpClient.Timeout; t > 0 {
				c.Timeout = t
			}
			c.Transport = x.cfg.httpClient.Transport
		}
		c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		x.httpClient = c
	})
	return x.httpClient
}

func contentTypeAllowed(allowed []string, ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	if ct == "" {
		return false
	}
	for _, a := range allowed {
		if a == ct || (strings.HasSuffix(a, "/") && strings.HasPrefix(ct, a)) {
			return true
		}
	}
	return false
}

func isTimeout(err error) bool {
	var netErr interface{ Timeout() bool }
	return errors.As(err, &netErr) && netErr.Timeout()
}
