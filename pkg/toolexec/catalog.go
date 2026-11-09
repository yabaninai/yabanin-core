package toolexec

// TOOL-03 (full catalog): the built-in server-side tool registry. Tools run
// IN the gateway process — egress happens from the gateway's network
// position and jurisdiction, not from the developer's machine. Every tool
// gets the same discipline: SSRF validation where it dials out, pre-egress
// guard hooks, bounded timeouts, size caps and an audit trail.
//
// Effective tool names for policy evaluation: most tools are checked under
// their own name; http_request is checked under the COMPOSED name
// http_<method> (http_get, http_post, …) so name-based presets
// (network-readonly denies http_post) compose naturally.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ToolDescriptor describes one built-in tool for the discovery surface.
type ToolDescriptor struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Params      []string `json:"params,omitempty"`
	// EffectiveName documents the policy-evaluation name when it differs
	// from Name (http_request → http_<method>).
	EffectiveName string `json:"effective_name,omitempty"`
}

// builtin is one registered tool handler.
type builtin struct {
	descriptor ToolDescriptor
	handler    func(ctx context.Context, x *Executor, params json.RawMessage) (*Result, error)
	// effectiveName resolves the policy-evaluation name from the params
	// (nil → same as Name).
	effectiveName func(params json.RawMessage) string
}

// builtins is the catalog (order = discovery order).
var builtins = []builtin{
	{
		descriptor: ToolDescriptor{
			Name:        ToolWebFetch,
			Description: "HTTP GET a URL from the gateway's network position; text-like content only, size-capped.",
			Params:      []string{"url"},
		},
		handler: handleWebFetch,
	},
	{
		descriptor: ToolDescriptor{
			Name:          ToolHTTPRequest,
			Description:   "Arbitrary HTTP request (GET/POST/PUT/PATCH/DELETE) with a JSON body; evaluated by policy as http_<method>.",
			Params:        []string{"url", "method", "body", "content_type"},
			EffectiveName: "http_<method>",
		},
		handler:       handleHTTPRequest,
		effectiveName: httpRequestEffectiveName,
	},
	{
		descriptor: ToolDescriptor{
			Name:        ToolHTTPHead,
			Description: "HEAD request: response headers (set-cookie and friends stripped) without the body.",
			Params:      []string{"url"},
		},
		handler: handleHTTPHead,
	},
	{
		descriptor: ToolDescriptor{
			Name:        ToolDNSLookup,
			Description: "Resolve a hostname to its A/AAAA records from the gateway's resolver.",
			Params:      []string{"host"},
		},
		handler: handleDNSLookup,
	},
	{
		descriptor: ToolDescriptor{
			Name:        ToolTimeNow,
			Description: "Current gateway time (RFC3339 UTC + epoch seconds). No egress.",
			Params:      nil,
		},
		handler: handleTimeNow,
	},
}

// Catalog returns the tool descriptors (discovery surface).
func Catalog() []ToolDescriptor {
	out := make([]ToolDescriptor, 0, len(builtins))
	for _, b := range builtins {
		out = append(out, b.descriptor)
	}
	return out
}

// EffectiveToolName resolves the policy-evaluation name for (tool, params).
// Unknown tools return the raw name; http_request composes http_<method>.
func EffectiveToolName(tool string, params json.RawMessage) string {
	for _, b := range builtins {
		if b.descriptor.Name == tool && b.effectiveName != nil {
			return b.effectiveName(params)
		}
	}
	return tool
}

func httpRequestEffectiveName(params json.RawMessage) string {
	var p struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(params, &p)
	m := strings.ToLower(strings.TrimSpace(p.Method))
	if m == "" {
		m = "get"
	}
	return "http_" + m
}

// ---- handlers -------------------------------------------------------------

func handleWebFetch(ctx context.Context, x *Executor, params json.RawMessage) (*Result, error) {
	return x.webFetch(ctx, params)
}

type httpReqParams struct {
	URL         string          `json:"url"`
	Method      string          `json:"method"`
	Body        json.RawMessage `json:"body"`
	ContentType string          `json:"content_type"`
}

func handleHTTPRequest(ctx context.Context, x *Executor, params json.RawMessage) (*Result, error) {
	start := x.now()
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	if x.hook != nil {
		var deny string
		params, deny, _ = x.hook.Scan(ctx, params)
		if deny != "" {
			return nil, &ExecError{Code: ErrCodeDenied, Message: deny}
		}
	}
	var p httpReqParams
	if err := json.Unmarshal(params, &p); err != nil || p.URL == "" {
		return nil, &ExecError{Code: ErrCodeBadReq, Message: `http_request requires {"url":"...", "method":"get|post|put|patch|delete"}`}
	}
	method := strings.ToUpper(strings.TrimSpace(p.Method))
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return nil, &ExecError{Code: ErrCodeBadReq, Message: "method must be one of get/post/put/patch/delete"}
	}
	if x.validate != nil {
		if err := x.validate(p.URL); err != nil {
			return nil, &ExecError{Code: ErrCodeSSRF, Message: err.Error()}
		}
	}

	var bodyReader io.Reader
	if len(p.Body) > 0 && method != http.MethodGet {
		bodyReader = strings.NewReader(string(p.Body))
	}
	req, err := http.NewRequestWithContext(ctx, method, p.URL, bodyReader)
	if err != nil {
		return nil, &ExecError{Code: ErrCodeBadReq, Message: "invalid url: " + err.Error()}
	}
	req.Header.Set("User-Agent", "yabanin-http/1")
	ct := p.ContentType
	if ct == "" {
		ct = "application/json"
	}
	if method != http.MethodGet && bodyReader != nil {
		req.Header.Set("Content-Type", ct)
	}

	resp, err := x.client().Do(req)
	if err != nil {
		if isTimeout(err) {
			return nil, &ExecError{Code: ErrCodeTimeout, Message: "request timeout: " + err.Error()}
		}
		return nil, &ExecError{Code: ErrCodeUpstream, Message: "request failed: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	latency := x.now().Sub(start).Milliseconds()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &ExecError{Code: ErrCodeUpstream,
			Message: fmt.Sprintf("request status %d for %s", resp.StatusCode, p.URL)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, x.cfg.MaxResponseBytes+1))
	if err != nil {
		return nil, &ExecError{Code: ErrCodeUpstream, Message: "read body: " + err.Error()}
	}
	truncated := int64(len(body)) > x.cfg.MaxResponseBytes
	if truncated {
		body = body[:x.cfg.MaxResponseBytes]
	}
	out, err := json.Marshal(map[string]any{
		"url": p.URL, "status": resp.StatusCode, "content_type": resp.Header.Get("Content-Type"),
		"body": string(body), "truncated": truncated,
	})
	if err != nil {
		return nil, &ExecError{Code: ErrCodeUpstream, Message: "encode result: " + err.Error()}
	}
	return &Result{
		Tool: ToolHTTPRequest, UpstreamURL: p.URL, Status: resp.StatusCode,
		LatencyMS: latency, Body: out, ParamsRedacted: params,
	}, nil
}

func handleHTTPHead(ctx context.Context, x *Executor, params json.RawMessage) (*Result, error) {
	start := x.now()
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	if x.hook != nil {
		var deny string
		params, deny, _ = x.hook.Scan(ctx, params)
		if deny != "" {
			return nil, &ExecError{Code: ErrCodeDenied, Message: deny}
		}
	}
	var p struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.URL == "" {
		return nil, &ExecError{Code: ErrCodeBadReq, Message: `http_head requires {"url":"..."}`}
	}
	if x.validate != nil {
		if err := x.validate(p.URL); err != nil {
			return nil, &ExecError{Code: ErrCodeSSRF, Message: err.Error()}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, p.URL, nil)
	if err != nil {
		return nil, &ExecError{Code: ErrCodeBadReq, Message: "invalid url: " + err.Error()}
	}
	req.Header.Set("User-Agent", "yabanin-http/1")
	resp, err := x.client().Do(req)
	if err != nil {
		if isTimeout(err) {
			return nil, &ExecError{Code: ErrCodeTimeout, Message: "request timeout: " + err.Error()}
		}
		return nil, &ExecError{Code: ErrCodeUpstream, Message: "request failed: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	// Sanitize: credential-shaped headers never leave the executor.
	safe := map[string]string{}
	for k, vs := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "set-cookie" || lk == "authorization" || lk == "proxy-authenticate" || lk == "www-authenticate" {
			continue
		}
		safe[k] = strings.Join(vs, ", ")
	}
	out, err := json.Marshal(map[string]any{"url": p.URL, "status": resp.StatusCode, "headers": safe})
	if err != nil {
		return nil, &ExecError{Code: ErrCodeUpstream, Message: "encode result: " + err.Error()}
	}
	return &Result{
		Tool: ToolHTTPHead, UpstreamURL: p.URL, Status: resp.StatusCode,
		LatencyMS: x.now().Sub(start).Milliseconds(), Body: out, ParamsRedacted: params,
	}, nil
}

func handleDNSLookup(ctx context.Context, x *Executor, params json.RawMessage) (*Result, error) {
	start := x.now()
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	if x.hook != nil {
		var deny string
		params, deny, _ = x.hook.Scan(ctx, params)
		if deny != "" {
			return nil, &ExecError{Code: ErrCodeDenied, Message: deny}
		}
	}
	var p struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.Host == "" {
		return nil, &ExecError{Code: ErrCodeBadReq, Message: `dns_lookup requires {"host":"..."}`}
	}
	host := strings.TrimSpace(p.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h // tolerate "host:port"
	}
	if net.ParseIP(host) == nil {
		if _, err := url.Parse("//" + host); err != nil || !strings.Contains(host, ".") {
			return nil, &ExecError{Code: ErrCodeBadReq, Message: "host must be a hostname or IP"}
		}
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		return nil, &ExecError{Code: ErrCodeUpstream, Message: "resolve failed: " + err.Error()}
	}
	var records []string
	for _, ip := range ips {
		records = append(records, ip.IP.String())
	}
	out, err := json.Marshal(map[string]any{"host": host, "records": records})
	if err != nil {
		return nil, &ExecError{Code: ErrCodeUpstream, Message: "encode result: " + err.Error()}
	}
	return &Result{
		Tool: ToolDNSLookup, UpstreamURL: "dns:" + host, Status: 0,
		LatencyMS: x.now().Sub(start).Milliseconds(), Body: out, ParamsRedacted: params,
	}, nil
}

func handleTimeNow(_ context.Context, x *Executor, _ json.RawMessage) (*Result, error) {
	now := x.now().UTC()
	out, err := json.Marshal(map[string]any{
		"rfc3339": now.Format(time.RFC3339), "epoch": now.Unix(),
	})
	if err != nil {
		return nil, &ExecError{Code: ErrCodeUpstream, Message: err.Error()}
	}
	return &Result{
		Tool: ToolTimeNow, UpstreamURL: "", Status: 0,
		LatencyMS: 0, Body: out, ParamsRedacted: nil,
	}, nil
}

// unknownToolErr is the shared "not in the catalog" error.
func unknownToolErr(tool string) *ExecError {
	names := make([]string, 0, len(builtins))
	for _, b := range builtins {
		names = append(names, b.descriptor.Name)
	}
	return &ExecError{Code: ErrCodeNotFound,
		Message: fmt.Sprintf("unknown yabanin built-in tool %q (available: %s)", tool, strings.Join(names, ", "))}
}
