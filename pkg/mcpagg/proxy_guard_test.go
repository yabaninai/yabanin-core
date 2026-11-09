package mcpagg

// OP-6 tool-call guardrails on the invoke path: pre-egress args guards
// (deny/mcp_tool_blocked BEFORE any upstream traffic) and post-egress
// result checks (mask/deny/flag), wired through the ToolGuard interface.
// The e2e cases run a REAL toolpolicy.Engine over mock policy rows against
// a counting mock MCP upstream.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// metricDelta reads the toolpolicy decision counter before/after — the
// counters are process-global (promauto), so assertions must be delta-based
// to survive any test order (shuffle) and repetition (count).
func metricDelta(t *testing.T, org, server, tool, outcome string, fn func()) float64 {
	t.Helper()
	label := metrics.ToolpolicyDecisionsTotal.WithLabelValues(org, server, tool, outcome)
	before := testutil.ToFloat64(label)
	fn()
	return testutil.ToFloat64(label) - before
}

// fakeGuard records the calls and returns scripted verdicts.
type fakeGuard struct {
	args   toolpolicy.ArgsReport
	result toolpolicy.ResultReport

	argsCalls   int
	resultCalls int
	gotArgs     string
}

func (g *fakeGuard) GuardArgs(_ context.Context, _, _, _, _ string, args json.RawMessage) toolpolicy.ArgsReport {
	g.argsCalls++
	g.gotArgs = string(args)
	return g.args
}

func (g *fakeGuard) GuardResult(_ context.Context, _, _, _, _ string, _ json.RawMessage) toolpolicy.ResultReport {
	g.resultCalls++
	return g.result
}

// guardUpstream is a mock MCP server (JSON-RPC tools/call) with a request
// counter and a fixed result body.
type guardUpstream struct {
	URL    string
	calls  atomic.Int32
	result string
}

func newGuardUpstream(t *testing.T, result string) *guardUpstream {
	t.Helper()
	u := &guardUpstream{result: result}
	if u.result == "" {
		u.result = `{"content":[{"type":"text","text":"echo"}]}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%s}`, u.result)
	}))
	t.Cleanup(srv.Close)
	u.URL = srv.URL
	return u
}

func TestProxy_GuardArgsDeny_BlockedBeforeUpstream(t *testing.T) {
	up := newGuardUpstream(t, "")
	g := &fakeGuard{args: toolpolicy.ArgsReport{Denied: true,
		Reason: "tool call blocked: schema check failed (required)",
		Findings: []toolpolicy.Finding{{Source: "schema", Category: "required",
			Span: "/", Action: "deny"}}}}
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(g)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
		t.Fatalf("want mcp_tool_blocked, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("denied call must not reach the upstream, got %d requests", up.calls.Load())
	}
	if g.argsCalls != 1 || !strings.Contains(g.gotArgs, `"q"`) {
		t.Fatalf("guard must receive the serialized args once: %+v", g)
	}
	if d := metricDelta(t, "org-1", "knowledge", "search", "deny", func() {
		_, _ = p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
			InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	}); d != 1 {
		t.Fatalf("deny decision metric delta = %v", d)
	}
}

func TestProxy_GuardDegraded_ProceedsAndCountsError(t *testing.T) {
	up := newGuardUpstream(t, "")
	g := &fakeGuard{args: toolpolicy.ArgsReport{Degraded: true}}
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(g)
	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("degraded (fail-open) must proceed: %v", err)
	}
	if d := metricDelta(t, "org-1", "knowledge", "search", "error", func() {
		_, _ = p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
			InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	}); d != 1 {
		t.Fatalf("degraded must count as error, delta = %v", d)
	}
}

func TestProxy_GuardResultMask(t *testing.T) {
	const secret = "sk-abcdef1234567890abcdef"
	up := newGuardUpstream(t, `{"content":[{"type":"text","text":"key `+secret+`"}]}`)
	g := &fakeGuard{result: toolpolicy.ResultReport{Action: toolpolicy.ResultMask,
		Masked: []byte(`{"content":[{"type":"text","text":"key [REDACTED]"}]}`)}}
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(g)
	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream must have been called once, got %d", up.calls.Load())
	}
	if strings.Contains(string(res), secret) {
		t.Fatal("the caller must never see the unmasked secret")
	}
	if !strings.Contains(string(res), "[REDACTED]") {
		t.Fatalf("masked result expected, got %s", res)
	}
	if d := metricDelta(t, "org-1", "knowledge", "search", "mask", func() {
		_, _ = p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
			InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	}); d != 1 {
		t.Fatalf("mask decision metric delta = %v", d)
	}
}

func TestProxy_GuardResultDeny(t *testing.T) {
	up := newGuardUpstream(t, "")
	g := &fakeGuard{result: toolpolicy.ResultReport{Action: toolpolicy.ResultDeny,
		Reason: "policy deny: secrets check failed (secret)"}}
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(g)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
		t.Fatalf("want mcp_tool_blocked, got %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("the upstream ran (the result is dropped, not the call), got %d", up.calls.Load())
	}
}

// --- e2e: REAL toolpolicy.Engine over mock rows vs the mock MCP upstream ---

func guardEngine(t *testing.T, policies ...toolpolicy.Policy) *toolpolicy.Engine {
	t.Helper()
	return toolpolicy.NewEngine(&guardMemLoader{policies: policies}, 0)
}

// guardMemLoader filters by OrgID (the store's `WHERE org_id = $1` parity).
type guardMemLoader struct {
	policies []toolpolicy.Policy
}

func (m *guardMemLoader) ListEnabled(_ context.Context, orgID string) ([]toolpolicy.Policy, error) {
	var out []toolpolicy.Policy
	for _, p := range m.policies {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	return out, nil
}

const guardArgsSchema = `{"args":{"schema":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"],"additionalProperties":false}}}`

func TestE2E_ValidArgsPasses(t *testing.T) {
	up := newGuardUpstream(t, "")
	eng := guardEngine(t, toolpolicy.Policy{OrgID: "org-1", Name: "schema", Subject: "*",
		Server: "knowledge", Tool: "*", Action: toolpolicy.ActionAllow,
		Rules: json.RawMessage(guardArgsSchema), Enabled: true})
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(eng)
	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	if err != nil {
		t.Fatalf("valid args must pass: %v", err)
	}
	if !strings.Contains(string(res), "echo") {
		t.Fatalf("upstream result expected: %s", res)
	}
}

func TestE2E_SchemaViolationBlocked(t *testing.T) {
	up := newGuardUpstream(t, "")
	eng := guardEngine(t, toolpolicy.Policy{OrgID: "org-1", Name: "schema", Subject: "*",
		Server: "knowledge", Tool: "*", Action: toolpolicy.ActionAllow,
		Rules: json.RawMessage(guardArgsSchema), Enabled: true})
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(eng)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"nope":1}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
		t.Fatalf("want mcp_tool_blocked, got %v", err)
	}
	if !strings.Contains(iErr.Message, "schema") {
		t.Fatalf("the error must name the failing check: %q", iErr.Message)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("blocked call must not reach the upstream, got %d", up.calls.Load())
	}
}

func TestE2E_SecretInResultMasked(t *testing.T) {
	const secret = "ghp_Abcd" + "EfghAbcdEfghAbcdEfghAbcdEfgh1"
	up := newGuardUpstream(t, `{"content":[{"type":"text","text":"token `+secret+`"}]}`)
	eng := guardEngine(t, toolpolicy.Policy{OrgID: "org-1", Name: "mask", Subject: "*",
		Server: "knowledge", Tool: "*", Action: toolpolicy.ActionAllow,
		Rules: json.RawMessage(`{"result":{"mode":"mask","secrets":true}}`), Enabled: true})
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(eng)
	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if strings.Contains(string(res), secret) {
		t.Fatal("masked result still carries the secret")
	}
	if !strings.Contains(string(res), "[REDACTED_SECRET]") {
		t.Fatalf("redaction token expected: %s", res)
	}
}

func TestE2E_SecretInResultDenied(t *testing.T) {
	const secret = "ghp_Abcd" + "EfghAbcdEfghAbcdEfghAbcdEfgh1"
	up := newGuardUpstream(t, `{"content":[{"type":"text","text":"token `+secret+`"}]}`)
	eng := guardEngine(t, toolpolicy.Policy{OrgID: "org-1", Name: "deny", Subject: "*",
		Server: "knowledge", Tool: "*", Action: toolpolicy.ActionAllow,
		Rules: json.RawMessage(`{"result":{"mode":"deny","secrets":true}}`), Enabled: true})
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(eng)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
		t.Fatalf("want mcp_tool_blocked, got %v", err)
	}
}

// TestE2E_OrgWithoutRulesUnaffected pins the off-by-default posture: an org
// with no policy rows pays nothing and loses nothing.
func TestE2E_OrgWithoutRulesUnaffected(t *testing.T) {
	up := newGuardUpstream(t, "")
	eng := guardEngine(t, toolpolicy.Policy{OrgID: "org-OTHER", Name: "cap", Subject: "*",
		Server: "knowledge", Tool: "*", Action: toolpolicy.ActionAllow,
		Rules: json.RawMessage(`{"args":{"max_bytes":2}}`), Enabled: true})
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(eng)
	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"big":"payload"}`)}); err != nil {
		t.Fatalf("another org's rules must not apply: %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream called once, got %d", up.calls.Load())
	}
}

// TestProxy_NoGuard_BitForBit pins the nil-guard contract: without
// WithToolGuard the invoke path is unchanged (the legacy tests pin the rest
// of that behavior; here the args guard specifically).
func TestProxy_NoGuard_BitForBit(t *testing.T) {
	up := newGuardUpstream(t, "")
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil)
	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"no":"schema"}`)}); err != nil {
		t.Fatalf("no guard = no enforcement: %v", err)
	}
}
