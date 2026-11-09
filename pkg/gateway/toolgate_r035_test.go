package cli

// §4, each pinned the way pkg/mcpagg/proxy_guard_test.go pins the invoke
// path — a denied call must never reach the executor/upstream, proven by a
// zero request counter.
//
//   - G1: builtin yabanin:* executor guardrails (per-tool AND per-argument
//     permissions on the second half of the egress surface).
//   - G2: the chat response surface gates the DECLARED ARGUMENTS of
//     model-declared tool_calls, not only their names (JSON + SSE).
//   - G3: the native MCP catalog/pre-gate decides SERVER-AWARE
//     (DecideTool with the server from the flat name), so server-scoped
//     deny rows hide tools and block calls instead of only the inner
//     invoke path denying them later.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/mcpserver"
	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

func mcpserverPrincipal(org, agent string) mcpserver.Principal {
	return mcpserver.Principal{OrgID: org, AgentID: agent}
}

// builtinUpstream is a counting fetch target for the builtin executor:
// is calls == 0 for every denied call.
type builtinUpstream struct {
	URL   string
	calls int
	body  string
}

func newBuiltinUpstream(t *testing.T) *builtinUpstream {
	t.Helper()
	return newBuiltinUpstreamBody(t, "upstream-seen")
}

func newBuiltinUpstreamBody(t *testing.T, body string) *builtinUpstream {
	t.Helper()
	u := &builtinUpstream{body: body}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		u.calls++
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(u.body))
	}))
	t.Cleanup(srv.Close)
	u.URL = srv.URL
	return u
}

// rulesRow is an enabled allow row carrying args guard rules (the OP-6
// wire shape stored in tool_policies.rules).
func rulesRow(name, server, tool, rules string) toolpolicy.Policy {
	return toolpolicy.Policy{OrgID: "org-1", Name: name, Subject: "*",
		Server: server, Tool: tool, Action: toolpolicy.ActionAllow,
		Rules: json.RawMessage(rules), Enabled: true}
}

// TestBuiltinToolInvoke_ArgsDeny_BlockedBeforeUpstream is the G1 acceptance:
// an org args rule (deny_regex) on the builtin server must block the call
// with the documented mcp_tool_blocked error and the upstream counter must
// stay at ZERO — the denied call never reaches the tool.
func TestBuiltinToolInvoke_ArgsDeny_BlockedBeforeUpstream(t *testing.T) {
	up := newBuiltinUpstream(t)
	gw := gateWith(rulesRow("block-evil", "yabanin", "web_fetch",
		`{"args":{"deny_regex":["evil-"]}}`))
	gw.toolExec = toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil).WithToolGuard(gw.toolPolicies) // production wiring (gateway.go)

	w := httptest.NewRecorder()
	gw.builtinToolInvoke(w, mkBuiltinReq(), "org-1", mcpagg.Identity{AgentID: "agent-1"},
		mcpagg.InvokeRequest{Server: "yabanin", Tool: "web_fetch",
			Params: json.RawMessage(`{"url":"` + up.URL + `/evil-page"}`)})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("args-deny status = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "mcp_tool_blocked") {
		t.Fatalf("deny must surface the documented code, got %s", w.Body.String())
	}
	if up.calls != 0 {
		t.Fatalf("denied call must not reach the upstream tool, got %d requests", up.calls)
	}
}

// TestBuiltinToolInvoke_ArgsAllow_ReachesUpstream pins the off-by-default
// posture: valid arguments of a guarded tool still execute (the rule is a
// guardrail, not a wall).
func TestBuiltinToolInvoke_ArgsAllow_ReachesUpstream(t *testing.T) {
	up := newBuiltinUpstream(t)
	gw := gateWith(rulesRow("block-evil", "yabanin", "web_fetch",
		`{"args":{"deny_regex":["evil-"]}}`))
	gw.toolExec = toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil).WithToolGuard(gw.toolPolicies) // production wiring (gateway.go)

	w := httptest.NewRecorder()
	gw.builtinToolInvoke(w, mkBuiltinReq(), "org-1", mcpagg.Identity{AgentID: "agent-1"},
		mcpagg.InvokeRequest{Server: "yabanin", Tool: "web_fetch",
			Params: json.RawMessage(`{"url":"` + up.URL + `/fine"}`)})

	if w.Code != http.StatusOK {
		t.Fatalf("valid args must execute, got %d (body %s)", w.Code, w.Body.String())
	}
	if up.calls != 1 {
		t.Fatalf("upstream must have been called once, got %d", up.calls)
	}
}

// TestBuiltinToolInvoke_ServerScopedDenyRow is the per-tool half of G1: a
// server-qualified deny row (Server='yabanin') blocks the builtin call with
// the GuardArgs deny winner (the chat-path name gate cannot see it).
func TestBuiltinToolInvoke_ServerScopedDenyRow(t *testing.T) {
	up := newBuiltinUpstream(t)
	deny := toolpolicy.Policy{OrgID: "org-1", Name: "no-dns", Subject: "*",
		Server: "yabanin", Tool: "dns_lookup", Action: toolpolicy.ActionDeny, Enabled: true}
	gw := gateWith(deny)
	gw.toolExec = toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil).WithToolGuard(gw.toolPolicies) // production wiring (gateway.go)

	w := httptest.NewRecorder()
	gw.builtinToolInvoke(w, mkBuiltinReq(), "org-1", mcpagg.Identity{AgentID: "agent-1"},
		mcpagg.InvokeRequest{Server: "yabanin", Tool: "dns_lookup",
			Params: json.RawMessage(`{"host":"example.test"}`)})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("server-scoped deny status = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	if up.calls != 0 {
		t.Fatalf("denied call must not reach the upstream tool, got %d requests", up.calls)
	}
}

// TestBuiltinToolInvoke_ResultDeny checks the post-egress half: a result
// rule in deny mode drops the result (the call already ran) with
// mcp_tool_blocked.
func TestBuiltinToolInvoke_ResultDeny(t *testing.T) {
	const secret = "ghp_Abcd" + "EfghAbcdEfghAbcdEfghAbcdEfgh1"
	up := newBuiltinUpstreamBody(t, "token "+secret)
	gw := gateWith(rulesRow("no-keys", "yabanin", "web_fetch",
		`{"result":{"mode":"deny","secrets":true}}`))
	gw.toolExec = toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil).WithToolGuard(gw.toolPolicies) // production wiring (gateway.go)

	w := httptest.NewRecorder()
	gw.builtinToolInvoke(w, mkBuiltinReq(), "org-1", mcpagg.Identity{AgentID: "agent-1"},
		mcpagg.InvokeRequest{Server: "yabanin", Tool: "web_fetch",
			Params: json.RawMessage(`{"url":"` + up.URL + `/leak"}`)})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("result-deny status = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	if up.calls != 1 {
		t.Fatalf("the upstream ran (the result is dropped, not the call), got %d", up.calls)
	}
	if strings.Contains(w.Body.String(), "upstream-seen") {
		t.Fatal("the denied result must never reach the caller")
	}
}

func mkBuiltinReq() *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/mcp/invoke", nil)
	r.Header.Set("X-Org-Id", "org-1")
	r.Header.Set("X-Agent-Id", "agent-1")
	return r
}

// --- G2: the chat response surface must gate DECLARED ARGUMENTS ------------

func declaredCall(name, args string) string {
	return `{"id":"1","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[` +
		`{"id":"c1","type":"function","function":{"name":"` + name + `","arguments":` + args + `}}]},` +
		`"finish_reason":"tool_calls"}],"usage":{"total_tokens":5}}`
}

// TestGateToolCallsJSON_ArgsDenyStripsCall: a schema-violating declared
// tool_call is stripped before the client (the executor) sees it. The
// unrelated deny row activates the response surface (HasDenyPolicies
// fast-skip, unchanged posture).
func TestGateToolCallsJSON_ArgsDenyStripsCall(t *testing.T) {
	resp := []byte(declaredCall("web_fetch", `"{\"url\":\"https://x.test\"}"`))
	gw := gateWith(denyTool("unrelated_tool"), rulesRow("schema", "*", "web_fetch",
		`{"args":{"schema":{"type":"object","properties":{"url":{"type":"string","maxLength":3}},"required":["url"],"additionalProperties":false}}}`))

	got, denied := gw.gateToolCallsJSON(context.Background(), "org-1", "agent-1", resp)
	if len(denied) != 1 || denied[0] != "web_fetch" {
		t.Fatalf("denied = %v, want the schema-violating call stripped", denied)
	}
	if strings.Contains(string(got), "web_fetch") {
		t.Fatalf("the violating declared call reached the client: %s", got)
	}
	var doc struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("filtered body must be valid JSON: %v", err)
	}
	if doc.Choices[0].FinishReason != "stop" {
		t.Fatalf("finish_reason must normalize, got %q", doc.Choices[0].FinishReason)
	}
}

// TestGateToolCallsJSON_ArgsAllowByteIdentity: valid declared arguments
// pass byte-identical (surface activated by the unrelated deny row).
func TestGateToolCallsJSON_ArgsAllowByteIdentity(t *testing.T) {
	resp := []byte(declaredCall("web_fetch", `"{\"url\":\"https://x.test\"}"`))
	gw := gateWith(denyTool("unrelated_tool"), rulesRow("schema", "*", "web_fetch",
		`{"args":{"schema":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}}`))

	got, denied := gw.gateToolCallsJSON(context.Background(), "org-1", "agent-1", resp)
	if len(denied) != 0 || string(got) != string(resp) {
		t.Fatalf("valid args must pass byte-identical (denied=%v): %s", denied, got)
	}
}

// TestSSEToolGate_ArgsDenyHeldUntilComplete: argument fragments of an
// allowed-name call are held until the calls complete; an args-denied call
// is then dropped whole — the client never receives a single fragment.
func TestSSEToolGate_ArgsDenyHeldUntilComplete(t *testing.T) {
	engine := toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{
		rulesRow("cap", "*", "web_fetch", `{"args":{"schema":{"type":"object","properties":{"url":{"type":"string","maxLength":3}},"required":["url"]}}}`),
	}}, time.Minute)
	rec := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), rec, engine, "org-1", "agent-1", true)

	// An allowed-name call whose arguments stream in fragments.
	mustWrite(t, g, []byte(`data: {"id":1,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"web_fetch","arguments":"{\"url\":\"https"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"id":1,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"://x.test\"}"}}]}}]}`+"\n\n"))
	// Terminal: the accumulated arguments violate maxLength → drop.
	mustWrite(t, g, []byte(`data: {"id":1,"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))
	g.Flush()

	body := rec.Body.String()
	if strings.Contains(body, "web_fetch") || strings.Contains(body, "x.test") {
		t.Fatalf("the args-denied declared call leaked to the client:\n%s", body)
	}
	if !strings.Contains(body, `"finish_reason":"stop"`) {
		t.Fatalf("finish_reason must be rewritten when every call was dropped:\n%s", body)
	}
	if g.DeniedCount() != 1 {
		t.Fatalf("denied count = %d, want 1", g.DeniedCount())
	}
}

// TestSSEToolGate_ArgsAllowStreamsKept: an args-valid call streams out
// (held until complete, then released unchanged).
func TestSSEToolGate_ArgsAllowStreamsKept(t *testing.T) {
	engine := toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{
		rulesRow("cap", "*", "web_fetch", `{"args":{"schema":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}}`),
	}}, time.Minute)
	rec := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), rec, engine, "org-1", "agent-1", true)

	mustWrite(t, g, []byte(`data: {"id":1,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"web_fetch","arguments":"{\"url\":"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"id":1,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"https://x.test\"}"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"id":1,"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))
	g.Flush()

	body := rec.Body.String()
	if !strings.Contains(body, "x.test") {
		t.Fatalf("the valid declared call must stream to the client:\n%s", body)
	}
	if g.DeniedCount() != 0 {
		t.Fatalf("denied count = %d, want 0", g.DeniedCount())
	}
}

// --- G3: the native MCP catalog/pre-gate must be server-aware --------------

// TestBackendServerScopedDenyHidesAndBlocks: a Server='github' deny row is
// INVISIBLE to the old chat-path Decide — the catalog listed the tool and
// the pre-gate passed the call to the (guarded) invoke path. Server-aware
// the row hides the tool from tools/list and blocks tools/call BEFORE the
// proxy seam (zero downstream calls).
func TestBackendServerScopedDenyHidesAndBlocks(t *testing.T) {
	gw := testGatewayForMCP(t)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{
		{OrgID: "org1", Name: "no-gh-delete", Subject: "*", Server: "github",
			Tool: "delete_issue", Action: toolpolicy.ActionDeny, Enabled: true},
	}}, time.Minute)

	b := mcpServerBackend{gw: gw}
	b.listGrants = func(context.Context, string, string) ([]*mcpagg.Grant, error) {
		return []*mcpagg.Grant{{ServerName: "github", AllowedTools: nil, Enabled: true}}, nil
	}
	b.getServer = func(context.Context, string, string) (*mcpagg.Server, error) {
		return &mcpagg.Server{Name: "github", Enabled: true}, nil
	}
	b.listUpstreamTools = func(context.Context, string, mcpagg.Identity, string) ([]mcpagg.ToolDescriptor, error) {
		return []mcpagg.ToolDescriptor{
			{Name: "search"}, {Name: "delete_issue"},
		}, nil
	}
	invoked := 0
	b.invoke = func(context.Context, string, mcpagg.Identity, mcpagg.InvokeRequest) (json.RawMessage, error) {
		invoked++
		return json.RawMessage(`{"content":[]}`), nil
	}

	tools, err := b.Tools(context.Background(), mcpserverPrincipal("org1", "agent1"))
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	for _, tl := range tools {
		if tl.Name == "delete_issue" {
			t.Fatalf("server-scoped denied tool still listed: %+v", tools)
		}
	}
	if len(tools) != 1 || tools[0].Name != "search" {
		t.Fatalf("catalog = %+v", tools)
	}

	_, err = b.Call(context.Background(), mcpserverPrincipal("org1", "agent1"),
		"github:delete_issue", json.RawMessage(`{"id":42}`))
	var tcErr *mcpserver.ToolCallError
	if !errors.As(err, &tcErr) || tcErr.Code != "policy_denied" {
		t.Fatalf("server-scoped deny must block the call pre-proxy, got %v", err)
	}
	if invoked != 0 {
		t.Fatalf("denied call must not reach the invoke path, got %d calls", invoked)
	}

	// A different server with the same tool name stays visible: the row is
	// scoped to "github".
	b.listGrants = func(context.Context, string, string) ([]*mcpagg.Grant, error) {
		return []*mcpagg.Grant{{ServerName: "gitlab", AllowedTools: nil, Enabled: true}}, nil
	}
	b.getServer = func(_ context.Context, _ string, name string) (*mcpagg.Server, error) {
		return &mcpagg.Server{Name: name, Enabled: true}, nil
	}
	tools, err = b.Tools(context.Background(), mcpserverPrincipal("org1", "agent1"))
	if err != nil {
		t.Fatalf("Tools[gitlab]: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("server-scoped row must not leak into other servers: %+v", tools)
	}
}
