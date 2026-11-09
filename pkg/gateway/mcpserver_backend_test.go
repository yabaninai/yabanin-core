package cli

// grant/policy catalog assembly, flat-name splitting, and the reuse of the
// mcpagg invoke path with its error vocabulary. The store/proxy are
// narrowed to function seams so no DB is needed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/mcpserver"
	"github.com/reireirei/yabanin/pkg/requestid"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

func testGatewayForMCP(t *testing.T) *gateway {
	t.Helper()
	return &gateway{log: slog.New(slog.DiscardHandler)}
}

func backendWith(t *testing.T, mutate func(b *mcpServerBackend)) mcpServerBackend {
	t.Helper()
	b := mcpServerBackend{gw: testGatewayForMCP(t)}
	mutate(&b)
	return b
}

var (
	grantSearch = &mcpagg.Grant{
		OrgID: "org1", AgentID: "agent1", ServerName: "knowledge",
		AllowedTools: []string{"search"}, Enabled: true,
	}
	serverKnowledge = &mcpagg.Server{
		OrgID: "org1", Name: "knowledge", URL: "https://mcp.example.com",
		AllowedTools: []string{"search", "admin_wipe"}, Enabled: true,
	}
	upstreamTools = []mcpagg.ToolDescriptor{
		{Name: "search", Description: "search docs", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "admin_wipe", Description: "dangerous"},
	}
)

func TestBackendToolsGrantFiltering(t *testing.T) {
	b := backendWith(t, func(b *mcpServerBackend) {
		b.listGrants = func(context.Context, string, string) ([]*mcpagg.Grant, error) {
			return []*mcpagg.Grant{grantSearch}, nil
		}
		b.getServer = func(_ context.Context, orgID, name string) (*mcpagg.Server, error) {
			if orgID != "org1" || name != "knowledge" {
				return nil, mcpagg.ErrNotFound
			}
			return serverKnowledge, nil
		}
		b.listUpstreamTools = func(_ context.Context, orgID string, id mcpagg.Identity, server string) ([]mcpagg.ToolDescriptor, error) {
			if orgID != "org1" || id.AgentID != "agent1" || server != "knowledge" {
				t.Errorf("upstream discovery called with org=%q agent=%q server=%q", orgID, id.AgentID, server)
			}
			return upstreamTools, nil
		}
	})
	tools, err := b.Tools(context.Background(), mcpserver.Principal{OrgID: "org1", AgentID: "agent1"})
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	// grant search-only ∩ server {search, admin_wipe} → search only; the
	// allow-list ceiling hides admin_wipe even though upstream advertises it.
	if len(tools) != 1 || tools[0].Name != "search" {
		t.Fatalf("catalog = %+v", tools)
	}
	if tools[0].Description != "search docs" || string(tools[0].InputSchema) != `{"type":"object"}` {
		t.Fatalf("descriptor = %+v", tools[0])
	}
}

func TestBackendToolsPolicyDenyHidesTool(t *testing.T) {
	b := backendWith(t, func(b *mcpServerBackend) {
		b.listGrants = func(context.Context, string, string) ([]*mcpagg.Grant, error) {
			return []*mcpagg.Grant{grantSearch}, nil
		}
		b.getServer = func(context.Context, string, string) (*mcpagg.Server, error) { return serverKnowledge, nil }
		b.listUpstreamTools = func(context.Context, string, mcpagg.Identity, string) ([]mcpagg.ToolDescriptor, error) {
			return upstreamTools, nil
		}
		b.decide = func(_ context.Context, _, _, _ string, tool string) toolpolicy.Decision {
			if tool == "search" {
				return toolpolicy.Decision{Action: toolpolicy.ActionDeny}
			}
			return toolpolicy.Decision{}
		}
	})
	tools, err := b.Tools(context.Background(), mcpserver.Principal{OrgID: "org1", AgentID: "agent1"})
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(tools) != 0 {
		t.Fatalf("denied tool still listed: %+v", tools)
	}
}

func TestBackendToolsDeadUpstreamSkipped(t *testing.T) {
	b := backendWith(t, func(b *mcpServerBackend) {
		b.listGrants = func(context.Context, string, string) ([]*mcpagg.Grant, error) {
			return []*mcpagg.Grant{
				{ServerName: "dead", AllowedTools: []string{"x"}, Enabled: true},
				{ServerName: "alive", AllowedTools: []string{"y"}, Enabled: true},
			}, nil
		}
		b.getServer = func(_ context.Context, _ string, name string) (*mcpagg.Server, error) {
			if name == "removed" {
				return nil, mcpagg.ErrNotFound
			}
			return &mcpagg.Server{Name: name, Enabled: true}, nil
		}
		b.listUpstreamTools = func(_ context.Context, _ string, _ mcpagg.Identity, server string) ([]mcpagg.ToolDescriptor, error) {
			if server == "dead" {
				return nil, errors.New("connection refused")
			}
			return []mcpagg.ToolDescriptor{{Name: "y"}}, nil
		}
	})
	tools, err := b.Tools(context.Background(), mcpserver.Principal{OrgID: "org1", AgentID: "agent1"})
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "y" {
		t.Fatalf("dead upstream must not break the catalog: %+v", tools)
	}
}

// AUTH-02: the native MCP catalog must apply the delegation-chain ceiling —
// the same fact the invoke path enforces — so discovery cannot leak a tool
// that a parent restriction (or a missing ancestor grant) would reject at
// call time.
func TestBackendTools_DelegationChainCeiling(t *testing.T) {
	// Child's OWN grant on knowledge is unrestricted; only the chain ceiling
	// (parent search-only) narrows the catalog.
	b := backendWith(t, func(b *mcpServerBackend) {
		b.listGrants = func(context.Context, string, string) ([]*mcpagg.Grant, error) {
			return []*mcpagg.Grant{{ServerName: "knowledge", AllowedTools: nil, Enabled: true}}, nil
		}
		b.getServer = func(context.Context, string, string) (*mcpagg.Server, error) {
			return serverKnowledge, nil // allows search + admin_wipe
		}
		b.listUpstreamTools = func(context.Context, string, mcpagg.Identity, string) ([]mcpagg.ToolDescriptor, error) {
			return upstreamTools, nil
		}
		b.chainAllowance = func(_ context.Context, _ string, _ string) (mcpagg.ChainAllowance, error) {
			return mcpagg.ChainAllowance{"knowledge": []string{"search"}}, nil
		}
	})
	tools, err := b.Tools(context.Background(), mcpserver.Principal{OrgID: "org1", AgentID: "agent1"})
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "search" {
		t.Fatalf("chain ceiling must hide parent-restricted tools: %+v", tools)
	}
}

// AUTH-02: a server the delegation chain has no access to (an ancestor
// holds no enabled grant) must not appear in the catalog at all.
func TestBackendTools_DelegationChainHidesServer(t *testing.T) {
	b := backendWith(t, func(b *mcpServerBackend) {
		b.listGrants = func(context.Context, string, string) ([]*mcpagg.Grant, error) {
			return []*mcpagg.Grant{grantSearch}, nil
		}
		b.getServer = func(context.Context, string, string) (*mcpagg.Server, error) {
			t.Fatal("server lookup must not run for a chain-hidden server")
			return nil, errors.New("unreachable: chain-hidden server")
		}
		b.chainAllowance = func(context.Context, string, string) (mcpagg.ChainAllowance, error) {
			return mcpagg.ChainAllowance{}, nil // broken chain: nothing allowed
		}
	})
	tools, err := b.Tools(context.Background(), mcpserver.Principal{OrgID: "org1", AgentID: "agent1"})
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(tools) != 0 {
		t.Fatalf("chain-hidden server must contribute no tools: %+v", tools)
	}
}

func TestBackendCallReusesInvokePath(t *testing.T) {
	var gotReq mcpagg.InvokeRequest
	b := backendWith(t, func(b *mcpServerBackend) {
		b.invoke = func(_ context.Context, orgID string, id mcpagg.Identity, req mcpagg.InvokeRequest) (json.RawMessage, error) {
			if orgID != "org1" || id.AgentID != "agent1" || id.RequestID != "req-1" {
				t.Errorf("identity = %+v org=%q", id, orgID)
			}
			gotReq = req
			return json.RawMessage(`{"content":[]}`), nil
		}
	})
	res, err := b.Call(context.Background(),
		mcpserver.Principal{OrgID: "org1", AgentID: "agent1", RequestID: "req-1"},
		"knowledge:search", json.RawMessage(`{"q":"x"}`))
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if gotReq.Server != "knowledge" || gotReq.Tool != "search" || string(gotReq.Params) != `{"q":"x"}` {
		t.Fatalf("invoke request = %+v", gotReq)
	}
	if string(res) != `{"content":[]}` {
		t.Fatalf("result = %s", res)
	}
}

func TestBackendCallPolicyDenied(t *testing.T) {
	b := backendWith(t, func(b *mcpServerBackend) {
		b.invoke = func(context.Context, string, mcpagg.Identity, mcpagg.InvokeRequest) (json.RawMessage, error) {
			t.Fatal("policy-denied call must not reach the proxy")
			return nil, nil
		}
		b.decide = func(context.Context, string, string, string, string) toolpolicy.Decision {
			return toolpolicy.Decision{Action: toolpolicy.ActionDeny}
		}
	})
	_, err := b.Call(context.Background(), mcpserver.Principal{OrgID: "org1", AgentID: "a"},
		"srv:tool", json.RawMessage(`{}`))
	var tcErr *mcpserver.ToolCallError
	if !errors.As(err, &tcErr) || tcErr.Code != "policy_denied" {
		t.Fatalf("policy denial = %v", err)
	}
}

func TestBackendCallErrorMapping(t *testing.T) {
	b := backendWith(t, func(b *mcpServerBackend) {
		b.invoke = func(_ context.Context, _ string, _ mcpagg.Identity, req mcpagg.InvokeRequest) (json.RawMessage, error) {
			switch req.Tool {
			case "locked":
				return nil, &mcpagg.AuthRequiredError{Kind: "oauth", URL: "/api/mcp/auth/srv/begin", Message: "re-auth"}
			case "blocked":
				return nil, &mcpagg.InvokeError{Code: mcpagg.ErrCodeToolBlocked, Message: "deny_regex"}
			default:
				return nil, errors.New("boom")
			}
		}
	})
	p := mcpserver.Principal{OrgID: "org1", AgentID: "a"}

	// mcp_auth_required carries kind + url through.
	_, err := b.Call(context.Background(), p, "srv:locked", nil)
	var tcErr *mcpserver.ToolCallError
	if !errors.As(err, &tcErr) || tcErr.Code != "mcp_auth_required" || tcErr.Kind != "oauth" || tcErr.URL != "/api/mcp/auth/srv/begin" {
		t.Fatalf("auth required = %v", err)
	}

	// Guard blocks map code-for-code.
	_, err = b.Call(context.Background(), p, "srv:blocked", nil)
	if !errors.As(err, &tcErr) || tcErr.Code != mcpagg.ErrCodeToolBlocked {
		t.Fatalf("tool blocked = %v", err)
	}

	// Unknown infrastructure errors stay plain (internal -32603 upstream).
	_, err = b.Call(context.Background(), p, "srv:other", nil)
	if errors.As(err, &tcErr) {
		t.Fatalf("plain error must stay plain: %v", err)
	}
}

func TestSplitToolName(t *testing.T) {
	for _, tc := range []struct {
		in      string
		server  string
		tool    string
		wantErr bool
	}{
		{"knowledge:search", "knowledge", "search", false},
		{"a:b:c", "a", "b:c", false}, // tool names may contain colons
		{"noseparator", "", "", true},
		{":tool", "", "", true},
		{"server:", "", "", true},
	} {
		server, tool, err := splitToolName(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("splitToolName(%q) err = %v", tc.in, err)
		}
		if err == nil && (server != tc.server || tool != tc.tool) {
			t.Fatalf("splitToolName(%q) = %q, %q", tc.in, server, tool)
		}
	}
}

func TestMCPStreamablePrincipal(t *testing.T) {
	gw := testGatewayForMCP(t)
	extract := mcpStreamablePrincipal(gw)

	// No org → 401.
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/mcp", nil)
	if _, err := extract(req); err == nil {
		t.Fatal("missing org must fail")
	}

	// Org but no agent → 403 agent_only (a ypk_ key shape).
	req = httptest.NewRequestWithContext(context.Background(), "POST", "/mcp", nil)
	req.Header.Set("X-Org-Id", "org1")
	_, err := extract(req)
	pe, ok := err.(*mcpserver.PrincipalError)
	if !ok || pe.Status != 403 || pe.Code != "agent_only" {
		t.Fatalf("non-agent = %v", err)
	}

	// Full principal: the request id comes from the logctx.
	req = httptest.NewRequestWithContext(context.Background(), "POST", "/mcp", nil)
	req.Header.Set("X-Org-Id", "org1")
	req.Header.Set("X-Agent-Id", "agent1")
	req.Header.Set("X-Team-Id", "team1")
	req.Header.Set("X-Yabanin-Task", "task-9")
	req = req.WithContext(requestid.NewContext(req.Context(), requestid.ID("req-42")))
	p, err := extract(req)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if p.OrgID != "org1" || p.AgentID != "agent1" || p.TeamID != "team1" ||
		p.RequestID != "req-42" || p.TaskID != "task-9" {
		t.Fatalf("principal = %+v", p)
	}
}

func TestToolOnBothAllowLists(t *testing.T) {
	if !toolOnBothAllowLists(nil, nil, "x") {
		t.Fatal("empty lists allow all")
	}
	if !toolOnBothAllowLists([]string{"a", "b"}, []string{"b"}, "b") {
		t.Fatal("intersection passes")
	}
	if toolOnBothAllowLists([]string{"a"}, []string{"b"}, "x") {
		t.Fatal("non-member denied")
	}
	if toolOnBothAllowLists([]string{"a"}, nil, "b") {
		t.Fatal("server ceiling binds")
	}
}

func TestSortCatalogEntries(t *testing.T) {
	entries := []catalogEntry{
		{server: "wiki", desc: mcpserver.ToolDesc{Name: "search"}},
		{server: "knowledge", desc: mcpserver.ToolDesc{Name: "search"}},
		{server: "git", desc: mcpserver.ToolDesc{Name: "admin_wipe"}},
	}
	sortCatalogEntries(entries)
	// (name, server) order: equal names resolve deterministically by server,
	// so pagination and ambiguity listings never depend on grant order.
	if entries[0].desc.Name != "admin_wipe" ||
		entries[1].server != "knowledge" || entries[2].server != "wiki" {
		t.Fatalf("sorted = %+v", entries)
	}
}

// TestMCPStreamableEndToEnd is the composition smoke: the protocol handler
// wired to the real gateway adapters (seamed store/proxy), driven the way
// an MCP client drives it over the gateway router surface.
func TestMCPStreamableEndToEnd(t *testing.T) {
	gw := testGatewayForMCP(t)
	backend := mcpServerBackend{gw: gw}
	backend.listGrants = func(context.Context, string, string) ([]*mcpagg.Grant, error) {
		return []*mcpagg.Grant{{ServerName: "knowledge", AllowedTools: nil, Enabled: true}}, nil
	}
	backend.getServer = func(context.Context, string, string) (*mcpagg.Server, error) {
		return &mcpagg.Server{Name: "knowledge", Enabled: true}, nil
	}
	backend.listUpstreamTools = func(context.Context, string, mcpagg.Identity, string) ([]mcpagg.ToolDescriptor, error) {
		return []mcpagg.ToolDescriptor{{Name: "search"}}, nil
	}
	backend.invoke = func(context.Context, string, mcpagg.Identity, mcpagg.InvokeRequest) (json.RawMessage, error) {
		return json.RawMessage(`{"content":[{"type":"text","text":"hi"}],"isError":false}`), nil
	}

	handler := mcpserver.New(mcpserver.Config{Principal: mcpStreamablePrincipal(gw)}, backend, gw.log, []byte("e2e-secret"))

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), "POST", "/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Org-Id", "org1")
		req.Header.Set("X-Agent-Id", "agent1")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`); rec.Code != 200 {
		t.Fatalf("initialize: %d %s", rec.Code, rec.Body.String())
	}
	rec := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	var listResp struct {
		Result struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil || len(listResp.Result.Tools) != 1 || listResp.Result.Tools[0].Name != "search" {
		t.Fatalf("tools/list: %d %s", rec.Code, rec.Body.String())
	}
	rec = post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"knowledge:search","arguments":{}}}`)
	var callResp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &callResp); err != nil || len(callResp.Result.Content) != 1 || callResp.Result.Content[0].Text != "hi" {
		t.Fatalf("tools/call: %d %s", rec.Code, rec.Body.String())
	}
}

// newMCPBackendTwoServers builds a backend whose catalog carries the same
// bare tool name from two granted servers (the AUDIT-P1-02 collision
// scenario). The invoke seam records every (server, tool) it receives.
func newMCPBackendTwoServers(t *testing.T) (mcpServerBackend, *[]mcpagg.InvokeRequest) {
	t.Helper()
	gw := testGatewayForMCP(t)
	b := mcpServerBackend{gw: gw}
	b.listGrants = func(context.Context, string, string) ([]*mcpagg.Grant, error) {
		return []*mcpagg.Grant{
			{ServerName: "knowledge", AllowedTools: nil, Enabled: true},
			{ServerName: "wiki", AllowedTools: nil, Enabled: true},
		}, nil
	}
	b.getServer = func(_ context.Context, _ string, name string) (*mcpagg.Server, error) {
		return &mcpagg.Server{Name: name, Enabled: true}, nil
	}
	b.listUpstreamTools = func(_ context.Context, _ string, _ mcpagg.Identity, server string) ([]mcpagg.ToolDescriptor, error) {
		// both servers advertise the identical bare tool name "search";
		// wiki additionally exposes a unique name so the catalog keeps both
		// servers visible.
		if server == "knowledge" {
			return []mcpagg.ToolDescriptor{{Name: "search"}}, nil
		}
		return []mcpagg.ToolDescriptor{{Name: "search"}, {Name: "wiki_pages"}}, nil
	}
	var calls []mcpagg.InvokeRequest
	b.invoke = func(_ context.Context, _ string, _ mcpagg.Identity, req mcpagg.InvokeRequest) (json.RawMessage, error) {
		calls = append(calls, req)
		return json.RawMessage(`{"content":[{"type":"text","text":"from ` + req.Server + `"}],"isError":false}`), nil
	}
	return b, &calls
}

// AUDIT-P1-02 unit level: the bare advertised name must resolve through the
// exact catalog pipeline and reach the invoke path with the owning
// (server, tool); an unknown bare name stays not_found without touching the
// proxy.
func TestBackendCallBareAdvertisedName(t *testing.T) {
	b, calls := newMCPBackendTwoServers(t)
	p := mcpserver.Principal{OrgID: "org1", AgentID: "agent1"}

	// The wiki server's "search" is ambiguous (knowledge also advertises it)
	// but "wiki_pages" resolves uniquely — the single-owner advertised name
	// must invoke with its owning server.
	if _, err := b.Call(context.Background(), p, "wiki_pages", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("bare unique name: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0].Server != "wiki" || (*calls)[0].Tool != "wiki_pages" {
		t.Fatalf("upstream calls = %+v", *calls)
	}

	// Unknown bare name → not_found, zero proxy traffic.
	before := len(*calls)
	_, err := b.Call(context.Background(), p, "no_such_tool", json.RawMessage(`{}`))
	var tcErr *mcpserver.ToolCallError
	if !errors.As(err, &tcErr) || tcErr.Code != mcpagg.ErrCodeNotFound {
		t.Fatalf("unknown bare name = %v", err)
	}
	if len(*calls) != before {
		t.Fatalf("unknown name must not reach the proxy")
	}
}

// AUDIT-P1-02 collision: the same bare tool name advertised by two granted
// servers must resolve deterministically — the bare form refuses with
// not_found naming both namespaced candidates in catalog order, and only
// the namespaced forms reach a tool (namespaced form wins/disambiguates).
func TestBackendCallBareNameAmbiguous(t *testing.T) {
	b, calls := newMCPBackendTwoServers(t)
	p := mcpserver.Principal{OrgID: "org1", AgentID: "agent1"}

	_, err := b.Call(context.Background(), p, "search", json.RawMessage(`{}`))
	var tcErr *mcpserver.ToolCallError
	if !errors.As(err, &tcErr) || tcErr.Code != mcpagg.ErrCodeNotFound {
		t.Fatalf("ambiguous bare name = %v", err)
	}
	// Deterministic: candidates from the caller's own catalog, sorted.
	if tcErr.Message != `tool "search" is ambiguous across servers; use the namespaced "server:tool" form: knowledge:search, wiki:search` {
		t.Fatalf("ambiguity message = %q", tcErr.Message)
	}
	if len(*calls) != 0 {
		t.Fatalf("ambiguous bare form must not invoke upstream, got %+v", *calls)
	}

	// The namespaced forms disambiguate — each reaches its own server.
	if _, err := b.Call(context.Background(), p, "knowledge:search", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("namespaced knowledge call: %v", err)
	}
	if _, err := b.Call(context.Background(), p, "wiki:search", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("namespaced wiki call: %v", err)
	}
	if len(*calls) != 2 ||
		(*calls)[0].Server != "knowledge" || (*calls)[1].Server != "wiki" {
		t.Fatalf("upstream calls = %+v", *calls)
	}
}

// AUDIT-P1-02: a bare name the catalog hides (org deny policy) resolves to
// not_found — hidden, never policy_denied — and never reaches the proxy;
// the namespaced form of the same denied tool keeps the documented
// pre-invoke policy_denied refusal; both paths are pinned by regression
// tests above.
func TestBackendCallBareNamePolicyHidden(t *testing.T) {
	b, calls := newMCPBackendTwoServers(t)
	b.decide = func(_ context.Context, _, _, server, tool string) toolpolicy.Decision {
		if server == "wiki" && tool == "wiki_pages" {
			return toolpolicy.Decision{Action: toolpolicy.ActionDeny}
		}
		return toolpolicy.Decision{}
	}
	p := mcpserver.Principal{OrgID: "org1", AgentID: "agent1"}

	_, err := b.Call(context.Background(), p, "wiki_pages", json.RawMessage(`{}`))
	var tcErr *mcpserver.ToolCallError
	if !errors.As(err, &tcErr) || tcErr.Code != mcpagg.ErrCodeNotFound {
		t.Fatalf("policy-hidden bare name = %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("hidden bare name must not reach the proxy, got %+v", *calls)
	}

	// Namespaced form of the denied tool → policy_denied pre-invoke.
	_, err = b.Call(context.Background(), p, "wiki:wiki_pages", json.RawMessage(`{}`))
	if !errors.As(err, &tcErr) || tcErr.Code != "policy_denied" {
		t.Fatalf("namespaced denied tool = %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("denied call must not reach the proxy, got %+v", *calls)
	}
}

// mcpPost rounds one JSON-RPC message through the real protocol handler
// (the way an MCP client drives the gateway endpoint).
func mcpPost(t *testing.T, handler *mcpserver.Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Org-Id", "org1")
	req.Header.Set("X-Agent-Id", "agent1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestMCPStreamableEndToEndAdvertisedName is the AUDIT-P1-02 acceptance
// probe: tools/list through the REAL protocol handler, then tools/call of
// the EXACT name string the listing returned (parsed from the wire, not
// hardcoded) — the call must succeed and reach the invoke seam exactly once
// with the owning (server, tool). Before the fix this exact scenario
// answered not_found with zero upstream traffic.
func TestMCPStreamableEndToEndAdvertisedName(t *testing.T) {
	gw := testGatewayForMCP(t)
	backend := mcpServerBackend{gw: gw}
	backend.listGrants = func(context.Context, string, string) ([]*mcpagg.Grant, error) {
		return []*mcpagg.Grant{{ServerName: "knowledge", AllowedTools: nil, Enabled: true}}, nil
	}
	backend.getServer = func(context.Context, string, string) (*mcpagg.Server, error) {
		return &mcpagg.Server{Name: "knowledge", Enabled: true}, nil
	}
	backend.listUpstreamTools = func(context.Context, string, mcpagg.Identity, string) ([]mcpagg.ToolDescriptor, error) {
		return []mcpagg.ToolDescriptor{{Name: "search", Description: "search docs"}}, nil
	}
	upstreamInvoked := false
	backend.invoke = func(_ context.Context, _ string, _ mcpagg.Identity, req mcpagg.InvokeRequest) (json.RawMessage, error) {
		upstreamInvoked = true
		if req.Server != "knowledge" || req.Tool != "search" {
			t.Errorf("invoke seam got %+v, want knowledge/search", req)
		}
		return json.RawMessage(`{"content":[{"type":"text","text":"hi"}],"isError":false}`), nil
	}

	handler := mcpserver.New(mcpserver.Config{Principal: mcpStreamablePrincipal(gw)}, backend, gw.log, []byte("e2e-secret"))

	if rec := mcpPost(t, handler, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`); rec.Code != 200 {
		t.Fatalf("initialize: %d %s", rec.Code, rec.Body.String())
	}
	rec := mcpPost(t, handler, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	var listResp struct {
		Result struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil || len(listResp.Result.Tools) != 1 {
		t.Fatalf("tools/list: %d %s", rec.Code, rec.Body.String())
	}
	advertised := listResp.Result.Tools[0].Name // the EXACT discovery-derived name

	rec = mcpPost(t, handler, fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":%s,"arguments":{}}}`, mustJSON(t, advertised)))
	var callResp struct {
		Result struct {
			Content []struct{ Text string } `json:"content"`
		} `json:"result"`
		Error *struct {
			Data struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &callResp); err != nil {
		t.Fatalf("tools/call decode: %v body=%s", err, rec.Body.String())
	}
	if callResp.Error != nil {
		t.Fatalf("advertised name %q must be callable, got error %+v (%s)", advertised, callResp.Error, rec.Body.String())
	}
	if len(callResp.Result.Content) != 1 || callResp.Result.Content[0].Text != "hi" {
		t.Fatalf("tools/call result = %s", rec.Body.String())
	}
	if !upstreamInvoked {
		t.Fatal("upstream_invoked=false: the advertised call never reached the invoke seam")
	}
}

// TestMCPStreamableEndToEndCollision drives the two-server collision
// through the real protocol handler: tools/list advertises "search" twice
// (one entry per server), the bare form answers a DETERMINISTIC not_found
// ambiguity error naming both namespaced candidates in catalog order, and
// each namespaced form reaches its own upstream server.
func TestMCPStreamableEndToEndCollision(t *testing.T) {
	gw := testGatewayForMCP(t)
	backend, calls := newMCPBackendTwoServers(t)

	handler := mcpserver.New(mcpserver.Config{Principal: mcpStreamablePrincipal(gw)}, backend, gw.log, []byte("e2e-secret"))

	if rec := mcpPost(t, handler, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`); rec.Code != 200 {
		t.Fatalf("initialize: %d %s", rec.Code, rec.Body.String())
	}

	// The catalog advertises the colliding bare name twice.
	rec := mcpPost(t, handler, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	var listResp struct {
		Result struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("tools/list decode: %v body=%s", err, rec.Body.String())
	}
	var bare int
	for _, tl := range listResp.Result.Tools {
		if tl.Name == "search" {
			bare++
		}
	}
	if bare != 2 {
		t.Fatalf("both servers must advertise %q, listing = %+v", "search", listResp.Result.Tools)
	}

	// Bare colliding form: deterministic ambiguity refusal (no silent pick).
	rec = mcpPost(t, handler, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{}}}`)
	var callResp struct {
		Error *struct {
			Data struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &callResp); err != nil {
		t.Fatalf("bare call decode: %v body=%s", err, rec.Body.String())
	}
	if callResp.Error == nil || callResp.Error.Data.Code != mcpagg.ErrCodeNotFound {
		t.Fatalf("bare colliding call must be not_found, got %s", rec.Body.String())
	}
	wantMsg := `tool "search" is ambiguous across servers; use the namespaced "server:tool" form: knowledge:search, wiki:search`
	if callResp.Error.Data.Message != wantMsg {
		t.Fatalf("ambiguity message = %q, want %q", callResp.Error.Data.Message, wantMsg)
	}
	if len(*calls) != 0 {
		t.Fatalf("ambiguous bare form must not reach upstream, got %+v", *calls)
	}

	// Namespaced forms win the disambiguation, each hitting its own server.
	for i, name := range []string{"knowledge:search", "wiki:search"} {
		rec := mcpPost(t, handler, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, 4+i, name))
		if rec.Code != 200 || strings.Contains(rec.Body.String(), `"error"`) {
			t.Fatalf("namespaced call %q: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if len(*calls) != 2 || (*calls)[0].Server != "knowledge" || (*calls)[1].Server != "wiki" {
		t.Fatalf("upstream calls = %+v", *calls)
	}
}

// mustJSON marshals v or fails the test — small helper for embedding
// client-controlled strings into JSON-RPC bodies verbatim.
func mustJSON(t *testing.T, v string) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %q: %v", v, err)
	}
	return string(b)
}
