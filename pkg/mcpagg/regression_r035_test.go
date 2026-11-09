package mcpagg

// scenario-level regressions on the MCP invoke path, e2e through the REAL
// toolpolicy.Engine. Acceptance criterion of the packet: a denied call never
// reaches the upstream tool (counting mock == 0) with a documented error,
// while the working path executes exactly once under the same policy set.
//
//	§3.1 per-tool: the deny-gh-delete / allow-github row pair on the registry server (named `knowledge` by the store mock; the contract example names it `github`).
//	§3.2 per-argument: the create_issue rules row (schema required title +
//	     deny_regex "BEGIN (RSA )?PRIVATE KEY"), inputs А (valid), Б
//	     (secret material), В (truncated JSON).
//	§3.3 foreign tenant + subject scoping: an org without rows implicitly
//	     allows the same coordinates; a subject-scoped row bites only its
//	     subject.
//
// mechanism boundaries stay pinned by proxy_boundary_r035_test.go.
// and are not duplicated here.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// regGrant is an enabled agent grant (AllowedTools nil = every tool).
func regGrant(agentID, serverName string) *Grant {
	return &Grant{ID: "gr-reg", OrgID: "org-1", AgentID: agentID,
		ServerName: serverName, AllowedActions: defaultActions(), Enabled: true}
}

func regInvoke(p *Proxy, org, agent, server, tool, params string) (json.RawMessage, error) {
	return p.Invoke(context.Background(), org, Identity{AgentID: agent},
		InvokeRequest{Server: server, Tool: tool, Params: json.RawMessage(params)})
}

// contract example §3.1: per-tool permissions.
func TestRegression_PerToolDenyRow_ZeroUpstream(t *testing.T) {
	up := newBoundaryUpstream(t)
	eng := guardEngine(t,
		toolpolicy.Policy{OrgID: "org-1", Name: "deny-gh-delete", Subject: "*",
			Server: "knowledge", Tool: "delete_issue", Action: toolpolicy.ActionDeny,
			Priority: 50, Enabled: true},
		toolpolicy.Policy{OrgID: "org-1", Name: "allow-github", Subject: "*",
			Server: "knowledge", Tool: "*", Action: toolpolicy.ActionAllow,
			Priority: 100, Enabled: true},
	)
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, regGrant("ag-1", "knowledge")),
		testConfig(), loopbackAllow(t), nil, nil).WithToolGuard(eng)

	_, err := regInvoke(p, "org-1", "ag-1", "knowledge", "delete_issue", `{"id":42}`)
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
		t.Fatalf("denied tool must surface mcp_tool_blocked, got %v", err)
	}
	if !strings.Contains(iErr.Message, "deny-gh-delete") {
		t.Fatalf("refusal must name the policy row (diagnosable): %q", iErr.Message)
	}
	if up.Calls() != 0 {
		t.Fatalf("denied call must not reach the upstream, got %d requests", up.Calls())
	}

	if _, err := regInvoke(p, "org-1", "ag-1", "knowledge", "search", `{"q":"x"}`); err != nil {
		t.Fatalf("allowed tool must pass: %v", err)
	}
	if up.Calls() != 1 {
		t.Fatalf("the working path must execute exactly once, got %d requests", up.Calls())
	}
	if got := up.LastName(); got != "search" {
		t.Fatalf("egress name must be the decision name, got %q", got)
	}
}

// contract example §3.2: per-argument permissions (guard rules).
func TestRegression_PerArgumentRules_ValidPassesInvalidBlocked(t *testing.T) {
	up := newBoundaryUpstream(t)
	eng := guardEngine(t,
		toolpolicy.Policy{OrgID: "org-1", Name: "create-guard", Subject: "*",
			Server: "knowledge", Tool: "create_issue", Action: toolpolicy.ActionAllow,
			Rules:   json.RawMessage(`{"args":{"schema":{"type":"object","properties":{"title":{"type":"string"}},"required":["title"],"additionalProperties":false},"deny_regex":["BEGIN (RSA )?PRIVATE KEY"]}}`),
			Enabled: true},
	)
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, regGrant("ag-1", "knowledge")),
		testConfig(), loopbackAllow(t), nil, nil).WithToolGuard(eng)

	// Input А: valid args pass and execute exactly once.
	if _, err := regInvoke(p, "org-1", "ag-1", "knowledge", "create_issue", `{"title":"t"}`); err != nil {
		t.Fatalf("valid args must pass: %v", err)
	}
	if up.Calls() != 1 {
		t.Fatalf("valid call must reach the upstream once, got %d", up.Calls())
	}

	// Input Б: secret material in args → deny pre-egress, value-free.
	_, err := regInvoke(p, "org-1", "ag-1", "knowledge", "create_issue",
		`{"body":"BEGIN RSA PRIVATE KEY MIIEpA..."}`)
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
		t.Fatalf("secret material must be guard-denied, got %v", err)
	}
	if strings.Contains(iErr.Message, "BEGIN RSA") || strings.Contains(iErr.Message, "MIIEpA") {
		t.Fatalf("refusal must be value-free: %q", iErr.Message)
	}

	// Input В: truncated JSON → diagnosable deny, never a panic/egress.
	_, err = regInvoke(p, "org-1", "ag-1", "knowledge", "create_issue", `{"title":`)
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
		t.Fatalf("truncated JSON must be guard-denied, got %v", err)
	}
	if !strings.Contains(iErr.Message, "schema") {
		t.Fatalf("refusal must name the failing check: %q", iErr.Message)
	}
	if up.Calls() != 1 {
		t.Fatalf("denied calls must not reach the upstream, got %d requests", up.Calls())
	}
}

// contract example §3.3: foreign-tenant isolation and subject scoping — the
// SAME coordinates flip verdict per org/subject, never per payload.
func TestRegression_TenantAndSubjectScoping(t *testing.T) {
	up := newBoundaryUpstream(t)
	eng := guardEngine(t,
		toolpolicy.Policy{OrgID: "org-1", Name: "deny-gh-delete", Subject: "*",
			Server: "knowledge", Tool: "delete_issue", Action: toolpolicy.ActionDeny,
			Priority: 50, Enabled: true},
		toolpolicy.Policy{OrgID: "org-1", Name: "deny-ag9-search", Subject: "ag-9",
			Server: "knowledge", Tool: "search", Action: toolpolicy.ActionDeny,
			Priority: 10, Enabled: true},
	)
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, regGrant("ag-1", "knowledge")),
		testConfig(), loopbackAllow(t), nil, nil).WithToolGuard(eng)

	// org-2 holds no rows: the same denied coordinates implicitly allow
	// (org with an empty policy set restricts nothing) — isolation, not a
	// global deny.
	if _, err := regInvoke(p, "org-2", "ag-1", "knowledge", "delete_issue", `{"id":42}`); err != nil {
		t.Fatalf("a foreign org without rows must implicitly allow: %v", err)
	}
	if up.Calls() != 1 {
		t.Fatalf("foreign-org call must execute exactly once, got %d", up.Calls())
	}

	// org-1 still denies its own coordinates.
	if _, err := regInvoke(p, "org-1", "ag-1", "knowledge", "delete_issue", `{"id":42}`); err == nil {
		t.Fatal("org-1 deny must still fire")
	}

	// A subject-scoped row bites only its subject: ag-1 keeps search,
	// ag-9 loses it — on identical coordinates.
	if _, err := regInvoke(p, "org-1", "ag-1", "knowledge", "search", `{"q":"x"}`); err != nil {
		t.Fatalf("unrelated subject must keep the tool: %v", err)
	}
	if _, err := regInvoke(p, "org-1", "ag-9", "knowledge", "search", `{"q":"x"}`); err == nil {
		t.Fatal("subject-scoped deny must fire for its subject")
	}
	if up.Calls() != 2 {
		t.Fatalf("denied calls must not add upstream traffic, got %d requests", up.Calls())
	}
}
