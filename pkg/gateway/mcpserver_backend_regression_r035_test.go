package cli

// through the REAL toolpolicy engine — the server-aware pre-gate (decider →
// DecideTool) must hide a denied tool family from tools/list, refuse its
// tools/call BEFORE the invoke seam (zero downstream calls), and let the
// allowed tool of the same server execute exactly once. This is the
// mutation anchor for the G3 mechanism: falling back to the chat-path
// Decide (server-blind) must surface the denied tool and pass the denied
// call through to the invoke seam (see

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/mcpserver"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

func TestBackendRegression_ServerFamilyDeny_Scenario(t *testing.T) {
	gw := testGatewayForMCP(t)
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{
		// Per-tool deny over a SERVER FAMILY: every admin_* tool of every
		// git* server is refused (a wildcard-family row as docs prescribe).
		{OrgID: "org1", Name: "no-git-admin", Subject: "*", Server: "git*",
			Tool: "admin*", Action: toolpolicy.ActionDeny, Priority: 50, Enabled: true},
		// A chat-path allow row: never hides nor sinks anything (allow).
		{OrgID: "org1", Name: "allow-all", Subject: "*", Server: "*",
			Tool: "*", Action: toolpolicy.ActionAllow, Priority: 100, Enabled: true},
	}}, 0)

	b := mcpServerBackend{gw: gw}
	b.listGrants = func(context.Context, string, string) ([]*mcpagg.Grant, error) {
		return []*mcpagg.Grant{{OrgID: "org1", AgentID: "agent1",
			ServerName: "github", AllowedTools: nil, Enabled: true}}, nil
	}
	b.getServer = func(context.Context, string, string) (*mcpagg.Server, error) {
		return &mcpagg.Server{OrgID: "org1", Name: "github", Enabled: true}, nil
	}
	b.listUpstreamTools = func(context.Context, string, mcpagg.Identity, string) ([]mcpagg.ToolDescriptor, error) {
		return []mcpagg.ToolDescriptor{{Name: "search"}, {Name: "admin_wipe"}}, nil
	}
	invoked := 0
	b.invoke = func(context.Context, string, mcpagg.Identity, mcpagg.InvokeRequest) (json.RawMessage, error) {
		invoked++
		return json.RawMessage(`{"content":[]}`), nil
	}

	// Catalog: the denied family is hidden, the allowed tool stays listed.
	tools, err := b.Tools(context.Background(), mcpserverPrincipal("org1", "agent1"))
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "search" {
		t.Fatalf("denied family must be hidden from the catalog: %+v", tools)
	}

	// tools/call on the denied family refuses pre-invoke (zero downstream
	// calls) with the documented policy_denied error.
	_, err = b.Call(context.Background(), mcpserverPrincipal("org1", "agent1"),
		"github:admin_wipe", json.RawMessage(`{"confirm":true}`))
	var tcErr *mcpserver.ToolCallError
	if !errors.As(err, &tcErr) || tcErr.Code != "policy_denied" {
		t.Fatalf("denied family call must be policy_denied pre-invoke, got %v", err)
	}
	if invoked != 0 {
		t.Fatalf("denied call must not reach the invoke path, got %d calls", invoked)
	}

	// Working path: the allowed tool of the same server executes exactly once.
	if _, err := b.Call(context.Background(), mcpserverPrincipal("org1", "agent1"),
		"github:search", json.RawMessage(`{"q":"x"}`)); err != nil {
		t.Fatalf("allowed call must pass: %v", err)
	}
	if invoked != 1 {
		t.Fatalf("working path must execute exactly once, got %d calls", invoked)
	}
}
