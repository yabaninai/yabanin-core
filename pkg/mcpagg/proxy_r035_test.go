package mcpagg

// (per-tool deny + wildcard allow on one server), driven through the REAL
// toolpolicy.Engine against a counting mock upstream. Acceptance: the
// denied call is answered mcp_tool_blocked (400) with the reason naming the
// deny row, the upstream counter stays at ZERO and the deny decision is

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

func TestR035_ContractFixture_PerToolDenyZeroUpstream(t *testing.T) {
	up := newGuardUpstream(t, "")
	// The harness registers the mock upstream under the fixed server name
	// "knowledge" (storeForUpstreamWithGrant); the row shapes are the exact
	// contract §3 example 1 pair (deny specific tool @ priority 50, wildcard
	// allow @ priority 100) pointed at that server name.
	eng := guardEngine(t,
		toolpolicy.Policy{OrgID: "org-1", Name: "deny-gh-delete", Subject: "*",
			Server: "knowledge", Tool: "delete_issue", Action: toolpolicy.ActionDeny,
			Priority: 50, Enabled: true},
		toolpolicy.Policy{OrgID: "org-1", Name: "allow-github", Subject: "*",
			Server: "knowledge", Tool: "*", Action: toolpolicy.ActionAllow,
			Priority: 100, Enabled: true},
	)
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(eng)

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "delete_issue", Params: json.RawMessage(`{"id":42}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
		t.Fatalf("want mcp_tool_blocked, got %v", err)
	}
	if !strings.Contains(iErr.Message, "deny-gh-delete") {
		t.Fatalf("the reason must name the deny row: %q", iErr.Message)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("denied call must not reach the upstream, got %d requests", up.calls.Load())
	}
	if d := metricDelta(t, "org-1", "knowledge", "delete_issue", "deny", func() {
		_, _ = p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
			InvokeRequest{Server: "knowledge", Tool: "delete_issue", Params: json.RawMessage(`{"id":42}`)})
	}); d != 1 {
		t.Fatalf("deny decision metric delta = %v", d)
	}

	// The wildcard allow row keeps every other tool of the server callable.
	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)}); err != nil {
		t.Fatalf("non-denied tool must pass: %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream called once for the allowed tool, got %d", up.calls.Load())
	}
}
