package cli

// TOOL-DEGRADED-01 (Astra R2 follow-up): the invoke path's indeterminate
// policy verdict must surface as an actual HTTP 503 response carrying the
// documented policy_unavailable code, and the tool sink must never be
// reached - an unresolved permit never dispatches.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// degradedGuard reports an indeterminate args verdict for every tool: the
// policy store is unreachable, so the permit cannot be established.
type degradedGuard struct{}

func (degradedGuard) GuardArgs(context.Context, string, string, string, string, json.RawMessage) toolpolicy.ArgsReport {
	return toolpolicy.ArgsReport{Degraded: true}
}

func (degradedGuard) GuardResult(context.Context, string, string, string, string, json.RawMessage) toolpolicy.ResultReport {
	return toolpolicy.ResultReport{}
}

// TestBuiltinToolInvoke_PolicyUnavailable_Returns503 drives the REAL
// builtinToolInvoke with a degraded args verdict and asserts the literal
// HTTP status, the documented error code in the body, and zero upstream
// sink hits.
func TestBuiltinToolInvoke_PolicyUnavailable_Returns503(t *testing.T) {
	up := newBuiltinUpstream(t)
	gw := gateWith(rulesRow("allow-any", "yabanin", "web_fetch", `{}`))
	gw.toolExec = toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil).WithToolGuard(degradedGuard{})

	w := httptest.NewRecorder()
	gw.builtinToolInvoke(w, mkBuiltinReq(), "org-1", mcpagg.Identity{AgentID: "agent-1"},
		mcpagg.InvokeRequest{Server: "yabanin", Tool: "web_fetch",
			Params: json.RawMessage(`{"url":"` + up.URL + `/page"}`)})

	if w.Code != 503 {
		t.Fatalf("degraded policy status = %d, want literal 503 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "policy_unavailable") {
		t.Fatalf("degraded policy must surface the documented policy_unavailable code, got %s", w.Body.String())
	}
	if up.calls != 0 {
		t.Fatalf("indeterminate permit must never dispatch, got %d upstream requests", up.calls)
	}
}
