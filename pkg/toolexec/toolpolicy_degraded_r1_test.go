package toolexec

// TOOL-DEGRADED-01 (auth/SSE/tool-policy correction R1, original
// behavioral reproducer): ExecuteGuarded requires a determinate permit
// BEFORE dispatch - a degraded (indeterminate) policy verdict is not a
// permit, so the call must be refused with a typed error and the upstream
// sink must see ZERO egress. Legs, all against the real executor path
// and the counting loopback upstream (no clocks, no sleeps):
//
//	TOOL-DEGRADED-01a  degraded guard verdict alone -> refusal, 0 egress
//	TOOL-DEGRADED-01b  outage under EVERY policy address -> refusal, 0 egress
//	TOOL-DEGRADED-01c  deny under one form + outage under the other
//	                     -> tool_blocked refusal, 0 egress (deny wins)
//	TOOL-DEGRADED-01d  clean allow -> call runs, result returned, 1 egress
//
// The degraded refusal still counts ONE "error" policy decision, never an
// allow. Original behavior fails legs a, b and e: the call proceeds with
// one egress.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

func guardedCall(x *Executor, org, url string) (*Result, error) {
	return x.ExecuteGuarded(context.Background(), org, "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+url+`"}`))
}

func degradedVerdictAlone(t *testing.T) {
	up := newGuardUpstream(t)
	g := &fakeToolGuard{args: toolpolicy.ArgsReport{Degraded: true, Reason: "loader outage"}}
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	_, err := guardedCall(x, "org-r1a", up.URL)
	var eErr *ExecError
	if !errors.As(err, &eErr) {
		t.Fatalf("TOOL-DEGRADED-01a: degraded verdict must refuse with a typed ExecError, got %v", err)
	}
	if eErr.Code != ErrCodePolicyUnavailable {
		t.Fatalf("TOOL-DEGRADED-01a: degraded verdict must refuse as policy_unavailable, got %q", eErr.Code)
	}
	if n := up.calls.Load(); n != 0 {
		t.Fatalf("TOOL-DEGRADED-01a: refused call must reach the upstream ZERO times, got %d", n)
	}
}

func outageEveryAddress(t *testing.T) {
	up := newGuardUpstream(t)
	g := &outageGuard{denyTool: "__no_deny__", outageTool: ""}
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	_, err := guardedCall(x, "org-r1b", up.URL)
	var eErr *ExecError
	if !errors.As(err, &eErr) {
		t.Fatalf("TOOL-DEGRADED-01b: all-address outage must refuse with a typed ExecError, got %v", err)
	}
	if eErr.Code != ErrCodePolicyUnavailable {
		t.Fatalf("TOOL-DEGRADED-01b: all-address outage must refuse as policy_unavailable, got %q", eErr.Code)
	}
	if n := up.calls.Load(); n != 0 {
		t.Fatalf("TOOL-DEGRADED-01b: refused call must reach the upstream ZERO times, got %d", n)
	}
}

func denyPlusOutageStaysBlocked(t *testing.T) {
	up := newGuardUpstream(t)
	g := &outageGuard{denyTool: ToolWebFetch, outageTool: PolicyKey(ToolWebFetch)}
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	_, err := guardedCall(x, "org-r1c", up.URL)
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
		t.Fatalf("TOOL-DEGRADED-01c: determinate deny must win the merge as tool_blocked, got %v", err)
	}
	if n := up.calls.Load(); n != 0 {
		t.Fatalf("TOOL-DEGRADED-01c: refused call must reach the upstream ZERO times, got %d", n)
	}
}

func cleanAllowStillRuns(t *testing.T) {
	up := newGuardUpstream(t)
	g := &fakeToolGuard{args: toolpolicy.ArgsReport{}}
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	res, err := guardedCall(x, "org-r1d", up.URL)
	if err != nil {
		t.Fatalf("TOOL-DEGRADED-01d: clean allow must still run: %v", err)
	}
	if n := up.calls.Load(); n != 1 {
		t.Fatalf("TOOL-DEGRADED-01d: allowed call must run exactly once, got %d", n)
	}
	if res == nil || !bytes.Contains(res.Body, []byte("upstream-seen")) {
		t.Fatalf("TOOL-DEGRADED-01d: expected upstream result body, got %+v", res)
	}
}

func TestExecuteGuarded_IndeterminatePermitRefusesPreEgress(t *testing.T) {
	t.Run("degraded-verdict-alone", degradedVerdictAlone)
	t.Run("outage-every-address", outageEveryAddress)
	t.Run("deny-plus-outage-stays-blocked", denyPlusOutageStaysBlocked)
	t.Run("clean-allow-still-runs", cleanAllowStillRuns)
}

// TOOL-DEGRADED-01e: the degraded refusal still counts exactly ONE
// "error" policy decision on the shared counter - never an allow - and
// still never egresses.
func TestExecuteGuarded_DegradedRefusalCountsErrorDecision(t *testing.T) {
	up := newGuardUpstream(t)
	g := &fakeToolGuard{args: toolpolicy.ArgsReport{Degraded: true, Reason: "loader outage"}}
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	if d := decisionDelta(t, "org-r1e", ToolWebFetch, "error", func() {
		_, _ = guardedCall(x, "org-r1e", up.URL)
	}); d != 1 {
		t.Fatalf("TOOL-DEGRADED-01e: degraded refusal must count one error decision, delta = %v", d)
	}
	if n := up.calls.Load(); n != 0 {
		t.Fatalf("TOOL-DEGRADED-01e: refused call must reach the upstream ZERO times, got %d", n)
	}
}
