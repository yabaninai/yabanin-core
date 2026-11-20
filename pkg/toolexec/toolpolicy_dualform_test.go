package toolexec

// Dual-form policy addressing: built-in calls are guarded under BOTH the
// bare effective name and the "yabanin:<name>" key (PolicyKeys). A deny in
// either form refuses; guard rules compose most-restrictively across the
// two evaluations (engine cross-policy composition parity). Pins, frozen
// before implementation:
//
//	DG-BOTH-KEYS       the guard sees exactly [effective, yabanin:effective]
//	                   per phase, args AND result, in that stable order
//	DG-MERGE-ARGS      cross-form args composition: deny wins, Degraded sticky
//	DG-MERGE-RESULT    cross-form result lattice: deny > mask > flag
//	DG-E2E-BARE        bare deny row blocks the call, zero egress
//	DG-E2E-PREFIXED    yabanin:<name> deny row blocks the call, zero egress
//	DG-E2E-MIX-BA      bare deny + prefixed ALLOW -> blocked (bare deny holds)
//	DG-E2E-MIX-AB      prefixed deny + bare allow -> blocked
//	DG-E2E-PRIORITY    prefixed allow p10 + prefixed deny p50 (one form)
//	                   -> ALLOWED (within-form ranking preserved)
//	DG-E2E-RESULT-LATTICE bare-row mask + prefixed-row deny -> result dropped

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// dualFormRecorder records every (server, tool) the guard is consulted for.
type dualFormRecorder struct {
	argsCalls   [][2]string
	resultCalls [][2]string
	deny        bool
}

func (g *dualFormRecorder) GuardArgs(_ context.Context, _, _, server, tool string, _ json.RawMessage) toolpolicy.ArgsReport {
	g.argsCalls = append(g.argsCalls, [2]string{server, tool})
	if g.deny {
		return toolpolicy.ArgsReport{Denied: true, Reason: "dual-form deny"}
	}
	return toolpolicy.ArgsReport{}
}

func (g *dualFormRecorder) GuardResult(_ context.Context, _, _, server, tool string, _ json.RawMessage) toolpolicy.ResultReport {
	g.resultCalls = append(g.resultCalls, [2]string{server, tool})
	return toolpolicy.ResultReport{}
}

// DG-BOTH-KEYS: one guarded call consults the guard under both addresses,
// args phase and result phase alike, in the stable bare-first order.
func TestExecuteGuarded_BothPolicyKeysConsulted(t *testing.T) {
	up := newGuardUpstream(t)
	g := &dualFormRecorder{}
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	if _, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`"}`)); err != nil {
		t.Fatalf("DG-BOTH-KEYS: allow-path call failed: %v", err)
	}
	want := [][2]string{{BuiltinServerName, ToolWebFetch}, {BuiltinServerName, PolicyKey(ToolWebFetch)}}
	assertCallSeq(t, "args", g.argsCalls, want)
	assertCallSeq(t, "result", g.resultCalls, want)

	// The composed effective name is addressed the same way.
	g2 := &dualFormRecorder{}
	x2 := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g2)
	if _, err := x2.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolHTTPRequest,
		json.RawMessage(`{"url":"https://x.test","method":"post"}`)); err == nil {
		t.Fatal("DG-BOTH-KEYS: http_post against x.test must fail upstream, not pass")
	}
	wantEff := [][2]string{{BuiltinServerName, "http_post"}, {BuiltinServerName, PolicyKey("http_post")}}
	assertCallSeq(t, "args-effective", g2.argsCalls, wantEff)
}

func assertCallSeq(t *testing.T, phase string, got, want [][2]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("DG-BOTH-KEYS: %s phase consulted %d times, want %d: %v", phase, len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("DG-BOTH-KEYS: %s phase call %d = %v, want %v", phase, i, got[i], want[i])
		}
	}
}

// DG-MERGE-ARGS: a deny under either form denies; otherwise Degraded is
// sticky across the merge.
func TestMergeArgsReports(t *testing.T) {
	cases := []struct {
		name         string
		a, b, merged toolpolicy.ArgsReport
	}{
		{"bare deny wins", toolpolicy.ArgsReport{Denied: true, Reason: "bare"}, toolpolicy.ArgsReport{}, toolpolicy.ArgsReport{Denied: true, Reason: "bare"}},
		{"prefixed deny wins", toolpolicy.ArgsReport{}, toolpolicy.ArgsReport{Denied: true, Reason: "prefixed"}, toolpolicy.ArgsReport{Denied: true, Reason: "prefixed"}},
		{"both deny: stable first attribution", toolpolicy.ArgsReport{Denied: true, Reason: "bare"}, toolpolicy.ArgsReport{Denied: true, Reason: "prefixed"}, toolpolicy.ArgsReport{Denied: true, Reason: "bare"}},
		{"degraded left sticky", toolpolicy.ArgsReport{Degraded: true}, toolpolicy.ArgsReport{}, toolpolicy.ArgsReport{Degraded: true}},
		{"degraded right sticky", toolpolicy.ArgsReport{}, toolpolicy.ArgsReport{Degraded: true}, toolpolicy.ArgsReport{Degraded: true}},
		{"clean clean stays clean", toolpolicy.ArgsReport{}, toolpolicy.ArgsReport{}, toolpolicy.ArgsReport{}},
	}
	for _, tc := range cases {
		got := mergeArgsReports(tc.a, tc.b)
		if got.Denied != tc.merged.Denied || got.Reason != tc.merged.Reason || got.Degraded != tc.merged.Degraded {
			t.Fatalf("DG-MERGE-ARGS %s: got %+v, want %+v", tc.name, got, tc.merged)
		}
	}
}

// DG-MERGE-RESULT: the most restrictive action wins (ResultAction.Rank),
// Degraded is sticky.
func TestMergeResultReports(t *testing.T) {
	deny := toolpolicy.ResultReport{Action: toolpolicy.ResultDeny, Reason: "d"}
	mask := toolpolicy.ResultReport{Action: toolpolicy.ResultMask, Masked: []byte("m")}
	flag := toolpolicy.ResultReport{Action: toolpolicy.ResultFlag}
	cases := []struct {
		name         string
		a, b, merged toolpolicy.ResultReport
	}{
		{"deny beats mask (a)", deny, mask, deny},
		{"deny beats mask (b)", mask, deny, deny},
		{"mask beats flag (a)", mask, flag, mask},
		{"mask beats flag (b)", flag, mask, mask},
		{"flag beats none", toolpolicy.ResultReport{}, flag, flag},
		{"deny beats none", toolpolicy.ResultReport{}, deny, deny},
	}
	for _, tc := range cases {
		if got := mergeResultReports(tc.a, tc.b); got.Action != tc.merged.Action || string(got.Masked) != string(tc.merged.Masked) ||
			got.Reason != tc.merged.Reason {
			t.Fatalf("DG-MERGE-RESULT %s: got %+v, want %+v", tc.name, got, tc.merged)
		}
	}
	if got := mergeResultReports(toolpolicy.ResultReport{Degraded: true}, mask); !got.Degraded || got.Action != toolpolicy.ResultMask {
		t.Fatalf("DG-MERGE-RESULT degraded sticky under mask: got %+v", got)
	}
}

// dualFormRow is one engine row for the E2E pins.
func dualFormRow(org, name, tool, action string, priority int, rules json.RawMessage) toolpolicy.Policy {
	return toolpolicy.Policy{OrgID: org, Name: name, Subject: "*", Server: BuiltinServerName,
		Tool: tool, Action: action, Priority: priority, Rules: rules, Enabled: true}
}

// dualFormBlocked runs one guarded web_fetch against the counting upstream
// under the given engine and reports the verdict and egress count.
func dualFormBlocked(t *testing.T, eng *toolpolicy.Engine, org string) (blocked bool, egress int32) {
	t.Helper()
	up := newGuardUpstream(t)
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)
	_, err := x.ExecuteGuarded(context.Background(), org, "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`"}`))
	var eErr *ExecError
	blocked = errors.As(err, &eErr) && eErr.Code == ErrCodeToolBlocked
	return blocked, up.calls.Load()
}

// DG-E2E-BARE / DG-E2E-PREFIXED / DG-E2E-MIX-BA / DG-E2E-MIX-AB: each deny
// form alone blocks; in mixed deny/allow conflicts the deny holds regardless
// of the other form's allow row or its higher precedence (lower priority
// number).
func TestE2E_DualFormDenyHolds(t *testing.T) {
	cases := []struct {
		name string
		rows []toolpolicy.Policy
	}{
		{"DG-E2E-BARE: bare deny blocks", []toolpolicy.Policy{
			dualFormRow("org-1", "bare-deny", ToolWebFetch, toolpolicy.ActionDeny, 50, nil)}},
		{"DG-E2E-PREFIXED: yabanin: deny blocks", []toolpolicy.Policy{
			dualFormRow("org-1", "prefixed-deny", PolicyKey(ToolWebFetch), toolpolicy.ActionDeny, 50, nil)}},
		{"DG-E2E-MIX-BA: bare deny + prefixed ALLOW (p10) blocks", []toolpolicy.Policy{
			dualFormRow("org-1", "mix-ba-bare", ToolWebFetch, toolpolicy.ActionDeny, 50, nil),
			dualFormRow("org-1", "mix-ba-prefixed-allow", PolicyKey(ToolWebFetch), toolpolicy.ActionAllow, 10, nil)}},
		{"DG-E2E-MIX-AB: prefixed deny + bare ALLOW (p10) blocks", []toolpolicy.Policy{
			dualFormRow("org-1", "mix-ab-prefixed", PolicyKey(ToolWebFetch), toolpolicy.ActionDeny, 50, nil),
			dualFormRow("org-1", "mix-ab-bare-allow", ToolWebFetch, toolpolicy.ActionAllow, 10, nil)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, egress := dualFormBlocked(t, guardExecEngine(t, tc.rows...), "org-1")
			if !blocked {
				t.Fatalf("%s: call must be blocked", tc.name)
			}
			if egress != 0 {
				t.Fatalf("%s: denied call must not reach the tool, got %d requests", tc.name, egress)
			}
		})
	}
}

// DG-E2E-PRIORITY: within ONE form the engine ranking is untouched — an
// allow row at priority 10 beats a deny row at priority 50, so the call
// runs (the dual-form merge must not flatten within-form precedence).
func TestE2E_DualFormWithinFormPriorityPreserved(t *testing.T) {
	eng := guardExecEngine(t,
		dualFormRow("org-1", "allow-p10", PolicyKey(ToolWebFetch), toolpolicy.ActionAllow, 10, nil),
		dualFormRow("org-1", "deny-p50", PolicyKey(ToolWebFetch), toolpolicy.ActionDeny, 50, nil))
	blocked, egress := dualFormBlocked(t, eng, "org-1")
	if blocked {
		t.Fatal("DG-E2E-PRIORITY: allow p10 must beat deny p50 within one form")
	}
	if egress != 1 {
		t.Fatalf("DG-E2E-PRIORITY: the tool must run once, got %d", egress)
	}
}

// DG-E2E-RESULT-LATTICE: result rules compose most-restrictively across the
// two forms — a bare-form mask row plus a prefixed-form deny row drops the
// result after egress (the call ran, the caller gets tool_blocked).
func TestE2E_DualFormResultLatticeMaskPlusDeny(t *testing.T) {
	eng := guardExecEngine(t,
		dualFormRow("org-1", "mask-bare", ToolWebFetch, toolpolicy.ActionAllow, 50,
			json.RawMessage(`{"result":{"mode":"mask","secrets":true}}`)),
		dualFormRow("org-1", "deny-prefixed", PolicyKey(ToolWebFetch), toolpolicy.ActionAllow, 50,
			json.RawMessage(`{"result":{"mode":"deny","deny_regex":["upstream-seen"]}}`)))
	up := newGuardUpstream(t)
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)
	_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`"}`))
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
		t.Fatalf("DG-E2E-RESULT-LATTICE: want tool_blocked (deny beats mask across forms), got %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("DG-E2E-RESULT-LATTICE: the call itself ran, got %d requests", up.calls.Load())
	}
}

// outageGuard is a scripted loader/guard (controlled dependency, NOT a
// replacement for the production executor): it answers deterministically
// per key form — a deny row under one address, a loader outage (Degraded,
// fail-open report) under the other. No clocks, no sleeps. denyTool is a
// key form or a sentinel matching no real tool ("__no_deny__" = no deny
// anywhere); outageTool is a key form, or empty meaning EVERY address is
// under outage.
type outageGuard struct {
	denyTool   string
	outageTool string
	consulted  [][2]string
}

func (g *outageGuard) GuardArgs(_ context.Context, _, _, server, tool string, _ json.RawMessage) toolpolicy.ArgsReport {
	g.consulted = append(g.consulted, [2]string{server, tool})
	switch {
	case tool == g.denyTool:
		return toolpolicy.ArgsReport{Denied: true, Reason: "deny-form row"}
	case g.outageTool == "" || tool == g.outageTool:
		return toolpolicy.ArgsReport{Degraded: true, Reason: "loader outage"}
	}
	return toolpolicy.ArgsReport{}
}

func (g *outageGuard) GuardResult(_ context.Context, _, _, server, tool string, _ json.RawMessage) toolpolicy.ResultReport {
	g.consulted = append(g.consulted, [2]string{server, tool})
	return toolpolicy.ResultReport{}
}

// outageBlocked drives the REAL ExecuteGuarded path against the counting
// loopback upstream under the scripted guard and reports whether the call
// was refused (tool_blocked) and how many upstream egresses happened.
func outageBlocked(t *testing.T, g *outageGuard) (blocked bool, egress int32) {
	t.Helper()
	up := newGuardUpstream(t)
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`"}`))
	var eErr *ExecError
	blocked = errors.As(err, &eErr) && eErr.Code == ErrCodeToolBlocked
	return blocked, up.calls.Load()
}

// DG-OUTAGE-BARE-DENY / DG-OUTAGE-PREFIXED-DENY: a deny under one form plus
// a loader outage (Degraded) under the other must still refuse the call with
// ZERO upstream egress in BOTH orders — the deny report wins the merge and
// Degraded is dropped, never the other way around. The production executor
// path is exercised end to end; the scripted guard only stands in for the
// policy loader.
func TestE2E_DualFormDenyPlusLoaderOutageBothOrders(t *testing.T) {
	cases := []struct {
		name string
		g    *outageGuard
	}{
		{"DG-OUTAGE-BARE-DENY", &outageGuard{denyTool: ToolWebFetch, outageTool: PolicyKey(ToolWebFetch)}},
		{"DG-OUTAGE-PREFIXED-DENY", &outageGuard{denyTool: PolicyKey(ToolWebFetch), outageTool: ToolWebFetch}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, egress := outageBlocked(t, tc.g)
			if !blocked {
				t.Fatalf("%s: deny under one form + outage under the other must return tool_blocked", tc.name)
			}
			if egress != 0 {
				t.Fatalf("%s: refused call must reach the upstream zero times, got %d", tc.name, egress)
			}
		})
	}
}

// DG-OUTAGE-FAILOPEN: with an outage under every form and NO deny anywhere
// (deny sentinel matches no tool), the intended fail-open Degraded posture
// is preserved — the call proceeds (one egress) instead of being blocked.
func TestE2E_DualFormLoaderOutageFailOpen(t *testing.T) {
	g := &outageGuard{denyTool: "__no_deny__", outageTool: ""}
	blocked, egress := outageBlocked(t, g)
	if blocked {
		t.Fatal("DG-OUTAGE-FAILOPEN: outage without any deny must not block (fail-open Degraded)")
	}
	if egress != 1 {
		t.Fatalf("DG-OUTAGE-FAILOPEN: the call must run exactly once, got %d", egress)
	}
}
