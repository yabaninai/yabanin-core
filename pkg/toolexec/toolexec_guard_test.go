package toolexec

// acceptance is the same as the mcpagg invoke path (proxy_guard_test.go
// pattern): a denied call must never reach the tool, proven by a zero
// request counter on a counting mock upstream, with the REAL
// toolpolicy.Engine for the e2e cases.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// fakeToolGuard scripts verdicts and counts calls.
type fakeToolGuard struct {
	args   toolpolicy.ArgsReport
	result toolpolicy.ResultReport

	argsCalls   int
	resultCalls int
	gotServer   string
	gotTool     string
	gotArgs     string
	argsSeq     [][2]string // every (server, tool) the args phase consulted
}

func (g *fakeToolGuard) GuardArgs(_ context.Context, _, _, server, tool string, args json.RawMessage) toolpolicy.ArgsReport {
	g.argsCalls++
	g.gotServer, g.gotTool, g.gotArgs = server, tool, string(args)
	g.argsSeq = append(g.argsSeq, [2]string{server, tool})
	return g.args
}

func (g *fakeToolGuard) GuardResult(_ context.Context, _, _, server, tool string, _ json.RawMessage) toolpolicy.ResultReport {
	g.resultCalls++
	g.gotServer, g.gotTool = server, tool
	return g.result
}

// guardUpstream is a counting fetch target: every egress increments calls.
type guardUpstream struct {
	URL   string
	calls atomic.Int32
}

func newGuardUpstream(t *testing.T) *guardUpstream {
	t.Helper()
	u := &guardUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		u.calls.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("upstream-seen"))
	}))
	t.Cleanup(srv.Close)
	u.URL = srv.URL
	return u
}

func decisionDelta(t *testing.T, org, tool, outcome string, fn func()) float64 {
	t.Helper()
	label := metrics.ToolpolicyDecisionsTotal.WithLabelValues(org, BuiltinServerName, tool, outcome)
	before := testutil.ToFloat64(label)
	fn()
	return testutil.ToFloat64(label) - before
}

// TestExecuteGuarded_NilGuardBitForBit pins the nil-guard contract: without
// WithToolGuard the executor path is unchanged.
func TestExecuteGuarded_NilGuardBitForBit(t *testing.T) {
	up := newGuardUpstream(t)
	x := NewExecutor(NewDefaultConfig(), nil, nil)
	res, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`"}`))
	if err != nil {
		t.Fatalf("no guard = no enforcement: %v", err)
	}
	if up.calls.Load() != 1 || res == nil {
		t.Fatalf("upstream called once, got %d", up.calls.Load())
	}
}

// TestExecuteGuarded_ArgsDeny_BlockedBeforeUpstream: an args rule deny (the
// fake guard) blocks the call pre-dispatch with tool_blocked; the tool
// (here: the network) is never contacted.
func TestExecuteGuarded_ArgsDeny_BlockedBeforeUpstream(t *testing.T) {
	up := newGuardUpstream(t)
	g := &fakeToolGuard{args: toolpolicy.ArgsReport{Denied: true,
		Reason: "tool call blocked: deny_regex check failed",
		Findings: []toolpolicy.Finding{{Source: "deny_regex", Category: "forbidden",
			Span: "8:13", Action: "deny"}}}}
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`"}`))
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
		t.Fatalf("want tool_blocked, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("denied call must not reach the tool, got %d requests", up.calls.Load())
	}
	// Dual-form contract pin: the deny may fire on either address, and the
	// guard is consulted for BOTH (bare + qualified) with the args intact.
	want := [][2]string{{BuiltinServerName, ToolWebFetch}, {BuiltinServerName, PolicyKey(ToolWebFetch)}}
	if g.argsCalls != len(want) {
		t.Fatalf("guard must be consulted under both policy addresses, got %d calls: %v", g.argsCalls, g.argsSeq)
	}
	for i := range want {
		if g.argsSeq[i] != want[i] {
			t.Fatalf("guard address order = %v, want %v", g.argsSeq, want)
		}
	}
	if !strings.Contains(g.gotArgs, up.URL) {
		t.Fatalf("guard must see the args: %s", g.gotArgs)
	}
}

// TestExecuteGuarded_EffectiveNameGuarded: http_request is guarded under
// its COMPOSED name http_<method> — the same name the per-tool policy
// gate checks.
func TestExecuteGuarded_EffectiveNameGuarded(t *testing.T) {
	g := &fakeToolGuard{args: toolpolicy.ArgsReport{Denied: true, Reason: "post denied"}}
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolHTTPRequest,
		json.RawMessage(`{"url":"https://x.test","method":"post"}`))
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
		t.Fatalf("want tool_blocked, got %v", err)
	}
	want := [][2]string{{BuiltinServerName, "http_post"}, {BuiltinServerName, PolicyKey("http_post")}}
	if len(g.argsSeq) != len(want) || g.argsSeq[0] != want[0] || g.argsSeq[1] != want[1] {
		t.Fatalf("guard must see the effective name under both addresses, got %v", g.argsSeq)
	}
}

// TestExecuteGuarded_ResultDeny: a result rule deny drops the result (the
// call already ran) with tool_blocked.
func TestExecuteGuarded_ResultDeny(t *testing.T) {
	up := newGuardUpstream(t)
	g := &fakeToolGuard{result: toolpolicy.ResultReport{Action: toolpolicy.ResultDeny,
		Reason: "policy deny: secrets check failed (secret)"}}
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`"}`))
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
		t.Fatalf("want tool_blocked, got %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("the tool ran (the result is dropped, not the call), got %d", up.calls.Load())
	}
}

// TestExecuteGuarded_ResultMask rewrites the body with the masked version.
func TestExecuteGuarded_ResultMask(t *testing.T) {
	up := newGuardUpstream(t)
	g := &fakeToolGuard{result: toolpolicy.ResultReport{Action: toolpolicy.ResultMask,
		Masked: []byte(`{"masked":true}`)}}
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	res, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`"}`))
	if err != nil {
		t.Fatalf("mask must proceed: %v", err)
	}
	if string(res.Body) != `{"masked":true}` {
		t.Fatalf("masked body expected, got %s", res.Body)
	}
}

// TestExecuteGuarded_DegradedRefusesTyped: an indeterminate (degraded)
// org outage is not a permit — the call is refused with the typed
// policy-unavailable error and never egresses, while the decision counter
// still records exactly one error decision, never an allow.
func TestExecuteGuarded_DegradedRefusesTyped(t *testing.T) {
	up := newGuardUpstream(t)
	g := &fakeToolGuard{args: toolpolicy.ArgsReport{Degraded: true}}
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(g)
	_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`"}`))
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodePolicyUnavailable {
		t.Fatalf("degraded must refuse as policy_unavailable, got %v", err)
	}
	if n := up.calls.Load(); n != 0 {
		t.Fatalf("degraded refusal must never egress, got %d", n)
	}
	if d := decisionDelta(t, "org-1", ToolWebFetch, "error", func() {
		_, _ = x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
			json.RawMessage(`{"url":"`+up.URL+`"}`))
	}); d != 1 {
		t.Fatalf("degraded must count as error (one per call), delta = %v", d)
	}
}

// --- e2e: REAL toolpolicy.Engine over mock rows vs the counting upstream ---

func guardExecEngine(t *testing.T, policies ...toolpolicy.Policy) *toolpolicy.Engine {
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

// TestE2E_BuiltinDenyRegexBlockedBeforeUpstream is the G1 acceptance with
// the real engine: an org deny_regex args rule on (yabanin, web_fetch)
// blocks the call with zero egress.
func TestE2E_BuiltinDenyRegexBlockedBeforeUpstream(t *testing.T) {
	up := newGuardUpstream(t)
	eng := guardExecEngine(t, toolpolicy.Policy{OrgID: "org-1", Name: "no-evil",
		Subject: "*", Server: "yabanin", Tool: "web_fetch",
		Action: toolpolicy.ActionAllow,
		Rules:  json.RawMessage(`{"args":{"deny_regex":["evil-"]}}`), Enabled: true})
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)

	_, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"https://evil-host.example.test/page"}`))
	var eErr *ExecError
	if !errors.As(err, &eErr) || eErr.Code != ErrCodeToolBlocked {
		t.Fatalf("want tool_blocked, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("blocked call must not reach the tool, got %d requests", up.calls.Load())
	}
	if d := decisionDelta(t, "org-1", "web_fetch", "deny", func() {
		_, _ = x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
			json.RawMessage(`{"url":"https://evil-host.example.test/page"}`))
	}); d != 1 {
		t.Fatalf("deny decision metric delta = %v", d)
	}

	// The same rule does not touch another org (org isolation of the rules):
	// the "evil-" URL egresses for an org without the row.
	if _, err := x.ExecuteGuarded(context.Background(), "org-OTHER", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+up.URL+`/evil-page"}`)); err != nil {
		t.Fatalf("another org's rules must not apply: %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("other org egress ran once, got %d", up.calls.Load())
	}
}

// TestE2E_BuiltinSecretResultMasked: a result mask rule redacts the secret
// from the body the caller receives (the tool ran once).
func TestE2E_BuiltinSecretResultMasked(t *testing.T) {
	const secret = "ghp_Abcd" + "EfghAbcdEfghAbcdEfghAbcdEfgh1"
	bodySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("token " + secret))
	}))
	t.Cleanup(bodySrv.Close)

	eng := guardExecEngine(t, toolpolicy.Policy{OrgID: "org-1", Name: "mask",
		Subject: "*", Server: "yabanin", Tool: "web_fetch",
		Action: toolpolicy.ActionAllow,
		Rules:  json.RawMessage(`{"result":{"mode":"mask","secrets":true}}`), Enabled: true})
	x := NewExecutor(NewDefaultConfig(), nil, nil).WithToolGuard(eng)

	res, err := x.ExecuteGuarded(context.Background(), "org-1", "ag-1", ToolWebFetch,
		json.RawMessage(`{"url":"`+bodySrv.URL+`"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if strings.Contains(string(res.Body), secret) {
		t.Fatal("the caller must never see the unmasked secret")
	}
	if !strings.Contains(string(res.Body), "[REDACTED_SECRET]") {
		t.Fatalf("redaction token expected: %s", res.Body)
	}
}
