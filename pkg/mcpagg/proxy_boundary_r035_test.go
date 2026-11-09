package mcpagg

// path, e2e through the REAL toolpolicy.Engine against counting mock
// upstreams. Vectors: payload-coordinate spoofing (args claiming another
// tool/server), case variants vs the exact-match allow-list ceiling,
// invalid input (truncated JSON / wrong types / oversize), URL injection in
// guard-checked args (metadata IP, file://), redirects after allow, repeat
// denies (one decision per call) and cancelled invokes (the D-15 contrast:
// the invoke path fails CLOSED / never reads a cancelled call as success).
// Every refusal is diagnosable (documented code + reason naming the row or
// check, value-free) with a zero upstream request counter.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// boundaryUpstream is a mock MCP upstream that counts requests, records the
// JSON-RPC tool name it was called with, and can be put into redirect mode
// (302 to target — the second hop must never be contacted).
type boundaryUpstream struct {
	URL   string
	calls int32 // guarded by mu
	name  string
	mu    sync.Mutex

	redirectTo string
}

func (u *boundaryUpstream) Calls() int32 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

func (u *boundaryUpstream) LastName() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.name
}

func (u *boundaryUpstream) handler(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.calls++
	u.mu.Unlock()
	if u.redirectTo != "" {
		http.Redirect(w, r, u.redirectTo, http.StatusFound)
		return
	}
	var req struct {
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	u.mu.Lock()
	u.name = req.Params.Name
	u.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"echo"}]}}`)
}

func newBoundaryUpstream(t *testing.T) *boundaryUpstream {
	t.Helper()
	u := &boundaryUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(u.handler))
	t.Cleanup(srv.Close)
	u.URL = srv.URL
	return u
}

// TestProxy_ArgsCannotSpoofPolicyCoordinates: the allow-list, the policy
// decision AND the JSON-RPC egress name all key on req.Tool — the args
// payload cannot redirect any of them to another tool or server.
func TestProxy_ArgsCannotSpoofPolicyCoordinates(t *testing.T) {
	up := newBoundaryUpstream(t)
	eng := guardEngine(t,
		toolpolicy.Policy{OrgID: "org-1", Name: "deny-delete", Subject: "*",
			Server: "knowledge", Tool: "delete_issue", Action: toolpolicy.ActionDeny,
			Priority: 50, Enabled: true},
	)
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(eng)

	// An allowed call whose args merely MENTION the denied tool and another
	// server must pass — and egress under exactly the requested name.
	spoofing := json.RawMessage(`{"tool":"delete_issue","server":"other-org-server"}`)
	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: spoofing})
	if err != nil {
		t.Fatalf("args content must not shift the decision coordinates: %v", err)
	}
	if up.Calls() != 1 {
		t.Fatalf("upstream called once, got %d", up.Calls())
	}
	if got := up.LastName(); got != "search" {
		t.Fatalf("egress name must be the decision name %q, got %q", "search", got)
	}
	if !strings.Contains(string(res), "echo") {
		t.Fatalf("upstream result expected: %s", res)
	}

	// The same payload under the denied coordinates is refused pre-egress.
	_, err = p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "delete_issue", Params: spoofing})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
		t.Fatalf("want mcp_tool_blocked, got %v", err)
	}
	if !strings.Contains(iErr.Message, "deny-delete") {
		t.Fatalf("refusal must name the deny row: %q", iErr.Message)
	}
	if up.Calls() != 1 {
		t.Fatalf("denied call must not reach the upstream, got %d requests", up.Calls())
	}
}

// TestProxy_CaseVariantToolRefusedByAllowListCeiling: pattern matching is
// byte-exact, so a case variant of an allowed tool is NOT silently resolved
// to it — the exact-match allow-list ceiling refuses it with a diagnosable
// not_found and zero upstream contact.
func TestProxy_CaseVariantToolRefusedByAllowListCeiling(t *testing.T) {
	up := newBoundaryUpstream(t)
	p := NewProxy(storeForUpstreamWithGrant(up.URL, []string{"search"}, testGrant("ag-1")),
		testConfig(), loopbackAllow(t), nil, nil)

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "Search", Params: json.RawMessage(`{"q":"x"}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeNotFound {
		t.Fatalf("case variant must be refused by the allow-list ceiling, got %v", err)
	}
	if !strings.Contains(iErr.Message, "Search") || !strings.Contains(iErr.Message, "knowledge") {
		t.Fatalf("refusal must name the tool and server (diagnosable): %q", iErr.Message)
	}
	if up.Calls() != 0 {
		t.Fatalf("refused variant must not reach the upstream, got %d requests", up.Calls())
	}

	// The canonical name still passes (guardrail, not a wall).
	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)}); err != nil {
		t.Fatalf("canonical tool must pass: %v", err)
	}
	if up.Calls() != 1 {
		t.Fatalf("upstream called once, got %d", up.Calls())
	}
}

// TestProxy_InvalidInputRefusedZeroUpstream: contract §3 example 2, inputs
// Б/В at the proxy level — truncated JSON, wrong-typed values and oversize
// args are refused pre-egress with a diagnosable, value-free
// mcp_tool_blocked reason; the oversized payload is never echoed.
func TestProxy_InvalidInputRefusedZeroUpstream(t *testing.T) {
	up := newBoundaryUpstream(t)
	eng := guardEngine(t,
		toolpolicy.Policy{OrgID: "org-1", Name: "cap", Subject: "*",
			Server: "knowledge", Tool: "*", Action: toolpolicy.ActionAllow,
			Rules: json.RawMessage(`{"args":{"max_bytes":16}}`), Enabled: true},
		toolpolicy.Policy{OrgID: "org-1", Name: "schema", Subject: "*",
			Server: "knowledge", Tool: "*", Action: toolpolicy.ActionAllow,
			Rules: json.RawMessage(`{"args":{"schema":{"type":"object","properties":{"title":{"type":"string"}},"required":["title"],"additionalProperties":false}}}`), Enabled: true},
	)
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(eng)

	cases := []struct {
		name    string
		params  string
		inDiag  string // substring the refusal must name
		noLeak  string // substring that must NOT appear (value-free)
		outcome string // decision metric outcome
	}{
		{"truncated-json", `{"title":`, "schema", "", "deny"},
		{"wrong-type", `{"title":123}`, "schema", "123", "deny"},
		{"missing-required", `{"nope":1}`, "schema", "", "deny"},
		{"oversize", `{"title":"` + strings.Repeat("x", 64) + `"}`, "max_size", strings.Repeat("x", 64), "deny"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := up.Calls()
			_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
				InvokeRequest{Server: "knowledge", Tool: "create_issue", Params: json.RawMessage(tc.params)})
			var iErr *InvokeError
			if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
				t.Fatalf("want mcp_tool_blocked, got %v", err)
			}
			if !strings.Contains(iErr.Message, tc.inDiag) {
				t.Fatalf("refusal must name the failing check (%s): %q", tc.inDiag, iErr.Message)
			}
			if tc.noLeak != "" && strings.Contains(iErr.Message, tc.noLeak) {
				t.Fatalf("refusal must be value-free (no %q): %q", tc.noLeak, iErr.Message)
			}
			if up.Calls() != before {
				t.Fatalf("refused input must not reach the upstream, delta %d", up.Calls()-before)
			}
			if d := metricDelta(t, "org-1", "knowledge", "create_issue", tc.outcome, func() {
				_, _ = p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
					InvokeRequest{Server: "knowledge", Tool: "create_issue", Params: json.RawMessage(tc.params)})
			}); d != 1 {
				t.Fatalf("%s decision metric delta = %v", tc.outcome, d)
			}
		})
	}
}

// TestProxy_URLInjectionInArgs_GuardDeniesBeforeEgress: the contract-default
// posture for URL injection inside guard-checked args — an args deny_regex
// row forbidding the metadata IP / file scheme blocks the call at the guard
// (pre-egress, zero upstream, value-free reason), before the SSRF layer
// would ever see it.
func TestProxy_URLInjectionInArgs_GuardDeniesBeforeEgress(t *testing.T) {
	up := newBoundaryUpstream(t)
	eng := guardEngine(t, toolpolicy.Policy{OrgID: "org-1", Name: "no-ssrf-urls", Subject: "*",
		Server: "knowledge", Tool: "*", Action: toolpolicy.ActionAllow,
		Rules: json.RawMessage(`{"args":{"deny_regex":["169\\.254\\.169\\.254","file://"]}}`), Enabled: true})
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(eng)

	for _, params := range []string{
		`{"q":"http://169.254.169.254/latest/meta-data/"}`,
		`{"q":"file:///etc/passwd"}`,
	} {
		before := up.Calls()
		_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
			InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(params)})
		var iErr *InvokeError
		if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
			t.Fatalf("injected URL %q must be guard-denied, got %v", params, err)
		}
		if strings.Contains(iErr.Message, "169.254") || strings.Contains(iErr.Message, "passwd") {
			t.Fatalf("refusal must be value-free: %q", iErr.Message)
		}
		if up.Calls() != before {
			t.Fatalf("guard-denied call must not reach the upstream, delta %d", up.Calls()-before)
		}
	}

	// A benign URL-shaped arg passes (the row targets the forbidden hosts).
	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search",
			Params: json.RawMessage(`{"q":"https://docs.example.test/x"}`)}); err != nil {
		t.Fatalf("benign args must pass: %v", err)
	}
	if up.Calls() != 1 {
		t.Fatalf("upstream called once, got %d", up.Calls())
	}
}

// TestProxy_RedirectNeverFollowed_ZeroSecondHop: the redirect vector of the
// failure scenario at the invoke-path level — an upstream answering 302 is
// never followed (the client refuses redirects), the redirect target
// receives ZERO requests and the caller gets a diagnosable upstream error.
func TestProxy_RedirectNeverFollowed_ZeroSecondHop(t *testing.T) {
	target := newBoundaryUpstream(t)
	redirector := newBoundaryUpstream(t)
	redirector.redirectTo = target.URL + "/stolen"

	p := NewProxy(storeForUpstreamWithGrant(redirector.URL, nil, testGrant("ag-1")),
		testConfig(), loopbackAllow(t), nil, nil)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeUpstream {
		t.Fatalf("redirect must surface as an upstream error, got %v", err)
	}
	if redirector.Calls() != 1 || target.Calls() != 0 {
		t.Fatalf("302 must not be followed: redirector=%d target=%d", redirector.Calls(), target.Calls())
	}
}

// TestProxy_DoubleDeny_CountsExactlyOneDecisionPerCall: a repeated deny
// counts exactly one deny decision per call — no double counting per
// invocation, no miss across repetitions.
func TestProxy_DoubleDeny_CountsExactlyOneDecisionPerCall(t *testing.T) {
	up := newBoundaryUpstream(t)
	eng := guardEngine(t, toolpolicy.Policy{OrgID: "org-1", Name: "deny-delete", Subject: "*",
		Server: "knowledge", Tool: "delete_issue", Action: toolpolicy.ActionDeny,
		Priority: 50, Enabled: true})
	p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithToolGuard(eng)
	call := func() {
		_, _ = p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
			InvokeRequest{Server: "knowledge", Tool: "delete_issue", Params: json.RawMessage(`{"id":42}`)})
	}
	if d := metricDelta(t, "org-1", "knowledge", "delete_issue", "deny", func() { call(); call() }); d != 2 {
		t.Fatalf("two denied calls must count exactly 2 deny decisions, delta = %v", d)
	}
	if up.Calls() != 0 {
		t.Fatalf("repeated denies must not reach the upstream, got %d requests", up.Calls())
	}
}

// cancelAwareLoader serves its rows on a healthy context and fails with the
// context error on a cancelled one (the store outage an in-flight cancelled
// request meets).
type cancelAwareLoader struct {
	policies []toolpolicy.Policy
}

func (l *cancelAwareLoader) ListEnabled(ctx context.Context, orgID string) ([]toolpolicy.Policy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []toolpolicy.Policy
	for _, p := range l.policies {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	return out, nil
}

// TestProxy_CancelledInvoke_NeverReadsAsSuccess: the D-15 contrast at the
// invoke path. A cancelled invoke with a sticky fail-closed org posture is
// DENIED (mcp_tool_blocked, zero upstream); a deny already served from the
// cache survives cancellation; a fail-open org degrades and the downstream
// call then FAILS on the cancelled context — every branch ends in a
// diagnosable error or deny, never in a silent success.
func TestProxy_CancelledInvoke_NeverReadsAsSuccess(t *testing.T) {
	ctx := context.Background()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	t.Run("fail-closed posture denies on outage", func(t *testing.T) {
		up := newBoundaryUpstream(t)
		eng := toolpolicy.NewEngine(&cancelAwareLoader{policies: []toolpolicy.Policy{{
			OrgID: "org-1", Name: "cap", Subject: "*", Server: "knowledge", Tool: "*",
			Action: toolpolicy.ActionAllow, Rules: json.RawMessage(`{"args":{"max_bytes":64}}`), Enabled: true,
		}}}, 0)
		p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
			WithToolGuard(eng)
		// Warm the sticky fail-closed posture on a healthy load.
		if _, err := p.Invoke(ctx, "org-1", Identity{AgentID: "ag-1"},
			InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)}); err != nil {
			t.Fatalf("warm invoke must pass: %v", err)
		}
		eng.Invalidate("org-1") // force a cache miss under the cancelled ctx

		_, err := p.Invoke(cancelled, "org-1", Identity{AgentID: "ag-1"},
			InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
		var iErr *InvokeError
		if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
			t.Fatalf("fail-closed org must deny the cancelled invoke, got %v", err)
		}
		if !strings.Contains(iErr.Message, "fail-closed") {
			t.Fatalf("refusal must name the posture (diagnosable): %q", iErr.Message)
		}
		if up.Calls() != 1 { // only the warm call reached the upstream
			t.Fatalf("denied invoke must not reach the upstream, got %d requests", up.Calls())
		}
	})

	t.Run("cached deny survives cancellation", func(t *testing.T) {
		up := newBoundaryUpstream(t)
		eng := guardEngine(t, toolpolicy.Policy{OrgID: "org-1", Name: "deny-delete", Subject: "*",
			Server: "knowledge", Tool: "delete_issue", Action: toolpolicy.ActionDeny,
			Priority: 50, Enabled: true})
		p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
			WithToolGuard(eng)
		if _, err := p.Invoke(ctx, "org-1", Identity{AgentID: "ag-1"},
			InvokeRequest{Server: "knowledge", Tool: "delete_issue", Params: json.RawMessage(`{}`)}); err == nil {
			t.Fatal("warm deny expected")
		}
		_, err := p.Invoke(cancelled, "org-1", Identity{AgentID: "ag-1"},
			InvokeRequest{Server: "knowledge", Tool: "delete_issue", Params: json.RawMessage(`{}`)})
		var iErr *InvokeError
		if !errors.As(err, &iErr) || iErr.Code != ErrCodeToolBlocked {
			t.Fatalf("cached deny must survive cancellation, got %v", err)
		}
		if up.Calls() != 0 {
			t.Fatalf("denied calls must not reach the upstream, got %d requests", up.Calls())
		}
	})

	t.Run("fail-open org degrades and the call fails, not succeeds", func(t *testing.T) {
		up := newBoundaryUpstream(t)
		eng := toolpolicy.NewEngine(&cancelAwareLoader{}, 0) // org with no rows, no posture
		p := NewProxy(storeForUpstreamWithGrant(up.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
			WithToolGuard(eng)
		d := metricDelta(t, "org-1", "knowledge", "search", "error", func() {
			_, err := p.Invoke(cancelled, "org-1", Identity{AgentID: "ag-1"},
				InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{"q":"x"}`)})
			if err == nil {
				t.Fatal("a cancelled invoke must never read as success")
			}
		})
		if d != 1 {
			t.Fatalf("degraded guard must count one error decision, delta = %v", d)
		}
		if up.Calls() != 0 {
			t.Fatalf("cancelled call must not reach the upstream, got %d requests", up.Calls())
		}
	})
}
