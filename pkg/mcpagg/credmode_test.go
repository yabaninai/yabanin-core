package mcpagg

// N05-P02-T04 tests: the credential-mode policy enforcement on the proxy —
// the pin is enforced in BOTH directions (a delegated pin never runs on the
// org's service credential and vice versa), fail-closed on every
// unverifiable state (selector error, unknown mode, non-level-aware source),
// the miss path stays the legacy unauthenticated posture, the retry window
// is held to the same pin, discovery (tools/list) enforces the same way,
// and grant revocation stops access before ANY credential resolution.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// staticModePolicy is the CredModePolicy double: a canned mode or error.
type staticModePolicy struct {
	mode  string
	err   error
	calls atomic.Int64
}

func (s *staticModePolicy) SelectCredentialMode(context.Context, string, string, string, string) (string, error) {
	s.calls.Add(1)
	return s.mode, s.err
}

// levelCredSource is a CredSource that also implements LevelAwareCredSource:
// canned headers + the layer they were resolved from, with probe accounting.
// level == "" means "no credential resolved" (the miss path).
type levelCredSource struct {
	headers      map[string][]string
	kind         string
	level        string
	authCalls    atomic.Int64
	unauthCalls  atomic.Int64
	refreshed    map[string][]string
	refreshLevel string
	retry        bool
	refreshErr   error
}

func (f *levelCredSource) AuthHeaders(context.Context, string, string, string) (map[string][]string, string, error) {
	f.authCalls.Add(1)
	if f.headers == nil {
		return nil, f.kind, nil
	}
	return f.headers, f.kind, nil
}

func (f *levelCredSource) AuthHeadersLevel(context.Context, string, string, string) (map[string][]string, string, string, error) {
	f.authCalls.Add(1)
	if f.headers == nil {
		return nil, f.kind, "", nil
	}
	return f.headers, f.kind, f.level, nil
}

func (f *levelCredSource) OnUpstreamUnauthorized(context.Context, string, string, string, string) (map[string][]string, bool, error) {
	f.unauthCalls.Add(1)
	return f.refreshed, f.retry, f.refreshErr
}

func (f *levelCredSource) OnUpstreamUnauthorizedLevel(context.Context, string, string, string, string) (map[string][]string, string, string, bool, error) {
	f.unauthCalls.Add(1)
	if f.refreshErr != nil {
		return nil, f.kind, "", false, f.refreshErr
	}
	if f.retry {
		return f.refreshed, f.kind, f.refreshLevel, true, nil
	}
	return nil, f.kind, "", false, nil
}

// modeProxy builds a proxy with a bearer upstream, a level-aware credential
// source, a canned mode policy and no audit (unneeded for these paths).
func modeProxy(t *testing.T, up *bearerUpstream, cs CredSource, mp CredModePolicy) *Proxy {
	t.Helper()
	return NewProxy(storeForUpstreamWithGrant(up.srv.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithCredsSource(cs).
		WithCredModePolicy(mp)
}

func credModeMetric(t *testing.T, server, mode, outcome string) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.MCPCredModeTotal.WithLabelValues(server, mode, outcome))
}

// bumpCredModeMetric returns the current value of the cred-mode counter so
// an action can be asserted as exactly +1 (the registry is process-global
// and test order may shuffle).
func bumpCredModeMetric(t *testing.T, server, mode, outcome string) float64 {
	t.Helper()
	return credModeMetric(t, server, mode, outcome)
}

func TestProxy_CredMode_Delegated_UserCredential_Passes(t *testing.T) {
	up := newBearerUpstream(t, "")
	cs := &levelCredSource{headers: map[string][]string{"Authorization": {"Bearer u-1"}}, kind: CredKindHeaders, level: CredLevelUser}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := modeProxy(t, up, cs, mp)
	beforeAllow := bumpCredModeMetric(t, "knowledge", CredModeDelegated, "allow")
	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("delegated + user credential must pass: %v", err)
	}
	if !strings.Contains(string(res), "ok") {
		t.Fatalf("bad result: %s", res)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", up.calls.Load())
	}
	if got := credModeMetric(t, "knowledge", CredModeDelegated, "allow") - beforeAllow; got != 1 {
		t.Fatalf("credmode allow metric delta = %v, want 1", got)
	}
}

func TestProxy_CredMode_Delegated_ServerCredential_Refused(t *testing.T) {
	up := newBearerUpstream(t, "")
	cs := &levelCredSource{headers: map[string][]string{"Authorization": {"Bearer svc-1"}}, kind: CredKindHeaders, level: CredLevelServer}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := modeProxy(t, up, cs, mp)
	beforeDeny := bumpCredModeMetric(t, "knowledge", CredModeDelegated, "deny")
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
		t.Fatalf("delegated pin + server credential must refuse denied, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("refusal must be pre-egress; upstream calls = %d", up.calls.Load())
	}
	if got := credModeMetric(t, "knowledge", CredModeDelegated, "deny") - beforeDeny; got != 1 {
		t.Fatalf("credmode deny metric delta = %v, want 1", got)
	}
}

func TestProxy_CredMode_Service_UserCredential_Refused(t *testing.T) {
	up := newBearerUpstream(t, "")
	cs := &levelCredSource{headers: map[string][]string{"Authorization": {"Bearer u-1"}}, kind: CredKindHeaders, level: CredLevelUser}
	mp := &staticModePolicy{mode: CredModeService}
	p := modeProxy(t, up, cs, mp)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
		t.Fatalf("service pin + user credential must refuse denied, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("refusal must be pre-egress; upstream calls = %d", up.calls.Load())
	}
}

func TestProxy_CredMode_SelectorError_FailClosed(t *testing.T) {
	up := newBearerUpstream(t, "")
	cs := &levelCredSource{headers: map[string][]string{"Authorization": {"Bearer u-1"}}, kind: CredKindHeaders, level: CredLevelUser}
	mp := &staticModePolicy{err: errors.New("policy store down")}
	p := modeProxy(t, up, cs, mp)
	beforeErr := bumpCredModeMetric(t, "knowledge", "-", "error")
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
		t.Fatalf("selector outage must fail closed denied, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("fail-closed refusal must be pre-egress; upstream calls = %d", up.calls.Load())
	}
	if cs.authCalls.Load() != 0 {
		t.Fatalf("credential resolution must not run after a selector failure; calls = %d", cs.authCalls.Load())
	}
	if got := credModeMetric(t, "knowledge", "-", "error") - beforeErr; got != 1 {
		t.Fatalf("credmode error metric delta = %v, want 1", got)
	}
}

func TestProxy_CredMode_UnknownMode_FailClosed(t *testing.T) {
	up := newBearerUpstream(t, "")
	cs := &levelCredSource{headers: map[string][]string{"Authorization": {"Bearer u-1"}}, kind: CredKindHeaders, level: CredLevelUser}
	mp := &staticModePolicy{mode: "root"}
	p := modeProxy(t, up, cs, mp)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
		t.Fatalf("unknown mode must fail closed denied, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", up.calls.Load())
	}
}

func TestProxy_CredMode_NoCredential_MissPathStands(t *testing.T) {
	// delegated pin + NO credential: the miss path keeps the legacy
	// posture — the call egresses unauthenticated and the upstream verdict
	// decides (401 → mcp_auth_required), never a pin violation.
	up := newBearerUpstream(t, "real")
	cs := &levelCredSource{kind: CredKindNone, level: ""}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := modeProxy(t, up, cs, mp)
	beforeAllow := bumpCredModeMetric(t, "knowledge", CredModeDelegated, "allow")
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var authErr *AuthRequiredError
	if !errors.As(err, &authErr) {
		t.Fatalf("no-credential miss under a pin must end in mcp_auth_required, got %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1 (single unauthenticated attempt)", up.calls.Load())
	}
	if got := credModeMetric(t, "knowledge", CredModeDelegated, "allow") - beforeAllow; got != 1 {
		t.Fatalf("miss must count as allow (no layer to violate); delta = %v, want 1", got)
	}
}

func TestProxy_CredMode_Retry_RefreshedServerCredential_Refused(t *testing.T) {
	// The first attempt rides a user credential that the upstream rejects;
	// the refresh produces a SERVER-level credential — the retry must
	// refuse instead of silently upgrading the layer.
	up := newBearerUpstream(t, "u-1")
	cs := &levelCredSource{
		headers: map[string][]string{"Authorization": {"Bearer stale"}},
		kind:    CredKindHeaders, level: CredLevelUser,
		refreshed:    map[string][]string{"Authorization": {"Bearer svc"}},
		refreshLevel: CredLevelServer,
		retry:        true,
	}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := modeProxy(t, up, cs, mp)
	beforeDeny := bumpCredModeMetric(t, "knowledge", CredModeDelegated, "deny")
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
		t.Fatalf("retry refresh to a server credential under a delegated pin must refuse, got %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("the refreshed credential must never egress; upstream calls = %d", up.calls.Load())
	}
	if cs.unauthCalls.Load() != 1 {
		t.Fatalf("exactly one refresh round; refresh calls = %d", cs.unauthCalls.Load())
	}
	if got := credModeMetric(t, "knowledge", CredModeDelegated, "deny") - beforeDeny; got != 1 {
		t.Fatalf("credmode deny metric delta = %v, want 1", got)
	}
}

func TestProxy_CredMode_Retry_RefreshedUserCredential_Retries(t *testing.T) {
	up := newBearerUpstream(t, "u-2")
	cs := &levelCredSource{
		headers: map[string][]string{"Authorization": {"Bearer stale"}},
		kind:    CredKindHeaders, level: CredLevelUser,
		refreshed:    map[string][]string{"Authorization": {"Bearer u-2"}},
		refreshLevel: CredLevelUser,
		retry:        true,
	}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := modeProxy(t, up, cs, mp)
	res, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("level-preserving refresh must retry: %v", err)
	}
	if up.calls.Load() != 2 || up.lastAuth.Load() != "Bearer u-2" {
		t.Fatalf("calls = %d lastAuth = %v, want 2 / Bearer u-2", up.calls.Load(), up.lastAuth.Load())
	}
	if !strings.Contains(string(res), "ok") {
		t.Fatalf("bad result: %s", res)
	}
}

func TestProxy_CredMode_Auto_NoEnforcement(t *testing.T) {
	// auto = explicitly unconstrained: a server-level credential is fine.
	up := newBearerUpstream(t, "")
	cs := &levelCredSource{headers: map[string][]string{"Authorization": {"Bearer svc"}}, kind: CredKindHeaders, level: CredLevelServer}
	mp := &staticModePolicy{mode: CredModeAuto}
	p := modeProxy(t, up, cs, mp)
	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("auto mode must not enforce a layer: %v", err)
	}
}

func TestProxy_CredMode_UnconstrainedLegacyPathUntouched(t *testing.T) {
	// A non-level-aware source + NO mode policy: the pre-T04 behavior
	// bit-for-bit (the legacy AuthHeaders surface, zero enforcement).
	up := newBearerUpstream(t, "")
	cs := &fakeCredSource{headers: map[string][]string{"Authorization": {"Bearer legacy"}}, kind: CredKindHeaders}
	p := NewProxy(storeForUpstreamWithGrant(up.srv.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithCredsSource(cs)
	if _, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("legacy path must pass: %v", err)
	}
	if cs.authCalls.Load() != 1 {
		t.Fatalf("legacy source calls = %d, want 1", cs.authCalls.Load())
	}
}

func TestProxy_CredMode_Constrained_NonLevelAwareSource_Refused(t *testing.T) {
	// A pin requires a source that can report the resolved layer. A legacy
	// source cannot — refuse, never assume.
	up := newBearerUpstream(t, "")
	cs := &fakeCredSource{headers: map[string][]string{"Authorization": {"Bearer maybe-any-layer"}}, kind: CredKindHeaders}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := modeProxy(t, up, cs, mp)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
		t.Fatalf("constrained call on a non-level-aware source must refuse, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", up.calls.Load())
	}
}

func TestProxy_ListTools_CredMode_Enforced(t *testing.T) {
	up := newBearerUpstream(t, "")
	cs := &levelCredSource{headers: map[string][]string{"Authorization": {"Bearer svc"}}, kind: CredKindHeaders, level: CredLevelServer}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := modeProxy(t, up, cs, mp)
	beforeDeny := bumpCredModeMetric(t, "knowledge", CredModeDelegated, "deny")
	_, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "knowledge")
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
		t.Fatalf("list under a delegated pin with a server credential must refuse, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", up.calls.Load())
	}
	if got := credModeMetric(t, "knowledge", CredModeDelegated, "deny") - beforeDeny; got != 1 {
		t.Fatalf("credmode deny metric delta = %v, want 1", got)
	}
}

func TestProxy_ListTools_CredMode_PassThrough(t *testing.T) {
	up := newBearerUpstream(t, "")
	cs := &levelCredSource{headers: map[string][]string{"Authorization": {"Bearer u-1"}}, kind: CredKindHeaders, level: CredLevelUser}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := modeProxy(t, up, cs, mp)
	tools, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "knowledge")
	if err != nil {
		t.Fatalf("list under a delegated pin with a user credential must pass: %v", err)
	}
	if tools == nil {
		t.Fatal("tools must be a non-nil slice")
	}
}

func TestProxy_CredMode_GrantRevoked_StopsBeforeCredentials(t *testing.T) {
	// The revocation acceptance: flipping the grant's enabled flag stops
	// ALL dependent access — not_found, and the credential path (either
	// layer) never even runs.
	up := newBearerUpstream(t, "")
	grant := testGrant("ag-1")
	grant.Enabled = false
	cs := &levelCredSource{headers: map[string][]string{"Authorization": {"Bearer u-1"}}, kind: CredKindHeaders, level: CredLevelUser}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := NewProxy(storeForUpstreamWithGrant(up.srv.URL, nil, grant), testConfig(), loopbackAllow(t), nil, nil).
		WithCredsSource(cs).
		WithCredModePolicy(mp)
	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeNotFound {
		t.Fatalf("revoked grant must refuse not_found, got %v", err)
	}
	if cs.authCalls.Load() != 0 {
		t.Fatalf("credential resolution must not run for a revoked grant; calls = %d", cs.authCalls.Load())
	}
	if up.calls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", up.calls.Load())
	}
}

func TestGrantAllowsAction_Vocabulary(t *testing.T) {
	g := testGrant("ag-1")
	if !grantAllowsAction(g, GrantActionInvoke) || !grantAllowsAction(g, GrantActionList) {
		t.Fatal("an enabled grant authorizes invoke and list")
	}
	g.Enabled = false
	if grantAllowsAction(g, GrantActionInvoke) || grantAllowsAction(g, GrantActionList) {
		t.Fatal("a disabled grant authorizes nothing")
	}
	g = nil
	if grantAllowsAction(g, GrantActionInvoke) {
		t.Fatal("nil grant authorizes nothing")
	}
	if grantAllowsAction(testGrant("ag-1"), "delete") || grantAllowsAction(testGrant("ag-1"), "") {
		t.Fatal("unknown actions are refused (fail-closed)")
	}
}

func TestCredModeVocabulary_MatchesToolpolicy(t *testing.T) {
	// The pin test: mcpagg's enforcement vocabulary and toolpolicy's
	// rules-document vocabulary must stay identical (toolpolicy must not
	// import mcpagg — cycle — so the equality is asserted here).
	if CredModeAuto != toolpolicy.CredentialModeAuto ||
		CredModeService != toolpolicy.CredentialModeService ||
		CredModeDelegated != toolpolicy.CredentialModeDelegated {
		t.Fatalf("vocabularies diverged: mcpagg (%s, %s, %s) vs toolpolicy (%s, %s, %s)",
			CredModeAuto, CredModeService, CredModeDelegated,
			toolpolicy.CredentialModeAuto, toolpolicy.CredentialModeService, toolpolicy.CredentialModeDelegated)
	}
}

func TestCredModeViolation_Matrix(t *testing.T) {
	cases := []struct {
		mode, level string
		want        bool
	}{
		{CredModeService, CredLevelServer, false},
		{CredModeService, CredLevelUser, true},
		{CredModeDelegated, CredLevelUser, false},
		{CredModeDelegated, CredLevelServer, true},
		{CredModeDelegated, "", false}, // miss path: the upstream verdict decides
		{CredModeService, "", false},
		{CredModeAuto, CredLevelServer, false},
		{"", CredLevelUser, false},
	}
	for _, tc := range cases {
		if got := credModeViolation(tc.mode, tc.level); got != tc.want {
			t.Fatalf("credModeViolation(%q, %q) = %v, want %v", tc.mode, tc.level, got, tc.want)
		}
	}
}

func TestNormalizeCredMode_Vocabulary(t *testing.T) {
	for _, m := range []string{"", CredModeAuto, CredModeService, CredModeDelegated} {
		got, err := normalizeCredMode(m)
		if err != nil || got != m {
			t.Fatalf("normalizeCredMode(%q) = (%q, %v)", m, got, err)
		}
	}
	if _, err := normalizeCredMode("sudo"); err == nil {
		t.Fatal("unknown mode must be an error (fail-closed)")
	}
}
