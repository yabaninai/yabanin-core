package mcpagg

// N05-P02-T05 negative-scenario reproducibility suite (packet N05-P02):
// «Сбой пользовательской авторизации не переключается молча на более сильные
// service credentials; вход в gateway не равен авторизации внешнего сервера».
//
// Stage acceptance: the negative scenario is REPRODUCIBLE and yields NO
// false-success status; each test below names its scenario (N1..N6) and
// documents the cause and the expected result inline. The gateway resolver
// layer of the same negative is pinned separately in pkg/gateway
// (mcpcreds_mode_test.go: a delegated user miss never falls back to the
// service credential) — this suite pins the policy-pin enforcement layer.
//
// Scenarios:
//   N1  discovery (tools/list) retry window: a rejected user credential
//       whose refresh lands on the org service credential refuses — zero
//       second egress, never a silent layer switch (list-side mirror of the
//       invoke-side pin the T04 tests carry).
//   N2  invoke retry window under a service pin: a refresh that lands on
//       the user credential refuses — the pin holds in BOTH directions
//       (a service pin must not leak the org credential into a user
//       identity through the retry window either).
//   N3  user-credential RESOLUTION failure under a delegated pin surfaces
//       as an infrastructure error with ZERO egress — no unauthenticated
//       fallback, no service-credential fallback, no false success.
//   N4  gateway entry ≠ external-server authorization: a fully
//       gateway-authorized agent (verified principal + enabled grant) with
//       no stored external credential egresses NO Authorization header at
//       all (gateway secrets are never forwarded as external credentials,
//       I54) while its identity still rides the identity headers; the
//       external server's own verdict decides (401 → mcp_auth_required).
//   N5  grant revocation stops discovery the same way it stops calls:
//       not_found before ANY credential resolution or egress (the
//       acceptance half of the card, on the list call site).
//   N6  an unrecognized credential layer under a pin refuses fail-closed —
//       a source reporting outside {"", user, server} (a plausible wiring
//       bug: the credential kind in the level slot) can never silently
//       egress under a pin (N05-P02-T05 hardening of the T04-review F-2
//       seam).
//
// Every behavioral claim here is mutation-verified: reverting the pinned
// enforcement in a scratch worktree makes exactly the scenario test RED;
// restoring it goes GREEN again (teeth matrix in the work record).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// N1: list-side retry window. First attempt rides a user credential the
// upstream rejects; the refresh produces a SERVER-level credential; the
// discovery call must refuse instead of silently upgrading the layer.
func TestNegative_ListRetry_WrongLayerRefresh_Refused(t *testing.T) {
	up := newBearerUpstream(t, "u-9") // only the fresh user token would succeed
	cs := &levelCredSource{
		headers: map[string][]string{"Authorization": {"Bearer stale-user"}},
		kind:    CredKindHeaders, level: CredLevelUser,
		refreshed:    map[string][]string{"Authorization": {"Bearer svc"}},
		refreshLevel: CredLevelServer,
		retry:        true,
	}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := modeProxy(t, up, cs, mp)
	beforeDeny := bumpCredModeMetric(t, "knowledge", CredModeDelegated, "deny")

	_, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "knowledge")
	// The retry-window refusal surfaces as *credModeRefusal, deliberately
	// opaque to errors.As on *InvokeError (Invoke converts it first for the
	// OutcomeCredMode audit; the list surface carries the wrapper as-is
	// until the T06 wiring maps the wire codes). Pin the wrapper form: it
	// proves the RETRY-window enforcement fired, not the pre-egress check.
	var cmErr *credModeRefusal
	if !errors.As(err, &cmErr) || cmErr.Code != ErrCodeDenied {
		t.Fatalf("N1: list retry to a server credential under a delegated pin must refuse denied, got %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("N1: the refreshed service credential must never egress; upstream calls = %d", up.calls.Load())
	}
	if got := up.lastAuth.Load(); got != "Bearer stale-user" {
		t.Fatalf("N1: the only egress must carry the original user credential, got %v", got)
	}
	if cs.unauthCalls.Load() != 1 {
		t.Fatalf("N1: exactly one refresh round; refresh calls = %d", cs.unauthCalls.Load())
	}
	if got := credModeMetric(t, "knowledge", CredModeDelegated, "deny") - beforeDeny; got != 1 {
		t.Fatalf("N1: credmode deny metric delta = %v, want 1", got)
	}
}

// N2: invoke-side retry window under a service pin. The rejected credential
// is the org's; the refresh lands on the USER layer — refuse, zero second
// egress (the mirror direction: the org credential must not leak into a
// user identity through the retry window).
func TestNegative_InvokeRetry_ServicePin_RefreshToUser_Refused(t *testing.T) {
	up := newBearerUpstream(t, "svc-1") // only the service token would succeed
	cs := &levelCredSource{
		headers: map[string][]string{"Authorization": {"Bearer stale-svc"}},
		kind:    CredKindHeaders, level: CredLevelServer,
		refreshed:    map[string][]string{"Authorization": {"Bearer user-tok"}},
		refreshLevel: CredLevelUser,
		retry:        true,
	}
	mp := &staticModePolicy{mode: CredModeService}
	p := modeProxy(t, up, cs, mp)
	beforeDeny := bumpCredModeMetric(t, "knowledge", CredModeService, "deny")

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
		t.Fatalf("N2: service-pin retry to a user credential must refuse denied, got %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("N2: the refreshed user credential must never egress; upstream calls = %d", up.calls.Load())
	}
	if got := up.lastAuth.Load(); got != "Bearer stale-svc" {
		t.Fatalf("N2: the only egress must carry the original service credential, got %v", got)
	}
	if cs.unauthCalls.Load() != 1 {
		t.Fatalf("N2: exactly one refresh round; refresh calls = %d", cs.unauthCalls.Load())
	}
	if got := credModeMetric(t, "knowledge", CredModeService, "deny") - beforeDeny; got != 1 {
		t.Fatalf("N2: credmode deny metric delta = %v, want 1", got)
	}
}

// failResolveSource is a level-aware source whose credential RESOLUTION
// fails (the user-credential store is unavailable): the N3 scenario. The
// refresh surface is never reached (zero egress precedes it).
type failResolveSource struct {
	levelCredSource
	resolveErr error
}

func (f *failResolveSource) AuthHeadersLevel(context.Context, string, string, string) (map[string][]string, string, string, error) {
	f.authCalls.Add(1)
	return nil, "", "", f.resolveErr
}

// N3: a user-authorization resolution failure under a delegated pin is
// LOUD: an infrastructure error, zero egress — never a silent fallback to
// the service credential and never a silent unauthenticated attempt.
func TestNegative_ResolverFailure_NoSilentFallback(t *testing.T) {
	up := newBearerUpstream(t, "svc-1")
	cs := &failResolveSource{resolveErr: errors.New("user credential store unavailable")}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := modeProxy(t, up, cs, mp)

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("N3: a resolution failure must never yield a successful call")
	}
	var iErr *InvokeError
	if errors.As(err, &iErr) {
		t.Fatalf("N3: a resolution failure is an infrastructure error, not a documented denial: %v", err)
	}
	var authErr *AuthRequiredError
	if errors.As(err, &authErr) {
		t.Fatalf("N3: a resolution failure must not masquerade as mcp_auth_required: %v", err)
	}
	if !strings.Contains(err.Error(), "resolve credential") {
		t.Fatalf("N3: want the resolver error surfaced, got %v", err)
	}
	if up.calls.Load() != 0 {
		t.Fatalf("N3: zero egress on a resolution failure; upstream calls = %d", up.calls.Load())
	}
	if cs.authCalls.Load() != 1 {
		t.Fatalf("N3: exactly one resolution attempt; calls = %d", cs.authCalls.Load())
	}
}

// negRecordingUpstream answers 401 unconditionally and records the exact
// Authorization and identity headers each request carried (the N4 external
// server: it accepts NO credential the gateway could send).
type negRecordingUpstream struct {
	srv      *httptest.Server
	calls    atomic.Int64
	lastAuth atomic.Value // string
	lastAgen atomic.Value // string (X-Yabanin-Agent-Id)
}

func newNegRecordingUpstream(t *testing.T) *negRecordingUpstream {
	t.Helper()
	r := &negRecordingUpstream{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.calls.Add(1)
		r.lastAuth.Store(req.Header.Get("Authorization"))
		r.lastAgen.Store(req.Header.Get("X-Yabanin-Agent-Id"))
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// N4: gateway entry is NOT external-server authorization. The agent passes
// every gateway-side check (verified principal, enabled grant, delegation
// chain) but stores no external credential: the proxy egresses NO
// Authorization header (gateway principal material is never forwarded as an
// external credential, I54), keeps the identity in the identity headers,
// and the external server's own verdict decides — 401 → mcp_auth_required,
// never a fabricated success.
func TestNegative_GatewayEntry_IsNotExternalAuth(t *testing.T) {
	up := newNegRecordingUpstream(t) // rejects everything
	cs := &levelCredSource{kind: CredKindNone, level: ""}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := NewProxy(storeForUpstreamWithGrant(up.srv.URL, nil, testGrant("ag-1")), testConfig(), loopbackAllow(t), nil, nil).
		WithCredsSource(cs).
		WithCredModePolicy(mp)

	_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1", AgentName: "principal-name"},
		InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
	var authErr *AuthRequiredError
	if !errors.As(err, &authErr) {
		t.Fatalf("N4: gateway entry without an external credential must end in mcp_auth_required, got %v", err)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("N4: exactly one attempt (no retry round for a missing credential); calls = %d", up.calls.Load())
	}
	if got := up.lastAuth.Load(); got != "" {
		t.Fatalf("N4: no Authorization header may egress without a resolved credential; got %q", got)
	}
	if got := up.lastAgen.Load(); got != "ag-1" {
		t.Fatalf("N4: identity must still ride the identity headers, got %q", got)
	}
}

// N5: grant revocation stops DISCOVERY the same way it stops calls —
// not_found before any credential resolution or egress (the acceptance half
// of the card on the list call site; the invoke site is pinned by the T04
// suite).
func TestNegative_ListGrantRevoked_StopsAccess(t *testing.T) {
	up := newBearerUpstream(t, "")
	grant := testGrant("ag-1")
	grant.Enabled = false
	cs := &levelCredSource{headers: map[string][]string{"Authorization": {"Bearer u-1"}}, kind: CredKindHeaders, level: CredLevelUser}
	mp := &staticModePolicy{mode: CredModeDelegated}
	p := NewProxy(storeForUpstreamWithGrant(up.srv.URL, nil, grant), testConfig(), loopbackAllow(t), nil, nil).
		WithCredsSource(cs).
		WithCredModePolicy(mp)

	_, err := p.ListServerTools(context.Background(), "org-1", Identity{AgentID: "ag-1"}, "knowledge")
	var iErr *InvokeError
	if !errors.As(err, &iErr) || iErr.Code != ErrCodeNotFound {
		t.Fatalf("N5: revoked grant must refuse discovery as not_found, got %v", err)
	}
	if cs.authCalls.Load() != 0 {
		t.Fatalf("N5: credential resolution must not run for a revoked grant; calls = %d", cs.authCalls.Load())
	}
	if up.calls.Load() != 0 {
		t.Fatalf("N5: upstream calls = %d, want 0", up.calls.Load())
	}
}

// N6: an unrecognized credential layer under a pin refuses fail-closed —
// BOTH pin directions. The simulated wiring bug: the gateway source returns
// the credential KIND ("headers") in the level slot; before the T05
// tightening that value silently passed the delegated pin and egressed.
func TestNegative_UnknownLayer_UnderPin_FailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
	}{
		{"delegated pin, kind-in-level-slot", CredModeDelegated},
		{"service pin, kind-in-level-slot", CredModeService},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := newBearerUpstream(t, "")
			cs := &levelCredSource{
				headers: map[string][]string{"Authorization": {"Bearer whoever"}},
				kind:    CredKindHeaders,
				level:   CredKindHeaders, // "headers" — outside {"", user, server}
			}
			mp := &staticModePolicy{mode: tc.mode}
			p := modeProxy(t, up, cs, mp)

			_, err := p.Invoke(context.Background(), "org-1", Identity{AgentID: "ag-1"},
				InvokeRequest{Server: "knowledge", Tool: "search", Params: json.RawMessage(`{}`)})
			var iErr *InvokeError
			if !errors.As(err, &iErr) || iErr.Code != ErrCodeDenied {
				t.Fatalf("N6: an unrecognized layer must refuse denied under %s, got %v", tc.mode, err)
			}
			if up.calls.Load() != 0 {
				t.Fatalf("N6: an unverifiable layer must never egress; upstream calls = %d", up.calls.Load())
			}
		})
	}
}

// TestCredModeViolation_UnknownLevel_Matrix pins the T05-tightened
// credModeViolation at unit level: "" stays the miss path (never a
// violation), the two known layers keep their T04 semantics, and any other
// value is a violation under a pin (and irrelevant without one).
func TestCredModeViolation_UnknownLevel_Matrix(t *testing.T) {
	cases := []struct {
		mode, level string
		want        bool
	}{
		// Known-layer semantics unchanged (T04 matrix parity).
		{CredModeService, CredLevelServer, false},
		{CredModeService, CredLevelUser, true},
		{CredModeDelegated, CredLevelUser, false},
		{CredModeDelegated, CredLevelServer, true},
		// The miss path: decided by the upstream verdict, never a violation.
		{CredModeService, "", false},
		{CredModeDelegated, "", false},
		// N05-P02-T05: unrecognized layers fail closed under a pin.
		{CredModeService, CredKindHeaders, true},
		{CredModeService, "oauth", true},
		{CredModeService, "admin", true},
		{CredModeDelegated, CredKindHeaders, true},
		{CredModeDelegated, "oauth", true},
		{CredModeDelegated, "admin", true},
		// Without a pin nothing constrains the layer.
		{CredModeAuto, "admin", false},
		{"", "admin", false},
	}
	for _, tc := range cases {
		if got := credModeViolation(tc.mode, tc.level); got != tc.want {
			t.Fatalf("credModeViolation(%q, %q) = %v, want %v", tc.mode, tc.level, got, tc.want)
		}
	}
}
