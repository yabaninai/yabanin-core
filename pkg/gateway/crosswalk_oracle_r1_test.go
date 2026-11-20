package cli

// CROSSWALK-ORACLE-R1 — ordinary fixture/oracle coverage for the CI
// crosswalk (regular-vs-seeds.json, sha256 123c19d5…): of the 681
// pkg/gateway functions untouched by the default installed-seed replay,
// 651 are already reached by regular tests (reuse, do not duplicate);
// this file pins 13 of the 30 reached by NEITHER, at the current
// integrated-source function names (line spans in the crosswalk refer to
// head 0e32ff48 and drift after integration — targets are name-keyed).
// These are ordinary tests, NOT dedicated fuzz proof; the installed
// fuzz-seed validation with populated profiles and a real 300s budget
// remains a separate coordinator-side gate.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/router"
)

func TestCrosswalkR1_JWTAuthErrorMessage(t *testing.T) {
	e := jwtAuthErr(http.StatusServiceUnavailable, "jwks_unreachable", "auth unavailable")
	if got := e.Error(); got != "auth unavailable" {
		t.Fatalf("jwtAuthError.Error() = %q, want the client-safe message", got)
	}
	if e.status != http.StatusServiceUnavailable || e.reason != "jwks_unreachable" {
		t.Fatalf("jwtAuthErr fields not carried: %+v", e)
	}
}

func TestCrosswalkR1_TokenEndpointErrorUnwrap(t *testing.T) {
	cause := errors.New("dial tcp: refused")
	e := &tokenEndpointError{cause: cause}
	if !errors.Is(e, cause) {
		t.Fatalf("errors.Is must traverse tokenEndpointError.Unwrap")
	}
	if got := (&tokenEndpointError{}).Unwrap(); got != nil {
		t.Fatalf("zero tokenEndpointError unwraps nil, got %v", got)
	}
}

func TestCrosswalkR1_RealtimeStreamTooLargeMessage(t *testing.T) {
	var err error = errRealtimeStreamTooLarge{}
	if got := err.Error(); got != "upstream stream exceeds the realtime size limit" {
		t.Fatalf("errRealtimeStreamTooLarge.Error() = %q", got)
	}
	if !errors.Is(errRealtimeStreamTooLarge{}, errRealtimeStreamTooLarge{}) {
		t.Fatalf("the realtime limit error must compare by value")
	}
}

func TestCrosswalkR1_GuardFailureMode(t *testing.T) {
	shadow := &gateway{policyRuntime: &PolicyRuntime{mode: PolicyModeShadow}}
	if fm := shadow.guardFailureMode(); fm != guardhooks.FailureModeShadow {
		t.Fatalf("shadow runtime must map to FailureModeShadow, got %v", fm)
	}
	enforce := &gateway{policyRuntime: &PolicyRuntime{mode: PolicyModeEnforce}}
	if fm := enforce.guardFailureMode(); fm != guardhooks.FailureModeEnforce {
		t.Fatalf("enforce runtime must map to FailureModeEnforce, got %v", fm)
	}
	bare := &gateway{}
	if fm := bare.guardFailureMode(); fm != guardhooks.FailureModeEnforce {
		t.Fatalf("no runtime must default to enforce (fail closed), got %v", fm)
	}
}

func TestCrosswalkR1_ResolvePolicyColdFailureMode(t *testing.T) {
	cases := []struct {
		in, wantMode, wantWarn string
	}{
		{"", string(PolicyColdFailureFailClosed), ""},
		{"fail-closed", string(PolicyColdFailureFailClosed), ""},
		{"  FAIL-OPEN  ", string(PolicyColdFailureFailOpen), ""},
		{"bogus", string(PolicyColdFailureFailClosed),
			"YABANIN_POLICY_COLD_FAILURE_MODE is invalid; defaulting to fail-closed"},
	}
	for _, c := range cases {
		mode, warn := ResolvePolicyColdFailureMode(c.in)
		if string(mode) != c.wantMode || warn != c.wantWarn {
			t.Fatalf("ResolvePolicyColdFailureMode(%q) = (%q, %q), want (%q, %q)",
				c.in, mode, warn, c.wantMode, c.wantWarn)
		}
	}
	// The unknown-value warning must never echo operator input.
	_, warn := ResolvePolicyColdFailureMode("SECRET-INPUT")
	if strings.Contains(warn, "SECRET-INPUT") {
		t.Fatalf("cold-failure warning must not echo input: %q", warn)
	}
}

func TestCrosswalkR1_ResolveCircuitScope(t *testing.T) {
	if s, warn := ResolveCircuitScope(""); s != circuit.ScopePerEndpoint || warn != "" {
		t.Fatalf("empty scope: (%v, %q)", s, warn)
	}
	for _, v := range []string{"per-endpoint", "PER_ENDPOINT", " per-endpoint "} {
		if s, warn := ResolveCircuitScope(v); s != circuit.ScopePerEndpoint || warn != "" {
			t.Fatalf("%q: (%v, %q)", v, s, warn)
		}
	}
	if s, warn := ResolveCircuitScope("global"); s != circuit.ScopeGlobal || warn != "" {
		t.Fatalf("global: (%v, %q)", s, warn)
	}
	s, warn := ResolveCircuitScope("galactic")
	if s != circuit.ScopePerEndpoint || !strings.Contains(warn, "galactic") {
		t.Fatalf("unknown scope must fall back per-endpoint with a warning, got (%v, %q)", s, warn)
	}
}

func TestCrosswalkR1_CircuitScopeWiringDefault(t *testing.T) {
	w := CircuitScopeWiring{}
	if w.ResolvedScope() != circuit.ScopePerEndpoint {
		t.Fatalf("zero wiring must resolve per-endpoint default")
	}
	if (CircuitScopeWiring{Scope: circuit.ScopeGlobal}).ResolvedScope() != circuit.ScopeGlobal {
		t.Fatalf("global wiring must pass through")
	}
	if (CircuitScopeWiring{Scope: circuit.Scope(42)}).ResolvedScope() != circuit.ScopePerEndpoint {
		t.Fatalf("junk wiring must fall back to per-endpoint")
	}
}

func TestCrosswalkR1_QuoteLiteral(t *testing.T) {
	cases := map[string]string{
		"":        "''",
		"plain":   "'plain'",
		"O'Brien": "'O''Brien'",
	}
	for in, want := range cases {
		if got := quoteLiteral(in); got != want {
			t.Fatalf("quoteLiteral(%q) = %q, want %q", in, got, want)
		}
	}
	if got := quoteLiteral("a" + strings.Repeat("'", 2) + "b"); got != "'a"+strings.Repeat("'", 4)+"b'" {
		t.Fatalf("quoteLiteral must double every quote: %q", got)
	}
}

func TestCrosswalkR1_SessionCostKey(t *testing.T) {
	if got := sessionCostKey("abc123"); got != "yb:skey:abc123:ucost" {
		t.Fatalf("sessionCostKey = %q", got)
	}
}

func TestCrosswalkR1_GetPeerURLs(t *testing.T) {
	regions := config.RegionMap{
		"eu": {Name: "eu", GatewayURL: "https://eu.example.internal"},
		"sg": {Name: "sg", GatewayURL: "https://sg.example.internal"},
		"in": {Name: "in", GatewayURL: ""},
	}
	peers := getPeerURLs(regions)
	if len(peers) != 2 {
		t.Fatalf("regions without GatewayURL must be skipped, got %d peers", len(peers))
	}
	seen := map[string]string{}
	for _, p := range peers {
		seen[p.Region] = p.URL
	}
	if seen["eu"] != "https://eu.example.internal" || seen["sg"] != "https://sg.example.internal" {
		t.Fatalf("peer URLs not carried: %+v", peers)
	}
	if _, ok := seen["in"]; ok {
		t.Fatalf("empty GatewayURL must not produce a peer")
	}
	if got := getPeerURLs(nil); got != nil {
		t.Fatalf("nil RegionMap must yield nil peers, got %+v", got)
	}
	if got := getPeerURLs(config.RegionMap{}); got != nil {
		t.Fatalf("empty RegionMap must yield nil peers, got %+v", got)
	}
}

func TestCrosswalkR1_CanarySnapshotLoadFuncDelegates(t *testing.T) {
	want := []router.CanaryRollout{{RolloutID: "ro-1", Name: "nightly", Percent: 5}}
	calls := 0
	f := canarySnapshotLoadFunc(func(_ context.Context, orgID string) ([]router.CanaryRollout, error) {
		calls++
		if orgID != "org-7" {
			t.Fatalf("orgID not forwarded: %q", orgID)
		}
		return want, nil
	})
	got, err := f.LoadCanaryRollouts(context.Background(), "org-7")
	if err != nil || len(got) != 1 || got[0].RolloutID != "ro-1" || calls != 1 {
		t.Fatalf("canarySnapshotLoadFunc delegation: got=%v err=%v calls=%d", got, err, calls)
	}
}

func TestCrosswalkR1_SSEPolicyWriterPassthrough(t *testing.T) {
	rec := httptest.NewRecorder()
	pw := &sseStreamPolicyWriter{w: rec}
	pw.WriteHeader(http.StatusTeapot)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("WriteHeader must delegate verbatim, recorder=%d", rec.Code)
	}
	pw.Header().Set("X-Crosswalk-R1", "set")
	if rec.Header().Get("X-Crosswalk-R1") != "set" {
		t.Fatalf("Header must be the inner writer's map")
	}

	// prefixTimerFired no-op legs: a finished writer and an unwired gate
	// must never touch the client writer (no panic, no bytes, no header).
	done := &sseStreamPolicyWriter{w: rec, done: true}
	done.prefixTimerFired()
	if rec.Code != http.StatusTeapot || rec.Body.Len() != 0 {
		t.Fatalf("finished writer must stay terminal: code=%d body=%q", rec.Code, rec.Body.String())
	}
	unwired := &sseStreamPolicyWriter{w: rec}
	unwired.prefixTimerFired()
	if rec.Code != http.StatusTeapot || rec.Body.Len() != 0 {
		t.Fatalf("nil gate must be a no-op: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestCrosswalkR1_WriteMCPUserCredErr(t *testing.T) {
	gw := &gateway{log: fuzzDiscardLogger()}

	w := httptest.NewRecorder()
	gw.writeMCPUserCredErr(w, adminstore.ErrNotFound)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "not_found") {
		t.Fatalf("not-found must map to 404/not_found, got %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	gw.writeMCPUserCredErr(w, errors.New("driver: connection refused"))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "internal") {
		t.Fatalf("driver errors must map to a generic 500, got %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "connection refused") {
		t.Fatalf("driver text must never reach the client: %s", w.Body.String())
	}
}
