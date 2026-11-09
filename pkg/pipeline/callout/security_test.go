package callout

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// TestFactoryValidation: policy LOAD rejects every malformed or
// egress-widening step definition before it can ever run.
func TestFactoryValidation(t *testing.T) {
	base := func(url string) map[string]any {
		return map[string]any{"url": url}
	}
	newRT := func(t *testing.T, hosts ...string) *Runtime {
		t.Helper()
		if len(hosts) == 0 {
			hosts = []string{"detector.internal", "*.scanner.example"}
		}
		rt, err := New(Deps{AllowHosts: hosts, Timeout: time.Second})
		if err != nil {
			t.Fatalf("new runtime: %v", err)
		}
		return rt
	}

	cases := []struct {
		name    string
		mutate  bool
		params  map[string]any
		wantErr string
	}{
		{"url-required", false, map[string]any{}, "URL is required"},
		{"url-type", false, map[string]any{"url": 42}, "URL is required"},
		{"scheme-ftp", false, base("ftp://detector.internal/x"), "scheme must be http or https"},
		{"userinfo", false, base("http://user:secret@detector.internal/x"), "userinfo"},
		{"no-host", false, base("http:///x"), "host is required"},
		{"fragment", false, base("http://detector.internal/x#frag"), "fragment"},
		{"host-not-allow-listed", false, base("http://evil.example/x"), "allow-list"},
		{"bad-expose", false, func() map[string]any { p := base("http://detector.internal/x"); p["expose"] = "everything"; return p }(), "want messages | body | fields"},
		{"bad-response", false, func() map[string]any { p := base("http://detector.internal/x"); p["response"] = "maybe"; return p }(), "want findings|boolean"},
		{"bad-action", false, func() map[string]any { p := base("http://detector.internal/x"); p["finding_action"] = "nuke"; return p }(), "want deny|mask|flag|allow"},
		{"bad-max-response", false, func() map[string]any { p := base("http://detector.internal/x"); p["max_response_bytes"] = -1; return p }(), "must be positive"},
		{"mutate-response-param", true, func() map[string]any {
			p := base("http://detector.internal/x")
			p["mode"] = "mutate"
			p["response"] = "findings"
			return p
		}(), "not valid for mutate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRT(t)
			build := rt.DetectFactory
			if tc.mutate {
				build = rt.MutateFactory
			}
			if _, err := build(tc.params); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("factory err = %v, want contains %q", err, tc.wantErr)
			}
		})
	}

	t.Run("wildcard-allow-list", func(t *testing.T) {
		rt := newRT(t)
		if _, err := rt.DetectFactory(base("https://sub.scanner.example/detect")); err != nil {
			t.Fatalf("wildcard subdomain refused: %v", err)
		}
	})

	t.Run("response-and-boolean-params-valid", func(t *testing.T) {
		rt := newRT(t)
		p := base("http://detector.internal/x")
		p["response"] = "boolean"
		if _, err := rt.DetectFactory(p); err != nil {
			t.Fatalf("valid config refused: %v", err)
		}
	})
}

// TestNew_EmptyAllowListRejected: a Runtime without an explicit egress list
// is a construction error — callout egress can never default to open.
func TestNew_EmptyAllowListRejected(t *testing.T) {
	if _, err := New(Deps{}); err == nil || !strings.Contains(err.Error(), "AllowHosts") {
		t.Fatalf("err = %v, want AllowHosts rejection", err)
	}
	if _, err := New(Deps{AllowHosts: []string{"bad_*pattern"}}); err == nil {
		t.Fatal("invalid allow-list pattern accepted")
	}
}

// TestRedirect_Refused: a 3xx is a step error — a redirect would silently
// change the method and re-target the request. The metadata-IP Location is
// never dialed (the client refuses before any second request).
func TestRedirect_Refused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	rt := newTestRuntimeAt(t)
	recorded := &countingDialer{base: &net.Dialer{Timeout: 2 * time.Second}}
	rt.client = newClient(Deps{Timeout: 2 * time.Second}, recorded.DialContext)
	comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "")))

	res := runOne(t, comp, msgPayload("p"))
	if res.Verdict != pipeline.ActionDeny {
		t.Fatalf("verdict = %s, want deny on redirect", res.Verdict)
	}
	if !strings.Contains(res.Trace[0].Error, "redirect") {
		t.Fatalf("error = %q, want redirect refusal", res.Trace[0].Error)
	}
	if n := recorded.metadataDials.Load(); n != 0 {
		t.Fatalf("metadata IP was dialed %d times", n)
	}
}

// countingDialer records dials to reserved addresses.
type countingDialer struct {
	base          *net.Dialer
	metadataDials atomic.Int32
}

func (d *countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if strings.HasPrefix(addr, "169.254.") {
		d.metadataDials.Add(1)
	}
	return d.base.DialContext(ctx, network, addr)
}

// TestGuard_BlocksReservedDial: the production guarded client resolves the
// endpoint host itself and refuses any reserved answer (DNS rebinding
// closed) — here a hijacked resolver points detector.test at the cloud
// metadata IP and the dial never happens. The client stays the production
// guarded one; only the ssrf seams are injected.
func TestGuard_BlocksReservedDial(t *testing.T) {
	var dials atomic.Int32
	rt, err := New(Deps{
		AllowHosts: []string{"detector.test"},
		Timeout:    time.Second,
		Lookup: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("must not dial")
		},
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}

	comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, "http://detector.test/detect", "")))
	res := runOne(t, comp, msgPayload("p"))
	if res.Verdict != pipeline.ActionDeny {
		t.Fatalf("verdict = %s, want deny", res.Verdict)
	}
	traceErr := errors.New(res.Trace[0].Error)
	if !errors.Is(traceErr, ssrf.ErrReservedTarget) && !strings.Contains(res.Trace[0].Error, "forbidden") {
		t.Fatalf("error = %q, want reserved-target refusal", res.Trace[0].Error)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("dial happened %d times despite the guard", n)
	}
}

// TestBreaker_OpensAndStopsHitting: after the failure threshold the per-URL
// breaker sheds the endpoint — further steps fail fast with
// circuit.ErrCircuitOpen and the upstream request counter stops growing.
func TestBreaker_OpensAndStopsHitting(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusServiceUnavailable, "application/json", ""
	}}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce",
		fmt.Sprintf("%s\n    on_error: fail_open", stepYAML(testStepID, srv.URL, ""))))

	// Threshold is 2: runs 1-2 reach the server, 3-5 are shed.
	for i := 1; i <= 5; i++ {
		res := runOne(t, comp, msgPayload("p"))
		if res.Trace[0].Outcome != pipeline.StepError {
			t.Fatalf("run %d: outcome = %s, want error", i, res.Trace[0].Outcome)
		}
		if got := int(rec.requests.Load()); got != min(i, 2) {
			t.Fatalf("run %d: upstream hits = %d, want %d (breaker must stop dialing)", i, got, min(i, 2))
		}
	}
	state, ok := rt.breakerState(srv.URL)
	if !ok || state != circuit.StateOpen {
		t.Fatalf("breaker state = %s (found=%v), want open", state, ok)
	}
	if !IsBreakerOpen(fmt.Errorf("step failed: %w", circuit.ErrCircuitOpen)) {
		t.Fatal("IsBreakerOpen lost its sentinel classification")
	}
	// Breaker rejections are counted as callout errors.
	if n := testutil.ToFloat64(calloutErrors.WithLabelValues(srv.URL)); n < 5 {
		t.Fatalf("callout_errors_total = %v, want ≥ 5 (incl. shed calls)", n)
	}
	if n := testutil.ToFloat64(calloutRequests.WithLabelValues(srv.URL)); n != 2 {
		t.Fatalf("callout_requests_total = %v, want 2 (only real sends)", n)
	}
}

// TestSingleflight_ConcurrentIdentical: N concurrent Engine.Run calls with
// the same (url, content) share exactly ONE upstream call and all receive
// the shared verdict.
func TestSingleflight_ConcurrentIdentical(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		time.Sleep(200 * time.Millisecond) // hold the flight window open
		return http.StatusOK, "application/json", findingsResponse(map[string]any{"category": "pii", "action": "flag"})
	}}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "")))

	const n = 10
	results := make([]*pipeline.Result, n)
	var wg sync.WaitGroup
	ready := make(chan struct{}, n)
	release := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			ready <- struct{}{}
			<-release
			results[i] = runOne(t, comp, msgPayload("same content"))
		})
	}
	for range n {
		<-ready // every worker is dispatched
	}
	close(release)
	wg.Wait()

	if got := rec.requests.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1 for N=%d identical calls", got, n)
	}
	for i, res := range results {
		if res.Verdict != pipeline.ActionFlag || len(res.Findings) != 1 || res.Findings[0].Category != "pii" {
			t.Fatalf("result %d: verdict=%s findings=%+v", i, res.Verdict, res.Findings)
		}
	}
}

// TestSingleflight_DifferentContent: only identical (url, content) pairs
// dedup — different payloads each get their own upstream call.
func TestSingleflight_DifferentContent(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		time.Sleep(20 * time.Millisecond)
		return http.StatusOK, "application/json", findingsResponse()
	}}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "")))

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			runOne(t, comp, msgPayload(fmt.Sprintf("payload-%d", i)))
		})
	}
	wg.Wait()
	if got := rec.requests.Load(); got != 4 {
		t.Fatalf("upstream hits = %d, want 4 (different content)", got)
	}
}

// TestNoRetries: one-shot semantics — a failing endpoint is attempted
// exactly once per step run (no transport or client retries).
func TestNoRetries(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusInternalServerError, "application/json", ""
	}}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)
	comp := compileWith(t, rt, policyYAML("enforce",
		fmt.Sprintf("%s\n    on_error: fail_open", stepYAML(testStepID, srv.URL, ""))))
	runOne(t, comp, msgPayload("p"))
	if got := rec.requests.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want exactly 1 (no retries)", got)
	}
}

// TestCalloutKindDispatch: the core "callout" kind dispatches on
// params.mode — detect by default, mutate explicitly; both spellings
// (callout kind with url, builtin/* with url in params) compile.
func TestCalloutKindDispatch(t *testing.T) {
	rec := &recorder{respond: respondContent(`["mutated"]`)}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)

	comp := compileWith(t, rt, policyYAML("enforce", stepYAML(testStepID, srv.URL, "mode: mutate")))
	res := runOne(t, comp, msgPayload("original"))
	if res.Mutated == nil || res.Mutated.Messages[0].Content != "mutated" {
		t.Fatalf("callout kind + mode=mutate did not mutate: %+v", res.Mutated)
	}

	det := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusOK, "application/json", findingsResponse(map[string]any{"category": "x"})
	}}
	detSrv := det.server(t)
	alt := fmt.Sprintf(`apiVersion: ypp/v1
kind: Policy
name: callout-test
mode: enforce
hooks: [pre_upstream]
steps:
  - id: %s
    detector: builtin/callout-detect
    params:
      url: %q
      expose: messages
`, testStepID, detSrv.URL)
	comp2 := compileWith(t, rt, []byte(alt))
	res = runOne(t, comp2, msgPayload("p"))
	if len(res.Findings) != 1 || res.Findings[0].Category != "x" {
		t.Fatalf("detector spelling: findings=%+v", res.Findings)
	}

	det2 := &recorder{respond: respondContent(`["rewritten"]`)}
	alt2 := fmt.Sprintf(`apiVersion: ypp/v1
kind: Policy
name: callout-test
mode: enforce
hooks: [pre_upstream]
steps:
  - id: %s
    mutator: builtin/callout-mutate
    params:
      url: %q
`, testStepID, det2.server(t).URL)
	comp3 := compileWith(t, rt, []byte(alt2))
	res = runOne(t, comp3, msgPayload("in"))
	if res.Mutated == nil || res.Mutated.Messages[0].Content != "rewritten" {
		t.Fatalf("mutator spelling did not mutate: %+v", res.Mutated)
	}
}

// TestDetect_ParallelGroup: a detect step participates in a parallel join
// group (read-only Detector) alongside another detector; findings merge in
// declaration order.
func TestDetect_ParallelGroup(t *testing.T) {
	rec := &recorder{respond: func(int, *http.Request) (int, string, string) {
		return http.StatusOK, "application/json", findingsResponse(map[string]any{"category": "from-callout", "action": "flag"})
	}}
	srv := rec.server(t)
	rt := newTestRuntimeAt(t)

	fake := pipeline.StepFactory(func(map[string]any) (pipeline.Step, error) {
		return fakeDetector{}, nil
	})
	eng := pipeline.NewEngine()
	if err := rt.RegisterAll(eng.Steps()); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := eng.Steps().Register("test/fake", fake); err != nil {
		t.Fatalf("register fake: %v", err)
	}
	policy := fmt.Sprintf(`apiVersion: ypp/v1
kind: Policy
name: callout-test
mode: enforce
hooks: [pre_upstream]
steps:
%s
    parallel: [static]
  - id: static
    detector: test/fake
`, stepYAML(testStepID, srv.URL, ""))
	comp, err := eng.LoadPolicy([]byte(policy))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	res := runOne(t, comp, msgPayload("p"))
	if res.Verdict != pipeline.ActionFlag {
		t.Fatalf("verdict = %s", res.Verdict)
	}
	if len(res.Findings) != 2 || res.Findings[0].Category != "from-callout" || res.Findings[1].Category != "static" {
		t.Fatalf("findings order/content = %+v", res.Findings)
	}
}

// fakeDetector appends one static finding (mirrors pkg/pipeline test style).
type fakeDetector struct {
	pipeline.DetectorBase
}

func (fakeDetector) Name() string { return "test/fake" }

func (fakeDetector) Run(_ context.Context, p *pipeline.Pipeline, _ *pipeline.Payload, out *pipeline.Result) error {
	out.Findings = append(out.Findings, pipeline.Finding{
		Step: p.StepID(), Category: "static", Severity: "low", Action: pipeline.ActionFlag,
	})
	return nil
}
