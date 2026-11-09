package cli

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/pipeline"
)

type countedPolicyStore struct {
	*fakePolicyStore
	listCalls atomic.Int64
}

func (s *countedPolicyStore) ListPolicies(ctx context.Context, orgID string) ([]adminstore.PolicyPipeline, error) {
	s.listCalls.Add(1)
	return s.fakePolicyStore.ListPolicies(ctx, orgID)
}

type policyAvailabilityContextKey struct{}
type normalizedPolicyContextKey struct{}

// The count is a prehook-boundary continuation sentinel, not an HTTP/upstream test.
func TestPolicyAvailabilityColdFailClosed(t *testing.T) {
	store := newFakePolicyStore()
	store.listErr = errors.New("synthetic policy store unavailable")
	gw := testHookGateway(newTestRuntime(t, store, nil, PolicyModeEnforce))
	w, r := policyRequest(`{"model":"test","messages":[]}`)
	var upstreamContinuations int

	if _, _, ok := gw.policyPreUpstream(w, r, "chat", "test", "openai", []byte(`{"model":"test","messages":[]}`)); ok {
		upstreamContinuations++
	}

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cold failure status = %d, want %d; upstream continuation sentinel = %d", w.Code, http.StatusServiceUnavailable, upstreamContinuations)
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("cold failure is not an API error envelope: %v", err)
	}
	if envelope.Error.Code != "policy_temporarily_unavailable" {
		t.Fatalf("cold failure code = %q, want policy_temporarily_unavailable", envelope.Error.Code)
	}
	if strings.Contains(w.Body.String(), "synthetic policy store unavailable") {
		t.Fatalf("store error leaked into response: %s", w.Body.String())
	}
	if upstreamContinuations != 0 {
		t.Fatalf("upstream continuation sentinel = %d, want 0", upstreamContinuations)
	}
}

func TestPolicyAvailabilityColdJudgeHeaderBaseRed(t *testing.T) {
	store := newFakePolicyStore()
	store.listErr = errors.New("synthetic policy store unavailable")
	gw := testHookGateway(newTestRuntime(t, store, nil, PolicyModeEnforce))
	w, r := policyRequest(`{"model":"test","messages":[]}`)
	r.Header.Set("X-Yabanin-Judge", "true")
	var upstreamContinuations int

	if _, _, ok := gw.policyPreUpstream(w, r, "chat", "test", "openai", []byte(`{"model":"test","messages":[]}`)); ok {
		upstreamContinuations++
	}

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cold judge request status = %d, want %d; upstream continuation sentinel = %d", w.Code, http.StatusServiceUnavailable, upstreamContinuations)
	}
	if upstreamContinuations != 0 {
		t.Fatalf("upstream continuation sentinel = %d, want 0", upstreamContinuations)
	}
}

func TestPolicyAvailabilityColdFailOpen(t *testing.T) {
	store := newFakePolicyStore()
	store.listErr = errors.New("synthetic policy store unavailable")
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	rt.coldFailureMode = PolicyColdFailureFailOpen
	gw := testHookGateway(rt)
	w, r := policyRequest(`{"model":"test","messages":[]}`)
	before := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))
	var upstreamContinuations int

	if _, _, ok := gw.policyPreUpstream(w, r, "chat", "test", "openai", []byte(`{"model":"test","messages":[]}`)); ok {
		upstreamContinuations++
	}
	if w.Code != http.StatusOK || upstreamContinuations != 1 {
		t.Fatalf("fail-open result: status=%d upstream continuation=%d; want 200 and 1", w.Code, upstreamContinuations)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != before+1 {
		t.Fatalf("cold failure counter = %v, want %v", after, before+1)
	}
	if _, ok := policyEntryOutcomeFromContext(r.Context(), rt, testOrg); !ok {
		t.Fatal("prehook did not attach the outcome to this request context")
	}
	if strings.Contains(w.Body.String(), "synthetic policy store unavailable") {
		t.Fatalf("store error leaked into response: %s", w.Body.String())
	}
}

func TestPolicyAvailabilityFailOpenDoesNotDisableHealthyEnforcement(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "deny-cold-override", OrgID: testOrg, Name: "deny-cold-override", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("deny-cold-override", "blocked-marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	rt.coldFailureMode = PolicyColdFailureFailOpen
	gw := testHookGateway(rt)
	w, r := policyRequest(`{"messages":[{"role":"user","content":"blocked-marker"}]}`)
	_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"blocked-marker"}]}`))
	if ok || w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), policyDenyErrorCode) {
		t.Fatalf("healthy deny changed under cold fail-open: ok=%v status=%d body=%s", ok, w.Code, w.Body.String())
	}
}

func TestPolicyAvailabilityHealthyEmptySnapshot(t *testing.T) {
	store := newFakePolicyStore()
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	gw := testHookGateway(rt)
	w, r := policyRequest(`{"messages":[]}`)
	before := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))
	_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
	if !ok || w.Code != http.StatusOK {
		t.Fatalf("healthy empty snapshot should continue: ok=%v status=%d", ok, w.Code)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != before {
		t.Fatalf("healthy empty snapshot incremented failure counter: before=%v after=%v", before, after)
	}
}

func TestPolicyAvailabilityColdFailureRecoversOnNextRequest(t *testing.T) {
	store := &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}
	store.mu.Lock()
	store.listErr = errors.New("synthetic policy store unavailable")
	store.mu.Unlock()
	gw := testHookGateway(newTestRuntime(t, store, nil, PolicyModeEnforce))
	beforeFailures := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))

	w, r := policyRequest(`{"messages":[{"role":"user","content":"blocked-marker"}]}`)
	_, _, continued := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"blocked-marker"}]}`))
	if continued || w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "policy_temporarily_unavailable") {
		t.Fatalf("cold request: continued=%v status=%d body=%s; want a fail-closed 503", continued, w.Code, w.Body.String())
	}
	if got := store.listCalls.Load(); got != 1 {
		t.Fatalf("cold store reads = %d, want 1", got)
	}

	store.mu.Lock()
	store.listErr = nil
	store.mu.Unlock()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "cold-recovery-deny", OrgID: testOrg, Name: "cold-recovery-deny", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("cold-recovery-deny", "blocked-marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})

	w, r = policyRequest(`{"messages":[{"role":"user","content":"blocked-marker"}]}`)
	_, _, continued = gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"blocked-marker"}]}`))
	if continued || w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), policyDenyErrorCode) {
		t.Fatalf("recovered deny: continued=%v status=%d body=%s; want the recovered policy to deny before upstream", continued, w.Code, w.Body.String())
	}
	if got := store.listCalls.Load(); got != 2 {
		t.Fatalf("reads after first recovered request = %d, want one retry (2 total)", got)
	}

	w, r = policyRequest(`{"messages":[{"role":"user","content":"ordinary text"}]}`)
	_, _, continued = gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"ordinary text"}]}`))
	if !continued || w.Code != http.StatusOK {
		t.Fatalf("recovered allow: continued=%v status=%d body=%s; want normal progress", continued, w.Code, w.Body.String())
	}
	if got := store.listCalls.Load(); got != 2 {
		t.Fatalf("recovered snapshot was not reused: store reads = %d, want 2 total", got)
	}
	if afterFailures := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); afterFailures != beforeFailures+1 {
		t.Fatalf("cold failure counter delta = %v, want exactly 1", afterFailures-beforeFailures)
	}
}

func TestPolicyAvailabilityJudgeHeaderCannotBypassColdFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
	}{{"true", []string{"true"}}, {"false", []string{"false"}}, {"arbitrary", []string{"untrusted"}}, {"duplicates", []string{"true", "false"}}} {
		t.Run(tc.name, func(t *testing.T) {
			store := &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}
			store.listErr = errors.New("synthetic policy store unavailable")
			gw := testHookGateway(newTestRuntime(t, store, nil, PolicyModeEnforce))
			w, r := policyRequest(`{"messages":[]}`)
			for _, value := range tc.values {
				r.Header.Add("X-Yabanin-Judge", value)
			}
			_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
			if ok || w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "policy_temporarily_unavailable") {
				t.Fatalf("judge header bypassed cold failure: ok=%v status=%d body=%s", ok, w.Code, w.Body.String())
			}
			if got := store.listCalls.Load(); got != 1 {
				t.Fatalf("judge cold decision store reads = %d, want exactly one load attempt to make the decision", got)
			}
		})
	}
}

func TestPolicyAvailabilityWarmJudgeHeaderRejected(t *testing.T) {
	store := newFakePolicyStore()
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	if rt.entry(t.Context(), testOrg) == nil {
		t.Fatal("empty store must install a healthy snapshot")
	}
	gw := testHookGateway(rt)
	w, r := policyRequest(`{"messages":[]}`)
	r.Header.Set("X-Yabanin-Judge", "true")
	_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
	if ok || w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "judge_reentry_unsupported") {
		t.Fatalf("warm judge request was not rejected: ok=%v status=%d body=%s", ok, w.Code, w.Body.String())
	}
}

func TestPolicyAvailabilityUnavailableRuntimeModes(t *testing.T) {
	for _, tc := range []struct {
		mode       PolicyMode
		wantStatus int
	}{
		{PolicyModeEnforce, http.StatusServiceUnavailable},
		{PolicyModeShadow, http.StatusOK},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			gw := testHookGateway(newUnavailablePolicyRuntime(tc.mode, PolicyColdFailureFailClosed, testLogger()))
			w, r := policyRequest(`{"messages":[]}`)
			_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
			if w.Code != tc.wantStatus || (tc.mode == PolicyModeEnforce && ok) || (tc.mode == PolicyModeShadow && !ok) {
				t.Fatalf("unavailable runtime: ok=%v status=%d, want status %d", ok, w.Code, tc.wantStatus)
			}
		})
	}
}

func TestPolicyAvailabilityColdFailureDoesNotPublishPolicyDenial(t *testing.T) {
	store := newFakePolicyStore()
	store.listErr = errors.New("synthetic policy store unavailable")
	gw := testHookGateway(newTestRuntime(t, store, nil, PolicyModeEnforce))
	getEvents := captureEvents(t)
	w, r := policyRequest(`{"messages":[]}`)
	_, _, _ = gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
	for _, event := range getEvents() {
		if event.EventType == "request.invalid" {
			t.Fatal("cold store failure published a policy-denial event")
		}
	}
}

// This builder-level regression proves no-DB wiring reaches the real compliance
// composition path rather than manually installing an unavailable runtime.
func TestPolicyAvailabilityNoDatabaseBuild(t *testing.T) {
	cases := []struct {
		name         string
		wiring       PolicyWiring
		wantRuntime  bool
		wantStatus   int
		wantContinue bool
		wantDegraded bool
	}{
		{
			name:         "enforce default closed",
			wiring:       PolicyWiring{Mode: PolicyModeEnforce},
			wantRuntime:  true,
			wantStatus:   http.StatusServiceUnavailable,
			wantContinue: false,
			wantDegraded: true,
		},
		{
			name:         "enforce explicit closed",
			wiring:       PolicyWiring{Mode: PolicyModeEnforce, ColdFailureMode: PolicyColdFailureFailClosed},
			wantRuntime:  true,
			wantStatus:   http.StatusServiceUnavailable,
			wantContinue: false,
			wantDegraded: true,
		},
		{
			name:         "enforce explicit open",
			wiring:       PolicyWiring{Mode: PolicyModeEnforce, ColdFailureMode: PolicyColdFailureFailOpen},
			wantRuntime:  true,
			wantStatus:   http.StatusOK,
			wantContinue: true,
			wantDegraded: true,
		},
		{
			name:         "shadow",
			wiring:       PolicyWiring{Mode: PolicyModeShadow},
			wantRuntime:  true,
			wantStatus:   http.StatusOK,
			wantContinue: true,
			wantDegraded: true,
		},
		{
			name:         "explicit off",
			wiring:       PolicyWiring{Mode: PolicyModeOff},
			wantRuntime:  false,
			wantStatus:   http.StatusOK,
			wantContinue: true,
			wantDegraded: false,
		},
		{
			name:         "omitted wiring",
			wiring:       PolicyWiring{},
			wantRuntime:  false,
			wantStatus:   http.StatusOK,
			wantContinue: true,
			wantDegraded: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw := &gateway{log: testLogger()}
			w := &gatewayWiring{policy: tc.wiring, l: testLogger()}
			buildGatewayCompliance(t.Context(), w, gw)
			if (gw.policyRuntime != nil) != tc.wantRuntime {
				t.Fatalf("builder runtime present=%v, want %v", gw.policyRuntime != nil, tc.wantRuntime)
			}

			modeLabel := string(tc.wiring.Mode)
			if modeLabel == "" {
				modeLabel = string(PolicyModeOff)
			}
			before := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues(modeLabel, "cold"))
			wrec, req := policyRequest(`{"messages":[]}`)
			_, _, continued := gw.policyPreUpstream(wrec, req, "chat", "m", "openai", []byte(`{"messages":[]}`))
			if wrec.Code != tc.wantStatus || continued != tc.wantContinue {
				t.Fatalf("prehook result status=%d continued=%v; want status=%d continued=%v body=%s", wrec.Code, continued, tc.wantStatus, tc.wantContinue, wrec.Body.String())
			}
			if tc.wantStatus == http.StatusServiceUnavailable && !strings.Contains(wrec.Body.String(), "policy_temporarily_unavailable") {
				t.Fatalf("closed no-DB response missing stable policy error code: %s", wrec.Body.String())
			}
			after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues(modeLabel, "cold"))
			wantDelta := 0.0
			if tc.wantDegraded {
				wantDelta = 1
			}
			if after != before+wantDelta {
				t.Fatalf("cold degradation counter delta=%v, want %v", after-before, wantDelta)
			}
		})
	}
}

func TestPolicyAvailabilityOutcomeContextPreservesParentAndReusesStreamLoad(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func() (context.Context, context.CancelFunc)
	}{
		{
			name: "canceled parent",
			make: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
		},
		{
			name: "expired deadline",
			make: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, cancel := tc.make()
			defer cancel()
			parent = context.WithValue(parent, policyAvailabilityContextKey{}, "caller-value")

			store := &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}
			store.listErr = errors.New("synthetic policy store unavailable")
			rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
			rt.coldFailureMode = PolicyColdFailureFailOpen
			gw := testHookGateway(rt)
			w, r := policyRequest(`{"messages":[]}`)
			r = r.WithContext(context.WithValue(context.Background(), normalizedPolicyContextKey{}, "normalized-only"))
			before := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))

			_, _, continued := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
			if !continued || w.Code != http.StatusOK {
				t.Fatalf("fail-open prefix: continued=%v status=%d", continued, w.Code)
			}
			ctx := withRequestPolicyEntryOutcome(parent, r, rt, testOrg)
			outcome, ok := policyEntryOutcomeFromContext(ctx, rt, testOrg)
			if !ok || outcome.loadErr == nil || outcome.entry != nil {
				t.Fatalf("propagated outcome = %+v, found=%v; want failed cold outcome", outcome, ok)
			}
			gate := &reservationGate{endpoint: "chat.completions"}
			ctx = withReservationGate(ctx, gate)

			if ctx.Err() == nil {
				t.Fatal("outcome context lost canceled/deadline parent")
			}
			if got := ctx.Value(policyAvailabilityContextKey{}); got != "caller-value" {
				t.Fatalf("outcome context lost parent value: got %v", got)
			}
			if got := ctx.Value(normalizedPolicyContextKey{}); got != nil {
				t.Fatalf("propagation replaced the original parent with normalized request value %v", got)
			}
			if reservationGateFrom(ctx) != gate {
				t.Fatal("reservation gate was not retained after outcome propagation")
			}
			if got, found := policyEntryOutcomeFromContext(ctx, rt, testOrg); !found || got.loadErr == nil {
				t.Fatalf("stream context lost matching cold outcome: %+v found=%v", got, found)
			}

			prefixQ := policyQuery{endpoint: "chat", hook: pipeline.HookStreamPrefix, model: "m"}
			finalQ := prefixQ
			finalQ.hook = pipeline.HookStreamFinal
			rt.streamPlans(ctx, testOrg, prefixQ)
			rt.streamPlans(ctx, testOrg, finalQ)
			if got := store.listCalls.Load(); got != 1 {
				t.Fatalf("prefix and final stream hooks performed %d policy reads, want 1", got)
			}
			if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != before+1 {
				t.Fatalf("cold failure counter delta=%v, want exactly 1", after-before)
			}
		})
	}
}

func TestPolicyAvailabilityOutcomeContextRejectsForeignRuntimeAndOrg(t *testing.T) {
	storeA := &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}
	storeA.listErr = errors.New("synthetic policy store unavailable")
	rtA := newTestRuntime(t, storeA, nil, PolicyModeEnforce)
	rtA.coldFailureMode = PolicyColdFailureFailOpen
	gwA := testHookGateway(rtA)
	w, r := policyRequest(`{"messages":[]}`)
	_, _, continued := gwA.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
	if !continued {
		t.Fatal("source runtime should fail open for this context-mismatch test")
	}
	outcome, ok := policyEntryOutcomeFromContext(r.Context(), rtA, testOrg)
	if !ok {
		t.Fatal("source request did not receive its policy outcome")
	}
	ctx := withRequestPolicyEntryOutcome(context.Background(), r, rtA, testOrg)
	if got, found := policyEntryOutcomeFromContext(ctx, rtA, testOrg); !found || got != outcome {
		t.Fatalf("helper did not carry source outcome: got=%+v found=%v", got, found)
	}

	storeB := &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}
	storeB.listErr = errors.New("synthetic policy store unavailable")
	rtB := newTestRuntime(t, storeB, nil, PolicyModeEnforce)
	rtB.requestOutcome(ctx, testOrg)
	if got := storeB.listCalls.Load(); got != 1 {
		t.Fatalf("foreign runtime reused another runtime's outcome: reads=%d, want 1", got)
	}

	rtA.requestOutcome(ctx, "other-org")
	if got := storeA.listCalls.Load(); got != 2 {
		t.Fatalf("foreign org reused another org's outcome: reads=%d, want 2 total", got)
	}

	original := context.WithValue(context.Background(), policyAvailabilityContextKey{}, "untouched")
	if got := withRequestPolicyEntryOutcome(original, r, rtB, testOrg); got != original {
		t.Fatal("runtime mismatch should return the exact original context")
	}
}

// capturedPolicyLog records structured log records in order so tests can
// assert the fixed failure classes and the recovery log without echoing
// backend error text.
type capturedPolicyLog struct {
	mu      sync.Mutex
	records []capturedPolicyLogRecord
}

type capturedPolicyLogRecord struct {
	message string
	attrs   map[string]string
}

func (l *capturedPolicyLog) Enabled(context.Context, slog.Level) bool { return true }

func (l *capturedPolicyLog) Handle(_ context.Context, r slog.Record) error {
	rec := capturedPolicyLogRecord{message: r.Message, attrs: map[string]string{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, rec)
	return nil
}

func (l *capturedPolicyLog) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *capturedPolicyLog) WithGroup(string) slog.Handler      { return l }

// find returns the index of the first record with the message and all wanted
// attrs, or -1.
func (l *capturedPolicyLog) find(message string, attrs map[string]string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, rec := range l.records {
		if rec.message != message {
			continue
		}
		matched := true
		for k, v := range attrs {
			if rec.attrs[k] != v {
				matched = false
				break
			}
		}
		if matched {
			return i
		}
	}
	return -1
}

// findAfter returns the first index > after with the message, or -1.
func (l *capturedPolicyLog) findAfter(message string, after int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := after + 1; i < len(l.records); i++ {
		if l.records[i].message == message {
			return i
		}
	}
	return -1
}

// orgFaultPolicyStore fails one org's snapshot reads while siblings stay
// reachable, counting loads per org.
type orgFaultPolicyStore struct {
	*fakePolicyStore
	mu         sync.Mutex
	failingOrg string
	failErr    error
	loads      map[string]int
}

func newOrgFaultPolicyStore() *orgFaultPolicyStore {
	return &orgFaultPolicyStore{fakePolicyStore: newFakePolicyStore(), loads: map[string]int{}}
}

func (s *orgFaultPolicyStore) LoadPolicySnapshot(ctx context.Context, orgID string) (adminstore.PolicyPipelineSnapshot, error) {
	s.mu.Lock()
	s.loads[orgID]++
	fail := s.failingOrg == orgID
	s.mu.Unlock()
	if fail {
		return adminstore.PolicyPipelineSnapshot{}, s.failErr
	}
	return s.fakePolicyStore.LoadPolicySnapshot(ctx, orgID)
}

func (s *orgFaultPolicyStore) loadCount(orgID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loads[orgID]
}

// orgRequest is policyRequest for an explicit tenant.
func orgRequest(orgID, body string) (*httptest.ResponseRecorder, *http.Request) {
	w, r := policyRequest(body)
	r.Header.Set("X-Org-Id", orgID)
	return w, r
}

// warm-boundary contract: a refresh failure at the TTL/version boundary keeps
// the immutable last-good entry and its original loadedAt enforcing, records
// stale degradation, and a later request retries and installs the recovered
// snapshot with a success log.
func TestPolicyAvailabilityLastGoodRefreshFailureAndRecovery(t *testing.T) {
	base := newFakePolicyStore()
	base.add(testOrg, adminstore.PolicyPipeline{
		ID: "last-good-deny", OrgID: testOrg, Name: "last-good-deny", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("last-good-deny", "blocked-marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{testOrg: 1}}
	store := &countedPolicyStore{fakePolicyStore: base}
	logs := &capturedPolicyLog{}
	rt, err := NewPolicyRuntime(store, versions, PolicyModeEnforce, nil, slog.New(logs))
	if err != nil {
		t.Fatalf("NewPolicyRuntime: %v", err)
	}
	now := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	rt.now = func() time.Time { return now }
	gw := testHookGateway(rt)
	beforeStale := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "stale"))
	body := `{"messages":[{"role":"user","content":"blocked-marker"}]}`

	// The initial load installs the valid v1 snapshot and it enforces.
	w, r := policyRequest(body)
	if _, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(body)); ok || w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), policyDenyErrorCode) {
		t.Fatalf("initial enforce: ok=%v status=%d body=%s; want the v1 deny", ok, w.Code, w.Body.String())
	}
	loadedAt := now
	rt.mu.Lock()
	entry1 := rt.orgs[testOrg]
	rt.mu.Unlock()
	if entry1 == nil || !entry1.loadedAt.Equal(loadedAt) || entry1.version != 1 || !entry1.haveVer {
		t.Fatalf("initial entry = %+v, want the v1 snapshot stamped %v", entry1, loadedAt)
	}
	if got := store.listCalls.Load(); got != 1 {
		t.Fatalf("initial store reads = %d, want 1", got)
	}

	// Store outage at the TTL boundary: the last-good snapshot keeps
	// enforcing with its original timestamp, and stale degradation records.
	base.mu.Lock()
	base.listErr = errors.New("synthetic policy store unavailable")
	base.mu.Unlock()
	now = now.Add(policyCacheTTL + time.Nanosecond)
	w, r = policyRequest(body)
	if _, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(body)); ok || w.Code != http.StatusBadRequest {
		t.Fatalf("refresh outage: ok=%v status=%d body=%s; want the last-good deny, not 503", ok, w.Code, w.Body.String())
	}
	rt.mu.Lock()
	still := rt.orgs[testOrg]
	rt.mu.Unlock()
	if still != entry1 || !still.loadedAt.Equal(loadedAt) {
		t.Fatalf("failed refresh replaced or retimestamped the last-good entry: %+v, want loadedAt %v", still, loadedAt)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "stale")); after != beforeStale+1 {
		t.Fatalf("stale degradation counter = %v, want %v", after, beforeStale+1)
	}
	if got := store.listCalls.Load(); got != 2 {
		t.Fatalf("store reads after failed refresh = %d, want 2 (one retry)", got)
	}
	failureIdx := logs.find("policy load failed", map[string]string{"mode": "enforce", "cache_state": "stale", "failure_class": "store_read"})
	if failureIdx < 0 {
		t.Fatalf("stale refresh failure was not logged with its fixed class; records=%+v", logs.records)
	}

	// Recovery: the store returns an activated v2 revision; the next request
	// retries, installs it, and the recovery log follows the failure log.
	base.mu.Lock()
	base.listErr = nil
	base.policies[testOrg][0].CurrentVersion = 2
	base.versions[testOrg]["last-good-deny"][2] = denyWordYAML("last-good-deny", "recovered-marker")
	base.mu.Unlock()
	versions.bump(testOrg)
	w, r = policyRequest(`{"messages":[{"role":"user","content":"recovered-marker"}]}`)
	if _, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"recovered-marker"}]}`)); ok || w.Code != http.StatusBadRequest {
		t.Fatalf("recovered snapshot: ok=%v status=%d body=%s; want the v2 deny", ok, w.Code, w.Body.String())
	}
	rt.mu.Lock()
	entry2 := rt.orgs[testOrg]
	rt.mu.Unlock()
	if entry2 == entry1 || entry2.version != 2 || !entry2.haveVer || !entry2.loadedAt.Equal(now) {
		t.Fatalf("recovered entry = %+v, want a fresh v2 entry stamped %v", entry2, now)
	}
	if got := store.listCalls.Load(); got != 3 {
		t.Fatalf("store reads after recovery = %d, want 3 (one retry)", got)
	}
	if logs.findAfter("policy store load succeeded", failureIdx) < 0 {
		t.Fatal("recovery success log was not emitted after the failure log")
	}
	// The retired marker is no longer denied by the recovered snapshot.
	w, r = policyRequest(body)
	if _, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(body)); !ok || w.Code != http.StatusOK {
		t.Fatalf("retired marker under recovered snapshot: ok=%v status=%d body=%s; want normal progress", ok, w.Code, w.Body.String())
	}
	if got := store.listCalls.Load(); got != 3 {
		t.Fatalf("recovered snapshot was not reused: store reads = %d, want 3 total", got)
	}
}

// TestPolicyAvailabilityCanceledColdLoadDoesNotCacheAndRetryRecovers pins the
// cold-boundary contract: a canceled store read fails without caching a
// successful (empty) entry, records one cold degradation with its fixed
// class, and a later independent request retries and recovers. A successful
// empty list stays distinct: it installs a healthy entry and never counts as
// a load failure.
func TestPolicyAvailabilityCanceledColdLoadDoesNotCacheAndRetryRecovers(t *testing.T) {
	base := newFakePolicyStore()
	base.mu.Lock()
	base.listCtxBlock = true
	base.listStarted = make(chan struct{}, 1)
	base.mu.Unlock()
	store := &countedPolicyStore{fakePolicyStore: base}
	logs := &capturedPolicyLog{}
	rt, err := NewPolicyRuntime(store, nil, PolicyModeEnforce, nil, slog.New(logs))
	if err != nil {
		t.Fatalf("NewPolicyRuntime: %v", err)
	}
	gw := testHookGateway(rt)
	beforeCold := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	defer cancel()
	w, r := policyRequest(`{"messages":[]}`)
	r = r.WithContext(ctx)
	if _, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`)); ok || w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "policy_temporarily_unavailable") {
		t.Fatalf("canceled cold load: ok=%v status=%d body=%s; want fail-closed 503", ok, w.Code, w.Body.String())
	}
	if rt.hasSnapshot(testOrg) {
		t.Fatal("canceled store read was cached as a successful snapshot")
	}
	if got := store.listCalls.Load(); got != 1 {
		t.Fatalf("canceled cold store reads = %d, want exactly one load attempt", got)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != beforeCold+1 {
		t.Fatalf("cold degradation counter = %v, want %v", after, beforeCold+1)
	}
	if logs.find("policy load failed", map[string]string{"mode": "enforce", "cache_state": "cold", "failure_class": "context_canceled"}) < 0 {
		t.Fatalf("canceled load was not logged with its fixed class; records=%+v", logs.records)
	}

	// A later independent request retries the store and recovers.
	base.mu.Lock()
	base.listCtxBlock = false
	base.mu.Unlock()
	base.add(testOrg, adminstore.PolicyPipeline{
		ID: "cancel-recovery-deny", OrgID: testOrg, Name: "cancel-recovery-deny", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("cancel-recovery-deny", "blocked-marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	body := `{"messages":[{"role":"user","content":"blocked-marker"}]}`
	w, r = policyRequest(body)
	if _, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(body)); ok || w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), policyDenyErrorCode) {
		t.Fatalf("retry after cancellation: ok=%v status=%d body=%s; want the recovered deny", ok, w.Code, w.Body.String())
	}
	if got := store.listCalls.Load(); got != 2 {
		t.Fatalf("store reads after retry = %d, want 2 (one independent retry)", got)
	}
	if !rt.hasSnapshot(testOrg) {
		t.Fatal("successful retry did not install the recovered snapshot")
	}

	// A successful empty list is healthy and distinct from a top-level read
	// failure: the failure leaves no entry and counts, the empty success
	// installs an entry and never counts.
	emptyBase := newFakePolicyStore()
	emptyBase.listErr = errors.New("synthetic policy store unavailable")
	emptyRt := newTestRuntime(t, emptyBase, nil, PolicyModeEnforce)
	emptyGW := testHookGateway(emptyRt)
	emptyBefore := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))
	w, r = policyRequest(`{"messages":[]}`)
	if _, _, ok := emptyGW.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`)); ok || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("read failure: ok=%v status=%d; want 503 with no entry", ok, w.Code)
	}
	if emptyRt.hasSnapshot(testOrg) {
		t.Fatal("failed read installed a cache entry")
	}
	emptyBase.mu.Lock()
	emptyBase.listErr = nil
	emptyBase.mu.Unlock()
	w, r = policyRequest(`{"messages":[]}`)
	if _, _, ok := emptyGW.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`)); !ok || w.Code != http.StatusOK {
		t.Fatalf("successful empty list: ok=%v status=%d; want normal progress", ok, w.Code)
	}
	if !emptyRt.hasSnapshot(testOrg) {
		t.Fatal("successful empty list did not install a healthy empty snapshot")
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != emptyBefore+1 {
		t.Fatalf("healthy empty snapshot changed the failure counter: before=%v after=%v, want only the read failure", emptyBefore, after)
	}
}

// TestPolicyAvailabilityTenantIsolation pins per-org error containment: one
// tenant's cold store failure fails closed without touching a sibling's
// healthy empty snapshot, outcomes never cross tenants, and recovery is
// per-org.
func TestPolicyAvailabilityTenantIsolation(t *testing.T) {
	const orgB = "org-2"
	store := newOrgFaultPolicyStore()
	store.mu.Lock()
	store.failingOrg = testOrg
	store.failErr = errors.New("synthetic org outage")
	store.mu.Unlock()
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{testOrg: 1, orgB: 1}}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	gw := testHookGateway(rt)
	beforeCold := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))

	// org B loads a healthy empty snapshot.
	wB, rB := orgRequest(orgB, `{"messages":[]}`)
	if _, _, ok := gw.policyPreUpstream(wB, rB, "chat", "m", "openai", []byte(`{"messages":[]}`)); !ok || wB.Code != http.StatusOK {
		t.Fatalf("org B empty snapshot: ok=%v status=%d; want normal progress", ok, wB.Code)
	}
	rt.mu.Lock()
	entryB := rt.orgs[orgB]
	rt.mu.Unlock()
	if entryB == nil || len(entryB.plans) != 0 {
		t.Fatalf("org B entry = %+v, want a healthy empty snapshot", entryB)
	}

	// org A's cold failure is fail-closed and never touches org B's cache.
	wA, rA := policyRequest(`{"messages":[]}`)
	if _, _, ok := gw.policyPreUpstream(wA, rA, "chat", "m", "openai", []byte(`{"messages":[]}`)); ok || wA.Code != http.StatusServiceUnavailable || !strings.Contains(wA.Body.String(), "policy_temporarily_unavailable") {
		t.Fatalf("org A cold failure: ok=%v status=%d body=%s; want fail-closed 503", ok, wA.Code, wA.Body.String())
	}
	if rt.hasSnapshot(testOrg) {
		t.Fatal("org A failure was cached as a snapshot")
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != beforeCold+1 {
		t.Fatalf("org A cold counter = %v, want %v", after, beforeCold+1)
	}
	if got := store.loadCount(orgB); got != 1 {
		t.Fatalf("org B reloads after org A failure = %d, want 0", got-1)
	}

	// Outcomes are request- and tenant-scoped: neither side can read the
	// other's outcome, and org B's own outcome stays installed.
	if _, ok := policyEntryOutcomeFromContext(rA.Context(), rt, orgB); ok {
		t.Fatal("org A's failed outcome was readable under org B's identity")
	}
	if _, ok := policyEntryOutcomeFromContext(rB.Context(), rt, testOrg); ok {
		t.Fatal("org B's success outcome was readable under org A's identity")
	}
	if got, ok := policyEntryOutcomeFromContext(rB.Context(), rt, orgB); !ok || got.entry != entryB {
		t.Fatalf("org B outcome = (%+v %v), want its own empty snapshot", got, ok)
	}

	// org B keeps proceeding on its own snapshot.
	wB, rB = orgRequest(orgB, `{"messages":[]}`)
	if _, _, ok := gw.policyPreUpstream(wB, rB, "chat", "m", "openai", []byte(`{"messages":[]}`)); !ok || wB.Code != http.StatusOK {
		t.Fatalf("org B after org A failure: ok=%v status=%d; want normal progress", ok, wB.Code)
	}
	rt.mu.Lock()
	stillB := rt.orgs[orgB]
	rt.mu.Unlock()
	if stillB != entryB || store.loadCount(orgB) != 1 {
		t.Fatalf("org B entry reloaded or replaced: entry=%p want %p loads=%d", stillB, entryB, store.loadCount(orgB))
	}

	// Recovery is per-org: org A retries on its next request and enforces,
	// while org B keeps its untouched snapshot.
	store.mu.Lock()
	store.failingOrg = ""
	store.mu.Unlock()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "tenant-recovery-deny", OrgID: testOrg, Name: "tenant-recovery-deny", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("tenant-recovery-deny", "blocked-marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	body := `{"messages":[{"role":"user","content":"blocked-marker"}]}`
	wA, rA = policyRequest(body)
	if _, _, ok := gw.policyPreUpstream(wA, rA, "chat", "m", "openai", []byte(body)); ok || wA.Code != http.StatusBadRequest || !strings.Contains(wA.Body.String(), policyDenyErrorCode) {
		t.Fatalf("org A recovery: ok=%v status=%d body=%s; want the recovered deny", ok, wA.Code, wA.Body.String())
	}
	if got := store.loadCount(testOrg); got != 2 {
		t.Fatalf("org A loads after recovery = %d, want 2 (one retry)", got)
	}
	if got := store.loadCount(orgB); got != 1 {
		t.Fatalf("org B loads after org A recovery = %d, want 1", got)
	}
	rt.mu.Lock()
	entryA, afterB := rt.orgs[testOrg], rt.orgs[orgB]
	rt.mu.Unlock()
	if entryA == nil || entryA == entryB || afterB != entryB {
		t.Fatalf("tenant entries crossed: A=%+v B=%+v", entryA, afterB)
	}
}

// TestPolicyAvailabilityFailOpenColdPublishesNoDenialEvent pins the fail-open
// side of the cold regression set: a load failure under the operator override
// proceeds without policy exactly once (one store read, one cold degradation
// counter increment, fixed store_read class in the captured structured log),
// publishes no policy-denial analytics event, and leaks neither the store
// error text into the response nor the log.
func TestPolicyAvailabilityFailOpenColdPublishesNoDenialEvent(t *testing.T) {
	base := newFakePolicyStore()
	base.mu.Lock()
	base.listErr = errors.New("synthetic policy store unavailable")
	base.mu.Unlock()
	store := &countedPolicyStore{fakePolicyStore: base}
	logs := &capturedPolicyLog{}
	rt, err := NewPolicyRuntime(store, nil, PolicyModeEnforce, nil, slog.New(logs))
	if err != nil {
		t.Fatalf("NewPolicyRuntime: %v", err)
	}
	rt.coldFailureMode = PolicyColdFailureFailOpen
	gw := testHookGateway(rt)
	getEvents := captureEvents(t)
	beforeCold := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold"))

	w, r := policyRequest(`{"messages":[]}`)
	_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
	if !ok || w.Code != http.StatusOK {
		t.Fatalf("fail-open cold load: ok=%v status=%d body=%s; want documented progress without policy", ok, w.Code, w.Body.String())
	}
	if got := store.listCalls.Load(); got != 1 {
		t.Fatalf("fail-open cold store reads = %d, want exactly one load attempt", got)
	}
	if after := testutil.ToFloat64(metrics.GatewayPolicyLoadFailuresTotal.WithLabelValues("enforce", "cold")); after != beforeCold+1 {
		t.Fatalf("cold degradation counter = %v, want %v", after, beforeCold+1)
	}
	if logs.find("policy load failed", map[string]string{"mode": "enforce", "cache_state": "cold", "failure_class": "store_read"}) < 0 {
		t.Fatalf("fail-open cold load was not logged with its fixed class; records=%+v", logs.records)
	}
	for _, event := range getEvents() {
		if event.EventType == "request.invalid" {
			t.Fatalf("fail-open cold load published a policy-denial event: %+v", event)
		}
	}
	if strings.Contains(w.Body.String(), "synthetic policy store unavailable") {
		t.Fatalf("store error leaked into the response: %s", w.Body.String())
	}
	logs.mu.Lock()
	defer logs.mu.Unlock()
	for _, rec := range logs.records {
		if strings.Contains(rec.message, "synthetic policy store unavailable") {
			t.Fatalf("degradation log echoed the raw store error: %q", rec.message)
		}
		for _, v := range rec.attrs {
			if strings.Contains(v, "synthetic policy store unavailable") {
				t.Fatalf("degradation log echoed the raw store error in attr %q", v)
			}
		}
	}
}
