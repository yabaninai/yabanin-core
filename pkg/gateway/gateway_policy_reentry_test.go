package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	"github.com/reireirei/yabanin/pkg/resolver"
)

func TestPolicyReentryPresenceValuesModesAndNoOrg(t *testing.T) {
	store := newFakePolicyStore()
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	if rt.entry(t.Context(), testOrg) == nil {
		t.Fatal("empty store must install a healthy snapshot")
	}

	cases := []struct {
		name   string
		key    string
		values []string
	}{
		{name: "empty value", key: "X-Yabanin-Judge", values: []string{""}},
		{name: "empty value slice", key: "X-Yabanin-Judge", values: nil},
		{name: "true", key: "X-Yabanin-Judge", values: []string{"true"}},
		{name: "false", key: "X-Yabanin-Judge", values: []string{"false"}},
		{name: "arbitrary secret value", key: "X-Yabanin-Judge", values: []string{"marker-secret-canary"}},
		{name: "whitespace", key: "X-Yabanin-Judge", values: []string{" \t "}},
		{name: "duplicate values", key: "X-Yabanin-Judge", values: []string{"true", "marker-secret-canary"}},
		{name: "non canonical map key", key: "x-yabanin-judge", values: []string{"false"}},
	}
	var firstBody string
	getEvents := captureEvents(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r := policyRequest(`{"messages":[]}`)
			r.Header[tc.key] = append([]string(nil), tc.values...)
			_, policyEvent, ok := testHookGateway(rt).policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
			if ok || w.Code != http.StatusBadRequest {
				t.Fatalf("present marker result = (ok=%v status=%d), want terminal 400", ok, w.Code)
			}
			if policyEvent != "" {
				t.Fatalf("re-entry rejection returned policy event %q", policyEvent)
			}
			if strings.Contains(w.Body.String(), "marker-secret-canary") || strings.Contains(w.Body.String(), "false") || strings.Contains(w.Body.String(), "true") {
				t.Fatalf("response disclosed a marker value: %s", w.Body.String())
			}
			var envelope struct {
				Error struct {
					Type string `json:"type"`
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode error envelope: %v", err)
			}
			if envelope.Error.Type != "invalid_request_error" || envelope.Error.Code != "judge_reentry_unsupported" {
				t.Fatalf("error = %+v, want stable invalid_request_error/judge_reentry_unsupported", envelope.Error)
			}
			if firstBody == "" {
				firstBody = w.Body.String()
			} else if w.Body.String() != firstBody {
				t.Fatalf("marker form changed generic response: got %s, want %s", w.Body.String(), firstBody)
			}
		})
	}
	if got := len(getEvents()); got != 0 {
		t.Fatalf("re-entry rejection published %d events, want none", got)
	}

	for _, tc := range []struct {
		name string
		gw   *gateway
	}{
		{name: "nil runtime", gw: testHookGateway(nil)},
		{name: "off", gw: testHookGateway(newTestRuntime(t, newFakePolicyStore(), nil, PolicyModeOff))},
		{name: "shadow", gw: testHookGateway(newTestRuntime(t, newFakePolicyStore(), nil, PolicyModeShadow))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, r := policyRequest(`{"messages":[]}`)
			r.Header.Set("X-Yabanin-Judge", "mode-secret")
			_, _, ok := tc.gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
			assertReentryEnvelope(t, w, ok)
		})
	}
	t.Run("missing org", func(t *testing.T) {
		w, r := policyRequest(`{"messages":[]}`)
		r.Header.Del("X-Org-Id")
		r.Header.Set("X-Yabanin-Judge", "org-secret")
		_, _, ok := testHookGateway(rt).policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
		assertReentryEnvelope(t, w, ok)
	})

	// The unmarked control still follows the normal policy path.
	w, r := policyRequest(`{"messages":[]}`)
	if _, _, ok := testHookGateway(rt).policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`)); !ok || w.Code != http.StatusOK {
		t.Fatalf("unmarked control changed: ok=%v status=%d", ok, w.Code)
	}
}

func TestPolicyPostUpstreamDoesNotTrustRawJudgeHeader(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "post-deny", OrgID: testOrg, Name: "post-deny", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: strings.Replace(denyWordYAML("post-deny", "response-secret"), "pre_upstream", "post_upstream", 1)}, []adminstore.PolicyAttachment{chatAttachment(1)})
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	if rt.entry(t.Context(), testOrg) == nil {
		t.Fatal("post policy snapshot failed to load")
	}
	_, r := policyRequest(`{"messages":[]}`)
	r.Header.Set("X-Yabanin-Judge", "untrusted")
	_, event, denied := testHookGateway(rt).policyPostUpstream(r, "chat", "m", "openai", []byte(`{"text":"response-secret"}`))
	if !denied || event == "" {
		t.Fatalf("raw marker bypassed post policy: denied=%v event=%q", denied, event)
	}
}

func TestPolicyReentryColdEnforceKeepsOneAvailabilityOutcome(t *testing.T) {
	for _, tc := range []struct {
		name       string
		coldMode   PolicyColdFailureMode
		wantStatus int
		wantCode   string
	}{
		{name: "fail closed precedence", coldMode: PolicyColdFailureFailClosed, wantStatus: http.StatusServiceUnavailable, wantCode: "policy_temporarily_unavailable"},
		{name: "fail open still rejects marker", coldMode: PolicyColdFailureFailOpen, wantStatus: http.StatusBadRequest, wantCode: "judge_reentry_unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}
			store.listErr = errors.New("synthetic policy store unavailable")
			rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
			rt.coldFailureMode = tc.coldMode
			w, r := policyRequest(`{"messages":[]}`)
			r.Header.Set("X-Yabanin-Judge", "cold-secret")
			_, _, ok := testHookGateway(rt).policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[]}`))
			if ok || w.Code != tc.wantStatus {
				t.Fatalf("marked cold request = (ok=%v status=%d), want terminal %d", ok, w.Code, tc.wantStatus)
			}
			var envelope struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode error envelope: %v", err)
			}
			if envelope.Error.Code != tc.wantCode {
				t.Fatalf("error code = %q, want %q", envelope.Error.Code, tc.wantCode)
			}
			if strings.Contains(w.Body.String(), "cold-secret") || strings.Contains(w.Body.String(), "synthetic policy store unavailable") {
				t.Fatalf("response disclosed marker/store detail: %s", w.Body.String())
			}
			if got := store.listCalls.Load(); got != 1 {
				t.Fatalf("cold store reads = %d, want one request-scoped outcome", got)
			}
		})
	}
}

func assertReentryEnvelope(t *testing.T, w *httptest.ResponseRecorder, continued bool) {
	t.Helper()
	if continued || w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "judge_reentry_unsupported") {
		t.Fatalf("marked request was not rejected: continued=%v status=%d body=%s", continued, w.Code, w.Body.String())
	}
}

type reentryJudgeClient struct{ calls atomic.Int64 }

func (c *reentryJudgeClient) JudgeChat(context.Context, llmjudge.ChatRequest) (llmjudge.ChatResponse, error) {
	c.calls.Add(1)
	return llmjudge.ChatResponse{Content: `{"findings":[],"summary":"clean"}`, Model: "fake-judge"}, nil
}

func TestPolicyReentryActualInferenceRoutesStopBeforeJudgeUpstreamAndSSE(t *testing.T) {
	client := &reentryJudgeClient{}
	oldDeps := llmjudge.DefaultDeps()
	llmjudge.SetDefaultDeps(llmjudge.Deps{Client: client})
	t.Cleanup(func() { llmjudge.SetDefaultDeps(oldDeps) })

	store := newFakePolicyStore()
	for i, endpoint := range []string{"chat", "completions", "messages", "responses"} {
		id := "judge-" + endpoint
		store.add("org-a", adminstore.PolicyPipeline{
			ID: id, OrgID: "org-a", Name: id, Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: reentryJudgePolicyYAML(id)}, []adminstore.PolicyAttachment{{
			ModelPattern: "*", Endpoint: endpoint,
		}})
		_ = i
	}
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	if rt.entry(t.Context(), "org-a") == nil {
		t.Fatal("judge policy snapshot failed to load")
	}

	u := newRT02Upstream(t)
	openAI := resolver.ModelInfo{ModelName: "m-openai", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true}
	anthropic := resolver.ModelInfo{ModelName: "m-anthropic", Provider: "anthropic", UpstreamURL: u.srv.URL, Enabled: true}
	gw := rt02RouteGateway(t, u, nil, openAI, true)
	gw.res = stubModelResolver{"m-openai": openAI, "m-anthropic": anthropic}
	gw.policyRuntime = rt

	cases := []struct {
		name, path, body, model string
		markerValues            []string
	}{
		{name: "chat JSON", path: "/v1/chat/completions", model: "m-openai", body: `{"model":"m-openai","messages":[{"role":"user","content":"hello"}]}`, markerValues: []string{"true"}},
		{name: "chat stream", path: "/v1/chat/completions", model: "m-openai", body: `{"model":"m-openai","stream":true,"messages":[{"role":"user","content":"hello"}]}`, markerValues: []string{"stream-secret"}},
		{name: "legacy completions", path: "/v1/completions", model: "m-openai", body: `{"model":"m-openai","prompt":"hello"}`, markerValues: []string{"false"}},
		{name: "native messages", path: "/v1/messages", model: "m-anthropic", body: `{"model":"m-anthropic","max_tokens":8,"messages":[{"role":"user","content":"hello"}]}`, markerValues: []string{"arbitrary-secret"}},
		{name: "native responses", path: "/v1/responses", model: "m-openai", body: `{"model":"m-openai","input":"hello"}`, markerValues: []string{"true", "false"}},
	}
	getEvents := captureEvents(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Authorization", "Bearer test-key")
			r.Header.Set("Content-Type", "application/json")
			for _, value := range tc.markerValues {
				r.Header.Add("X-Yabanin-Judge", value)
			}
			rec := httptest.NewRecorder()
			mux := chi.NewRouter()
			gw.routes(mux)
			mux.ServeHTTP(rec, r)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s status=%d body=%s, want 400", tc.path, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if tc.path == "/v1/messages" {
				if !strings.Contains(body, `"type":"error"`) || !strings.Contains(body, "[judge_reentry_unsupported]") {
					t.Fatalf("messages route did not preserve its Anthropic error envelope/code: %s", body)
				}
			} else if !strings.Contains(body, `"code":"judge_reentry_unsupported"`) {
				t.Fatalf("route error code missing: %s", body)
			}
			for _, value := range tc.markerValues {
				if value != "" && strings.Contains(body, value) {
					t.Fatalf("route error disclosed marker value %q: %s", value, body)
				}
			}
			if strings.Contains(body, "data:") || strings.Contains(body, "text/event-stream") {
				t.Fatalf("re-entry response emitted stream data: %s", body)
			}
		})
	}
	if got := u.totalCalls(); got != 0 {
		t.Fatalf("inference upstream calls = %d, want 0", got)
	}
	if got := client.calls.Load(); got != 0 {
		t.Fatalf("policy judge calls = %d, want 0", got)
	}
	if got := len(getEvents()); got != 0 {
		t.Fatalf("re-entry requests published %d events, want none", got)
	}
}

func reentryJudgePolicyYAML(name string) string {
	return "apiVersion: ypp/v1\nkind: Policy\nname: " + name + "\nmode: enforce\nhooks: [pre_upstream]\nsteps:\n" +
		"  - id: judge\n    llm_judge:\n      model: fake-judge\n      prompt_ref: judges/toxicity@2\n    timeout: 5s\n    on_error: fail_open+flag\n"
}

// reentryOrgRecordingStore records the authoritative org passed to the cold
// policy reader while preserving the counted fake's behavior.
type reentryOrgRecordingStore struct {
	*countedPolicyStore
	mu   sync.Mutex
	orgs []string
}

func (s *reentryOrgRecordingStore) ListPolicies(ctx context.Context, orgID string) ([]adminstore.PolicyPipeline, error) {
	s.mu.Lock()
	s.orgs = append(s.orgs, orgID)
	s.mu.Unlock()
	return s.countedPolicyStore.ListPolicies(ctx, orgID)
}

func (s *reentryOrgRecordingStore) readOrgs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.orgs...)
}

func installReentryJudgeCounter(t *testing.T) *reentryJudgeClient {
	t.Helper()
	oldDeps := llmjudge.DefaultDeps()
	client := &reentryJudgeClient{}
	llmjudge.SetDefaultDeps(llmjudge.Deps{Client: client})
	t.Cleanup(func() { llmjudge.SetDefaultDeps(oldDeps) })
	return client
}

func TestPolicyReentryColdInvalidConfigurationKeepsR009Precedence(t *testing.T) {
	store := &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "invalid-marker-config", OrgID: testOrg, Name: "invalid-marker-config", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: "apiVersion: ypp/v1\nkind: Garbage\n"}, []adminstore.PolicyAttachment{chatAttachment(1)})
	judge := installReentryJudgeCounter(t)
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	getEvents := captureEvents(t)

	w, r := policyRequest(`{"messages":[{"role":"user","content":"safe"}]}`)
	r.Header.Set("X-Yabanin-Judge", "private-marker-canary")
	_, policyEvent, ok := testHookGateway(rt).policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"safe"}]}`))
	if ok || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid-config marker result = (ok=%v status=%d body=%s), want terminal 503", ok, w.Code, w.Body.String())
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if envelope.Error.Code != "policy_configuration_unavailable" {
		t.Fatalf("error code = %q, want policy_configuration_unavailable", envelope.Error.Code)
	}
	if policyEvent != "" || strings.Contains(w.Body.String(), "private-marker-canary") || strings.Contains(w.Body.String(), "kind: Garbage") {
		t.Fatalf("invalid-config response/event disclosed or emitted data: event=%q body=%s", policyEvent, w.Body.String())
	}
	if got := store.listCalls.Load(); got != 1 {
		t.Fatalf("invalid-config store reads = %d, want one", got)
	}
	if rt.hasSnapshot(testOrg) {
		t.Fatal("invalid candidate installed a snapshot")
	}
	if got := len(getEvents()); got != 0 {
		t.Fatalf("invalid-config re-entry emitted %d events, want none", got)
	}
	if got := judge.calls.Load(); got != 0 {
		t.Fatalf("invalid-config re-entry invoked policy judge %d times, want zero", got)
	}
}

func TestPolicyReentryAuthenticationFailurePrecedesMarker(t *testing.T) {
	store := &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}
	store.add("org-a", adminstore.PolicyPipeline{
		ID: "auth-marker-judge", OrgID: "org-a", Name: "auth-marker-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: reentryJudgePolicyYAML("auth-marker-judge")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	judge := installReentryJudgeCounter(t)
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	getEvents := captureEvents(t)
	u := newRT02Upstream(t)
	target := resolver.ModelInfo{ModelName: "m-openai", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true}
	gw := rt02RouteGateway(t, u, nil, target, false)
	gw.policyRuntime = rt

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m-openai","messages":[{"role":"user","content":"hello"}]}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Yabanin-Judge", "auth-marker-canary")
	rec := httptest.NewRecorder()
	mux := chi.NewRouter()
	gw.routes(mux)
	mux.ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "authentication_error") || !strings.Contains(rec.Body.String(), "missing or invalid Authorization header") {
		t.Fatalf("unauthenticated marker response = %d %s, want the existing 401 authentication error", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "judge_reentry_unsupported") || strings.Contains(rec.Body.String(), "auth-marker-canary") {
		t.Fatalf("authentication response was replaced by marker response or leaked marker: %s", rec.Body.String())
	}
	if got := store.listCalls.Load(); got != 0 {
		t.Fatalf("unauthenticated marker reached policy store %d times, want zero", got)
	}
	if got := u.totalCalls(); got != 0 {
		t.Fatalf("unauthenticated marker reached inference upstream %d times, want zero", got)
	}
	if got := judge.calls.Load(); got != 0 {
		t.Fatalf("unauthenticated marker invoked policy judge %d times, want zero", got)
	}
	if got := len(getEvents()); got != 0 {
		t.Fatalf("unauthenticated marker emitted %d events, want zero", got)
	}
}

func TestPolicyReentryMarkerCannotRedirectAuthenticatedTenant(t *testing.T) {
	store := &reentryOrgRecordingStore{countedPolicyStore: &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}}
	store.add("org-a", adminstore.PolicyPipeline{
		ID: "tenant-a-judge", OrgID: "org-a", Name: "tenant-a-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: reentryJudgePolicyYAML("tenant-a-judge")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	store.add("org-b", adminstore.PolicyPipeline{
		ID: "tenant-b-deny", OrgID: "org-b", Name: "tenant-b-deny", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: denyWordYAML("tenant-b-deny", "tenant-b-only")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	judge := installReentryJudgeCounter(t)
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	getEvents := captureEvents(t)
	u := newRT02Upstream(t)
	target := resolver.ModelInfo{ModelName: "m-openai", Provider: "openai", UpstreamURL: u.srv.URL, Enabled: true}
	gw := rt02RouteGateway(t, u, nil, target, false)
	gw.policyRuntime = rt

	serve := func(g *gateway, content string, marker bool, spoofOrg string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions",
			strings.NewReader(`{"model":"m-openai","messages":[{"role":"user","content":"`+content+`"}]}`))
		r.Header.Set("Authorization", "Bearer test-key")
		r.Header.Set("Content-Type", "application/json")
		if marker {
			r.Header.Set("X-Yabanin-Judge", "tenant-marker-canary")
		}
		if spoofOrg != "" {
			r.Header.Set("X-Org-Id", spoofOrg)
		}
		rec := httptest.NewRecorder()
		mux := chi.NewRouter()
		g.routes(mux)
		mux.ServeHTTP(rec, r)
		return rec
	}

	marked := serve(gw, "tenant-b-only", true, "org-b")
	if marked.Code != http.StatusBadRequest || !strings.Contains(marked.Body.String(), "judge_reentry_unsupported") {
		t.Fatalf("tenant-spoof marker response = %d %s, want generic marker 400", marked.Code, marked.Body.String())
	}
	if strings.Contains(marked.Body.String(), "tenant-marker-canary") || strings.Contains(marked.Body.String(), "content_policy_violation") {
		t.Fatalf("tenant-spoof response disclosed marker or ran org-B policy: %s", marked.Body.String())
	}
	if got, want := store.readOrgs(), []string{"org-a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cold policy lookup orgs = %v, want authenticated tenant only %v", got, want)
	}
	if !rt.hasSnapshot("org-a") || rt.hasSnapshot("org-b") {
		t.Fatalf("marker loaded wrong tenant snapshot: org-a=%v org-b=%v", rt.hasSnapshot("org-a"), rt.hasSnapshot("org-b"))
	}
	if got := judge.calls.Load(); got != 0 {
		t.Fatalf("marked request invoked policy judge %d times, want zero", got)
	}
	if got := u.totalCalls(); got != 0 {
		t.Fatalf("marked request reached inference upstream %d times, want zero", got)
	}
	if got := len(getEvents()); got != 0 {
		t.Fatalf("marked request emitted %d events, want zero", got)
	}

	// An ordinary tenant-B request remains governed by tenant B's policy.
	gwB := rt02RouteGateway(t, u, nil, target, false)
	gwB.policyRuntime = rt
	gwB.auth = NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, newTestResolver("org-b", nil))
	control := serve(gwB, "tenant-b-only", false, "")
	if control.Code != http.StatusBadRequest || !strings.Contains(control.Body.String(), policyDenyErrorCode) {
		t.Fatalf("unmarked org-B control = %d %s, want normal org-B deny", control.Code, control.Body.String())
	}
	if got, want := store.readOrgs(), []string{"org-a", "org-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("policy lookup orgs after control = %v, want %v", got, want)
	}
	if !rt.hasSnapshot("org-b") {
		t.Fatal("unmarked org-B control failed to install org-B snapshot")
	}
	if got := judge.calls.Load(); got != 0 {
		t.Fatalf("tenant control unexpectedly invoked policy judge %d times, want zero", got)
	}
	if got := u.totalCalls(); got != 0 {
		t.Fatalf("org-B deny reached inference upstream %d times, want zero", got)
	}
	if got := len(getEvents()); got != 1 {
		t.Fatalf("unmarked org-B deny events = %d, want one ordinary policy-denial event", got)
	}
}

func TestPolicyReentryColdFailureRecoveryAfterMarker(t *testing.T) {
	store := &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}
	store.listErr = errors.New("synthetic policy store unavailable")
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "recovery-judge", OrgID: testOrg, Name: "recovery-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: reentryJudgePolicyYAML("recovery-judge")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	judge := installReentryJudgeCounter(t)
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	getEvents := captureEvents(t)
	gw := testHookGateway(rt)

	request := func() (*httptest.ResponseRecorder, *http.Request, bool) {
		w, r := policyRequest(`{"messages":[{"role":"user","content":"safe"}]}`)
		r.Header.Set("X-Yabanin-Judge", "recovery-marker-canary")
		_, _, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"safe"}]}`))
		return w, r, ok
	}

	w, _, ok := request()
	if ok || w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "policy_temporarily_unavailable") {
		t.Fatalf("cold failed read = (ok=%v status=%d body=%s), want terminal R009 503", ok, w.Code, w.Body.String())
	}
	if got := store.listCalls.Load(); got != 1 {
		t.Fatalf("initial failed read count = %d, want one", got)
	}

	store.mu.Lock()
	store.listErr = nil
	store.mu.Unlock()
	w, _, ok = request()
	if ok || w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "judge_reentry_unsupported") {
		t.Fatalf("recovered marked request = (ok=%v status=%d body=%s), want terminal R008 400", ok, w.Code, w.Body.String())
	}
	if !rt.hasSnapshot(testOrg) {
		t.Fatal("successful recovery did not install the healthy snapshot")
	}
	w, _, ok = request()
	if ok || w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "judge_reentry_unsupported") {
		t.Fatalf("warm marked request = (ok=%v status=%d body=%s), want terminal R008 400", ok, w.Code, w.Body.String())
	}
	if got := store.listCalls.Load(); got != 2 {
		t.Fatalf("failed/recovery/warm list reads = %d, want exactly two", got)
	}
	if got := judge.calls.Load(); got != 0 {
		t.Fatalf("marker recovery invoked policy judge %d times, want zero", got)
	}
	if got := len(getEvents()); got != 0 {
		t.Fatalf("marker recovery emitted %d events, want zero", got)
	}
}

func TestPolicyReentryCanceledColdLoadDoesNotRetry(t *testing.T) {
	store := &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}
	store.listCtxBlock = true
	store.listStarted = make(chan struct{}, 1)
	judge := installReentryJudgeCounter(t)
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	getEvents := captureEvents(t)
	w, r := policyRequest(`{"messages":[{"role":"user","content":"safe"}]}`)
	r.Header.Set("X-Yabanin-Judge", "cancel-marker-canary")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	*r = *r.WithContext(ctx)

	_, _, ok := testHookGateway(rt).policyPreUpstream(w, r, "chat", "m", "openai", []byte(`{"messages":[{"role":"user","content":"safe"}]}`))
	if ok || w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "policy_temporarily_unavailable") {
		t.Fatalf("cancelled cold load = (ok=%v status=%d body=%s), want terminal existing availability 503", ok, w.Code, w.Body.String())
	}
	select {
	case <-store.listStarted:
	default:
		t.Fatal("cancelled request did not make its one bounded policy-load attempt")
	}
	if got := store.listCalls.Load(); got != 1 {
		t.Fatalf("cancelled load attempts = %d, want one", got)
	}
	if strings.Contains(w.Body.String(), "cancel-marker-canary") {
		t.Fatalf("cancelled response leaked marker: %s", w.Body.String())
	}
	if rt.hasSnapshot(testOrg) {
		t.Fatal("cancelled load installed a snapshot")
	}
	if got := judge.calls.Load(); got != 0 {
		t.Fatalf("cancelled request invoked policy judge %d times, want zero", got)
	}
	if got := len(getEvents()); got != 0 {
		t.Fatalf("cancelled request emitted %d events, want zero", got)
	}
}

// TestPolicyReentryActualHTTPWireBoundary proves marker rejection at the
// listener/client boundary, including repeated header field lines as encoded
// by net/http. Direct handler tests above remain useful for narrow ordering
// assertions; this test establishes the real HTTP path and wrappers.
func TestPolicyReentryActualHTTPWireBoundary(t *testing.T) {
	store := &reentryOrgRecordingStore{countedPolicyStore: &countedPolicyStore{fakePolicyStore: newFakePolicyStore()}}
	for _, endpoint := range []string{"chat", "completions", "messages", "responses"} {
		id := "wire-judge-" + endpoint
		store.add("org-a", adminstore.PolicyPipeline{
			ID: id, OrgID: "org-a", Name: id, Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: reentryJudgePolicyYAML(id)}, []adminstore.PolicyAttachment{{ModelPattern: "*", Endpoint: endpoint}})
	}
	judge := installReentryJudgeCounter(t)
	policyRuntime := newTestRuntime(t, store, nil, PolicyModeEnforce)
	events := captureEvents(t)
	provider := newRT02Upstream(t)
	openAI := resolver.ModelInfo{ModelName: "m-openai", Provider: "openai", UpstreamURL: provider.srv.URL, Enabled: true}
	anthropic := resolver.ModelInfo{ModelName: "m-anthropic", Provider: "anthropic", UpstreamURL: provider.srv.URL, Enabled: true}
	gw := rt02RouteGateway(t, provider, nil, openAI, true)
	gw.res = stubModelResolver{"m-openai": openAI, "m-anthropic": anthropic}
	gw.policyRuntime = policyRuntime
	router := chi.NewRouter()
	gw.routes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	client := server.Client()

	type requestCase struct{ name, path, body string }
	routes := []requestCase{
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"m-openai","messages":[{"role":"user","content":"hello"}]}`},
		{name: "chat stream", path: "/v1/chat/completions", body: `{"model":"m-openai","stream":true,"messages":[{"role":"user","content":"hello"}]}`},
		{name: "legacy completions", path: "/v1/completions", body: `{"model":"m-openai","prompt":"hello"}`},
		{name: "native messages", path: "/v1/messages", body: `{"model":"m-anthropic","max_tokens":8,"messages":[{"role":"user","content":"hello"}]}`},
		{name: "native responses", path: "/v1/responses", body: `{"model":"m-openai","input":"hello"}`},
	}
	markerForms := []struct {
		name, key string
		values    []string
	}{
		{name: "empty", key: "X-Yabanin-Judge", values: []string{""}},
		{name: "true", key: "X-Yabanin-Judge", values: []string{"true"}},
		{name: "false", key: "X-Yabanin-Judge", values: []string{"false"}},
		{name: "arbitrary", key: "X-Yabanin-Judge", values: []string{"wire-marker-canary"}},
		{name: "mixed-case field name", key: "x-yAbAnIn-jUdGe", values: []string{"wire-marker-canary"}},
		{name: "duplicate empty and non-empty", key: "X-Yabanin-Judge", values: []string{"", "wire-marker-canary"}},
		{name: "conflicting repeated values", key: "X-Yabanin-Judge", values: []string{"true", "false"}},
	}
	responseByRoute := make(map[string]string, len(routes))

	for _, route := range routes {
		for _, marker := range markerForms {
			t.Run(route.name+"/"+marker.name, func(t *testing.T) {
				beforeUpstream, beforeJudge, beforeEvents := provider.totalCalls(), judge.calls.Load(), len(events())
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+route.path, strings.NewReader(route.body))
				if err != nil {
					t.Fatalf("create client request: %v", err)
				}
				req.Header.Set("Authorization", "Bearer test-key")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Org-Id", "org-spoof-canary")
				// Assign the map key directly so mixed-case spelling reaches the
				// transport unchanged; multiple values are emitted as repeated fields.
				req.Header[marker.key] = append([]string(nil), marker.values...)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("HTTP client request: %v", err)
				}
				defer resp.Body.Close()
				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("read HTTP response: %v", err)
				}
				body := string(bodyBytes)
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("wire marker response = %d %s, want 400", resp.StatusCode, body)
				}
				if route.path == "/v1/messages" {
					if !strings.Contains(body, `"type":"error"`) || !strings.Contains(body, "[judge_reentry_unsupported]") {
						t.Fatalf("Anthropic wire error wrapper/code missing: %s", body)
					}
				} else if !strings.Contains(body, `"code":"judge_reentry_unsupported"`) {
					t.Fatalf("wire error code missing: %s", body)
				}
				if previous, ok := responseByRoute[route.name]; ok && previous != body {
					t.Fatalf("marker form changed route error body: got %q, want %q", body, previous)
				}
				responseByRoute[route.name] = body
				for _, value := range marker.values {
					if value != "" && strings.Contains(body, value) {
						t.Fatalf("wire error disclosed marker value %q: %s", value, body)
					}
				}
				if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") || strings.Contains(body, "data:") {
					t.Fatalf("wire rejection emitted SSE: content-type=%q body=%q", resp.Header.Get("Content-Type"), body)
				}
				if got := provider.totalCalls(); got != beforeUpstream {
					t.Fatalf("marker reached inference upstream: calls %d -> %d", beforeUpstream, got)
				}
				if got := judge.calls.Load(); got != beforeJudge {
					t.Fatalf("marker invoked policy judge: calls %d -> %d", beforeJudge, got)
				}
				if got := len(events()); got != beforeEvents {
					for _, e := range events()[beforeEvents:got] {
						t.Logf("STRAGGLER event: type=%s request_id=%s org=%s endpoint=%s error=%q", e.EventType, e.RequestID, e.OrgID, e.Endpoint, e.Error)
					}
					t.Fatalf("marker published policy event: events %d -> %d", beforeEvents, got)
				}
			})
		}
	}

	if got, want := store.readOrgs(), []string{"org-a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("wire marker policy lookups = %v, want authenticated org only %v", got, want)
	}
	if got := store.listCalls.Load(); got != 1 {
		t.Fatalf("wire marker cold policy reads = %d, want one cached org snapshot", got)
	}

	// Missing-auth is checked before the marker and has no policy/upstream effects.
	unauth, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+routes[0].path, strings.NewReader(routes[0].body))
	if err != nil {
		t.Fatalf("create unauthenticated control: %v", err)
	}
	unauth.Header.Set("Content-Type", "application/json")
	unauth.Header.Set("X-Yabanin-Judge", "wire-marker-canary")
	beforeUnauthUpstream, beforeUnauthJudge := provider.totalCalls(), judge.calls.Load()
	unauthResp, err := client.Do(unauth)
	if err != nil {
		t.Fatalf("unauthenticated HTTP control: %v", err)
	}
	unauthBody, readErr := io.ReadAll(unauthResp.Body)
	_ = unauthResp.Body.Close()
	if readErr != nil {
		t.Fatalf("read unauthenticated response: %v", readErr)
	}
	if unauthResp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(unauthBody), "authentication_error") || strings.Contains(string(unauthBody), "judge_reentry_unsupported") {
		t.Fatalf("unauthenticated marker status/body = %d %s, want existing 401", unauthResp.StatusCode, unauthBody)
	}
	if got := provider.totalCalls(); got != beforeUnauthUpstream {
		t.Fatalf("unauthenticated marker reached upstream: %d -> %d", beforeUnauthUpstream, got)
	}
	if got := judge.calls.Load(); got != beforeUnauthJudge {
		t.Fatalf("unauthenticated marker invoked judge: %d -> %d", beforeUnauthJudge, got)
	}
	if got := store.listCalls.Load(); got != 1 {
		t.Fatalf("unauthenticated marker triggered policy read, total=%d want 1", got)
	}

	// The same actual listener still allows a normal authenticated request through
	// the existing policy judge and then to the local provider.
	control, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+routes[0].path, strings.NewReader(routes[0].body))
	if err != nil {
		t.Fatalf("create unmarked control: %v", err)
	}
	control.Header.Set("Authorization", "Bearer test-key")
	control.Header.Set("Content-Type", "application/json")
	beforeControlUpstream, beforeControlJudge := provider.totalCalls(), judge.calls.Load()
	controlResp, err := client.Do(control)
	if err != nil {
		t.Fatalf("unmarked HTTP control: %v", err)
	}
	controlBody, readErr := io.ReadAll(controlResp.Body)
	_ = controlResp.Body.Close()
	if readErr != nil {
		t.Fatalf("read unmarked response: %v", readErr)
	}
	if controlResp.StatusCode != http.StatusOK {
		t.Fatalf("unmarked control = %d %s, want normal 200", controlResp.StatusCode, controlBody)
	}
	if got := provider.totalCalls(); got != beforeControlUpstream+1 {
		t.Fatalf("unmarked control upstream calls = %d, want %d", got, beforeControlUpstream+1)
	}
	if got := judge.calls.Load(); got != beforeControlJudge+1 {
		t.Fatalf("unmarked control judge calls = %d, want %d", got, beforeControlJudge+1)
	}
}
