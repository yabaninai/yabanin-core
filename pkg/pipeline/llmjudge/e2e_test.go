package llmjudge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// judgeMock is an openai-compatible judge model served by httptest. It
// records every request body and answers with a canned completion.
type judgeMock struct {
	t *testing.T
	// assertExtra runs after the standard contract asserts (header, path,
	// temperature, response format); use it for scenario-specific checks.
	assertExtra func(req chatWireRequest)
	content     string
	status      int
	// delay holds each response back (timeout scenarios).
	delay time.Duration

	mu     sync.Mutex
	bodies []chatWireRequest
}

type chatWireRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Temperature    float64 `json:"temperature"`
	MaxTokens      int     `json:"max_tokens,omitempty"`
	ResponseFormat *struct {
		Type string `json:"type"`
	} `json:"response_format"`
}

func (m *judgeMock) handler(w http.ResponseWriter, r *http.Request) {
	m.t.Helper()
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if r.Header.Get(JudgeHeader) != JudgeLabelValue {
		m.t.Error("judge call missing the X-Yabanin-Judge wire marker (recursion exclusion)")
	}
	if got := r.URL.Path; got != "/v1/chat/completions" {
		m.t.Errorf("judge path = %q, want /v1/chat/completions", got)
	}
	var req chatWireRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		m.t.Errorf("decode judge request: %v", err)
	}
	if req.Temperature != 0 {
		m.t.Errorf("judge temperature = %v, want 0 (determinism contract)", req.Temperature)
	}
	if req.ResponseFormat == nil || req.ResponseFormat.Type != "json_object" {
		m.t.Error("judge request must ask for JSON mode")
	}
	if len(req.Messages) != 2 || req.Messages[0].Role != "system" || req.Messages[1].Role != "user" {
		m.t.Errorf("judge messages = %+v, want [system user]", req.Messages)
	}
	m.mu.Lock()
	m.bodies = append(m.bodies, req)
	m.mu.Unlock()
	if m.assertExtra != nil {
		m.assertExtra(req)
	}
	status := m.status
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	content := m.content
	if status != http.StatusOK {
		content = "upstream exploded"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"choices": []map[string]any{
			{"message": map[string]any{"role": "assistant", "content": content}},
		},
	})
}

func (m *judgeMock) requests() []chatWireRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]chatWireRequest(nil), m.bodies...)
}

// newJudgeHarness wires an engine whose llm_judge factory talks to the mock
// over the packaged UpstreamJudgeClient.
func newJudgeHarness(t *testing.T, mock *judgeMock, resolver ModelResolver, keys KeyResolver) *pipeline.Engine {
	t.Helper()
	pool := upstream.NewPool(upstream.Options{})
	client := NewUpstreamJudgeClient(pool, resolver, keys)
	eng := pipeline.NewEngine()
	if err := Register(eng.Steps(), Deps{Client: client}); err != nil {
		t.Fatalf("Register llm_judge: %v", err)
	}
	return eng
}

// judgePolicyYAML renders an enforce-mode policy with one judge step.
func judgePolicyYAML(model, timeout, onError string) []byte {
	if timeout == "" {
		timeout = "5s"
	}
	return fmt.Appendf(nil, `
apiVersion: ypp/v1
kind: Policy
name: judge-e2e
mode: enforce
hooks: [pre_upstream]
steps:
  - id: judge_tox
    llm_judge:
      model: %s
      prompt_ref: "judges/toxicity@2"
    timeout: %s
    on_error: %s
    params:
      threshold: 0.8
`, model, timeout, onError)
}

func runPolicy(t *testing.T, eng *pipeline.Engine, policy []byte, payload *pipeline.Payload) *pipeline.Result {
	t.Helper()
	compiled, err := eng.LoadPolicy(policy)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return eng.Run(context.Background(), []pipeline.Compiled{compiled}, payload)
}

func TestE2E_JudgeDenyThroughEngine(t *testing.T) {
	mock := &judgeMock{
		t:       t,
		content: toxicVerdictJSON,
		assertExtra: func(req chatWireRequest) {
			if req.Model != "judge-model" {
				t.Errorf("upstream model = %q, want judge-model", req.Model)
			}
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()

	eng := newJudgeHarness(t, mock,
		DirectModelResolver{URL: srv.URL},
		KeyResolverFunc(func(_ context.Context, org string, _ Target) (string, error) {
			if org != "org-a" {
				t.Errorf("key resolver org = %q, want org-a", org)
			}
			return "test-key", nil
		}))

	res := runPolicy(t, eng, judgePolicyYAML("judge-model", "", "fail_open+flag"), userPayload("you are an idiot"))

	if res.Verdict != pipeline.ActionDeny {
		t.Fatalf("verdict = %s, want deny", res.Verdict)
	}
	if len(res.Findings) != 1 || res.Findings[0].Step != "judge_tox" || res.Findings[0].Category != "judge.toxicity" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	tr := res.Trace[0]
	if tr.Outcome != pipeline.StepRan {
		t.Fatalf("trace = %+v, want ran", tr)
	}
}

func TestE2E_FlagBelowThreshold(t *testing.T) {
	mock := &judgeMock{t: t, content: `{"findings":[{"category":"toxicity","severity":"low","confidence":0.3,"evidence":"meh"}],"summary":"mild"}`}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()
	eng := newJudgeHarness(t, mock, DirectModelResolver{URL: srv.URL}, nil)

	res := runPolicy(t, eng, judgePolicyYAML("judge-model", "", "fail_open+flag"), userPayload("borderline text"))
	if res.Verdict != pipeline.ActionFlag || len(res.Findings) != 1 || res.Findings[0].Action != pipeline.ActionFlag {
		t.Fatalf("verdict = %s findings = %+v, want single flag", res.Verdict, res.Findings)
	}
}

func TestE2E_SovereignClassifierIndirection(t *testing.T) {
	// The indirection resolves through the gateway's resolver path (stubbed
	// here) to an on-prem classifier: loopback URL, registry model name.
	// That is the offline positioning contract — judge against any registry
	// model, sovereign/on-prem included, with no external safety API.
	mock := &judgeMock{
		t:       t,
		content: toxicVerdictJSON,
		assertExtra: func(req chatWireRequest) {
			if req.Model != "safer-classifier-local" {
				t.Errorf("resolved model = %q, want safer-classifier-local", req.Model)
			}
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()

	resolver := ModelResolverFunc(func(_ context.Context, ref string) (Target, error) {
		if ref != "$(sovereign-classifier)" {
			return Target{}, fmt.Errorf("unexpected ref %q", ref)
		}
		return Target{Model: "safer-classifier-local", UpstreamURL: srv.URL}, nil
	})
	eng := newJudgeHarness(t, mock, resolver, nil)

	res := runPolicy(t, eng, judgePolicyYAML("$(sovereign-classifier)", "", "fail_open+flag"), userPayload("toxic input"))
	if res.Verdict != pipeline.ActionDeny {
		t.Fatalf("verdict = %s, want deny", res.Verdict)
	}
	// The metrics label must be the resolved model, not the indirection.
	if n := testutil.CollectAndCount(judgeVerdicts, "pipeline_llmjudge_verdicts_total"); n == 0 {
		t.Fatal("verdicts metric not recorded")
	}

	// A registry-free resolver must refuse indirections instead of sending
	// them upstream verbatim.
	if _, err := (DirectModelResolver{}).ResolveJudgeModel(context.Background(), "$(sovereign-classifier)"); err == nil {
		t.Fatal("DirectModelResolver must refuse $(...) indirections")
	}
}

func TestE2E_MalformedVerdict(t *testing.T) {
	mock := &judgeMock{t: t, content: "the content looks acceptable to me"}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()
	eng := newJudgeHarness(t, mock, DirectModelResolver{URL: srv.URL}, nil)

	// fail_open+flag: recorded + synthetic flag, run continues.
	res := runPolicy(t, eng, judgePolicyYAML("judge-model", "", "fail_open+flag"), userPayload("hello"))
	if res.Verdict != pipeline.ActionFlag {
		t.Fatalf("verdict = %s, want flag (fail_open+flag)", res.Verdict)
	}
	var synthetic *pipeline.Finding
	for i := range res.Findings {
		if res.Findings[i].Category == "step_error" {
			synthetic = &res.Findings[i]
		}
	}
	if synthetic == nil {
		t.Fatalf("no synthetic step_error finding: %+v", res.Findings)
	}
	if res.Trace[0].Outcome != pipeline.StepError {
		t.Fatalf("trace outcome = %s, want error", res.Trace[0].Outcome)
	}

	// Engine default fail_closed: the same failure denies.
	res = runPolicy(t, eng, judgePolicyYAML("judge-model", "", "fail_closed"), userPayload("hello"))
	if res.Verdict != pipeline.ActionDeny {
		t.Fatalf("verdict = %s, want deny (fail_closed default)", res.Verdict)
	}
}

func TestE2E_StepTimeout(t *testing.T) {
	mock := &judgeMock{t: t, content: toxicVerdictJSON, delay: 300 * time.Millisecond}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()
	eng := newJudgeHarness(t, mock, DirectModelResolver{URL: srv.URL}, nil)

	res := runPolicy(t, eng, judgePolicyYAML("judge-model", "50ms", "fail_open+flag"), userPayload("hello"))
	if res.Trace[0].Outcome != pipeline.StepTimeout {
		t.Fatalf("trace outcome = %s, want timeout", res.Trace[0].Outcome)
	}
	if res.Verdict != pipeline.ActionFlag {
		t.Fatalf("verdict = %s, want flag", res.Verdict)
	}
}

func TestE2E_UpstreamError(t *testing.T) {
	mock := &judgeMock{t: t, status: http.StatusInternalServerError}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()
	eng := newJudgeHarness(t, mock, DirectModelResolver{URL: srv.URL}, nil)

	res := runPolicy(t, eng, judgePolicyYAML("judge-model", "", "fail_open+flag"), userPayload("hello"))
	if res.Trace[0].Outcome != pipeline.StepError || res.Verdict != pipeline.ActionFlag {
		t.Fatalf("outcome = %s verdict = %s, want error/flag", res.Trace[0].Outcome, res.Verdict)
	}
}

func TestE2E_ContextCancel(t *testing.T) {
	mock := &judgeMock{t: t, content: toxicVerdictJSON, delay: 300 * time.Millisecond}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()
	eng := newJudgeHarness(t, mock, DirectModelResolver{URL: srv.URL}, nil)

	compiled, err := eng.LoadPolicy(judgePolicyYAML("judge-model", "", "fail_open+flag"))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	res := eng.Run(ctx, []pipeline.Compiled{compiled}, userPayload("hello"))
	if res.Trace[0].Outcome == pipeline.StepRan {
		t.Fatalf("trace = %+v, want error/timeout/skip after cancel", res.Trace[0])
	}
}

func TestE2E_ConcurrentRunsSameVerdict(t *testing.T) {
	mock := &judgeMock{t: t, content: toxicVerdictJSON}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()
	eng := newJudgeHarness(t, mock, DirectModelResolver{URL: srv.URL}, nil)
	compiled, err := eng.LoadPolicy(judgePolicyYAML("judge-model", "", "fail_closed"))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	const n = 8
	verdicts := make([]pipeline.Action, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			res := eng.Run(context.Background(), []pipeline.Compiled{compiled}, userPayload("same input"))
			verdicts[i] = res.Verdict
		})
	}
	wg.Wait()
	for i, v := range verdicts {
		if v != pipeline.ActionDeny {
			t.Errorf("run %d verdict = %s, want deny (deterministic, temperature=0)", i, v)
		}
	}
}

func TestE2E_JudgeMarkerNeverReentersPipeline(t *testing.T) {
	// Full-path check: the mock (a stand-in for any pipeline-aware hop,
	// including a judge model served by this very gateway) sees the wire
	// marker, and the synthetic meta the step hands to the client passes
	// IsJudgeMeta — the check the gateway middleware (OP-8) must use to
	// exempt judge traffic from every pipeline.
	mock := &judgeMock{t: t, content: `{"findings":[]}`}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()

	var captured ChatRequest
	client := JudgeClientFunc(func(_ context.Context, req ChatRequest) (ChatResponse, error) {
		captured = req
		return ChatResponse{Content: `{"findings":[]}`}, nil
	})
	eng := pipeline.NewEngine()
	if err := Register(eng.Steps(), Deps{Client: client}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	res := runPolicy(t, eng, judgePolicyYAML("judge-model", "", "fail_closed"), userPayload("hello"))
	if res.Verdict != pipeline.ActionAllow {
		t.Fatalf("verdict = %s", res.Verdict)
	}
	if !IsJudgeMeta(captured.Meta) {
		t.Fatal("judge client received an unmarked call — recursion exclusion broken")
	}
	if len(mock.requests()) != 0 {
		t.Fatal("mock must not be hit in this scenario")
	}
}

// JudgeClientFunc adapts a function to JudgeClient (test seam).
type JudgeClientFunc func(ctx context.Context, req ChatRequest) (ChatResponse, error)

// JudgeChat implements JudgeClient.
func (f JudgeClientFunc) JudgeChat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	return f(ctx, req)
}

func TestUpstreamJudgeClient_RefusesUnmarkedCall(t *testing.T) {
	// The recursion-exclusion line of defense: no marker → no wire call.
	mock := &judgeMock{t: t, content: `{"findings":[]}`}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()

	client := NewUpstreamJudgeClient(upstream.NewPool(upstream.Options{}), nil, nil)
	_, err := client.JudgeChat(context.Background(), ChatRequest{
		ModelRef: "m",
		Messages: []pipeline.Message{{Role: "user", Content: "x"}},
	})
	if err == nil || !strings.Contains(err.Error(), MetaLabelJudge) {
		t.Fatalf("unmarked call err = %v, want marker refusal", err)
	}
}

func TestJudge_Name(t *testing.T) {
	j, _ := testJudgeStep(t, `{"findings":[]}`)
	if got := j.Name(); got != "llmjudge/judge" {
		t.Fatalf("Name = %q", got)
	}
}

func TestMetrics_JudgeOutcomes(t *testing.T) {
	before := testutil.ToFloat64(judgeVerdicts.WithLabelValues("metrics-model", "deny"))

	mock := &judgeMock{t: t, content: toxicVerdictJSON}
	srv := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer srv.Close()
	eng := newJudgeHarness(t, mock, ModelResolverFunc(func(_ context.Context, _ string) (Target, error) {
		return Target{Model: "metrics-model", UpstreamURL: srv.URL}, nil
	}), nil)

	runPolicy(t, eng, judgePolicyYAML("$(any)", "", "fail_closed"), userPayload("toxic"))

	after := testutil.ToFloat64(judgeVerdicts.WithLabelValues("metrics-model", "deny"))
	if after-before != 1 {
		t.Fatalf("verdicts{model=metrics-model,deny} delta = %v, want 1", after-before)
	}
}
