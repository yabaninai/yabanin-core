package llmjudge

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// stubClient captures ChatRequests and answers with canned content.
type stubClient struct {
	got     []ChatRequest
	content string
	err     error
}

func (s *stubClient) JudgeChat(_ context.Context, req ChatRequest) (ChatResponse, error) {
	s.got = append(s.got, req)
	if s.err != nil {
		return ChatResponse{}, s.err
	}
	return ChatResponse{Content: s.content, Model: "stub-model"}, nil
}

func testJudgeStep(t *testing.T, content string) (*Judge, *stubClient) {
	t.Helper()
	cl := &stubClient{content: content}
	deps := Deps{Client: cl, Prompts: EmbeddedPromptSource{}}
	st, err := FactoryWith(deps)(map[string]any{
		"model":      "judge-model",
		"prompt_ref": "judges/toxicity@2",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	j, ok := st.(*Judge)
	if !ok {
		t.Fatalf("factory returned %T", st)
	}
	return j, cl
}

func runJudge(t *testing.T, j *Judge, payload *pipeline.Payload) (*pipeline.Result, error) {
	t.Helper()
	out := &pipeline.Result{Verdict: pipeline.ActionAllow}
	// Zero-value Pipeline: StepID() is empty here; the compiled-step id is
	// asserted in the engine-based tests (e2e_test.go).
	err := j.Run(context.Background(), &pipeline.Pipeline{}, payload, out)
	return out, err
}

// engineVerdict mirrors engine.runStep's composition: a step raises the
// verdict only through its findings (the engine takes the Max).
func engineVerdict(out *pipeline.Result) pipeline.Action {
	v := out.Verdict
	for _, f := range out.Findings {
		v = v.Max(f.Action)
	}
	return v
}

func userPayload(text string) *pipeline.Payload {
	return &pipeline.Payload{
		Kind:     pipeline.KindRequest,
		Endpoint: "chat",
		Messages: []pipeline.Message{{Role: "user", Content: text}},
		Meta:     &pipeline.RequestMeta{Org: "org-a", Model: "gpt-x"},
	}
}

const toxicVerdictJSON = `{"findings":[{"category":"toxicity","severity":"high","confidence":0.95,"evidence":"idiot"}],"summary":"toxic"}`

func TestJudge_RunDeny(t *testing.T) {
	j, _ := testJudgeStep(t, toxicVerdictJSON)
	out, err := runJudge(t, j, userPayload("you are an idiot"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if engineVerdict(out) != pipeline.ActionDeny {
		t.Fatalf("verdict = %s, want deny", out.Verdict)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("findings = %+v", out.Findings)
	}
	f := out.Findings[0]
	if f.Category != "judge.toxicity" || f.Action != pipeline.ActionDeny {
		t.Fatalf("finding = %+v", f)
	}
}

func TestJudge_RunAllow(t *testing.T) {
	j, _ := testJudgeStep(t, `{"findings":[],"summary":"clean"}`)
	out, err := runJudge(t, j, userPayload("hello world"))
	if err != nil || engineVerdict(out) != pipeline.ActionAllow || len(out.Findings) != 0 {
		t.Fatalf("Run = %v, %+v, %v", err, out.Findings, out.Verdict)
	}
}

func TestJudge_ThresholdFromParams(t *testing.T) {
	cl := &stubClient{content: `{"findings":[{"category":"toxicity","confidence":0.5}]}`}
	st, err := FactoryWith(Deps{Client: cl})(map[string]any{
		"model": "m", "prompt_ref": "judges/toxicity@2", "threshold": 0.4,
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	out, err := runJudge(t, st.(*Judge), userPayload("x"))
	if err != nil || engineVerdict(out) != pipeline.ActionDeny {
		t.Fatalf("threshold 0.4 vs conf 0.5: verdict = %s err = %v, want deny", out.Verdict, err)
	}
}

func TestJudge_MarkerOnSyntheticMeta_OriginalUntouched(t *testing.T) {
	j, cl := testJudgeStep(t, `{"findings":[]}`)
	p := userPayload("hello")
	if _, err := runJudge(t, j, p); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(cl.got) != 1 {
		t.Fatalf("judge calls = %d", len(cl.got))
	}
	meta := cl.got[0].Meta
	if !IsJudgeMeta(meta) {
		t.Fatal("judge call meta must carry the judge marker (recursion exclusion)")
	}
	if meta.Org != "org-a" {
		t.Fatalf("org lost: %+v", meta)
	}
	// Original payload meta must be untouched (read-only contract).
	if IsJudgeMeta(p.Meta) {
		t.Fatal("original payload meta must NOT gain the judge marker")
	}
	if _, ok := p.Meta.Labels[MetaLabelJudge]; ok {
		t.Fatal("original meta labels mutated")
	}
}

// TestJudgeMeta_CarriesParentLabels pins the judgeMeta propagation contract
// (T03 record §8 defect): the hop meta is a deep clone of the parent — every
// parent label (the gateway's team stamp among them) survives into the clone
// with the judge marker merged in, and the clone's label map is distinct
// from the parent's, so hop-side writes can never leak back into the
// request. Inverts the pre-fix behavior, where judgeMeta reassigned
// c.Labels to a fresh map before copying and dropped every parent label.
func TestJudgeMeta_CarriesParentLabels(t *testing.T) {
	parent := &pipeline.RequestMeta{
		Org:    "org-a",
		Key:    "key-1",
		Labels: map[string]string{"team": "team-7", "tenant": "acme"},
	}
	hop := judgeMeta(parent)

	if !IsJudgeMeta(hop) {
		t.Fatal("hop meta must carry the judge marker")
	}
	for k, want := range parent.Labels {
		if got := hop.Labels[k]; got != want {
			t.Fatalf("parent label %s lost: got %q, want %q", k, got, want)
		}
	}
	if hop.Org != parent.Org || hop.Key != parent.Key {
		t.Fatalf("parent identity lost: %+v", hop)
	}
	// Deep clone: the hop map is a distinct map; writes never reach the
	// parent.
	hop.Labels["team"] = "team-9"
	if parent.Labels["team"] != "team-7" {
		t.Fatal("hop meta aliases the parent label map")
	}
	if IsJudgeMeta(parent) {
		t.Fatal("original parent meta mutated")
	}
}

// TestJudgeMeta_NilAndLabellessParents covers the degenerate parents from
// the doc comment: a nil meta yields an org-less meta carrying only the
// marker, and a label-less parent yields a marker-only map.
func TestJudgeMeta_NilAndLabellessParents(t *testing.T) {
	hop := judgeMeta(nil)
	if !IsJudgeMeta(hop) || hop.Org != "" {
		t.Fatalf("nil parent must yield an org-less marker meta, got %+v", hop)
	}
	hop = judgeMeta(&pipeline.RequestMeta{Org: "org-b"})
	if !IsJudgeMeta(hop) || len(hop.Labels) != 1 {
		t.Fatalf("label-less parent must yield a marker-only map, got %+v", hop.Labels)
	}
}

// TestJudge_ParentLabelsReachHopMeta is the acceptance half of the T03 §8
// fix through a real Run: the parent labels — the team stamp
// policyMetaWithTeam puts on the gateway request — reach the judge call's
// meta together with the judge marker (the policyMetaWithTeam ->
// hopTeamScope channel), while the original payload meta stays untouched.
func TestJudge_ParentLabelsReachHopMeta(t *testing.T) {
	j, cl := testJudgeStep(t, `{"findings":[]}`)
	p := userPayload("hello")
	p.Meta.Labels = map[string]string{"team": "team-7"}
	if _, err := runJudge(t, j, p); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(cl.got) != 1 {
		t.Fatalf("judge calls = %d", len(cl.got))
	}
	hop := cl.got[0].Meta
	if !IsJudgeMeta(hop) {
		t.Fatal("hop meta must carry the judge marker")
	}
	if hop.Labels["team"] != "team-7" {
		t.Fatalf("team stamp lost in the hop meta: %+v", hop.Labels)
	}
	if hop.Org != "org-a" {
		t.Fatalf("parent org lost: %+v", hop)
	}
	if IsJudgeMeta(p.Meta) {
		t.Fatal("original payload meta must not gain the marker")
	}
	if p.Meta.Labels["team"] != "team-7" {
		t.Fatal("original payload labels mutated")
	}
}

// Recursion exclusion, payload-level contract: a gateway middleware consults
// IsJudgeMeta and skips pipelines for judge traffic. This test simulates
// that middleware and asserts the judge's own synthetic call would be
// exempt.
func TestJudge_CallNeverReentersPipeline(t *testing.T) {
	j, cl := testJudgeStep(t, `{"findings":[]}`)
	p := userPayload("hello")
	if _, err := runJudge(t, j, p); err != nil {
		t.Fatalf("Run: %v", err)
	}
	synthetic := &pipeline.Payload{Kind: pipeline.KindRequest, Meta: cl.got[0].Meta}
	if IsJudgeMeta(synthetic.Meta) != true {
		t.Fatal("synthetic judge payload must be marked")
	}
	// Middleware shape (OP-8 contract): skip when IsJudgeMeta.
	runsPolicies := !IsJudgeMeta(synthetic.Meta)
	if runsPolicies {
		t.Fatal("judge call would re-enter the pipeline — recursion exclusion broken")
	}
}

func TestJudge_OutputMode_UsesAssistantTurn(t *testing.T) {
	cl := &stubClient{content: `{"findings":[]}`}
	st, err := FactoryWith(Deps{Client: cl})(map[string]any{
		"model": "m", "prompt_ref": "judges/toxicity@2", "mode": "output",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	p := &pipeline.Payload{
		Kind: pipeline.KindResponse,
		Messages: []pipeline.Message{
			{Role: "user", Content: "question"},
			{Role: "assistant", Content: "answer text"},
		},
	}
	if _, err := runJudge(t, st.(*Judge), p); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := cl.got[0].Messages[1].Content; got != "answer text" {
		t.Fatalf("judged content = %q, want the assistant turn", got)
	}
}

func TestJudge_BodyFallback(t *testing.T) {
	cl := &stubClient{content: `{"findings":[]}`}
	j, _ := testJudgeStepWithClient(t, cl)
	p := &pipeline.Payload{
		Kind: pipeline.KindRequest,
		Body: []byte(`{"model":"m","messages":[{"role":"user","content":"body turn"}]}`),
	}
	if _, err := runJudge(t, j, p); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := cl.got[0].Messages[1].Content; got != "body turn" {
		t.Fatalf("judged content = %q, want body turn", got)
	}
}

func TestJudge_EmptyTurnNoops(t *testing.T) {
	j, cl := testJudgeStep(t, `{"findings":[]}`)
	out, err := runJudge(t, j, &pipeline.Payload{Kind: pipeline.KindRequest})
	if err != nil || len(cl.got) != 0 || engineVerdict(out) != pipeline.ActionAllow {
		t.Fatalf("empty turn must no-op: err=%v calls=%d verdict=%s", err, len(cl.got), out.Verdict)
	}
}

func TestJudge_ClientErrorSurfaces(t *testing.T) {
	cl := &stubClient{err: errBoom}
	j, _ := testJudgeStepWithClient(t, cl)
	_, err := runJudge(t, j, userPayload("hello"))
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Run err = %v, want wrapped boom", err)
	}
}

func TestJudge_MalformedVerdictSurfaces(t *testing.T) {
	j, _ := testJudgeStep(t, "the content looks acceptable")
	_, err := runJudge(t, j, userPayload("hello"))
	if err == nil {
		t.Fatal("malformed verdict must be a step error (on_error applies)")
	}
}

func TestJudge_FactoryValidation(t *testing.T) {
	valid := map[string]any{"model": "m", "prompt_ref": "judges/toxicity@2"}
	deps := Deps{Client: &stubClient{}}

	if _, err := FactoryWith(Deps{})(valid); err == nil {
		t.Error("nil client must be a load error")
	}
	if _, err := FactoryWith(deps)(map[string]any{"prompt_ref": "judges/toxicity@2"}); err == nil {
		t.Error("missing model must be a load error")
	}
	if _, err := FactoryWith(deps)(map[string]any{"model": "m"}); err == nil {
		t.Error("missing prompt_ref must be a load error")
	}
	for name, mutate := range map[string]func(map[string]any){
		"bad threshold type":  func(p map[string]any) { p["threshold"] = "high" },
		"zero threshold":      func(p map[string]any) { p["threshold"] = 0 },
		"threshold above one": func(p map[string]any) { p["threshold"] = 1.5 },
		"bad mode":            func(p map[string]any) { p["mode"] = "sideways" },
		"bad categories type": func(p map[string]any) { p["categories"] = "toxicity" },
		"empty category":      func(p map[string]any) { p["categories"] = []any{"", "ok"} },
		"unknown prompt":      func(p map[string]any) { p["prompt_ref"] = "judges/ghost@1" },
		"model not a string":  func(p map[string]any) { p["model"] = 42 },
	} {
		params := map[string]any{"model": "m", "prompt_ref": "judges/toxicity@2"}
		mutate(params)
		if _, err := FactoryWith(deps)(params); err == nil {
			t.Errorf("%s: must be a load error", name)
		}
	}
	if _, err := FactoryWith(deps)(valid); err != nil {
		t.Fatalf("valid params: %v", err)
	}
}

func TestRegister_FactoryName(t *testing.T) {
	reg := pipeline.NewRegistry()
	if err := Register(reg, Deps{Client: &stubClient{}}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, ok := reg.Factory(FactoryName); !ok {
		t.Fatalf("factory %q not registered; have %v", FactoryName, reg.Names())
	}
}

func TestFactory_DefaultDepsUnset(t *testing.T) {
	SetDefaultDeps(Deps{})
	if _, err := Factory(map[string]any{"model": "m", "prompt_ref": "judges/toxicity@2"}); err == nil {
		t.Fatal("Factory without wired deps must fail at load")
	}
	SetDefaultDeps(Deps{Client: &stubClient{}})
	defer SetDefaultDeps(Deps{})
	if _, err := Factory(map[string]any{"model": "m", "prompt_ref": "judges/toxicity@2"}); err != nil {
		t.Fatalf("Factory with wired deps: %v", err)
	}
}

var errBoom = errors.New("boom")

func testJudgeStepWithClient(t *testing.T, cl *stubClient) (*Judge, *stubClient) {
	t.Helper()
	st, err := FactoryWith(Deps{Client: cl})(map[string]any{
		"model": "judge-model", "prompt_ref": "judges/toxicity@2",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return st.(*Judge), cl
}
