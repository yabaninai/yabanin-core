package builtins

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

func TestModelRewrite_Basic(t *testing.T) {
	res := runMutatorOne(t, NameModelRewrite, map[string]any{"to": "gpt-4o-inregion"}, reqPayload("hello"))
	assertRan(t, res)
	if res.Mutated.Meta.Model != "gpt-4o-inregion" {
		t.Errorf("model = %q, want rewrite", res.Mutated.Meta.Model)
	}
	// Mandatory trace note: a content-free flag finding.
	fs := findingsOf(res, "s1")
	if len(fs) != 1 {
		t.Fatalf("findings = %v, want exactly the rewrite note", fs)
	}
	f := fs[0]
	if f.Category != "model_rewrite" || f.Action != pipeline.ActionFlag || f.Severity != sevLow {
		t.Errorf("note finding = %+v, want model_rewrite/flag/low", f)
	}
	if f.Evidence != "gpt-4o → gpt-4o-inregion" {
		t.Errorf("note evidence = %q, want \"gpt-4o → gpt-4o-inregion\"", f.Evidence)
	}
}

func TestModelRewrite_FromGate(t *testing.T) {
	params := map[string]any{"to": "gpt-4o-inregion", "from": "gpt-4o"}
	res := runMutatorOne(t, NameModelRewrite, params, reqPayload("hello"))
	assertRan(t, res)
	if res.Mutated.Meta.Model != "gpt-4o-inregion" {
		t.Errorf("from match: model = %q", res.Mutated.Meta.Model)
	}
	// Different current model: untouched.
	in := reqPayload("hello")
	in.Meta.Model = "claude-3"
	res = runMutatorOne(t, NameModelRewrite, params, in)
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("from mismatch mutated: %+v", res.Mutated.Meta)
	}
}

func TestModelRewrite_NoOps(t *testing.T) {
	// Already at target: no rewrite, no note.
	res := runMutatorOne(t, NameModelRewrite, map[string]any{"to": "gpt-4o"}, reqPayload("hello"))
	assertRan(t, res)
	if res.Mutated != nil || len(findingsOf(res, "s1")) != 0 {
		t.Errorf("identity rewrite mutated: %+v %v", res.Mutated, res.Findings)
	}
	// Nil Meta: nothing to rewrite, no note.
	in := &pipeline.Payload{Kind: pipeline.KindRequest, Messages: []pipeline.Message{{Role: "user", Content: "x"}}}
	res = runMutatorOne(t, NameModelRewrite, map[string]any{"to": "m2"}, in)
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("nil Meta mutated: %+v", res.Mutated)
	}
	// Response kind: request-only, untouched.
	in = respPayload("x")
	res = runMutatorOne(t, NameModelRewrite, map[string]any{"to": "m2"}, in)
	assertRan(t, res)
	if res.Mutated != nil {
		t.Errorf("response kind mutated: %+v", res.Mutated)
	}
	mustCompileErr(t, NameModelRewrite, nil)
	mustCompileErr(t, NameModelRewrite, map[string]any{"to": ""})
	mustCompileErr(t, NameModelRewrite, map[string]any{"to": "m", "kinds": []any{"response"}})
}

func TestModelRewrite_DataBoundaryFlow(t *testing.T) {
	// The RM-63..66 seam: detector flag → model-rewrite → in-region model,
	// driven by `when` at policy level. The engine records both steps.
	steps := []pipeline.StepSpec{
		{ID: "s1", Detector: NameNationalPII, Params: map[string]any{"action": "flag"}},
		{ID: "s2", Mutator: NameModelRewrite, Params: map[string]any{"to": "gpt-4o-inregion"}},
	}
	res := runStepSpecs(t, steps, reqPayload("снилс 112-233-445 95"))
	assertAllRan(t, res)
	if res.Mutated.Meta.Model != "gpt-4o-inregion" {
		t.Errorf("model = %q, want in-region rewrite", res.Mutated.Meta.Model)
	}
	if res.Verdict != pipeline.ActionFlag {
		t.Errorf("verdict = %q, want flag", res.Verdict)
	}
}

func TestModelRewrite_ContextCancellation(t *testing.T) {
	st, err := NewModelRewrite(map[string]any{"to": "m2"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in := reqPayload("hello")
	if err := st.Run(ctx, nil, in, &pipeline.Result{}); err == nil {
		t.Error("cancelled ctx: want error")
	}
	if in.Meta.Model != "gpt-4o" {
		t.Errorf("cancelled run rewrote: %q", in.Meta.Model)
	}
}
