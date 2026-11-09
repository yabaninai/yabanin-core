package toolpolicy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// runStepPolicy loads a YAML policy carrying one builtin/toolpolicy step and
// runs it against a payload (the engine clones the payload per policy).
func runStepPolicy(t *testing.T, yaml string, in *pipeline.Payload) *pipeline.Result {
	t.Helper()
	eng := pipeline.NewEngine()
	if err := RegisterStepFactory(eng.Steps()); err != nil {
		t.Fatalf("register step factory: %v", err)
	}
	compiled, err := eng.LoadPolicy([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return eng.Run(context.Background(), []pipeline.Compiled{compiled}, in)
}

func TestStep_ToolArgsSchemaDeny(t *testing.T) {
	const policy = `
apiVersion: ypp/v1
kind: Policy
name: guard-args
mode: enforce
hooks: [tool_pre]
steps:
  - id: args-guard
    detector: builtin/toolpolicy
    params:
      args:
        schema:
          type: object
          properties:
            q: {type: string}
          required: [q]
`
	res := runStepPolicy(t, policy, &pipeline.Payload{
		Kind: pipeline.KindToolArgs, Body: []byte(`{"wrong":1}`),
	})
	if res.Verdict != pipeline.ActionDeny {
		t.Fatalf("schema violation must deny: %+v", res)
	}
	found := false
	for _, f := range res.Findings {
		if f.Category == "toolpolicy.schema" {
			found = true
			if f.Action != pipeline.ActionDeny {
				t.Fatalf("finding action: %+v", f)
			}
			// Value-free invariant: no instance data in the finding.
			if strings.Contains(f.Evidence, "wrong") {
				t.Fatalf("finding must not echo instance values: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("toolpolicy.schema finding expected: %+v", res.Findings)
	}

	res = runStepPolicy(t, policy, &pipeline.Payload{
		Kind: pipeline.KindToolArgs, Body: []byte(`{"q":"ok"}`),
	})
	if res.Verdict != pipeline.ActionAllow {
		t.Fatalf("valid args must allow: %+v", res)
	}
}

func TestStep_ToolResultMask(t *testing.T) {
	const secret = "ghp_Abcd" + "EfghAbcdEfghAbcdEfghAbcdEfgh1"
	const policy = `
apiVersion: ypp/v1
kind: Policy
name: guard-result
mode: enforce
hooks: [tool_post]
steps:
  - id: result-guard
    detector: builtin/toolpolicy
    params:
      result:
        mode: mask
        secrets: true
`
	in := &pipeline.Payload{Kind: pipeline.KindToolResult,
		Body: []byte(`{"text":"token ` + secret + `"}`)}
	res := runStepPolicy(t, policy, in)
	if res.Verdict != pipeline.ActionMask {
		t.Fatalf("mask verdict: %+v", res)
	}
	if res.Mutated == nil {
		t.Fatal("mask must mutate the payload")
	}
	if strings.Contains(string(res.Mutated.Body), secret) {
		t.Fatalf("mutated body still carries the secret: %s", res.Mutated.Body)
	}
	// The caller's payload is never mutated (engine clones).
	if strings.Contains(string(in.Body), "[REDACTED") {
		t.Fatal("the engine must run steps on a clone")
	}
}

func TestStep_TargetingParams(t *testing.T) {
	const policy = `
apiVersion: ypp/v1
kind: Policy
name: targeted-guard
mode: enforce
hooks: [tool_pre]
steps:
  - id: guard
    detector: builtin/toolpolicy
    params:
      tool: "github_*"
      args:
        max_bytes: 5
`
	in := &pipeline.Payload{
		Kind: pipeline.KindToolArgs,
		Body: []byte(`{"too":"long"}`),
		Meta: &pipeline.RequestMeta{Labels: map[string]string{LabelTool: "github_search"}},
	}
	if res := runStepPolicy(t, policy, in); res.Verdict != pipeline.ActionDeny {
		t.Fatalf("targeted step must deny matching tool: %+v", res)
	}
	in.Meta.Labels[LabelTool] = "wiki_search"
	if res := runStepPolicy(t, policy, in); res.Verdict != pipeline.ActionAllow {
		t.Fatalf("non-matching tool must skip: %+v", res)
	}
	// No labels at all: a misscoped step never denies.
	in.Meta = nil
	if res := runStepPolicy(t, policy, in); res.Verdict != pipeline.ActionAllow {
		t.Fatalf("unlabeled payload must skip a targeted step: %+v", res)
	}
}

func TestStep_NonToolKindsNoop(t *testing.T) {
	const policy = `
apiVersion: ypp/v1
kind: Policy
name: guard
mode: enforce
hooks: [pre_upstream]
steps:
  - id: guard
    detector: builtin/toolpolicy
    params:
      args:
        max_bytes: 5
`
	res := runStepPolicy(t, policy, &pipeline.Payload{
		Kind: pipeline.KindRequest, Body: []byte(strings.Repeat("x", 100)),
	})
	if res.Verdict != pipeline.ActionAllow {
		t.Fatalf("non-tool payload must be a no-op: %+v", res)
	}
}

func TestStepFactory_InvalidParams(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
	}{
		{"bad regex", map[string]any{"args": map[string]any{"deny_regex": []any{"(["}}}},
		{"bad fail", map[string]any{"args": map[string]any{"max_bytes": 5}, "fail": "wat"}},
		{"empty args", map[string]any{"args": map[string]any{}}},
		{"bad server pattern", map[string]any{"args": map[string]any{"max_bytes": 5}, "server": "a*b"}},
		{"bad tool pattern", map[string]any{"args": map[string]any{"max_bytes": 5}, "tool": "*x"}},
		{"non-string fail", map[string]any{"fail": 5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := StepFactory(tc.params); err == nil {
				t.Fatalf("must reject %v", tc.params)
			}
		})
	}
	// A rules document without any check is a load error (never a silent
	// no-op step).
	if _, err := StepFactory(map[string]any{}); err == nil {
		t.Fatal("params without rules must fail to compile")
	}
}

// TestStep_NoValueLeakageInFindings pins the OP-6 invariant on the pipeline
// surface: a secret hitting a rule produces spans/categories only.
func TestStep_NoValueLeakageInFindings(t *testing.T) {
	const secret = "sk-abcdef1234567890abcdef"
	const policy = `
apiVersion: ypp/v1
kind: Policy
name: no-leak
mode: enforce
hooks: [tool_pre]
steps:
  - id: guard
    detector: builtin/toolpolicy
    params:
      args:
        deny_regex: ["sk-[A-Za-z0-9_-]{16,}"]
`
	in := &pipeline.Payload{Kind: pipeline.KindToolArgs,
		Body: []byte(`{"note":"value ` + secret + `"}`)}
	res := runStepPolicy(t, policy, in)
	if res.Verdict != pipeline.ActionDeny {
		t.Fatalf("deny expected: %+v", res)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, secret) || strings.Contains(f.Span, secret) || strings.Contains(string(f.Category), secret) {
			t.Fatalf("finding carries the matched value: %+v", f)
		}
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), secret) {
		t.Fatal("pipeline result serializes the matched value")
	}
}
