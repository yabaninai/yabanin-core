package pipeline

import (
	"context"
	"testing"
	"time"
)

// seed corpus for FuzzLoadPolicyAndRun: valid, near-valid and adversarial
// shapes. f.Add registers them; TestFuzzSeedCorpus re-checks the main seed
// compiles and runs in plain `go test` too.
const fuzzValid = `
apiVersion: ypp/v1
kind: Policy
name: fuzz
mode: enforce
hooks: [pre_upstream, post_upstream]
steps:
  - id: a
    detector: builtin/noop
    when: "true"
    timeout: 10ms
    on_error: fail_open+flag
  - id: b
    detector: builtin/noop
    parallel: [c]
  - id: c
    detector: builtin/noop
  - id: d
    mutator: test/mutator
  - id: e
    callout: http://presidio.internal:3000/analyze
    timeout: 250ms
    on_error: fail_open
  - id: f
    llm_judge:
      model: "$(sovereign-classifier)"
      prompt_ref: "judges/toxicity@2"
  - id: g
    decide: allow
  - id: h
    route_hint: in_region
`

// fuzzEngine wires every factory name a seed can reference plus the test
// condition engine, so valid mutations compile and run.
func fuzzEngine() *Engine {
	eng := NewEngine()
	for _, name := range []string{"builtin/noop", "callout", "llm_judge", "decide", "route_hint"} {
		eng.Steps().MustRegister(name, NoopFactory)
	}
	eng.Steps().MustRegister("test/mutator", func(map[string]any) (Step, error) { return &mutatorStep{}, nil })
	eng.Scripts().MustRegister("test", newTestEngine().Compile)
	return eng
}

// FuzzLoadPolicyAndRun bounds the compiler and engine against arbitrary
// input: no panic may escape, compilation errors stay errors, and a
// successful compile always runs with a complete trace, a known verdict and
// bounded wall time.
func FuzzLoadPolicyAndRun(f *testing.F) {
	f.Add(fuzzValid)
	f.Add("apiVersion: ypp/v1\nkind: Policy\nname: p\nmode: shadow\nhooks: [stream_prefix]\nsteps:\n  - id: x\n    detector: builtin/noop\n")
	f.Add("apiVersion: ypp/v1\nkind: Policy\nname: p\nmode: enforce\nhooks: [tool_pre]\nsteps:\n  - id: x\n    detector: ghost\n")
	f.Add("apiVersion: ypp/v1\nkind: Policy\nname: p\nmode: enforce\nhooks: [tool_pre]\nsteps:\n  - id: x\n    detector: builtin/noop\n    when: \"1 + \"\n")
	f.Add("apiVersion: ypp/v1\nkind: Policy\nname: p\nmode: enforce\nhooks: [tool_pre]\nsteps:\n  - id: x\n    detector: builtin/noop\n    parallel: [x]\n")
	f.Add("apiVersion: ypp/v9\nkind: Policy\nname: p\nmode: enforce\nhooks: [pre_upstream]\nsteps:\n  - id: x\n    detector: builtin/noop\n")
	f.Add("{{}}")
	f.Add("\t\tbroken: [")

	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 1<<15 { // bounded: keep fuzz runs fast and allocation-safe
			t.Skip()
		}
		eng := fuzzEngine()
		c, err := eng.LoadPolicy([]byte(src))
		if err != nil {
			if len(c.StepIDs()) != 0 {
				t.Fatalf("failed load returned a populated pipeline: %v", err)
			}
			return
		}
		if n := len(c.StepIDs()); n > 256 { // bounded engine runs
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		res := eng.Run(ctx, []Compiled{c}, chatPayload())

		assertTraceComplete(t, res, c)
		switch res.Verdict {
		case ActionDeny, ActionMask, ActionFlag, ActionAllow:
		default:
			t.Fatalf("verdict %q outside the vocabulary", res.Verdict)
		}
		for _, tr := range res.Trace {
			switch tr.Outcome {
			case StepRan, StepSkipped, StepError, StepTimeout:
			default:
				t.Fatalf("unknown outcome %q in trace", tr.Outcome)
			}
		}
	})
}

// TestFuzzSeedCorpus keeps the primary seed compiling and running in plain
// `go test` (CI without -fuzz).
func TestFuzzSeedCorpus(t *testing.T) {
	eng := fuzzEngine()
	c, err := eng.LoadPolicy([]byte(fuzzValid))
	if err != nil {
		t.Fatalf("seed corpus must compile: %v", err)
	}
	if len(c.StepIDs()) != 8 {
		t.Fatalf("seed steps = %d, want 8", len(c.StepIDs()))
	}
	res := eng.Run(context.Background(), []Compiled{c}, chatPayload())
	assertTraceComplete(t, res, c)
}
