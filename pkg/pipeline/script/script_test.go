package script

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// fakeEngine is a stand-in for an OP-7 implementation: compiles sources that
// are exactly "yes"/"no"; anything else fails compilation. It proves the
// seam contract: script.Engine registers into pipeline.Engine via Compile.
type fakeEngine struct{}

func (fakeEngine) Name() string { return "fake" }

func (fakeEngine) Compile(source string) (pipeline.ConditionProgram, error) {
	switch source {
	case "yes", "no":
		return fakeProgram{want: source == "yes"}, nil
	default:
		return nil, &compileError{src: source}
	}
}

type compileError struct{ src string }

func (e *compileError) Error() string { return "unsupported condition: " + e.src }

type fakeProgram struct{ want bool }

func (p fakeProgram) Evaluate(context.Context, pipeline.ConditionEnv) (bool, error) {
	return p.want, nil
}

// Compile-time seam check: a script.Engine implementation satisfies the
// registration signature the core expects.
var _ Engine = fakeEngine{}

const policyYAML = `
apiVersion: ypp/v1
kind: Policy
name: seam
mode: enforce
hooks: [pre_upstream]
steps:
  - id: gated
    detector: builtin/noop
    when: "yes"
    when_engine: fake
  - id: off
    detector: builtin/noop
    when: "no"
    when_engine: fake
`

func TestEngineSeamRegistersAndEvaluates(t *testing.T) {
	eng := pipeline.NewEngine()
	eng.Steps().MustRegister("builtin/noop", pipeline.NoopFactory)

	// Before registration: load fails with a clear message.
	if _, err := eng.LoadPolicy([]byte(policyYAML)); err == nil {
		t.Fatal("unregistered condition engine must fail policy load")
	} else if !strings.Contains(err.Error(), `condition engine "fake" is not registered`) {
		t.Fatalf("unhelpful load error: %v", err)
	}

	// After registration the script.Engine compiles policies.
	var e Engine = fakeEngine{}
	eng.Scripts().MustRegister(e.Name(), e.Compile)

	c, err := eng.LoadPolicy([]byte(policyYAML))
	if err != nil {
		t.Fatalf("load with registered engine: %v", err)
	}
	res := eng.Run(context.Background(), []pipeline.Compiled{c}, &pipeline.Payload{Kind: pipeline.KindRequest})
	if res.Verdict != pipeline.ActionAllow {
		t.Fatalf("verdict = %q, want allow", res.Verdict)
	}
	trace := map[string]pipeline.StepOutcome{}
	for _, tr := range res.Trace {
		trace[tr.Step] = tr.Outcome
	}
	if trace["gated"] != pipeline.StepRan || trace["off"] != pipeline.StepSkipped {
		t.Fatalf("trace outcomes = %v, want gated=ran off=skipped", trace)
	}
}

func TestEngineSeamCompileErrorFailsLoad(t *testing.T) {
	eng := pipeline.NewEngine()
	eng.Steps().MustRegister("builtin/noop", pipeline.NoopFactory)
	var e Engine = fakeEngine{}
	eng.Scripts().MustRegister(e.Name(), e.Compile)

	broken := strings.Replace(policyYAML, `when: "yes"`, `when: "boom"`, 1)
	_, err := eng.LoadPolicy([]byte(broken))
	if err == nil || !strings.Contains(err.Error(), "compile when-condition") {
		t.Fatalf("condition compile error must fail the load, got: %v", err)
	}
}
