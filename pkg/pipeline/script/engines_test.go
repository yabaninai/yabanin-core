package script_test

// Cross-engine OP-7 contract tests: all three condition engines (lua,
// starlark, expr) must behave identically through the pipeline seam —
// registration, compile-once policy load, when_engine resolution rules, and
// real Engine.Run branching (skip/deny/error scenarios).

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/script"
	"github.com/reireirei/yabanin/pkg/pipeline/script/expr"
	"github.com/reireirei/yabanin/pkg/pipeline/script/lua"
	"github.com/reireirei/yabanin/pkg/pipeline/script/starlark"
)

// enginesUnderTest maps registry names to factories. Adding an engine here
// automatically extends every contract test below.
var enginesUnderTest = map[string]func() script.Engine{
	// W-VER-style flake fix: the default 5ms wall-clock Lua budget is
	// load-sensitive (no debug hooks — F1 in the OP-7 decision doc);
	// under full-suite contention a legit evaluation can exceed it.
	// This test asserts concurrency safety, not budget enforcement —
	// give it a generous budget; the budget itself has a dedicated test.
	"lua":      func() script.Engine { return lua.New(lua.WithEvalTimeout(2 * time.Second)) },
	"starlark": func() script.Engine { return starlark.New() },
	"expr":     func() script.Engine { return expr.New() },
}

// trueCondition/falseCondition express "any high-severity finding" and its
// negation in each engine's dialect (see the env contract in script/env.go).
// badCondition compiles but errors at evaluation time (fail-closed path);
// brokenCondition fails compilation (policy load error).
var (
	trueCondition   = map[string]string{}
	falseCondition  = map[string]string{}
	badCondition    = map[string]string{}
	brokenCondition = map[string]string{}
)

func init() {
	trueCondition["lua"] = `findings.any(function(f) return f.severity == 'high' end)`
	trueCondition["starlark"] = `findings.any(lambda f: f.severity == 'high')`
	trueCondition["expr"] = `any(Findings, #.Severity == 'high')`

	falseCondition["lua"] = `findings.none(function(f) return f.severity == 'high' end)`
	falseCondition["starlark"] = `findings.none(lambda f: f.severity == 'high')`
	falseCondition["expr"] = `not any(Findings, #.Severity == 'high')`

	badCondition["lua"] = `return undefined_global()`
	badCondition["starlark"] = `1 // 0 == 0`
	badCondition["expr"] = `StepDurationMs('absent') < 40`

	brokenCondition["lua"] = `return (`
	brokenCondition["starlark"] = `)`
	brokenCondition["expr"] = `NoSuchIdentifier == 1`
}

// findingEmitter is a test detector that records one fixed finding, so the
// conditions have something to observe in Engine.Run. The action is flag so
// the pipeline continues past it (a deny would short-circuit the run).
type findingEmitter struct {
	finding pipeline.Finding
}

func (findingEmitter) Name() string        { return "test/emit" }
func (findingEmitter) ImplementsDetector() {}

func (s findingEmitter) Run(_ context.Context, _ *pipeline.Pipeline, _ *pipeline.Payload, out *pipeline.Result) error {
	out.Findings = append(out.Findings, s.finding)
	return nil
}

func emitFactory(f pipeline.Finding) pipeline.StepFactory {
	return func(map[string]any) (pipeline.Step, error) { return findingEmitter{finding: f}, nil }
}

// gatedPolicy: step emit records a high finding; gated_step runs only when
// the condition sees it; silent_step sees none and must skip on false.
const gatedPolicy = `
apiVersion: ypp/v1
kind: Policy
name: op7-contract
mode: enforce
hooks: [pre_upstream]
steps:
  - id: emit
    detector: test/emit-high
  - id: gated_step
    detector: builtin/noop
    when: "%TRUE%"
    when_engine: %ENGINE%
  - id: silent_step
    detector: builtin/noop
    when: "%FALSE%"
    when_engine: %ENGINE%
`

func TestEnginesContractThroughPipeline(t *testing.T) {
	for name, factory := range enginesUnderTest {
		t.Run(name, func(t *testing.T) {
			eng := pipeline.NewEngine()
			eng.Steps().MustRegister("builtin/noop", pipeline.NoopFactory)
			eng.Steps().MustRegister("test/emit-high", emitFactory(pipeline.Finding{
				Step: "emit", Category: "innsnils", Severity: "high", Action: pipeline.ActionFlag,
			}))

			// 1. Unregistered when_engine is a policy LOAD error, never a skip.
			policyYAML := strings.NewReplacer("%TRUE%", trueCondition[name], "%FALSE%", falseCondition[name], "%ENGINE%", name).Replace(gatedPolicy)
			if _, err := eng.LoadPolicy([]byte(policyYAML)); err == nil {
				t.Fatal("unregistered condition engine must fail policy load")
			} else if !strings.Contains(err.Error(), `condition engine "`+name+`" is not registered`) {
				t.Fatalf("unhelpful load error: %v", err)
			}

			// 2. Register (script.Engine → ConditionCompiler) and load once.
			e := factory()
			if e.Name() != name {
				t.Fatalf("engine name = %q, want %q", e.Name(), name)
			}
			eng.Scripts().MustRegister(e.Name(), e.Compile)

			compiled, err := eng.LoadPolicy([]byte(policyYAML))
			if err != nil {
				t.Fatalf("load: %v", err)
			}

			// 3. Engine.Run branches: gated_step ran, silent_step skipped.
			res := eng.Run(context.Background(), []pipeline.Compiled{compiled}, &pipeline.Payload{Kind: pipeline.KindRequest})
			outcomes := map[string]pipeline.StepOutcome{}
			for _, tr := range res.Trace {
				outcomes[tr.Step] = tr.Outcome
			}
			if outcomes["gated_step"] != pipeline.StepRan {
				t.Errorf("gated_step outcome = %v, want ran", outcomes["gated_step"])
			}
			if outcomes["silent_step"] != pipeline.StepSkipped {
				t.Errorf("silent_step outcome = %v, want skipped", outcomes["silent_step"])
			}
			if res.Verdict != pipeline.ActionFlag {
				t.Errorf("verdict = %v, want flag (emitter finding is flag)", res.Verdict)
			}

			// 4. Compile error in a condition fails the policy load.
			broken := strings.NewReplacer("%TRUE%", brokenCondition[name], "%FALSE%", falseCondition[name], "%ENGINE%", name).Replace(gatedPolicy)
			if _, err := eng.LoadPolicy([]byte(broken)); err == nil {
				t.Error("broken condition must fail policy load")
			}
		})
	}
}

// TestEnginesEvalErrorFailsClosed: a condition that errors at evaluation
// time must fail the step closed (default on_error): deny + error outcome.
func TestEnginesEvalErrorFailsClosed(t *testing.T) {
	for name, factory := range enginesUnderTest {
		t.Run(name, func(t *testing.T) {
			eng := pipeline.NewEngine()
			eng.Steps().MustRegister("builtin/noop", pipeline.NoopFactory)
			e := factory()
			eng.Scripts().MustRegister(e.Name(), e.Compile)

			// badCondition compiles but errors at evaluation time.
			policyYAML := `
apiVersion: ypp/v1
kind: Policy
name: op7-fail-closed
mode: enforce
hooks: [pre_upstream]
steps:
  - id: gated
    detector: builtin/noop
    when: "` + badCondition[name] + `"
`
			compiled, err := eng.LoadPolicy([]byte(policyYAML))
			if err != nil {
				t.Fatalf("runtime-error condition must load (error surfaces at eval): %v", err)
			}
			res := eng.Run(context.Background(), []pipeline.Compiled{compiled}, &pipeline.Payload{Kind: pipeline.KindRequest})
			if res.Verdict != pipeline.ActionDeny {
				t.Errorf("verdict = %v, want deny (fail_closed on_error)", res.Verdict)
			}
			var gated *pipeline.StepTrace
			for i := range res.Trace {
				if res.Trace[i].Step == "gated" {
					gated = &res.Trace[i]
				}
			}
			if gated == nil {
				t.Fatal("gated step missing from trace")
			}
			if gated.Outcome != pipeline.StepError {
				t.Errorf("outcome = %v, want error", gated.Outcome)
			}
			if !strings.HasPrefix(gated.Error, "when:") {
				t.Errorf("error = %q, want when: prefix", gated.Error)
			}
		})
	}
}

// TestMultipleEnginesRequireWhenEngine: with three engines registered, a
// when-condition without when_engine is a load error listing the options.
func TestMultipleEnginesRequireWhenEngine(t *testing.T) {
	eng := pipeline.NewEngine()
	eng.Steps().MustRegister("builtin/noop", pipeline.NoopFactory)
	for _, factory := range enginesUnderTest {
		e := factory()
		eng.Scripts().MustRegister(e.Name(), e.Compile)
	}
	policyYAML := `
apiVersion: ypp/v1
kind: Policy
name: op7-ambiguous
mode: enforce
hooks: [pre_upstream]
steps:
  - id: gated
    detector: builtin/noop
    when: "true"
`
	_, err := eng.LoadPolicy([]byte(policyYAML))
	if err == nil {
		t.Fatal("when_engine required when multiple engines are registered")
	}
	if !strings.Contains(err.Error(), "when_engine is required") {
		t.Fatalf("unhelpful ambiguity error: %v", err)
	}
}

// TestCompileOnceCacheConsistency: compiling the same source twice yields
// programs with identical behavior (cache hit path).
func TestCompileOnceCacheConsistency(t *testing.T) {
	for name, factory := range enginesUnderTest {
		t.Run(name, func(t *testing.T) {
			e := factory()
			env := pipeline.ConditionEnv{
				Findings: []pipeline.Finding{{Step: "s", Category: "c", Severity: "high", Action: pipeline.ActionDeny}},
				Meta:     &pipeline.RequestMeta{Org: "org-a"},
			}
			src := trueCondition[name]
			p1, err := e.Compile(src)
			if err != nil {
				t.Fatalf("first compile: %v", err)
			}
			p2, err := e.Compile(src)
			if err != nil {
				t.Fatalf("second compile: %v", err)
			}
			for i, p := range []pipeline.ConditionProgram{p1, p2} {
				got, err := p.Evaluate(context.Background(), env)
				if err != nil {
					t.Fatalf("program %d: %v", i, err)
				}
				if !got {
					t.Errorf("program %d: got false, want true", i)
				}
			}
		})
	}
}

// TestCompileAndEvaluateConcurrency: Compile and Evaluate from many
// goroutines at once must be race-free and consistent.
func TestCompileAndEvaluateConcurrency(t *testing.T) {
	for name, factory := range enginesUnderTest {
		t.Run(name, func(t *testing.T) {
			e := factory()
			env := pipeline.ConditionEnv{
				Findings: []pipeline.Finding{{Step: "s", Category: "c", Severity: "high", Action: pipeline.ActionDeny}},
			}
			var wg sync.WaitGroup
			for g := 0; g < 8; g++ {
				wg.Go(func() {
					for i := 0; i < 25; i++ {
						prog, err := e.Compile(trueCondition[name])
						if err != nil {
							t.Errorf("compile: %v", err)
							return
						}
						got, err := prog.Evaluate(context.Background(), env)
						if err != nil {
							t.Errorf("evaluate: %v", err)
							return
						}
						if !got {
							t.Error("inconsistent result")
							return
						}
					}
				})
			}
			wg.Wait()
		})
	}
}
