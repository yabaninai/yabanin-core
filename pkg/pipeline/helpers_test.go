package pipeline

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// --- fake condition engine ------------------------------------------------

// testEngine is a minimal condition engine for tests: source "true" and
// "false" evaluate to their literal; anything else is a compile error.
// Source "ERR" compiles but fails evaluation.
type testEngine struct {
	mu      sync.Mutex
	evaled  []string
	engName string
}

func newTestEngine() *testEngine { return &testEngine{engName: "test"} }

func (e *testEngine) Name() string { return e.engName }

func (e *testEngine) Compile(source string) (ConditionProgram, error) {
	switch source {
	case "true", "false", "ERR":
		return &testProgram{src: source, eng: e}, nil
	default:
		return nil, fmt.Errorf("cannot compile condition %q", source)
	}
}

type testProgram struct {
	src string
	eng *testEngine
}

func (p *testProgram) Evaluate(_ context.Context, env ConditionEnv) (bool, error) {
	p.eng.mu.Lock()
	p.eng.evaled = append(p.eng.evaled, p.src)
	p.eng.mu.Unlock()
	_ = env
	switch p.src {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("eval failed")
	}
}

// --- fake steps ------------------------------------------------------------

// mutatorStep appends a marker to Body (or sets "M" when empty).
type mutatorStep struct {
	MutatorBase
	marker string
}

func (m *mutatorStep) Name() string { return "test/mutator" }

func (m *mutatorStep) Run(_ context.Context, _ *Pipeline, in *Payload, _ *Result) error {
	marker := m.marker
	if marker == "" {
		marker = "M"
	}
	in.Body = append(in.Body, marker...)
	return nil
}

// fnStep is a generic Detector wired to an arbitrary function.
type fnStep struct {
	DetectorBase
	name string
	fn   func(ctx context.Context, p *Pipeline, in *Payload, out *Result) error
}

func (f *fnStep) Name() string { return f.name }

func (f *fnStep) Run(ctx context.Context, p *Pipeline, in *Payload, out *Result) error {
	return f.fn(ctx, p, in, out)
}

// detector returns a step appending one finding with the given action.
func detector(id string, action Action) *fnStep {
	return &fnStep{name: id, fn: func(_ context.Context, _ *Pipeline, _ *Payload, out *Result) error {
		out.Findings = append(out.Findings, Finding{
			Step: id, Category: "test", Severity: "high", Evidence: id, Action: action,
		})
		return nil
	}}
}

// bodyRecorder records the Body each run of the step sees (mutation-order
// and detector-sees-latest proofs). Safe for concurrent runs.
type bodyRecorder struct {
	DetectorBase
	mu   sync.Mutex
	seen []string
}

func (b *bodyRecorder) Name() string { return "test/recorder" }

func (b *bodyRecorder) Run(_ context.Context, _ *Pipeline, in *Payload, _ *Result) error {
	b.mu.Lock()
	b.seen = append(b.seen, string(in.Body))
	b.mu.Unlock()
	return nil
}

func (b *bodyRecorder) bodies() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.seen...)
}

// sleeper sleeps for d honoring ctx, then appends a flag finding.
type sleeper struct {
	DetectorBase
	id string
	d  time.Duration
}

func (s *sleeper) Name() string { return "test/sleep" }

func (s *sleeper) Run(ctx context.Context, _ *Pipeline, _ *Payload, out *Result) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(s.d):
	}
	out.Findings = append(out.Findings, Finding{Step: s.id, Category: "test", Action: ActionFlag})
	return nil
}

// errorStep returns an error on every run.
type errorStep struct {
	DetectorBase
}

func (errorStep) Name() string { return "test/error" }

func (errorStep) Run(context.Context, *Pipeline, *Payload, *Result) error {
	return fmt.Errorf("detector exploded")
}

// panicStep panics on every run.
type panicStep struct {
	DetectorBase
}

func (panicStep) Name() string { return "test/panic" }

func (panicStep) Run(context.Context, *Pipeline, *Payload, *Result) error {
	panic("boom")
}

// verdictStep raises the verdict explicitly (decide-step semantics).
type verdictStep struct {
	DetectorBase
	action Action
}

func (v *verdictStep) Name() string { return "test/verdict" }

func (v *verdictStep) Run(_ context.Context, _ *Pipeline, _ *Payload, out *Result) error {
	out.Verdict = v.action
	return nil
}

// registryFor wires test steps by name into a fresh engine. Defaults:
// builtin/noop (NoopFactory) and test/mutator (fresh mutatorStep per build).
func registryFor(steps map[string]Step) *Engine {
	eng := NewEngine()
	eng.Steps().MustRegister("builtin/noop", NoopFactory)
	eng.Steps().MustRegister("test/mutator", func(map[string]any) (Step, error) { return &mutatorStep{}, nil })
	for name, st := range steps {
		eng.Steps().MustRegister(name, func(map[string]any) (Step, error) { return st, nil })
	}
	return eng
}

// policyOf builds a minimal valid policy from specs.
func policyOf(mode Mode, specs ...StepSpec) Policy {
	return Policy{
		APIVersion: APIVersionYPP,
		Kind:       KindPolicy,
		Name:       "test-policy",
		Mode:       mode,
		Hooks:      []Hook{HookPreUpstream},
		Steps:      specs,
	}
}

// mustCompileOf compiles a policy against an engine wired with the given
// named step instances.
func mustCompileOf(t *testing.T, eng *Engine, p Policy) Compiled {
	t.Helper()
	c, err := eng.CompilePolicy(p)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	return c
}

// runPipelines executes pipelines against a chat payload.
func runPipelines(t *testing.T, eng *Engine, pipelines []Compiled, in *Payload) *Result {
	t.Helper()
	return eng.Run(context.Background(), pipelines, in)
}

// clock records monotonic nanos at run start and finish (join-order proofs).
type clock struct {
	DetectorBase
	id     string
	startN *syncMapInt64
	endN   *syncMapInt64
}

func (c *clock) Name() string { return "test/clock" }

func (c *clock) Run(_ context.Context, _ *Pipeline, _ *Payload, _ *Result) error {
	c.startN.Set(c.id, time.Now().UnixNano())
	time.Sleep(5 * time.Millisecond)
	c.endN.Set(c.id, time.Now().UnixNano())
	return nil
}

// syncMapInt64 is a tiny concurrent int64 map for test observations.
type syncMapInt64 struct {
	mu sync.Mutex
	m  map[string]int64
}

func newSyncMapInt64() *syncMapInt64 { return &syncMapInt64{m: map[string]int64{}} }

func (s *syncMapInt64) Set(k string, v int64) {
	s.mu.Lock()
	s.m[k] = v
	s.mu.Unlock()
}

func (s *syncMapInt64) Get(k string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k]
}

// chatPayload returns a minimal request payload.
func chatPayload() *Payload {
	return &Payload{
		Kind:     KindRequest,
		Endpoint: "chat",
		Messages: []Message{{Role: "user", Content: "hello"}},
		Body:     []byte(`{"model":"m"}`),
		Meta:     &RequestMeta{Org: "org-a", Key: "key-1", Model: "gpt-x", Provider: "openai"},
	}
}

// traceOf returns the trace entry for step id (must exist exactly once).
func traceOf(t *testing.T, res *Result, id string) StepTrace {
	t.Helper()
	found := -1
	for i, tr := range res.Trace {
		if tr.Step == id {
			if found >= 0 {
				t.Fatalf("step %q traced twice", id)
			}
			found = i
		}
	}
	if found < 0 {
		t.Fatalf("step %q missing from trace: %+v", id, res.Trace)
	}
	return res.Trace[found]
}

// assertTraceComplete asserts every compiled step of every passed pipeline
// appears in the trace exactly once, with no foreign entries.
func assertTraceComplete(t *testing.T, res *Result, pipelines ...Compiled) {
	t.Helper()
	want := make(map[string]int)
	for _, pl := range pipelines {
		for _, id := range pl.StepIDs() {
			want[id]++
		}
	}
	got := make(map[string]int)
	for _, tr := range res.Trace {
		got[tr.Step]++
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("step %q traced %d times, want %d", id, got[id], n)
		}
	}
	for id := range got {
		if want[id] == 0 {
			t.Errorf("unexpected trace entry %q", id)
		}
	}
}
