package pipeline

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"
)

// ParsePolicy decodes one strict YAML policy document: unknown fields — at
// the document, step or llm_judge level — are load errors, so a typo can
// never silently drop a rule. An empty document is an error.
func ParsePolicy(data []byte) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return Policy{}, fmt.Errorf("policy document is empty")
		}
		return Policy{}, fmt.Errorf("parse policy yaml: %w", err)
	}
	for {
		var trailing any
		if err := dec.Decode(&trailing); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return Policy{}, fmt.Errorf("parse policy yaml: %w", err)
		}
		if trailing != nil {
			return Policy{}, fmt.Errorf("policy document must contain only one YAML document")
		}
	}
	return p, nil
}

// Compile validates p and resolves it against steps (step factories) and
// scripts (condition engines) into a runnable pipeline. Unknown step or
// engine names fail with the sorted list of available registrations. Steps
// are built once per compile through their factories; the returned Compiled
// value is reusable and safe for concurrent Run invocations provided the
// produced steps are goroutine-safe (their contract).
func Compile(p Policy, steps *Registry, scripts *ScriptRegistry) (Compiled, error) {
	if steps == nil {
		steps = NewRegistry()
	}
	if scripts == nil {
		scripts = NewScriptRegistry()
	}
	if err := p.Validate(); err != nil {
		return Compiled{}, err
	}

	compiled := Compiled{Policy: p}
	compiled.steps = make([]compiledStep, len(p.Steps))
	for i := range p.Steps {
		cs, err := compileStep(&p.Steps[i], steps, scripts)
		if err != nil {
			return Compiled{}, err
		}
		compiled.steps[i] = cs
	}

	units, err := buildUnits(p, compiled.steps)
	if err != nil {
		return Compiled{}, err
	}
	compiled.units = units
	return compiled, nil
}

// compileStep normalizes one step spec: default on_error, parse timeout,
// merge reserved kind params, look up the factory, build the Step and
// compile the `when` condition through the script registry.
func compileStep(spec *StepSpec, steps *Registry, scripts *ScriptRegistry) (compiledStep, error) {
	cs := compiledStep{spec: *spec}
	if cs.spec.OnError == "" {
		cs.spec.OnError = OnErrorFailClosed
	}
	if spec.Timeout != "" {
		d, err := time.ParseDuration(spec.Timeout)
		if err != nil {
			return compiledStep{}, fmt.Errorf("step %q: invalid timeout %q: %w", spec.ID, spec.Timeout, err)
		}
		cs.dur = d
	}

	rk, err := spec.resolveKind()
	if err != nil {
		return compiledStep{}, fmt.Errorf("step %q: %w", spec.ID, err)
	}
	cs.params, err = mergeParams(spec, rk)
	if err != nil {
		return compiledStep{}, fmt.Errorf("step %q: %w", spec.ID, err)
	}

	factory, ok := steps.Factory(rk.registry)
	if !ok {
		return compiledStep{}, fmt.Errorf("step %q (%s kind): unknown step name %q (available: %s)",
			spec.ID, rk.kind, rk.registry, availableNames(steps.Names()))
	}
	st, err := factory(cs.params)
	if err != nil {
		return compiledStep{}, fmt.Errorf("step %q: build %s step: %w", spec.ID, rk.kind, err)
	}
	cs.step = st

	if spec.When != "" {
		prog, err := compileWhen(spec, scripts)
		if err != nil {
			return compiledStep{}, err
		}
		cs.when = prog
	}
	return cs, nil
}

// mergeParams merges the kind-reserved params into the step's declared
// params. A collision is a compile error: silent overrides would make the
// YAML lie about what runs.
func mergeParams(spec *StepSpec, rk resolvedKind) (map[string]any, error) {
	if len(rk.extra) == 0 {
		return spec.Params, nil
	}
	merged := make(map[string]any, len(spec.Params)+len(rk.extra))
	for k, v := range spec.Params {
		merged[k] = v
	}
	for k, v := range rk.extra {
		if _, exists := spec.Params[k]; exists {
			return nil, fmt.Errorf("params.%s collides with the reserved key of the %s kind", k, rk.kind)
		}
		merged[k] = v
	}
	return merged, nil
}

// compileWhen resolves the condition engine for spec.When and compiles the
// source once. With exactly one engine registered it is the default; with
// none, or with several and no explicit when_engine, loading fails with a
// message that names the fix (plan §2.2 п.2).
func compileWhen(spec *StepSpec, scripts *ScriptRegistry) (ConditionProgram, error) {
	engine := spec.WhenEngine
	switch {
	case engine != "":
		// pinned explicitly below
	case scripts.Len() == 1:
		engine = scripts.Names()[0]
	case scripts.Len() == 0:
		return nil, fmt.Errorf("step %q: when-condition set but no condition engine is registered; register one via Engine.Scripts().Register (see pkg/pipeline/script)", spec.ID)
	default:
		return nil, fmt.Errorf("step %q: when_engine is required when %d condition engines are registered (available: %s)",
			spec.ID, scripts.Len(), availableNames(scripts.Names()))
	}
	compiler, ok := scripts.Compiler(engine)
	if !ok {
		return nil, fmt.Errorf("step %q: condition engine %q is not registered (available: %s)",
			spec.ID, engine, availableNames(scripts.Names()))
	}
	prog, err := compiler(spec.When)
	if err != nil {
		return nil, fmt.Errorf("step %q: compile when-condition: %w", spec.ID, err)
	}
	return prog, nil
}

// availableNames renders registration names for error messages; empty means
// "none (register …)" so the fix is actionable.
func availableNames(names []string) string {
	if len(names) == 0 {
		return "none (register on the Engine before compiling)"
	}
	return joinComma(names)
}

// buildUnits groups compiled steps into scheduling units: linear steps are
// single-step units; a step with a parallel list heads a join group with its
// members (indexes preserved in declaration order). It also enforces the
// Detector-only rule for group participants — the step instances exist by
// now, so the type assertions are exact.
func buildUnits(p Policy, steps []compiledStep) ([]unit, error) {
	index := make(map[string]int, len(steps))
	for i := range steps {
		index[steps[i].spec.ID] = i
	}
	memberOf := make(map[string]string, len(steps)) // member id -> head id
	participant := make(map[string]bool, len(steps))

	for i := range p.Steps {
		spec := &p.Steps[i]
		if len(spec.Parallel) == 0 {
			continue
		}
		participant[spec.ID] = true
		for _, m := range spec.Parallel {
			memberOf[m] = spec.ID
			participant[m] = true
		}
	}

	for i := range steps {
		if !participant[steps[i].spec.ID] {
			continue
		}
		if _, isDetector := steps[i].step.(Detector); !isDetector {
			return nil, fmt.Errorf("step %q: parallel group participants must be read-only Detector steps; got %T", steps[i].spec.ID, steps[i].step)
		}
	}

	units := make([]unit, 0, len(steps))
	for i := range p.Steps {
		spec := &p.Steps[i]
		if memberOf[spec.ID] != "" {
			continue // a parallel member: scheduled inside its head's group
		}
		u := unit{head: i}
		for _, m := range spec.Parallel {
			u.members = append(u.members, index[m])
		}
		units = append(units, u)
	}
	return units, nil
}

// compiledStep is one normalized, resolved step: the spec with defaults
// applied, the parsed timeout, merged params, the built Step instance and
// the compiled condition (nil when unconditional).
type compiledStep struct {
	spec   StepSpec
	dur    time.Duration
	params map[string]any
	when   ConditionProgram
	step   Step
}

// unit is one scheduling slice of a compiled policy: a linear step when
// members is empty, otherwise head + members execute concurrently as one
// join group (members in declaration order).
type unit struct {
	head    int
	members []int
}

// Compiled is a validated, resolved, runnable policy produced by Compile.
// It is immutable after construction and safe for concurrent Engine.Run
// invocations provided its steps are goroutine-safe.
type Compiled struct {
	// Policy is the normalized policy the pipeline was compiled from.
	Policy Policy
	steps  []compiledStep
	units  []unit
}

// StepIDs returns the ids of all compiled steps in declaration order —
// parallel members included. Used by decision tooling (OP-9) and tests to
// verify trace completeness.
func (c Compiled) StepIDs() []string {
	ids := make([]string, 0, len(c.steps))
	for i := range c.steps {
		ids = append(ids, c.steps[i].spec.ID)
	}
	return ids
}

// The engine never truncates a trace: skip reasons are recorded on the
// skipped steps themselves.
var (
	skipReasonDeny = "short-circuited after deny"
	skipReasonCtx  = "caller context cancelled before step"
)
