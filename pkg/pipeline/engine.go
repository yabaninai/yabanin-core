package pipeline

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sync"
	"time"
)

// stepErrorCategory / stepErrorSeverity are the synthetic finding values
// emitted by on_error: fail_open+flag (see OnError).
const (
	stepErrorCategory = "step_error"
	stepErrorSeverity = "warning"
)

// Engine compiles policies against its registries and executes compiled
// pipelines. It holds no per-request state: Run is safe for concurrent use
// provided registered steps are goroutine-safe (their contract) and the
// registries are not mutated during a run.
type Engine struct {
	stepReg   *Registry
	scriptReg *ScriptRegistry
}

// NewEngine returns an engine with empty step and condition-engine
// registries (implementations are owned by other lanes; register before
// compiling policies that reference them).
func NewEngine() *Engine {
	return &Engine{stepReg: NewRegistry(), scriptReg: NewScriptRegistry()}
}

// Steps exposes the step factory registry. Register factories before
// compiling policies that reference them.
func (e *Engine) Steps() *Registry { return e.stepReg }

// Scripts exposes the condition-engine registry (the OP-7 seam; see
// pkg/pipeline/script).
func (e *Engine) Scripts() *ScriptRegistry { return e.scriptReg }

// LoadPolicy parses strict YAML and compiles it in one step — "policy load"
// in plan terms. Both syntax and resolution errors (unknown step names,
// unregistered condition engines, malformed conditions) surface here, at
// load time, never at request time.
func (e *Engine) LoadPolicy(data []byte) (Compiled, error) {
	p, err := ParsePolicy(data)
	if err != nil {
		return Compiled{}, err
	}
	return e.CompilePolicy(p)
}

// CompilePolicy validates and resolves an already-parsed policy.
func (e *Engine) CompilePolicy(p Policy) (Compiled, error) {
	return Compile(p, e.stepReg, e.scriptReg)
}

// Run executes the given compiled pipelines against in and returns the
// composed Result.
//
// COMPOSITION LAW (owner decision 2026-10-06, plan §2.2 п.0):
//
//  1. The caller pre-filters pipelines by attach and orders them by
//     attachment priority (org → key → model); the engine preserves that
//     order and executes every pipeline it is given.
//  2. Findings union across policies in declaration order; the verdict is
//     the most restrictive action (deny > mask > flag > allow).
//  3. Mutators apply in pipeline order — detectors always observe the
//     latest mutated payload, including across policy boundaries.
//  4. The first deny short-circuits: all remaining steps of the current
//     policy and all remaining policies are traced as skipped.
//  5. Shadow-mode policies run on a throwaway payload clone: they never
//     mutate the carried payload and never raise the composed verdict; their
//     findings ARE recorded. Internally a shadow policy still short-circuits
//     on its own deny so shadow reports mirror what enforce would do.
//  6. The caller's payload is never modified: the engine works on a deep
//     clone; Result.Mutated points at the final clone iff content changed.
//
// STEP SEMANTICS:
//
//   - Steps run linearly; `parallel` groups execute concurrently and join
//     before the next unit starts (a deny found inside a group short-circuits
//     after the join, never mid-flight).
//   - `when` conditions are evaluated before the step; a false condition
//     traces as skipped. A condition evaluation ERROR follows the step's
//     on_error mode.
//   - A per-step timeout bounds Run when configured; expiry traces as
//     outcome timeout and follows on_error.
//   - on_error: fail_closed (default) → verdict deny + short-circuit;
//     fail_open → recorded and ignored; fail_open+flag → recorded plus a
//     synthetic flag finding (Category "step_error", Severity "warning").
//   - Panics in steps are recovered and treated as step errors.
//   - A nil payload is fail-closed: verdict deny, no steps run.
func (e *Engine) Run(ctx context.Context, pipelines []Compiled, in *Payload) *Result {
	// ShadowVerdict starts at allow: Action.Max normalizes unknown values
	// (including the zero "") to deny, so the accumulator must be seeded.
	res := &Result{Verdict: ActionAllow, ShadowVerdict: ActionAllow}
	if in == nil {
		res.Verdict = ActionDeny
		res.Trace = append(res.Trace, StepTrace{Step: "engine", Outcome: StepError, Error: "nil payload"})
		return res
	}

	working := in.Clone()
	for i := range pipelines {
		pl := &pipelines[i]
		if res.Verdict == ActionDeny {
			e.tracePipelineSkipped(res, pl, skipReasonDeny)
			continue
		}
		e.runPipeline(ctx, pl, working, res)
	}
	if !payloadEqual(in, working) {
		res.Mutated = working
	}
	return res
}

// runPipeline executes one compiled policy against the working payload and
// accumulates trace + findings into res. It returns true only when the
// composed verdict reached deny AND the policy is enforce-mode (the only
// case that short-circuits remaining pipelines).
func (e *Engine) runPipeline(ctx context.Context, pl *Compiled, working *Payload, res *Result) bool {
	globalVerdict := res.Verdict
	payload := working
	shadow := pl.Policy.Mode == ModeShadow
	if shadow {
		payload = working.Clone() // shadow never touches the carried payload
	}

	composed := ActionAllow
	denied := false
	for ui := range pl.units {
		u := &pl.units[ui]
		switch {
		case denied:
			e.traceUnitSkipped(res, pl, u, skipReasonDeny)
			continue
		case ctx.Err() != nil:
			e.traceUnitSkipped(res, pl, u, fmt.Sprintf("%s: %v", skipReasonCtx, ctx.Err()))
			continue
		}
		if len(u.members) > 0 {
			composed = composed.Max(e.runGroup(ctx, pl, u, payload, res, composed))
		} else {
			composed = composed.Max(e.runStep(ctx, pl, &pl.steps[u.head], payload, res, composed))
		}
		if composed == ActionDeny {
			denied = true
		}
	}

	if shadow {
		// CORE-TRACE-05: record what this shadow policy WOULD have enforced
		// before restoring the composed verdict — the would-have action must
		// be explicit in the decision log, not inferred from findings (an
		// explicit step verdict raises no finding).
		res.ShadowVerdict = res.ShadowVerdict.Max(composed)
		res.Verdict = globalVerdict // shadow never raises the composed verdict
		return false
	}
	res.Verdict = globalVerdict.Max(composed)
	return composed == ActionDeny
}

// runGroup runs a head step and its parallel members concurrently, each with
// its own scratch Result (steps only append findings and raise verdicts, so
// a deterministic merge is semantically identical to shared state and
// race-free). Trace and findings merge in declaration order after the join.
func (e *Engine) runGroup(ctx context.Context, pl *Compiled, u *unit, payload *Payload, res *Result, composed Action) Action {
	idxs := make([]int, 0, 1+len(u.members))
	idxs = append(idxs, u.head)
	idxs = append(idxs, u.members...)

	scratches := make([]*Result, len(idxs))
	for i := range idxs {
		scratches[i] = &Result{Verdict: res.Verdict.Max(composed)}
	}

	var wg sync.WaitGroup
	for i, si := range idxs {
		wg.Go(func() {
			e.runStep(ctx, pl, &pl.steps[si], payload, scratches[i], composed)
		})
	}
	wg.Wait()

	for i := range idxs {
		sc := scratches[i]
		res.Findings = append(res.Findings, sc.Findings...)
		res.Trace = append(res.Trace, sc.Trace...)
		composed = composed.Max(sc.Verdict)
		for _, f := range sc.Findings {
			composed = composed.Max(f.Action)
		}
	}
	return composed
}

// runStep executes one step with condition evaluation, timeout bounding,
// panic recovery, on_error handling and trace recording. It returns the
// updated composed verdict for the current policy.
func (e *Engine) runStep(ctx context.Context, pl *Compiled, cs *compiledStep, payload *Payload, out *Result, composed Action) Action {
	start := time.Now()
	pv := &Pipeline{policyName: pl.Policy.Name, mode: pl.Policy.Mode, stepID: cs.spec.ID, params: cs.params}

	if cs.when != nil {
		env := ConditionEnv{
			Findings: slices.Clone(out.Findings),
			Steps:    slices.Clone(out.Trace),
			Meta:     payload.Meta,
		}
		ok, err := (Evaluator{}).EvaluateCondition(ctx, cs.when, env)
		if err != nil {
			return e.stepFailed(cs, out, composed, start, StepError, fmt.Sprintf("when: %v", err))
		}
		if !ok {
			return finishTrace(out, cs.spec.ID, start, StepSkipped, "", composed)
		}
	}

	stepCtx := ctx
	if cs.dur > 0 {
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithTimeout(ctx, cs.dur)
		defer cancel()
	}

	out.Verdict = out.Verdict.Max(composed) // baseline: a step may only raise
	before := len(out.Findings)
	err := e.invoke(stepCtx, pv, cs, payload, out)

	var outcome StepOutcome
	var errMsg string
	switch {
	case err != nil && stepCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil:
		outcome = StepTimeout
		errMsg = err.Error()
	case err != nil:
		outcome = StepError
		errMsg = err.Error()
	default:
		if stepCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
			return e.stepFailed(cs, out, composed, start, StepTimeout, context.DeadlineExceeded.Error())
		}
		contribution := composed.Max(out.Verdict)
		for _, f := range out.Findings[before:] {
			contribution = contribution.Max(f.Action)
		}
		return finishTrace(out, cs.spec.ID, start, StepRan, "", contribution)
	}
	return e.stepFailed(cs, out, composed, start, outcome, errMsg)
}

// invoke runs the step with panic recovery: a panicking builtin must degrade
// to a recorded step error, never take down the gateway.
func (e *Engine) invoke(ctx context.Context, pv *Pipeline, cs *compiledStep, payload *Payload, out *Result) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in step: %v", r)
		}
	}()
	return cs.step.Run(ctx, pv, payload, out)
}

// stepFailed applies on_error semantics and records the trace. fail_closed
// (the default) contributes deny; the other modes continue with the verdict
// they came in with, fail_open+flag adding the synthetic flag finding.
func (e *Engine) stepFailed(cs *compiledStep, out *Result, composed Action, start time.Time, outcome StepOutcome, errMsg string) Action {
	switch cs.spec.OnError {
	case OnErrorFailOpen:
		// recorded and ignored
	case OnErrorFailOpenFlag:
		out.Findings = append(out.Findings, Finding{
			Step:     cs.spec.ID,
			Category: stepErrorCategory,
			Severity: stepErrorSeverity,
			Evidence: errMsg,
			Action:   ActionFlag,
		})
		composed = composed.Max(ActionFlag)
	default: // OnErrorFailClosed
		finishTrace(out, cs.spec.ID, start, outcome, errMsg, ActionDeny)
		return ActionDeny
	}
	return finishTrace(out, cs.spec.ID, start, outcome, errMsg, composed)
}

// finishTrace appends the step trace and returns the given verdict
// contribution.
func finishTrace(out *Result, stepID string, start time.Time, outcome StepOutcome, errMsg string, contribution Action) Action {
	out.Trace = append(out.Trace, StepTrace{
		Step:     stepID,
		Duration: time.Since(start),
		Outcome:  outcome,
		Error:    errMsg,
	})
	return contribution
}

// traceUnitSkipped records skipped traces for a whole unit (head + parallel
// members, declaration order) — used for deny short-circuits and
// pre-cancelled contexts.
func (e *Engine) traceUnitSkipped(res *Result, pl *Compiled, u *unit, reason string) {
	idxs := append([]int{u.head}, u.members...) //nolint:gocritic // append to fresh literal; no aliasing
	for _, si := range idxs {
		res.Trace = append(res.Trace, StepTrace{Step: pl.steps[si].spec.ID, Outcome: StepSkipped, Error: reason})
	}
}

// tracePipelineSkipped records skipped traces for every step of a pipeline
// that was never run because an earlier policy denied.
func (e *Engine) tracePipelineSkipped(res *Result, pl *Compiled, reason string) {
	for ui := range pl.units {
		e.traceUnitSkipped(res, pl, &pl.units[ui], reason)
	}
}

// payloadEqual reports content equality of two payloads (deep for Messages,
// Body and Meta). Used to decide whether Result.Mutated is non-nil.
func payloadEqual(a, b *Payload) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Kind != b.Kind || a.Endpoint != b.Endpoint || a.StreamChunk != b.StreamChunk {
		return false
	}
	if string(a.Body) != string(b.Body) {
		return false
	}
	if len(a.Messages) != len(b.Messages) {
		return false
	}
	for i := range a.Messages {
		if a.Messages[i] != b.Messages[i] {
			return false
		}
	}
	if (a.Meta == nil) != (b.Meta == nil) {
		return false
	}
	if a.Meta != nil && !reflect.DeepEqual(a.Meta, b.Meta) {
		return false
	}
	// nil and empty Headers are equivalent: a mutator materializing an empty
	// map has not changed upstream-visible content.
	return maps.Equal(a.Headers, b.Headers)
}
