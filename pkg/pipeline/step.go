package pipeline

import "context"

// Step is one unit of policy work inside a compiled pipeline. Implementations
// live in sibling packages and are built at policy compile time through a
// StepFactory.
//
// Contract for implementations (engine-enforced where marked):
//   - Run must honor ctx cancellation and per-step timeouts: long work must
//     observe ctx and return promptly (ctx.Err() or a wrapped error).
//   - Steps communicate by appending Findings to out and — for decide steps
//     only — by raising out.Verdict. Lowering out.Verdict has no effect
//     (the engine re-applies Max). out.Mutated and out.Trace are
//     engine-owned: steps must never set them.
//   - Mutator steps edit `in` in place (Messages/Body/StreamChunk); all
//     other steps must treat `in` as read-only. Detectors always observe
//     the latest mutated payload.
//   - Run may be invoked concurrently (different Runs work on different
//     payload clones), so implementations must be goroutine-safe and must
//     not carry per-request state on the step value.
//   - Panics are recovered by the engine and recorded as a step error
//     (on_error semantics apply); implementations should still panic only
//     for truly unexpected bugs.
type Step interface {
	// Name returns the implementation name, for diagnostics. The trace key
	// is the compiled step id, not this name.
	Name() string
	Run(ctx context.Context, p *Pipeline, in *Payload, out *Result) error
}

// Detector is a Step that only inspects `in` and appends Findings to out.
// The marker exists for registries and the admin UI; the engine does not
// branch on it during execution — with one exception: every participant of a
// parallel group MUST implement Detector (groups are for read-only
// inspection; enforced at compile time).
type Detector interface {
	Step
	ImplementsDetector()
}

// Mutator is a Step that may rewrite `in` in place. Mutators are rejected in
// parallel groups at compile time (a group must stay read-only) and run in
// declaration order in enforce mode; in shadow mode they run against a
// throwaway clone and their changes are discarded.
type Mutator interface {
	Step
	ImplementsMutator()
}

// DetectorBase is embedded into concrete detector implementations to supply
// the Detector marker.
type DetectorBase struct{}

// ImplementsDetector satisfies the Detector marker; never called.
func (DetectorBase) ImplementsDetector() {}

// MutatorBase is embedded into concrete mutator implementations to supply
// the Mutator marker.
type MutatorBase struct{}

// ImplementsMutator satisfies the Mutator marker; never called.
func (MutatorBase) ImplementsMutator() {}

// Pipeline is the read-only runtime view of the compiled policy a step is
// executing in. Each step invocation receives its own value; implementations
// must not retain it beyond the call.
type Pipeline struct {
	policyName string
	mode       Mode
	stepID     string
	params     map[string]any
}

// PolicyName returns the name of the policy the step belongs to.
func (p *Pipeline) PolicyName() string { return p.policyName }

// Mode returns the policy mode (shadow | enforce).
func (p *Pipeline) Mode() Mode { return p.mode }

// StepID returns the compiled id of the running step (unique per policy).
func (p *Pipeline) StepID() string { return p.stepID }

// Params returns the step's declared params (plus kind-specific reserved
// keys, see StepSpec.Params). The map is shared between runs: read-only by
// contract.
func (p *Pipeline) Params() map[string]any { return p.params }

// Noop is the built-in do-nothing detector step for tests and as a
// placeholder when wiring lanes. It appends no findings and always allows.
type Noop struct {
	DetectorBase
}

// Name returns "builtin/noop".
func (Noop) Name() string { return "builtin/noop" }

// Run does nothing.
func (Noop) Run(context.Context, *Pipeline, *Payload, *Result) error { return nil }

// NoopFactory adapts Noop to StepFactory; register it as "builtin/noop".
func NoopFactory(map[string]any) (Step, error) { return Noop{}, nil }
