// Package starlark is the OP-7 Starlark condition engine (challenger #1):
// go.starlark.net, the Bazel configuration language, in expression mode.
//
// SANDBOX MODEL:
//
//   - The `when` source is wrapped as `def __condition__(findings, steps,
//     meta): return (SOURCE)` — an expression, so `while` statements and
//     named recursive functions are structurally impossible (the resolver
//     additionally runs with While=false, TopLevelControl=false,
//     Recursion=false, GlobalReassign=false). The only loop form is a
//     comprehension, which is bounded natively by the execution-step budget.
//   - Thread.SetMaxExecutionSteps provides a TRUE instruction-level budget
//     (deterministic, like the Lua engine's dispatch budget): every
//     operation counts, comprehension iterations included. A wall-clock
//     watchdog (thread.Cancel) backs up the step budget for single huge
//     operations such as `"a" * 10**9`, which complete in one step; New
//     scales it by raceWallScale on -race builds (see race_on.go) so race
//     instrumentation and runner load cannot abort legitimate evaluations.
//     KNOWN GAP for the owner decision: starlark-go has no per-value memory
//     cap either — one step can transiently allocate at operand size before
//     cancellation lands; the watchdog bounds the time, not the peak.
//   - The predeclared environment is empty apart from the three condition
//     roots (findings, steps, meta — contract in the parent package); the
//     Starlark universe is pure (no I/O, time, randomness). thread.Print is
//     a no-op. Env values are frozen, so conditions cannot mutate the
//     snapshot.
//   - The result must be a Starlark bool; anything else is an evaluation
//     error, so a condition can never fail open.
//
// Compilation (parse + resolve) happens once per source (sha256-keyed cache
// of the *starlark.Program); evaluation initializes a fresh module per call.
// Programs are immutable and safe for concurrent Evaluate through separate
// threads.
package starlark

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/script"
)

// Sandbox defaults. A typical condition consumes tens of steps and
// microseconds; budgets are ceilings (see bench_test.go in the parent).
const (
	maxConditionSourceBytes = 16 << 10
	maxEnvItems             = 4096
	maxEnvBytes             = 1 << 20
	// DefaultStepLimit bounds Starlark operations per evaluation.
	DefaultStepLimit = 100_000
	// DefaultEvalTimeout is the wall-clock watchdog backing up the step
	// budget for single huge operations that bypass per-step accounting.
	// New scales it by raceWallScale on -race builds (load tolerance, not
	// semantics); the step budget needs no scaling — step counts do not
	// depend on machine speed.
	DefaultEvalTimeout = 25 * time.Millisecond
	// raceWallScale is applied to the wall watchdog on -race builds only.
	raceWallScale = 10
	// cacheLimit caps the compiled-program cache (spike-simple FIFO reset).
	cacheLimit = 1024
)

// Engine compiles Starlark condition sources. Create with New, then register
// under Name ("starlark") on pipeline.Engine.Scripts.
type Engine struct {
	stepLimit   uint64
	evalTimeout time.Duration
	evalSlots   chan struct{}

	mu    sync.Mutex
	cache map[[sha256.Size]byte]*starlark.Program

	// evalProbe is a test-only hook (FIX-13): when non-nil it is invoked
	// synchronously while the evaluation slot is held — once with
	// probeAcquired right after acquisition and once with probeReleased just
	// before release. Production code never sets it; tests use it to make
	// concurrency-limit assertions event-driven instead of sampling
	// len(evalSlots). Not part of the exported surface.
	evalProbe func(evalProbeEvent)
}

// evalProbeEvent distinguishes the two slot-observation points reported to
// the test-only evalProbe hook.
type evalProbeEvent int

const (
	// probeAcquired is reported right after an evaluation slot is acquired.
	probeAcquired evalProbeEvent = iota
	// probeReleased is reported just before an evaluation slot is returned.
	probeReleased
)

// Option configures an Engine.
type Option func(*Engine)

// WithStepLimit overrides the native execution-step budget.
func WithStepLimit(n uint64) Option { return func(e *Engine) { e.stepLimit = n } }

// WithEvalTimeout overrides the wall-clock watchdog budget; on -race builds
// New scales it by raceWallScale. The step budget is unaffected.
func WithEvalTimeout(d time.Duration) Option { return func(e *Engine) { e.evalTimeout = d } }

// WithMaxWorkers sets the maximum number of concurrent VM evaluations. A
// value of zero or less is ignored and the engine keeps the
// script.DefaultMaxWorkers default set by New.
func WithMaxWorkers(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.evalSlots = make(chan struct{}, n)
		}
	}
}

// New returns a Starlark condition engine with sandbox defaults.
func New(opts ...Option) *Engine {
	e := &Engine{
		stepLimit:   DefaultStepLimit,
		evalTimeout: DefaultEvalTimeout,
		evalSlots:   make(chan struct{}, script.DefaultMaxWorkers),
		cache:       make(map[[sha256.Size]byte]*starlark.Program),
	}
	for _, opt := range opts {
		opt(e)
	}
	if raceEnabled {
		e.evalTimeout *= raceWallScale
	}
	return e
}

// Name is the registry name policies reference via when_engine: "starlark".
func (e *Engine) Name() string { return "starlark" }

// Compile parses, resolves and caches one condition source. Compile-time
// failures (syntax, disallowed statements) fail the policy load.
func (e *Engine) Compile(source string) (pipeline.ConditionProgram, error) {
	if len(source) > maxConditionSourceBytes {
		return nil, fmt.Errorf("starlark: source exceeds %d-byte limit", maxConditionSourceBytes)
	}
	key := sha256.Sum256([]byte(source))
	e.mu.Lock()
	if prog, ok := e.cache[key]; ok {
		e.mu.Unlock()
		return &program{engine: e, prog: prog}, nil
	}
	e.mu.Unlock()

	if source == "" {
		return nil, errors.New("starlark: condition source is empty")
	}
	wrapped := "def __condition__(findings, steps, meta):\n\treturn (" + source + ")\n"
	_, prog, err := starlark.SourceProgramOptions(&syntax.FileOptions{
		Set:             false,
		While:           false,
		TopLevelControl: false,
		GlobalReassign:  false,
		Recursion:       false,
	}, "when.starlark", wrapped, func(string) bool { return false })
	if err != nil {
		return nil, fmt.Errorf("starlark: %w", err)
	}
	e.mu.Lock()
	if len(e.cache) >= cacheLimit {
		e.cache = make(map[[sha256.Size]byte]*starlark.Program)
	}
	e.cache[key] = prog
	e.mu.Unlock()
	return &program{engine: e, prog: prog}, nil
}

// program is one compiled Starlark condition.
type program struct {
	engine *Engine
	prog   *starlark.Program
}

// Evaluate initializes the module on a fresh thread and calls
// __condition__(findings, steps, meta) under the step budget and watchdog.
func (p *program) Evaluate(ctx context.Context, env pipeline.ConditionEnv) (bool, error) {
	if ctx == nil {
		return false, errors.New("starlark: caller context is required")
	}
	if err := checkEnvironmentBudget(env); err != nil {
		return false, err
	}
	e := p.engine
	select {
	case e.evalSlots <- struct{}{}:
		if e.evalProbe != nil {
			e.evalProbe(probeAcquired)
		}
		defer func() {
			if e.evalProbe != nil {
				e.evalProbe(probeReleased)
			}
			<-e.evalSlots
		}()
	case <-ctx.Done():
		return false, fmt.Errorf("starlark: caller context: %w", ctx.Err())
	}
	thread := &starlark.Thread{Name: "when", Print: func(*starlark.Thread, string) {}}

	thread.SetMaxExecutionSteps(e.stepLimit)
	var watchdogFired atomic.Bool
	watchdog := time.AfterFunc(e.evalTimeout, func() {
		watchdogFired.Store(true)
		thread.Cancel("evaluation budget exceeded (wall-clock watchdog)")
	})
	defer watchdog.Stop()
	stopContext := context.AfterFunc(ctx, func() { thread.Cancel("caller context cancelled") })
	defer stopContext()

	globals, err := p.prog.Init(thread, nil)
	if err != nil {
		return false, classifyEvalErr(ctx, &watchdogFired, err)
	}
	fn, ok := globals["__condition__"].(starlark.Callable)
	if !ok {
		return false, errors.New("starlark: compiled module has no callable __condition__")
	}

	result, err := starlark.Call(thread, fn, starlark.Tuple{
		findingsValue(env.Findings),
		stepsValue(env.Steps),
		metaValue(env.Meta),
	}, nil)
	if err != nil {
		return false, classifyEvalErr(ctx, &watchdogFired, err)
	}
	b, ok := result.(starlark.Bool)
	if !ok {
		return false, fmt.Errorf("starlark: condition must return a bool, got %s", result.Type())
	}
	return bool(b), nil
}

// classifyEvalErr maps budget aborts and caller cancellation onto explicit
// errors so the pipeline's on_error semantics (fail-closed default) apply to
// both.
func classifyEvalErr(ctx context.Context, watchdogFired *atomic.Bool, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("starlark: caller context: %w", ctx.Err())
	}
	if watchdogFired.Load() || strings.Contains(err.Error(), "too many steps") {
		return fmt.Errorf("starlark: evaluation budget exceeded: %w", err)
	}
	return fmt.Errorf("starlark: %w", err)
}

func checkEnvironmentBudget(env pipeline.ConditionEnv) error {
	items := len(env.Findings) + len(env.Steps)
	bytes := 0
	add := func(value string) { bytes += len(value) }
	for _, finding := range env.Findings {
		add(finding.Step)
		add(finding.Category)
		add(finding.Severity)
		add(finding.Span)
		add(finding.Evidence)
		add(string(finding.Action))
	}
	for _, step := range env.Steps {
		add(step.Step)
		add(string(step.Outcome))
		add(step.Error)
	}
	if env.Meta != nil {
		add(env.Meta.Org)
		add(env.Meta.Key)
		add(env.Meta.Model)
		add(env.Meta.Provider)
		items += len(env.Meta.Tags) + len(env.Meta.Labels)
		for _, tag := range env.Meta.Tags {
			add(tag)
		}
		for key, value := range env.Meta.Labels {
			add(key)
			add(value)
		}
	}
	if items > maxEnvItems || bytes > maxEnvBytes {
		return fmt.Errorf("starlark: evaluation input exceeds limits (items=%d bytes=%d)", items, bytes)
	}
	return nil
}
