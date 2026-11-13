// Package expr is the OP-7 expr condition engine (challenger #2, minimal
// fallback): github.com/expr-lang/expr, a non-Turing-complete expression
// language with a typed environment.
//
// SANDBOX MODEL:
//
//   - Budgets (bounded, not stepped): the grammar has NO loop or recursion
//     constructs, so termination is guaranteed by construction and
//     evaluation cost is bounded by |expression| × |env data| — the syntax
//     and env budgets cap both factors before compilation, and the VM's
//     tracked MemoryBudget (a deterministic byte counter) caps allocations.
//     expr-lang exposes no per-instruction hook in production builds (its
//     debug step channel only compiles under the expr_debug tag), so a
//     deterministic step budget is infeasible without a fork. The residual
//     bound is a wall-clock CEILING (DefaultEvalTimeout, scaled on -race
//     builds, see race_on.go) that backstops slow-but-bounded work.
//     RESIDUAL LIMIT: that ceiling is wall-clock — a bounded evaluation can
//     still abort on a machine slow enough to exceed it.
//   - The environment is a typed Go struct: unknown identifiers and unknown
//     fields/methods are COMPILE errors, so a condition can only touch the
//     three roots (Findings, Steps, Meta — contract in the parent package;
//     expr uses Go-struct capitalisation) plus the builtins.
//   - Builtin `now` is disabled (nondeterminism); the remaining builtins are
//     pure (string/array helpers, JSON codecs). KNOWN CAVEATS for the owner
//     decision: allocation is bounded by operand size (script literals are
//     admin-supplied), and expr's all() over an empty collection is
//     vacuously TRUE (deviates from the contract's all(); use
//     count(Findings, ...) or any() where emptiness matters).
//   - expr.AsBool() enforces a boolean result at compile time; method errors
//     (e.g. StepDurationMs on an absent step) are evaluation errors — a
//     condition can never fail open.
//
// Compilation happens once per source (sha256-keyed cache of *vm.Program);
// programs are immutable and safe for concurrent Evaluate.
package expr

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/script"
)

// cacheLimit caps the compiled-program cache (spike-simple FIFO reset).
const cacheLimit = 1024

const (
	maxSourceBytes = 16 << 10
	maxSyntaxNodes = 2048
	maxSyntaxDepth = 64
	maxEnvItems    = 4096
	maxEnvBytes    = 1 << 20
)

const (
	// DefaultEvalTimeout is the per-evaluation wall-clock CEILING. It only
	// backstops bounded work on a slow machine; boundedness itself comes
	// from the loop-free grammar plus the deterministic VM MemoryBudget.
	// New scales it by raceWallScale on -race builds (load tolerance, not
	// semantics).
	DefaultEvalTimeout = 25 * time.Millisecond
	// DefaultMemoryBudget is the Expr VM's tracked allocation budget in bytes.
	DefaultMemoryBudget = 1 << 20
	// raceWallScale is applied to the wall ceiling on -race builds only.
	raceWallScale = 10
)

// Engine compiles expr condition sources. Create with New, then register
// under Name ("expr") on pipeline.Engine.Scripts.
type Engine struct {
	mu           sync.Mutex
	cache        map[[sha256.Size]byte]*vm.Program
	evalTimeout  time.Duration
	memoryBudget uint
	evalSlots    chan struct{}
}

// Option configures Expr evaluation budgets.
type Option func(*Engine)

// WithEvalTimeout sets the maximum time the caller waits for one evaluation;
// on -race builds New scales it by raceWallScale. The allocation budget is
// unaffected.
func WithEvalTimeout(timeout time.Duration) Option {
	return func(engine *Engine) { engine.evalTimeout = timeout }
}

// WithMemoryBudget limits allocations tracked by the Expr VM.
func WithMemoryBudget(bytes uint) Option {
	return func(engine *Engine) { engine.memoryBudget = bytes }
}

// New returns an expr condition engine with sandbox defaults.
func New(options ...Option) *Engine {
	e := &Engine{
		cache:       make(map[[sha256.Size]byte]*vm.Program),
		evalTimeout: DefaultEvalTimeout, memoryBudget: DefaultMemoryBudget,
		evalSlots: make(chan struct{}, script.DefaultMaxWorkers),
	}
	for _, option := range options {
		option(e)
	}
	if raceEnabled {
		e.evalTimeout *= raceWallScale
	}
	return e
}

// Name is the registry name policies reference via when_engine: "expr".
func (e *Engine) Name() string { return "expr" }

// Compile parses, type-checks against Env and caches one condition source.
// Compile-time failures (syntax, unknown names, non-bool result type) fail
// the policy load.
func (e *Engine) Compile(source string) (pipeline.ConditionProgram, error) {
	if len(source) > maxSourceBytes {
		return nil, fmt.Errorf("expr: source exceeds %d-byte limit", maxSourceBytes)
	}
	if err := checkSyntaxBudget(source); err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(source))
	e.mu.Lock()
	if prog, ok := e.cache[key]; ok {
		e.mu.Unlock()
		return e.newProgram(prog), nil
	}
	e.mu.Unlock()

	if source == "" {
		return nil, errors.New("expr: condition source is empty")
	}
	compiled, err := expr.Compile(source,
		expr.Env(Env{}),
		expr.AsBool(),
		expr.DisableBuiltin("now"),
	)
	if err != nil {
		return nil, fmt.Errorf("expr: %w", err)
	}

	e.mu.Lock()
	if len(e.cache) >= cacheLimit {
		e.cache = make(map[[sha256.Size]byte]*vm.Program)
	}
	e.cache[key] = compiled
	e.mu.Unlock()
	return e.newProgram(compiled), nil
}

func (e *Engine) newProgram(prog *vm.Program) *program {
	return &program{prog: prog, timeout: e.evalTimeout, memoryBudget: e.memoryBudget, evalSlots: e.evalSlots}
}

// program is one compiled expr condition.
type program struct {
	prog         *vm.Program
	timeout      time.Duration
	memoryBudget uint
	evalSlots    chan struct{}
}

// Evaluate runs the compiled expression against the bounded env snapshot.
// Expr has no loop constructs; the VM memory budget bounds allocations and
// the deadline bounds how long the caller waits.
func (p *program) Evaluate(ctx context.Context, env pipeline.ConditionEnv) (bool, error) {
	if ctx == nil {
		return false, errors.New("expr: caller context is required")
	}
	if ctx.Err() != nil {
		return false, fmt.Errorf("expr: caller context: %w", ctx.Err())
	}
	if p.timeout <= 0 {
		return false, fmt.Errorf("expr: evaluation budget exceeded (%s): %w", p.timeout, context.DeadlineExceeded)
	}
	if err := checkEnvBudget(env); err != nil {
		return false, err
	}
	evalCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	select {
	case p.evalSlots <- struct{}{}:
	case <-evalCtx.Done():
		if ctx.Err() != nil {
			return false, fmt.Errorf("expr: caller context: %w", ctx.Err())
		}
		return false, fmt.Errorf("expr: evaluation budget exceeded (%s): %w", p.timeout, context.DeadlineExceeded)
	}
	type evaluation struct {
		value any
		err   error
	}
	completed := make(chan evaluation, 1)
	envSnapshot := buildEnv(env)
	go func() {
		defer func() { <-p.evalSlots }()
		runner := vm.VM{MemoryBudget: p.memoryBudget}
		value, err := runner.Run(p.prog, envSnapshot)
		completed <- evaluation{value: value, err: err}
	}()
	select {
	case <-evalCtx.Done():
		if ctx.Err() != nil {
			return false, fmt.Errorf("expr: caller context: %w", ctx.Err())
		}
		return false, fmt.Errorf("expr: evaluation budget exceeded (%s): %w", p.timeout, context.DeadlineExceeded)
	case result := <-completed:
		if result.err != nil {
			return false, fmt.Errorf("expr: %w", result.err)
		}
		matched, ok := result.value.(bool)
		if !ok {
			return false, fmt.Errorf("expr: condition must return a bool, got %T", result.value)
		}
		return matched, nil
	}
}

// checkSyntaxBudget conservatively bounds parser work before invoking the
// third-party compiler. Delimiters bound nesting; lexical token starts bound
// the maximum AST size while respecting quoted strings and escapes.
func checkSyntaxBudget(source string) error {
	depth, nodes := 0, 0
	var quote rune
	escaped := false
	for _, r := range source {
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' || r == '`' {
			quote = r
			nodes++
			continue
		}
		if strings.ContainsRune("([{", r) {
			depth++
			if depth > maxSyntaxDepth {
				return fmt.Errorf("expr: nesting exceeds %d limit", maxSyntaxDepth)
			}
		}
		if strings.ContainsRune(")]}", r) {
			depth--
			if depth < 0 {
				depth = 0
			}
		}
		if !strings.ContainsRune(" \t\r\n,()[]{}", r) {
			nodes++
		}
		if nodes > maxSyntaxNodes {
			return fmt.Errorf("expr: syntax exceeds %d-node limit", maxSyntaxNodes)
		}
	}
	return nil
}

func checkEnvBudget(env pipeline.ConditionEnv) error {
	items, size := len(env.Findings)+len(env.Steps), 0
	add := func(s string) { size += len(s) }
	for _, f := range env.Findings {
		add(f.Step)
		add(f.Category)
		add(f.Severity)
		add(f.Span)
		add(f.Evidence)
		add(string(f.Action))
	}
	for _, s := range env.Steps {
		add(s.Step)
		add(string(s.Outcome))
		add(s.Error)
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
		for k, v := range env.Meta.Labels {
			add(k)
			add(v)
		}
	}
	if env.Decision != nil {
		decision := env.Decision
		for _, value := range []string{
			decision.Principal.ID.Value, decision.Principal.Kind.Value,
			decision.Action.Value, decision.Resource.Type.Value,
			decision.Resource.ID.Value, decision.Resource.Organization.Value,
		} {
			add(value)
		}
		items += len(decision.Context)
		for name, value := range decision.Context {
			add(name)
			add(value.Value)
		}
	}
	if items > maxEnvItems || size > maxEnvBytes {
		return fmt.Errorf("expr: evaluation input exceeds limits (items=%d bytes=%d)", items, size)
	}
	return nil
}

// Env is the typed condition environment (parent-package contract, Go-struct
// capitalisation). Fields are snapshots rebuilt per evaluation.
type Env struct {
	Findings  []Finding
	Steps     []Step
	Meta      Meta
	Principal DecisionPrincipal
	Action    string
	Resource  DecisionResource
	Context   map[string]string
}

// DecisionPrincipal is the trusted principal view exposed to decision rules.
type DecisionPrincipal struct {
	ID   string
	Kind string
}

// DecisionResource is the trusted resource view exposed to decision rules.
type DecisionResource struct {
	Type         string
	ID           string
	Organization string
}

// Finding is one recorded finding.
type Finding struct {
	Step     string
	Category string
	Severity string
	Span     string
	Evidence string
	Action   string
}

// Step is one step-trace record (duration in milliseconds).
type Step struct {
	Step       string
	DurationMs float64
	Outcome    string
	Error      string
}

// Meta is the request routing identity.
type Meta struct {
	Org      string
	Key      string
	Model    string
	Provider string
	Labels   map[string]string
	Tags     []string
}

// Label returns the label value or "" when absent.
func (m Meta) Label(name string) string {
	if m.Labels == nil {
		return ""
	}
	return m.Labels[name]
}

// HasTag reports whether tag is present.
func (m Meta) HasTag(tag string) bool {
	for _, t := range m.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// StepRan reports whether the step ran to completion.
func (e Env) StepRan(id string) bool {
	st, ok := e.findStep(id)
	return ok && st.Outcome == "ran"
}

// StepFailed reports whether the step ended in error or timeout.
func (e Env) StepFailed(id string) bool {
	st, ok := e.findStep(id)
	return ok && (st.Outcome == "error" || st.Outcome == "timeout")
}

// StepDurationMs returns the step duration; an absent step is an evaluation
// error (fail-closed), never 0.
func (e Env) StepDurationMs(id string) (float64, error) {
	st, ok := e.findStep(id)
	if !ok {
		return 0, fmt.Errorf("expr: unknown step %q", id)
	}
	return st.DurationMs, nil
}

// StepOutcome returns the step outcome; an absent step is an evaluation
// error (fail-closed).
func (e Env) StepOutcome(id string) (string, error) {
	st, ok := e.findStep(id)
	if !ok {
		return "", fmt.Errorf("expr: unknown step %q", id)
	}
	return st.Outcome, nil
}

func (e Env) findStep(id string) (Step, bool) {
	for _, st := range e.Steps {
		if st.Step == id {
			return st, true
		}
	}
	return Step{}, false
}

// buildEnv maps the pipeline snapshot onto the typed env.
func buildEnv(env pipeline.ConditionEnv) Env {
	out := Env{
		Findings: make([]Finding, 0, len(env.Findings)),
		Steps:    make([]Step, 0, len(env.Steps)),
	}
	for _, f := range env.Findings {
		out.Findings = append(out.Findings, Finding{
			Step: f.Step, Category: f.Category, Severity: f.Severity,
			Span: f.Span, Evidence: f.Evidence, Action: string(f.Action),
		})
	}
	for _, st := range env.Steps {
		out.Steps = append(out.Steps, Step{
			Step:       st.Step,
			DurationMs: float64(st.Duration.Nanoseconds()) / 1e6,
			Outcome:    string(st.Outcome),
			Error:      st.Error,
		})
	}
	if env.Meta != nil {
		out.Meta = Meta{
			Org: env.Meta.Org, Key: env.Meta.Key,
			Model: env.Meta.Model, Provider: env.Meta.Provider,
			Labels: env.Meta.Labels, Tags: env.Meta.Tags,
		}
	}
	if env.Decision != nil {
		out.Principal = DecisionPrincipal{ID: env.Decision.Principal.ID.Value, Kind: env.Decision.Principal.Kind.Value}
		out.Action = env.Decision.Action.Value
		out.Resource = DecisionResource{
			Type: env.Decision.Resource.Type.Value, ID: env.Decision.Resource.ID.Value,
			Organization: env.Decision.Resource.Organization.Value,
		}
		out.Context = make(map[string]string, len(env.Decision.Context))
		for name, value := range env.Decision.Context {
			out.Context[name] = value.Value
		}
	}
	return out
}
