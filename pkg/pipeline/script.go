package pipeline

import (
	"context"
	"fmt"
	"slices"
	"sync"
)

// ConditionCompiler compiles one `when` condition source into a runnable
// ConditionProgram. It is called ONCE per conditioned step at policy load
// time (plan §2.2 п.2); the returned program must be deterministic,
// side-effect free, safe for concurrent Evaluate calls and internally
// sandboxed (bounded time and memory — the engine enforces no budget around
// Evaluate beyond the caller's ctx; that is the OP-7 engine's job).
type ConditionCompiler func(source string) (ConditionProgram, error)

// ConditionProgram is one compiled `when` condition.
type ConditionProgram interface {
	// Evaluate reports whether the condition holds for the given context.
	// Implementations must return promptly, honor ctx, and treat env as
	// read-only.
	Evaluate(ctx context.Context, env ConditionEnv) (bool, error)
}

// ConditionEnv is the read-only evaluation context handed to programs:
// findings recorded so far, step traces so far, and request meta. Slices are
// snapshots owned by the call; mutating them is undefined behaviour.
type ConditionEnv struct {
	Findings []Finding            `json:"findings,omitempty"`
	Steps    []StepTrace          `json:"steps,omitempty"`
	Meta     *RequestMeta         `json:"meta,omitempty"`
	Decision *DecisionEnvironment `json:"decision,omitempty"`
}

// ScriptRegistry maps condition engine names to compilers — the OP-7 seam.
// The core never interprets condition sources: a policy step with a `when`
// value compiles only if an engine was registered here before compilation
// (Engine.Scripts().Register, typically from pkg/pipeline/script
// implementations). With exactly one engine registered it is the default for
// steps that omit when_engine; otherwise when_engine is required.
type ScriptRegistry struct {
	mu        sync.RWMutex
	compilers map[string]ConditionCompiler
}

// NewScriptRegistry returns an empty condition-engine registry.
func NewScriptRegistry() *ScriptRegistry {
	return &ScriptRegistry{compilers: make(map[string]ConditionCompiler)}
}

// Register adds a condition compiler under name. Empty names, nil compilers
// and duplicate names are errors.
func (r *ScriptRegistry) Register(name string, c ConditionCompiler) error {
	if name == "" {
		return fmt.Errorf("condition engine name is required")
	}
	if c == nil {
		return fmt.Errorf("condition engine %q: compiler is required", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.compilers[name]; exists {
		return fmt.Errorf("condition engine %q is already registered", name)
	}
	r.compilers[name] = c
	return nil
}

// MustRegister is Register for init-time wiring; it panics on error.
func (r *ScriptRegistry) MustRegister(name string, c ConditionCompiler) {
	if err := r.Register(name, c); err != nil {
		panic(err)
	}
}

// Compiler returns the compiler registered under name.
func (r *ScriptRegistry) Compiler(name string) (ConditionCompiler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.compilers[name]
	return c, ok
}

// Names returns all registered engine names sorted (for error messages).
func (r *ScriptRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.compilers))
	for name := range r.compilers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Len returns the number of registered engines.
func (r *ScriptRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.compilers)
}
