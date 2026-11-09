package pipeline

import (
	"fmt"
	"slices"
	"sync"
)

// StepFactory builds a fresh Step instance for one compiled policy. It is
// called once per step at policy compile time; factories must be safe for
// concurrent use and must not retain the params map (the engine may hand the
// same map to the step at runtime via Pipeline.Params).
type StepFactory func(params map[string]any) (Step, error)

// Registry maps step factory names to factories. Names use the
// "<family>/<name>" convention for builtins ("builtin/national-pii") and the
// bare kind name for kind-implemented steps ("callout", "llm_judge",
// "decide", "route_hint" — see StepSpec for the exact resolution rules).
// Implementations are owned by other lanes (OP-1..OP-7); the registry starts
// empty.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]StepFactory
}

// NewRegistry returns an empty step factory registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]StepFactory)}
}

// Register adds a factory under name. Empty names, nil factories and
// duplicate names are errors.
func (r *Registry) Register(name string, f StepFactory) error {
	if name == "" {
		return fmt.Errorf("step factory name is required")
	}
	if f == nil {
		return fmt.Errorf("step factory %q: factory is required", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[name]; exists {
		return fmt.Errorf("step factory %q is already registered", name)
	}
	r.factories[name] = f
	return nil
}

// MustRegister is Register for init-time wiring; it panics on error.
func (r *Registry) MustRegister(name string, f StepFactory) {
	if err := r.Register(name, f); err != nil {
		panic(err)
	}
}

// Factory returns the factory registered under name.
func (r *Registry) Factory(name string) (StepFactory, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.factories[name]
	return f, ok
}

// Names returns all registered factory names sorted (for error messages and
// admin tooling).
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Len returns the number of registered factories.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.factories)
}
