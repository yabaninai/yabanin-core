package policy

import "sync"

// Registry stores policy-packs keyed by Region. The zero value is NOT usable;
// construct with NewRegistry.
type Registry struct {
	mu    sync.RWMutex
	packs map[Region]Pack
}

// NewRegistry returns an empty Registry ready to accept Register calls.
func NewRegistry() *Registry {
	return &Registry{packs: make(map[Region]Pack)}
}

// Register adds (or replaces) a pack under its Region.
func (r *Registry) Register(p Pack) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.packs[p.Region()] = p
}

// Get returns the pack for region, or nil when no pack is registered
// (unregulated region → caller treats this as free-pass).
func (r *Registry) Get(region Region) Pack {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.packs[region]
}

// List returns all registered packs. Order is not guaranteed.
func (r *Registry) List() []Pack {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Pack, 0, len(r.packs))
	for _, p := range r.packs {
		out = append(out, p)
	}
	return out
}
