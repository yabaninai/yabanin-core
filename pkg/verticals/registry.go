package verticals

import (
	"context"
	"fmt"
	"sync"
)

// Registry manages the lifecycle of all registered vertical packs.
type Registry struct {
	mu     sync.RWMutex
	verts  map[string]Vertical // id -> Vertical
	orgMap map[string][]string // orgID -> []verticalIDs enabled for this org
}

// NewRegistry creates an empty vertical pack registry.
func NewRegistry() *Registry {
	return &Registry{
		verts:  make(map[string]Vertical),
		orgMap: make(map[string][]string),
	}
}

// Register adds a vertical pack to the registry.
func (r *Registry) Register(v Vertical) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := v.ID()
	if _, exists := r.verts[id]; exists {
		return fmt.Errorf("vertical %q already registered", id)
	}
	r.verts[id] = v
	return nil
}

// Unregister removes a vertical pack from the registry.
func (r *Registry) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.verts[id]; !exists {
		return fmt.Errorf("vertical %q not found", id)
	}
	delete(r.verts, id)

	// Remove from org mappings.
	for orgID, vIDs := range r.orgMap {
		newIDs := make([]string, 0, len(vIDs))
		for _, vid := range vIDs {
			if vid != id {
				newIDs = append(newIDs, vid)
			}
		}
		r.orgMap[orgID] = newIDs
	}

	return nil
}

// Get returns a vertical by ID.
func (r *Registry) Get(id string) Vertical {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.verts[id]
}

// EnabledFor returns all vertical IDs enabled for the given orgID.
func (r *Registry) EnabledFor(orgID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	vIDs, ok := r.orgMap[orgID]
	if !ok {
		return nil
	}
	result := make([]string, len(vIDs))
	copy(result, vIDs)
	return result
}

// EnableFor marks a vertical as active for an org (called from DB layer).
func (r *Registry) EnableFor(orgID, verticalID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.verts[verticalID]; !exists {
		return fmt.Errorf("vertical %q not registered", verticalID)
	}
	for _, id := range r.orgMap[orgID] {
		if id == verticalID {
			return nil // already enabled
		}
	}
	r.orgMap[orgID] = append(r.orgMap[orgID], verticalID)
	return nil
}

// DisableFor removes a vertical for an org.
func (r *Registry) DisableFor(orgID, verticalID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	vIDs, ok := r.orgMap[orgID]
	if !ok {
		return fmt.Errorf("org %q has no enabled verticals", orgID)
	}
	newIDs := make([]string, 0, len(vIDs))
	found := false
	for _, id := range vIDs {
		if id == verticalID {
			found = true
			continue
		}
		newIDs = append(newIDs, id)
	}
	if !found {
		return fmt.Errorf("vertical %q not enabled for org %q", verticalID, orgID)
	}
	r.orgMap[orgID] = newIDs
	return nil
}

// List returns all registered vertical IDs.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var ids []string
	for id := range r.verts {
		ids = append(ids, id)
	}
	return ids
}

// PreTransform runs Transform on all enabled verticals for an org in sequence.
// Each vertical's output becomes the next vertical's input.
func (r *Registry) PreTransform(ctx context.Context, orgID string, in Request) (context.Context, Request, error) {
	vIDs := r.EnabledFor(orgID)
	if len(vIDs) == 0 {
		return ctx, in, nil
	}

	for _, vid := range vIDs {
		v := r.Get(vid)
		if v == nil {
			continue
		}
		var err error
		ctx, in, err = preTransformOne(ctx, v, in)
		if err != nil {
			return ctx, in, fmt.Errorf("vertical %s transform: %w", vid, err)
		}
	}
	return ctx, in, nil
}

// PreTransformSingle runs Transform on one vertical.
func preTransformOne(ctx context.Context, v Vertical, in Request) (context.Context, Request, error) {
	newCtx, resp, err := v.Transform(ctx, in)
	if err != nil {
		return ctx, in, err
	}
	if resp.Deny {
		return ctx, in, fmt.Errorf("vertical %s denied: %s", v.ID(), resp.DenyReason)
	}
	in.ModelRequested = resp.Model
	in.Prompt = resp.Prompt
	for k, mv := range resp.Metadata {
		in.Metadata[k] = mv
	}
	return newCtx, in, nil
}
