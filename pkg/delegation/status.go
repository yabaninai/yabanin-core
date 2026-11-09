package delegation

import "context"

// ProviderStatus is the credential-free health view for OpenCode.
type ProviderStatus struct {
	Healthy   bool   `json:"healthy"`
	Available bool   `json:"available"`
	Cooldown  bool   `json:"cooldown"`
	LastError string `json:"last_error,omitempty"`
}

// StatusSnapshot is returned by tr_delegation_status.
type StatusSnapshot struct {
	Enabled   bool                      `json:"enabled"`
	Workspace string                    `json:"workspace,omitempty"`
	Sticky    string                    `json:"sticky_executor,omitempty"`
	Providers map[string]ProviderStatus `json:"providers"`
}

// Status reports executor availability without credentials or prompts.
func (o *Orchestrator) Status(ctx context.Context) StatusSnapshot {
	if o == nil {
		return StatusSnapshot{Enabled: false, Providers: map[string]ProviderStatus{}}
	}
	out := StatusSnapshot{
		Enabled:   true,
		Workspace: o.workspace,
		Providers: make(map[string]ProviderStatus, len(o.executors)),
	}
	o.mu.Lock()
	out.Sticky = string(o.sticky)
	o.mu.Unlock()
	for name, exec := range o.executors {
		if exec == nil {
			continue
		}
		healthy := o.health.Healthy(name)
		out.Providers[string(name)] = ProviderStatus{
			Healthy:   healthy,
			Available: exec.Available(ctx),
			Cooldown:  !healthy,
			LastError: o.health.LastError(name),
		}
	}
	return out
}

// LastError returns a sanitized provider error code, if any.
func (h *Health) LastError(p ProviderName) string {
	if h == nil {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastError[p]
}
