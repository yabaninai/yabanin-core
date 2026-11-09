package provider

import "errors"

// Capability vocabulary: the adapter-side feature axes a request can be
// refused for.
const (
	CapabilityStreaming  = "streaming"
	CapabilityTools      = "tools"
	CapabilityImageInput = "image_input"
)

// CapabilityError is an adapter capability refusal: the adapter rejected a
// request because the target model/family does not support the requested
// feature axis. The refusal is raised BEFORE any credential or network
// work, so the gateway can classify it as not-executed and render a
// client-shaped 400 (stable capability_not_supported code, adapter's
// precise message) instead of a fabricated upstream failure — a refusal is
// never retried and never silently downgraded to another model or a
// feature-less request.
type CapabilityError struct {
	// Provider is the adapter that refused ("vertex", "bedrock").
	Provider string
	// Capability is the refused feature axis (CapabilityStreaming, ...).
	Capability string
	// Model is the model/family the request targeted, when known.
	Model string
	// Detail is the exact refusal message (returned verbatim by Error).
	Detail string
}

// Error returns the adapter's precise refusal message byte-for-byte: the
// refusal strings are pinned contracts (adapter compat tests and gateway
// wire assertions match them exactly), so the typed carrier never
// reformats them.
func (e *CapabilityError) Error() string { return e.Detail }

// Refusal reports whether err is (or wraps) an adapter capability refusal
// and returns the typed refusal. It exists so the gateway can detect
// refusals through the upstream client's %w wraps
// ("translate request: ...", "create request: ...").
func Refusal(err error) (*CapabilityError, bool) {
	var ce *CapabilityError
	if errors.As(err, &ce) {
		return ce, true
	}
	return nil, false
}
