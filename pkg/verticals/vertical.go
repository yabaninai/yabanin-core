// Package verticals provides per-organisation compliance verticals that sit
// in front of (pre-upstream) and behind (post-upstream) the gateway router.
// Each vertical implements a residency-aware evaluation, optional request
// transformation, and compliance-export reporting.
package verticals

import (
	"context"
	"fmt"

	"github.com/reireirei/yabanin/pkg/policy"
)

// Vertical is the interface every compliance vertical pack must implement.
// It embeds policy.Pack for residency evaluation plus two extension points:
//   - Transform: pre-upstream request mutation (e.g., PHI redaction, carbon-aware model swap).
//   - Reporter: post-upstream compliance export (e.g., BRSR report generation, lineage attestation).
type Vertical interface {
	policy.Pack

	// Transform mutates a request before it is sent to the upstream provider.
	// Returns non-nil error on hard-deny; nil means pass-through (possibly modified).
	// The returned context may carry transformed fields for downstream handlers.
	Transform(ctx context.Context, in Request) (context.Context, Response, error)

	// Report produces a compliance-ready export for the given time window.
	// mode == "saas" or "onprem"; callers should use this to choose SSRF guard policy.
	Report(ctx context.Context, orgID string, from, until string, mode string) ([]byte, error)
}

// Request is the canonical request shape passed through a vertical's Transform.
type Request struct {
	OrgID          string            `json:"org_id"`
	ModelRequested string            `json:"model_requested"`
	Prompt         string            `json:"prompt"`
	SystemPrompt   string            `json:"system_prompt,omitempty"`
	Temperature    float32           `json:"temperature,omitempty"`
	MaxTokens      int               `json:"max_tokens,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// Response is the canonical response shape returned by a vertical's Transform.
type Response struct {
	Model    string            `json:"model"`
	Prompt   string            `json:"prompt"`
	Metadata map[string]string `json:"metadata,omitempty"`
	// Deny indicates the request was hard-blocked by this vertical.
	Deny bool `json:"-"`
	// DenyReason explains why the request was blocked (populated when Deny=true).
	DenyReason string `json:"-"`
}

// EvaluateRequest runs a Vertical's residency evaluation + Transform in sequence.
// Returns the transformed context, response body, and any error.
func EvaluateRequest(ctx context.Context, v Vertical, in Request, overrideRules *policy.ResidencyRule) (context.Context, Response, error) {
	evalCtx := policy.EvalContext{
		OrgID:          in.OrgID,
		ModelRequested: in.ModelRequested,
	}

	dec := v.Evaluate(ctx, evalCtx, overrideRules)
	if !dec.Allowed {
		return ctx, Response{Deny: true, DenyReason: dec.Reason}, fmt.Errorf("vertical %s denied: %s", v.ID(), dec.Reason)
	}

	return v.Transform(ctx, in)
}

// IsEnabled checks if the vertical is enabled for an org via a simple config lookup.
func IsEnabled(cfg map[string]any) bool {
	v, ok := cfg["enabled"]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// GetConfigValue returns a typed value from the vertical config JSON map.
func GetConfigValue[T ~string | ~int | ~float64](cfg map[string]any, key string) (T, bool) {
	var zero T
	v, ok := cfg[key]
	if !ok {
		return zero, false
	}
	switch any(v).(type) {
	case T:
		return v.(T), true
	default:
		return zero, false
	}
}
