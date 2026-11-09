package loopexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/reireirei/yabanin/pkg/agentloop"
	"github.com/reireirei/yabanin/pkg/toolexec"
)

// BuiltinExecutor is the core-owned extension of the SPI: it adapts the
// built-in tool executor (pkg/toolexec, server "yabanin") to the loopexec
// seam. It exists so the versioned contract has a first-class core citizen;
// the Enterprise loop module reaches built-in tools THROUGH this seam like
// any other executor — never around it.
//
// It is an adapter, not a loop: it executes exactly one admitted call per
// Execute invocation.
type BuiltinExecutor struct {
	exec *toolexec.Executor
}

// NewBuiltinExecutor wraps the deployment's built-in executor. A nil
// executor is refused (fail-closed wiring).
func NewBuiltinExecutor(x *toolexec.Executor) (*BuiltinExecutor, error) {
	if x == nil {
		return nil, errors.New("loopexec: builtin executor requires a non-nil toolexec executor")
	}
	return &BuiltinExecutor{exec: x}, nil
}

// Server is the registry name this executor serves.
const Server = toolexec.BuiltinServerName

// Execute adapts one built-in tool call through the deployment guard path
// (toolexec.ExecuteGuarded — tool policy, SSRF guard, redaction) after the
// route configuration admitted the call.
//
// Side-effect classification (honest-effects invariant): built-in tools are
// reads/computations except http_request with a mutating method. A mutating
// call that reached the wire and failed ambiguously (timeout, upstream
// failure) is classified SideEffectUncertain — the engine must stop and
// surface the uncertainty, never retry blind (I45/I55). Guard-level
// refusals (denied/ssrf/blocked/bad_request/not_found) never reached the
// wire and classify as no effect.
//
// On error the returned Result carries ONLY the effect classification.
func (b *BuiltinExecutor) Execute(ctx context.Context, cfg Config, call Call) (Result, error) {
	if call.Server != Server {
		return Result{}, fmt.Errorf("%w: builtin executor serves %q, got %q", ErrNoExecutor, Server, call.Server)
	}
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	if call.Scope != cfg.Scope {
		return Result{}, fmt.Errorf("%w: call scope %+v differs from config scope %+v", ErrNotPermitted, call.Scope, cfg.Scope)
	}
	if call.Action != ActionInvoke {
		return Result{}, fmt.Errorf("%w: builtin executor implements %q only, got %q", ErrNotPermitted, ActionInvoke, call.Action)
	}
	if call.Subject == "" {
		return Result{}, ErrSubjectRequired
	}
	if call.Credential.Mode == agentloop.CredentialDelegatedUser {
		// Built-in tools run on the deployment's own egress; there is no
		// delegated-user credential mode for them (I54). Refuse rather
		// than silently execute service-style under a user label.
		return Result{}, fmt.Errorf("%w: builtin tools do not accept delegated-user credentials", ErrNotPermitted)
	}
	if !cfg.Allows(Server, call.Tool) {
		return Result{}, fmt.Errorf("%w: %q is not on the route allow-list for scope %+v", ErrNotPermitted, ToolName(Server, call.Tool), cfg.Scope)
	}

	r, err := b.exec.ExecuteGuarded(ctx, cfg.Scope.OrgID, call.Subject, call.Tool, call.Params)
	if err != nil {
		return Result{Server: Server, Tool: call.Tool, SideEffect: b.classifyFailure(call.Tool, call.Params, err)},
			b.wrapError(call.Tool, err)
	}
	return Result{
		Server:     Server,
		Tool:       call.Tool,
		Payload:    r.Body,
		SideEffect: classifySuccess(call.Tool, call.Params),
		LatencyMS:  r.LatencyMS,
	}, nil
}

// classifyFailure maps a failed guarded execution to its effect class.
func (b *BuiltinExecutor) classifyFailure(tool string, params json.RawMessage, err error) agentloop.SideEffect {
	if !isMutatingHTTP(tool, params) {
		return agentloop.SideEffectNone
	}
	var ee *toolexec.ExecError
	if errors.As(err, &ee) {
		switch ee.Code {
		case toolexec.ErrCodeTimeout, toolexec.ErrCodeUpstream:
			// The request may have executed remotely; the outcome is
			// unknown. Durable uncertainty — the caller must stop.
			return agentloop.SideEffectUncertain
		default:
			// denied / ssrf_blocked / tool_blocked / bad_request /
			// not_found: refused before egress — nothing external changed.
			return agentloop.SideEffectNone
		}
	}
	// Non-typed errors from the guarded path (context cancellation and
	// friends): treat like a wire-level ambiguity.
	return agentloop.SideEffectUncertain
}

// classifySuccess maps a successful execution to its effect class.
func classifySuccess(tool string, params json.RawMessage) agentloop.SideEffect {
	if isMutatingHTTP(tool, params) {
		return agentloop.SideEffectDone
	}
	return agentloop.SideEffectNone
}

// isMutatingHTTP reports whether the call is an http_request with a
// mutating method (POST/PUT/PATCH/DELETE). Effective tool names
// (http_<method>) come from the toolexec catalog so classification and
// policy addressing stay in sync.
func isMutatingHTTP(tool string, params json.RawMessage) bool {
	if tool != "http_request" {
		return false
	}
	switch toolexec.EffectiveToolName(tool, params) {
	case "http_post", "http_put", "http_patch", "http_delete":
		return true
	default:
		return false
	}
}

// wrapError classifies guard-path errors into seam sentinels: unknown tool,
// guard refusal, or an honest execution failure (returned as-is so the
// caller sees the typed toolexec error).
func (b *BuiltinExecutor) wrapError(tool string, err error) error {
	var ee *toolexec.ExecError
	if !errors.As(err, &ee) {
		return err
	}
	switch ee.Code {
	case toolexec.ErrCodeNotFound:
		return fmt.Errorf("%w: %q: %s", ErrUnknownTool, tool, ee.Message)
	case toolexec.ErrCodeDenied, toolexec.ErrCodeSSRF, toolexec.ErrCodeToolBlocked, toolexec.ErrCodeBadReq:
		return fmt.Errorf("%w: %q refused by guard (%s): %s", ErrNotPermitted, tool, ee.Code, ee.Message)
	default:
		return err
	}
}
