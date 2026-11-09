// Package loopexec defines the open, versioned executor seam (SPI v1) that
// loop engines use to execute registered tools — built-in executors and
// external MCP tools alike — under the org/project/route configuration of a
// deployment.
//
// OWNERSHIP BOUNDARY (card N05-P06-T02, PRODUCT-CONTRACT.md §2/§11, owner
// decision I53 and D1 2026-11-05): the supplied loop engine is an Enterprise,
// experimental module under enterprise/loop. THIS package stays free Apache
// core: the contract types, the registration seam and the core-owned builtin
// adapter. Core ships no loop engine: no file in this package sequences
// steps, retries, resumes or drives a model — it only fixes how an engine
// reaches guarded execution.
//
// RELATION TO pkg/agentloop (frozen SPI v1): agentloop fixes the operation
// contract (steps, approvals, budgets, settlement). loopexec fixes the TOOL
// execution contract underneath it. An engine composes both; this package
// never duplicates agentloop types — it reuses agentloop.SideEffect and
// agentloop.CredentialRef so one vocabulary spans the stack.
//
// VERSIONING (docs/api/LOOP-EXEC-SPI.md): v1 is additive-only. New optional
// surface arrives as new interfaces, appended enum values or new executor
// registrations; a breaking change ships as a parallel v2, never as a
// mutation of v1.
//
// EDITION (owner decision D4 2026-11-05): every corp function built on this
// seam carries the explicit experimental-edition label. Config validation
// refuses any edition other than the one this version defines — an unknown
// or future edition never silently runs under v1 semantics.
package loopexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/reireirei/yabanin/pkg/agentloop"
)

// SPIVersion identifies the contract version implemented by this package.
// Engines and executors record it in configuration and diagnostics so
// operators can verify which seam semantics a deployment runs.
const SPIVersion = "v1"

// EditionExperimental is the edition label (owner decision D4) every corp
// function built on this seam must carry while the loop capability is
// experimental. Config.Validate refuses any other value: the label is
// load-bearing, not cosmetic — a deployment cannot accidentally present an
// experimental loop as generally available.
const EditionExperimental = "experimental"

// Scope addresses one loop-execution context: the organization, the project
// inside it and the configured route the loop runs on. All three parts are
// mandatory — an unscoped executor call is refused (fail-closed), because
// policy, credentials and tool configuration are all keyed by this scope.
type Scope struct {
	// OrgID is the organization identifier. Required.
	OrgID string
	// ProjectID is the project identifier inside the organization. Required.
	ProjectID string
	// Route is the configured loop route name (lowercase identifier, the
	// same shape as MCP server names). Required.
	Route string
}

// routeNameRe constrains Route to the identifier shape used by MCP server
// names (pkg/mcpagg store CHECK): lowercase alphanumeric with inner dashes
// or underscores.
var routeNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// Validate enforces the scope contract. Every part is required and the route
// must be a lowercase identifier; empty or malformed scopes are refused
// before any guard or executor runs.
func (s Scope) Validate() error {
	if s.OrgID == "" {
		return errors.New("loopexec: scope org_id is required")
	}
	if s.ProjectID == "" {
		return errors.New("loopexec: scope project_id is required")
	}
	if s.Route == "" {
		return errors.New("loopexec: scope route is required")
	}
	if !routeNameRe.MatchString(s.Route) {
		return fmt.Errorf("loopexec: scope route %q must match %s", s.Route, routeNameRe)
	}
	return nil
}

// Config is the org/project/route loop-execution configuration. It is the
// API-visible configuration surface for the loop capability (card N05-P06-T02
// acceptance): edition-marked, scoped and fail-closed by default.
type Config struct {
	// Edition must be EditionExperimental in v1. Anything else — empty,
	// "ga", a future label — is refused by Validate, so an experimental
	// capability never runs unmarked (D4).
	Edition string

	// Scope is the org/project/route context the config belongs to.
	Scope Scope

	// AllowedTools is the route's explicit allow-list of server-qualified
	// tools ("server:tool", the toolexec addressing convention). EMPTY
	// MEANS NONE: an unconfigured route executes no tools (fail-closed
	// default — a loop route opts in tool by tool, never by omission).
	AllowedTools []string

	// MaxToolCalls bounds how many tool calls ONE engine run may execute.
	// Zero means "not configured": the fail-closed reading — engines must
	// refuse to start (zero-bound deny posture, mirroring agentloop
	// BudgetLimits), never run unbounded. The executor seam is stateless;
	// enforcing the count across a run belongs to the driving engine, and
	// every engine built on this seam must honor it.
	MaxToolCalls int
}

// ToolName joins a server and tool into the server-qualified addressing
// convention ("server:tool") shared with pkg/toolexec.
func ToolName(server, tool string) string { return server + ":" + tool }

// SplitToolName splits a server-qualified name into server and tool parts.
// A name without a colon addresses no registry and yields ok=false.
func SplitToolName(name string) (server, tool string, ok bool) {
	for i := 0; i < len(name); i++ {
		if name[i] == ':' {
			return name[:i], name[i+1:], true
		}
	}
	return "", "", false
}

// Validate enforces the config contract: experimental edition (D4), a valid
// scope, an explicit positive tool-call bound. The allow-list is validated
// per entry (every entry must be server-qualified); an empty allow-list is
// legal and means no tools.
func (c Config) Validate() error {
	if c.Edition != EditionExperimental {
		return fmt.Errorf("loopexec: config edition %q is not supported by SPI %s (want %q)",
			c.Edition, SPIVersion, EditionExperimental)
	}
	if err := c.Scope.Validate(); err != nil {
		return err
	}
	if c.MaxToolCalls <= 0 {
		return errors.New("loopexec: config max_tool_calls must be positive (zero/negative bound denies the run — configure an explicit limit)")
	}
	for _, name := range c.AllowedTools {
		if _, _, ok := SplitToolName(name); !ok {
			return fmt.Errorf("loopexec: allowed tool %q must be server-qualified (%q)", name, "server:tool")
		}
	}
	return nil
}

// Allows reports whether the server-qualified tool passes the route
// allow-list. An empty list allows nothing.
func (c Config) Allows(server, tool string) bool {
	name := ToolName(server, tool)
	for _, allowed := range c.AllowedTools {
		if allowed == name {
			return true
		}
	}
	return false
}

// Action is the executor-level action vocabulary, mirroring the grant-action
// dimension of pkg/mcpagg (GrantActionInvoke/GrantActionList): the two things
// a loop asks of a tool surface. v1 executors implement Invoke; List support
// is additive.
type Action string

const (
	// ActionInvoke executes one tool call.
	ActionInvoke Action = "invoke"
	// ActionList discovers the tool surface (tools/list parity).
	ActionList Action = "list"
)

// Call is one executor-addressed tool request. It carries the guard inputs
// (scope, subject, credential reference) next to the addressing so an
// executor can never execute without them: Subject comes from the
// authenticated principal, never from client-controlled input.
type Call struct {
	// Scope is the org/project/route context of the call.
	Scope Scope
	// Server is the registry server name ("yabanin" for built-ins, the MCP
	// server name otherwise).
	Server string
	// Tool is the tool name within the server.
	Tool string
	// Action selects invoke (v1 executors) or list.
	Action Action
	// Params are the model-proposed arguments; the guard path — not the
	// model — decides whether they may execute.
	Params json.RawMessage
	// Subject is the authenticated principal the call runs for (guard and
	// audit input). Required.
	Subject string
	// Credential selects service or delegated-user credentials per
	// connection configuration and policy (I54); a denied user grant never
	// silently escalates to a service credential.
	Credential agentloop.CredentialRef
}

// Result is the post-guard outcome of one executed call. Payload is what the
// guard path released (result rules already applied); SideEffect uses the
// shared agentloop vocabulary so uncertain external effects stay uncertain
// across the whole stack.
type Result struct {
	Server     string
	Tool       string
	Payload    json.RawMessage
	SideEffect agentloop.SideEffect
	LatencyMS  int64
}

// Sentinel errors shared across the seam. Implementations wrap them with %w
// so callers classify with errors.Is without importing implementation
// packages.
var (
	// ErrNoExecutor reports that no executor is registered for the call's
	// server. Fail-closed: an unaddressable call never executes.
	ErrNoExecutor = errors.New("loopexec: no executor registered for server")

	// ErrNotPermitted reports that the call is refused by the route
	// configuration (allow-list, action vocabulary or bounds) — a policy
	// refusal, distinct from an unknown tool.
	ErrNotPermitted = errors.New("loopexec: call not permitted by route configuration")

	// ErrUnknownTool reports that the requested tool does not exist on the
	// addressed server.
	ErrUnknownTool = errors.New("loopexec: tool not registered on server")

	// ErrSubjectRequired reports a call without an authenticated subject.
	ErrSubjectRequired = errors.New("loopexec: call subject is required")
)

// Executor executes tool calls under a validated route configuration.
// Invariants:
//
//   - Fail-closed: a call that cannot be authorized (config, guard or
//     infrastructure) is refused with a wrapped sentinel or a typed error —
//     it never executes unguarded.
//   - Scoped: the executor honors Config.Scope; a call whose scope differs
//     from the config is refused rather than silently re-scoped.
//   - Guard-first: execution happens only after the deployment's guard path
//     (tool policy, args rules) admitted the concrete call — the executor
//     never bypasses or re-implements it.
//   - Honest effects: SideEffect classifies the external effect; an unknown
//     outcome is agentloop.SideEffectUncertain, never a fabricated success.
type Executor interface {
	// Execute runs one call addressed by cfg/call and reports the post-guard
	// result.
	Execute(ctx context.Context, cfg Config, call Call) (Result, error)
}

// Registry is the executor registration seam. Core and deployment extensions
// register per-server executors (the core-owned builtin adapter registers
// "yabanin"; MCP aggregation registers by server name); engines resolve
// through it. Registration is write-once: a duplicate name is refused so
// wiring cannot be silently overridden — re-wiring requires a new Registry.
type Registry struct {
	mu       sync.RWMutex
	byServer map[string]Executor
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{byServer: map[string]Executor{}}
}

// Register binds executor to the server name. The server name must be a
// lowercase identifier (the route-name shape); the executor must be
// non-nil. A duplicate registration is refused.
func (r *Registry) Register(server string, e Executor) error {
	if !routeNameRe.MatchString(server) {
		return fmt.Errorf("loopexec: registry server name %q must match %s", server, routeNameRe)
	}
	if e == nil {
		return errors.New("loopexec: registry executor must be non-nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byServer[server]; dup {
		return fmt.Errorf("loopexec: executor for server %q already registered", server)
	}
	r.byServer[server] = e
	return nil
}

// Executor returns the executor registered for the server.
func (r *Registry) Executor(server string) (Executor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.byServer[server]
	return e, ok
}

// Execute implements Executor by dispatching to the executor registered for
// call.Server. An unregistered server is refused (fail-closed).
func (r *Registry) Execute(ctx context.Context, cfg Config, call Call) (Result, error) {
	e, ok := r.Executor(call.Server)
	if !ok {
		return Result{}, fmt.Errorf("%w: %q", ErrNoExecutor, call.Server)
	}
	return e.Execute(ctx, cfg, call)
}
