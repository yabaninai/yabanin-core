package pipeline

import (
	"fmt"
	"strings"
	"time"
)

// APIVersionYPP is the only supported policy apiVersion.
const APIVersionYPP = "ypp/v1"

// KindPolicy is the only supported policy document kind.
const KindPolicy = "Policy"

// Mode selects how a compiled policy may affect traffic.
type Mode string

// Policy modes.
const (
	// ModeEnforce: findings raise the composed verdict and mutators rewrite
	// the carried payload.
	ModeEnforce Mode = "enforce"
	// ModeShadow: the policy NEVER mutates the carried payload and NEVER
	// raises the composed verdict (owner decision 2026-10-06); findings are
	// recorded for "what would have happened" diff reports (OP-9). An
	// org-level kill switch can further downgrade enforce → shadow.
	ModeShadow Mode = "shadow"
)

// Valid reports whether m is a defined mode.
func (m Mode) Valid() bool {
	switch m {
	case ModeEnforce, ModeShadow:
		return true
	default:
		return false
	}
}

// Hook names the gateway surface a policy attaches to. Which hook fires with
// which Payload kind is decided by the gateway middleware (OP-8), the single
// integration point.
type Hook string

// Gateway hooks.
const (
	HookPreUpstream  Hook = "pre_upstream"  // before the upstream call
	HookPostUpstream Hook = "post_upstream" // after the upstream response
	HookStreamPrefix Hook = "stream_prefix" // buffered stream prefix (OP-4)
	HookStreamFinal  Hook = "stream_final"  // full stream aggregate (OP-4)
	HookToolPre      Hook = "tool_pre"
	HookToolPost     Hook = "tool_post" // after a tool/MCP invocation
)

// Valid reports whether h is a defined hook.
func (h Hook) Valid() bool {
	switch h {
	case HookPreUpstream, HookPostUpstream, HookStreamPrefix, HookStreamFinal, HookToolPre, HookToolPost:
		return true
	default:
		return false
	}
}

// AllHooks returns every defined hook, sorted (for error messages).
func AllHooks() []Hook {
	return []Hook{HookPostUpstream, HookPreUpstream, HookStreamFinal, HookStreamPrefix, HookToolPost, HookToolPre}
}

// OnError selects what a step failure — error, panic or timeout — does to
// the policy run. Steps that omit on_error default to fail_closed (secure by
// default).
type OnError string

// on_error modes.
const (
	// OnErrorFailClosed: the failure denies the run (verdict deny) and
	// short-circuits the remaining steps of the policy.
	OnErrorFailClosed OnError = "fail_closed"
	// OnErrorFailOpen: the failure is recorded in Trace and ignored.
	OnErrorFailOpen OnError = "fail_open"
	// OnErrorFailOpenFlag: like fail_open, plus a synthetic finding
	// {Category: "step_error", Severity: "warning", Action: flag, Evidence:
	// error message} so downstream gates can observe the degradation.
	OnErrorFailOpenFlag OnError = "fail_open+flag"
)

// Valid reports whether o is a defined on_error mode.
func (o OnError) Valid() bool {
	switch o {
	case OnErrorFailClosed, OnErrorFailOpen, OnErrorFailOpenFlag:
		return true
	default:
		return false
	}
}

// Attach is the declarative attachment selector of a policy. Fields are
// OR-combined; lists are AND-compressed inside a field (a request matches
// when any listed value matches in at least one non-empty field). Matching
// itself lives in policystore/gateway (OP-0b/OP-8); the core only carries
// and validates the data.
type Attach struct {
	// Orgs lists org ids the policy attaches to.
	Orgs []string `yaml:"org,omitempty" json:"org,omitempty"`
	// KeyLabels lists API-key labels ("prod") the policy attaches to.
	KeyLabels []string `yaml:"key_labels,omitempty" json:"key_labels,omitempty"`
	// ModelPatterns lists glob patterns over model names ("*", "gpt-4o").
	ModelPatterns []string `yaml:"model_patterns,omitempty" json:"model_patterns,omitempty"`
	// Endpoints lists gateway endpoints ("chat", "messages", "mcp.invoke").
	Endpoints []string `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
}

// LLMJudgeSpec is the declarative llm_judge step kind payload. The judge
// implementation itself is OP-3, registered under the "llm_judge" factory
// name; model/prompt_ref travel to it as reserved params.
type LLMJudgeSpec struct {
	// Model is the judge model reference; "$(sovereign-classifier)" style
	// indirections are resolved by OP-3, not by the core.
	Model string `yaml:"model" json:"model"`
	// PromptRef is the versioned judge prompt resource ("judges/toxicity@2").
	PromptRef string `yaml:"prompt_ref,omitempty" json:"prompt_ref,omitempty"`
}

// StepSpec is one declarative pipeline step. Exactly ONE kind field must be
// set: detector | mutator | callout | llm_judge | decide | route_hint.
// Unknown YAML fields are load errors (strict decoding) — options not fixed
// by this schema (e.g. ssrf allow-lists for callout, reversible for
// mutators) travel inside params.
type StepSpec struct {
	// ID is the step identity: unique within the policy, and the key used
	// in Trace, `when` step references and decision-log (OP-9).
	ID string `yaml:"id" json:"id"`

	// Exactly one of the following kind fields is allowed.
	Detector  string        `yaml:"detector,omitempty" json:"detector,omitempty"`
	Mutator   string        `yaml:"mutator,omitempty" json:"mutator,omitempty"`
	Callout   string        `yaml:"callout,omitempty" json:"callout,omitempty"`
	LLMJudge  *LLMJudgeSpec `yaml:"llm_judge,omitempty" json:"llm_judge,omitempty"`
	Decide    string        `yaml:"decide,omitempty" json:"decide,omitempty"`
	RouteHint string        `yaml:"route_hint,omitempty" json:"route_hint,omitempty"`

	// When is an optional condition source (OP-7 seam), evaluated at run
	// time against findings-so-far / meta / step traces. Compilation happens
	// once at policy load: with no registered condition engine the policy
	// fails to LOAD, never silently skips.
	When string `yaml:"when,omitempty" json:"when,omitempty"`
	// WhenEngine pins the condition engine by registry name. Optional when
	// exactly one engine is registered (then it is the default); required
	// once two or more are registered.
	WhenEngine string `yaml:"when_engine,omitempty" json:"when_engine,omitempty"`

	// Timeout bounds one Run of the step, parsed with time.ParseDuration
	// ("50ms", "2s"); must be > 0 when set. Empty means unbounded by the
	// policy (still bounded by the caller's request context). The engine
	// records outcome timeout when the budget expires; on_error semantics
	// apply.
	Timeout string `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// OnError selects the failure mode; default fail_closed.
	OnError OnError `yaml:"on_error,omitempty" json:"on_error,omitempty"`

	// Parallel lists step ids of this policy that execute concurrently with
	// this step as one join group (this step is the group head). Every
	// participant — head and members — MUST resolve to a Detector (groups
	// are read-only inspection; mutators are a compile error). A step may
	// belong to at most one group; members must not declare their own
	// parallel list (no nested groups).
	Parallel []string `yaml:"parallel,omitempty" json:"parallel,omitempty"`

	// Params are passed to the step factory and back to the step at run
	// time (Pipeline.Params). Kind-reserved keys are merged in and collide
	// as compile errors: callout → "url"; llm_judge → "model",
	// "prompt_ref"; decide → "expr"; route_hint → "target".
	Params map[string]any `yaml:"params,omitempty" json:"params,omitempty"`
}

// Policy is the declarative YAML policy model (apiVersion ypp/v1). YAML is
// the source of truth (git → reconciliation); policystore versions and
// attaches it.
type Policy struct {
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	Kind       string `yaml:"kind" json:"kind"`
	// Name is the policy identity used in metrics, decision-log and error
	// messages; required.
	Name   string     `yaml:"name" json:"name"`
	Attach Attach     `yaml:"attach,omitempty" json:"attach,omitempty"`
	Mode   Mode       `yaml:"mode" json:"mode"`
	Hooks  []Hook     `yaml:"hooks" json:"hooks"`
	Steps  []StepSpec `yaml:"steps" json:"steps"`
}

// Validate checks the policy structure WITHOUT resolving steps or
// conditions (no registries needed): apiVersion/kind, name, mode, hooks,
// attachment entries, step kinds, ids, timeouts, on_error values and the
// parallel-group shape. Compile repeats it before resolution.
func (p Policy) Validate() error {
	if p.APIVersion != APIVersionYPP {
		return fmt.Errorf("apiVersion %q: want %q", p.APIVersion, APIVersionYPP)
	}
	if p.Kind != KindPolicy {
		return fmt.Errorf("kind %q: want %q", p.Kind, KindPolicy)
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.Mode == "" {
		return fmt.Errorf("mode is required (shadow|enforce)")
	}
	if !p.Mode.Valid() {
		return fmt.Errorf("mode %q: want shadow|enforce", p.Mode)
	}
	if len(p.Hooks) == 0 {
		return fmt.Errorf("hooks: at least one hook is required (available: %s)", hookList())
	}
	seenHooks := make(map[Hook]bool, len(p.Hooks))
	for _, h := range p.Hooks {
		if !h.Valid() {
			return fmt.Errorf("hook %q: unknown (available: %s)", h, hookList())
		}
		if seenHooks[h] {
			return fmt.Errorf("hook %q: duplicated", h)
		}
		seenHooks[h] = true
	}
	if err := validateAttach(p.Attach); err != nil {
		return err
	}
	if len(p.Steps) == 0 {
		return fmt.Errorf("steps: at least one step is required")
	}
	return validateSteps(p.Name, p.Steps)
}

// validateAttach rejects empty entries (an empty org/label/pattern would
// otherwise attach to everything or nothing depending on the matcher).
func validateAttach(a Attach) error {
	for _, list := range [][]string{a.Orgs, a.KeyLabels, a.ModelPatterns, a.Endpoints} {
		for _, v := range list {
			if v == "" {
				return fmt.Errorf("attach: empty entries are not allowed")
			}
		}
	}
	return nil
}

// validateSteps enforces id uniqueness, exactly-one kind, timeout/on_error
// values and the parallel-group shape.
func validateSteps(policyName string, steps []StepSpec) error {
	ids := make(map[string]bool, len(steps))
	for i := range steps {
		s := &steps[i]
		if s.ID == "" {
			return fmt.Errorf("policy %q, step %d: id is required", policyName, i)
		}
		if ids[s.ID] {
			return fmt.Errorf("policy %q: step id %q duplicated", policyName, s.ID)
		}
		ids[s.ID] = true

		if _, err := s.resolveKind(); err != nil {
			return fmt.Errorf("policy %q, step %q: %w", policyName, s.ID, err)
		}
		if s.Timeout != "" {
			d, err := time.ParseDuration(s.Timeout)
			if err != nil {
				return fmt.Errorf("policy %q, step %q: invalid timeout %q: %w", policyName, s.ID, s.Timeout, err)
			}
			if d <= 0 {
				return fmt.Errorf("policy %q, step %q: timeout %q must be positive", policyName, s.ID, s.Timeout)
			}
		}
		if s.OnError != "" && !s.OnError.Valid() {
			return fmt.Errorf("policy %q, step %q: on_error %q: want fail_closed|fail_open|fail_open+flag", policyName, s.ID, s.OnError)
		}
	}
	return validateParallelGroups(policyName, steps, ids)
}

// validateParallelGroups checks that every parallel reference resolves, no
// step belongs to two groups, no member declares its own group, and no step
// lists itself.
func validateParallelGroups(policyName string, steps []StepSpec, ids map[string]bool) error {
	grouped := make(map[string]string) // member id -> group head id
	for i := range steps {
		head := &steps[i]
		if len(head.Parallel) == 0 {
			continue
		}
		seen := make(map[string]bool, len(head.Parallel))
		for _, m := range head.Parallel {
			switch {
			case m == head.ID:
				return fmt.Errorf("policy %q, step %q: cannot list itself in parallel", policyName, head.ID)
			case !ids[m]:
				return fmt.Errorf("policy %q, step %q: parallel member %q is not a step of this policy", policyName, head.ID, m)
			case seen[m]:
				return fmt.Errorf("policy %q, step %q: parallel member %q listed twice", policyName, head.ID, m)
			case steps[lookupStep(steps, m)].OwnsParallelGroup():
				return fmt.Errorf("policy %q, step %q: parallel member %q must not declare its own parallel group (nested groups are not supported)", policyName, head.ID, m)
			case grouped[m] != "":
				return fmt.Errorf("policy %q: step %q is already a parallel member of step %q", policyName, m, grouped[m])
			}
			seen[m] = true
			grouped[m] = head.ID
		}
	}
	return nil
}

// OwnsParallelGroup reports whether the step declares its own parallel group.
func (s *StepSpec) OwnsParallelGroup() bool { return len(s.Parallel) > 0 }

// lookupStep returns the index of id in steps (ids are pre-validated unique).
func lookupStep(steps []StepSpec, id string) int {
	for i := range steps {
		if steps[i].ID == id {
			return i
		}
	}
	return -1
}

// resolvedKind is the registry resolution of one step kind field.
type resolvedKind struct {
	kind     string         // detector | mutator | callout | llm_judge | decide | route_hint
	registry string         // factory name to look up
	extra    map[string]any // kind-reserved params merged into step params
}

// stepKinds enumerates the kind fields for error messages.
const stepKinds = "detector|mutator|callout|llm_judge|decide|route_hint"

// resolveKind determines which single kind field is set and maps it to the
// registry lookup name plus reserved params (see StepSpec.Params). An empty
// or ambiguous kind set is an error.
func (s *StepSpec) resolveKind() (resolvedKind, error) {
	set := make([]string, 0, 2)
	if s.Detector != "" {
		set = append(set, "detector")
	}
	if s.Mutator != "" {
		set = append(set, "mutator")
	}
	if s.Callout != "" {
		set = append(set, "callout")
	}
	if s.LLMJudge != nil {
		set = append(set, "llm_judge")
	}
	if s.Decide != "" {
		set = append(set, "decide")
	}
	if s.RouteHint != "" {
		set = append(set, "route_hint")
	}
	switch len(set) {
	case 0:
		return resolvedKind{}, fmt.Errorf("exactly one kind field is required (%s)", stepKinds)
	case 1:
		// fall through to resolution below
	default:
		return resolvedKind{}, fmt.Errorf("kind fields %s are mutually exclusive", joinComma(set))
	}

	switch set[0] {
	case "detector":
		return resolvedKind{kind: "detector", registry: s.Detector}, nil
	case "mutator":
		return resolvedKind{kind: "mutator", registry: s.Mutator}, nil
	case "callout":
		return resolvedKind{kind: "callout", registry: "callout", extra: map[string]any{"url": s.Callout}}, nil
	case "llm_judge":
		if s.LLMJudge.Model == "" {
			return resolvedKind{}, fmt.Errorf("llm_judge: model is required")
		}
		extra := map[string]any{"model": s.LLMJudge.Model}
		if s.LLMJudge.PromptRef != "" {
			extra["prompt_ref"] = s.LLMJudge.PromptRef
		}
		return resolvedKind{kind: "llm_judge", registry: "llm_judge", extra: extra}, nil
	case "decide":
		return resolvedKind{kind: "decide", registry: "decide", extra: map[string]any{"expr": s.Decide}}, nil
	case "route_hint":
		return resolvedKind{kind: "route_hint", registry: "route_hint", extra: map[string]any{"target": s.RouteHint}}, nil
	default:
		return resolvedKind{}, fmt.Errorf("unknown kind %q", set[0])
	}
}

// hookList renders the available hooks for error messages.
func hookList() string {
	names := make([]string, 0, len(availableHooks))
	for _, h := range availableHooks {
		names = append(names, string(h))
	}
	return strings.Join(names, ", ")
}

// availableHooks mirrors AllHooks for error-message helpers.
var availableHooks = AllHooks()

// joinComma renders strings as a comma-separated list.
func joinComma(xs []string) string {
	return strings.Join(xs, ", ")
}
