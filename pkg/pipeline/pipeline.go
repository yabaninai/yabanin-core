// Package pipeline is the pure core of the Yabanin Policy Pipeline (YPP):
// payload/finding/result types, the Step contract, YAML→pipeline compilation
// and the execution engine. It intentionally has NO database, HTTP, LLM or
// logging side effects: detector/mutator/callout/llm-judge/script/streaming
// implementations live in sibling packages (builtins, callout, llmjudge,
// script, streaming — waves OP-1..OP-7) and are wired in through the step
// Registry and the script-engine seam at policy compile time.
//
//   - Payload is the single request model for every hook: Kind is exactly one
//     of request | response | stream_prefix | stream_final | tool_args |
//     tool_result; Endpoint names the gateway surface (chat, messages,
//     responses, embeddings, mcp.invoke, ...).
//   - Action strictness is fixed: deny > mask > flag > allow (Action.Max /
//     Action.Rank). Unrecognized actions are fail-closed: they rank as deny
//     and normalize to deny.
//   - Result.Findings is the union of every executed step's findings;
//     Result.Verdict is the most restrictive action observed (enforce-mode
//     policies only — shadow findings never raise the verdict);
//     Result.Mutated is non-nil iff an enforce-mode policy actually changed
//     the payload (nil = unchanged); Result.Trace records EVERY compiled
//     step of EVERY passed pipeline exactly once — ran, skipped, timed out
//     or failed — with duration and error. Trace is never truncated by deny
//     short-circuits.
//   - Engine.Run composes MULTIPLE compiled policies: the caller filters by
//     attach and orders them by attachment priority (org → key → model); the
//     engine preserves that order. Findings union across policies; the
//     verdict is the most restrictive; the first deny short-circuits all
//     remaining work (remaining steps traced as skipped). Detectors always
//     observe the latest mutated payload — including across policy
//     boundaries.
//   - `when` conditions compile ONCE at policy load through a registered
//     script engine (pkg/pipeline/script seam; OP-7 owns implementations).
//     A condition with no registered engine is a policy LOAD error, never a
//     silent skip.
//   - Mode shadow never mutates the carried payload and never raises the
//     composed verdict; its findings are recorded for diff reports
//     (shadow_compare parity, OP-9).
//
// Determinism: for identical inputs (payload, compiled policies, step
// implementations) Run produces findings and traces in declaration order and
// a single verdict. Parallel groups execute concurrently but always join and
// merge in declaration order; only durations vary between runs.
package pipeline

import (
	"maps"
	"slices"
	"time"
)

// PayloadKind identifies which gateway hook produced a payload.
type PayloadKind string

// Payload kinds. Exactly one is set on every Payload.
const (
	KindRequest      PayloadKind = "request"       // full non-streaming request
	KindResponse     PayloadKind = "response"      // full non-streaming response
	KindStreamPrefix PayloadKind = "stream_prefix" // buffered stream prefix (OP-4)
	KindStreamFinal  PayloadKind = "stream_final"  // full stream aggregate (OP-4)
	KindToolArgs     PayloadKind = "tool_args"
	KindToolResult   PayloadKind = "tool_result" // tool/MCP invocation result
)

// Valid reports whether k is one of the six defined payload kinds.
func (k PayloadKind) Valid() bool {
	switch k {
	case KindRequest, KindResponse, KindStreamPrefix, KindStreamFinal, KindToolArgs, KindToolResult:
		return true
	default:
		return false
	}
}

// Message is one chat message of the conversation under inspection.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// RequestMeta carries the routing identity of the request the payload came
// from. Steps must treat it as read-only: mutations are undefined behaviour
// and never reach the composed Result.Mutated.
type RequestMeta struct {
	Org      string            `json:"org"`
	Key      string            `json:"key"`
	Model    string            `json:"model"`
	Provider string            `json:"provider"`
	Labels   map[string]string `json:"labels,omitempty"`
	Tags     []string          `json:"tags,omitempty"`
}

// Payload is the single model passed through every pipeline hook. The engine
// hands each Run a private deep clone (Payload.Clone); the caller's payload
// is never modified by a run. Mutator steps edit the clone in place; every
// other step must treat it as read-only.
type Payload struct {
	Kind        PayloadKind  `json:"kind"`
	Endpoint    string       `json:"endpoint,omitempty"`
	Messages    []Message    `json:"messages,omitempty"`
	Body        []byte       `json:"body,omitempty"`
	StreamChunk string       `json:"stream_chunk,omitempty"`
	Meta        *RequestMeta `json:"meta,omitempty"`
	// Headers carries the upstream request headers of a request payload
	// (builtin/header-rewrite, OP-5). Nil means "no headers known" — every
	// producer, clone and comparison treats nil identically to an empty map,
	// so existing payloads and step implementations are unaffected. Populated
	// only on request payloads; steps must not read it as request META
	// (identity lives in Meta).
	Headers map[string]string `json:"headers,omitempty"`
}

// Clone returns a deep copy of p: the Messages slice, Body bytes, the Meta
// struct (including its Labels map and Tags slice) and the Headers map are
// all duplicated, so mutating the clone can never be observed through p. A
// nil payload clones to nil.
func (p *Payload) Clone() *Payload {
	if p == nil {
		return nil
	}
	c := *p
	if p.Messages != nil {
		c.Messages = slices.Clone(p.Messages)
	}
	if p.Body != nil {
		c.Body = slices.Clone(p.Body)
	}
	if p.Meta != nil {
		m := *p.Meta
		m.Labels = maps.Clone(p.Meta.Labels)
		m.Tags = slices.Clone(p.Meta.Tags)
		c.Meta = &m
	}
	c.Headers = maps.Clone(p.Headers)
	return &c
}

// Action is the strictness-ordered verdict vocabulary of the pipeline.
// Composition is always "most restrictive wins".
type Action string

// Actions in strictness order: deny > mask > flag > allow.
const (
	ActionDeny  Action = "deny"  // block the request/tool/stream
	ActionMask  Action = "mask"  // proceed, but only with a mutated payload
	ActionFlag  Action = "flag"  // proceed unchanged, record the observation
	ActionAllow Action = "allow" // nothing to act on
)

// Rank returns the strictness of a on the fixed scale deny(3) > mask(2) >
// flag(1) > allow(0). Unrecognized values rank as deny (fail closed: an
// unknown action from a buggy step can never loosen the verdict).
func (a Action) Rank() int {
	switch a {
	case ActionDeny:
		return 3
	case ActionMask:
		return 2
	case ActionFlag:
		return 1
	case ActionAllow:
		return 0
	default:
		return 3
	}
}

// Max returns the more restrictive of a and b on the fixed strictness scale.
// Unrecognized values normalize to deny before being returned, so Max can
// never yield an action outside the defined vocabulary.
func (a Action) Max(b Action) Action {
	if a.Rank() >= b.Rank() {
		return a.normalized()
	}
	return b.normalized()
}

// normalized maps unknown actions to deny (fail closed; see Rank).
func (a Action) normalized() Action {
	switch a {
	case ActionDeny, ActionMask, ActionFlag, ActionAllow:
		return a
	default:
		return ActionDeny
	}
}

// Finding is one observation a step attached to the result.
type Finding struct {
	// Step is the compiled step id that produced the finding.
	Step string `json:"step"`
	// Category is the detector-defined class (e.g. "innsnils", "pan",
	// "presidio.*"; "step_error" is reserved for synthetic on_error flags).
	Category string `json:"category"`
	// Severity is a free-form detector-defined scale; builtin detectors
	// converge on low | medium | high.
	Severity string `json:"severity"`
	// Span locates the evidence inside the inspected text in a
	// detector-defined format (e.g. "start:end" byte offsets).
	Span string `json:"span,omitempty"`
	// Evidence is a bounded excerpt or description. Callers must treat it as
	// sensitive: it may quote user content, so decision-log persistence
	// stores hashes only (OP-9) unless shadow/debug retention applies.
	Evidence string `json:"evidence,omitempty"`
	// Action is the strictness this finding contributes to the verdict.
	Action Action `json:"action"`
}

// StepOutcome classifies how one step ended in the trace.
type StepOutcome string

// Step outcomes. Every compiled step gets exactly one per run.
const (
	// StepRan: the step executed to completion without error.
	StepRan StepOutcome = "ran"
	// StepSkipped: the step did not execute — its `when` condition was
	// false, an earlier step denied (short-circuit), or the caller's context
	// was already cancelled.
	StepSkipped StepOutcome = "skipped"
	// StepError: the step returned an error or panicked (panics are
	// recovered and recorded here; on_error semantics apply).
	StepError StepOutcome = "error"
	// StepTimeout: the step exceeded its configured timeout. on_error
	// semantics apply to StepTimeout exactly as to StepError.
	StepTimeout StepOutcome = "timeout"
)

// StepTrace is the per-step record. The engine writes one for every
// compiled step of every passed pipeline on every run — decision-log (OP-9)
// and the shadow→enforce diff reports depend on this completeness.
type StepTrace struct {
	// Step is the compiled step id (unique inside a policy).
	Step string `json:"step"`
	// Duration is the wall-clock cost of the step including condition
	// evaluation; 0 for steps that never executed.
	Duration time.Duration `json:"duration"`
	// Outcome classifies how the step ended.
	Outcome StepOutcome `json:"outcome"`
	// Error carries the failure message for outcomes error and timeout
	// (and a skip reason for skipped steps); empty otherwise.
	Error string `json:"error,omitempty"`
}

// Result is the composed outcome of one Engine.Run.
type Result struct {
	// Verdict is the most restrictive action of all enforce-mode findings
	// and explicit step verdicts (deny > mask > flag > allow). Shadow-mode
	// findings never raise it.
	Verdict Action `json:"verdict"`
	// Findings is the union of every executed step's findings in
	// declaration order (across all passed pipelines). Shadow-mode findings
	// are included.
	Findings []Finding `json:"findings,omitempty"`
	// Mutated points at the final payload iff an enforce-mode policy
	// changed it; nil means unchanged. Engine-owned: steps must not set it.
	Mutated *Payload `json:"mutated,omitempty"`
	// Trace records every compiled step of every passed pipeline exactly
	// once, in declaration order — including skipped and short-circuited
	// steps. Engine-owned: steps must not append to it.
	Trace []StepTrace `json:"trace,omitempty"`
	// ShadowVerdict (CORE-TRACE-05) is the verdict the run's shadow-mode
	// policies would have composed in enforce mode (deny > mask > flag >
	// allow), accumulated across pipelines; ActionAllow when no shadow
	// pipeline ran or none raised an action. It never feeds Verdict —
	// decision-log readers use it to expose the shadow would-have action
	// explicitly instead of burying it in findings.
	ShadowVerdict Action `json:"shadow_verdict,omitempty"`
}

// ShadowAction reports ShadowVerdict with the zero value normalized: a
// zero-value Result (constructed outside Run) reads as allow, matching the
// engine's composed verdict convention.
func (r *Result) ShadowAction() Action {
	if r == nil || r.ShadowVerdict == "" {
		return ActionAllow
	}
	return r.ShadowVerdict
}
