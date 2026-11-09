// Package llmjudge implements the llm_judge pipeline step (plan card OP-3):
// it sends the inspected content to a judge model through the gateway's own
// upstream-client machinery and converts the model's verdict into pipeline
// findings and a verdict action.
//
// SEAMS (ownership boundaries for downstream lanes):
//
//   - JudgeClient is the pure seam between the pipeline core and model
//     transport. The packaged default implementation is UpstreamJudgeClient,
//     which routes chat.completions through upstream.Pool — the same pool the
//     gateway uses, so sovereign/on-prem models work identically offline.
//     Credential resolution mirrors the gateway's resolveUpstreamKey chain
//     (org BYOK → per-model key → global default) through the KeyResolver
//     interface; the gateway supplies the implementation (OP-8). The judge
//     package NEVER reads credentials itself.
//   - PromptSource supplies versioned judge prompts. The packaged default
//     reads embedded resources: "judges/toxicity@2" resolves to
//     in a store-backed PromptSource via Deps — nothing else changes.
//   - ModelResolver resolves "$(sovereign-classifier)" style indirections
//     through the gateway's normal resolver path (model registry →
//     resolver.ModelInfo). DirectModelResolver is the registry-free default
//     for tests and dev mode.
//
// RECURSION EXCLUSION (contract, enforced here and consumed by the gateway):
// every judge call carries the marker judge=true — in the synthetic payload
// meta (MetaLabelJudge inside RequestMeta.Labels) and on the wire
// (X-Yabanin-Judge header). The gateway middleware MUST treat a payload with
// IsJudgeMeta(meta) == true — the internal synthetic call — as
// pipeline-exempt, so a judge model served by this very gateway cannot
// recurse into judging its own judging. The wire header is NOT an exemption
// signal: any inbound HTTP request carrying JudgeHeader (any value, empty or
// duplicated included) is untrusted and is rejected at the shared
// pre-upstream boundary. The judge step never re-enters Engine.Run itself,
// and the adapter refuses to send unmarked calls; the header marks the
// outbound hop so downstream hops that only see HTTP can recognize it.
//
// WIRING: the gateway registers the step at startup with
// Register(registry, deps) or SetDefaultDeps(deps) + Factory. Policies
// reference it as the "llm_judge" step kind (see pkg/pipeline StepSpec).
//
// Offline positioning: the judge works against ANY model in the registry —
// including sovereign and on-prem classifiers — because transport is the
// gateway's own upstream client pool with SSRF allow-listing intact. No
// external safety API is contacted, ever.
package llmjudge

import (
	"context"
	"sync"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// FactoryName is the pipeline step registry name the judge registers under
// (the "llm_judge" step kind resolves to it, see pkg/pipeline resolveKind).
const FactoryName = "llm_judge"

// Recursion-exclusion markers. MetaLabelJudge is set inside
// RequestMeta.Labels on every judge call's synthetic payload; JudgeHeader is
// its wire-level twin set on the outbound HTTP request.
const (
	MetaLabelJudge  = "judge"
	JudgeLabelValue = "true"
	JudgeHeader     = "X-Yabanin-Judge"

	// CategoryPrefix namespaces judge findings in Result.Findings so `when`
	// conditions and decision-log queries can target judge output without
	// colliding with detector categories ("judge.toxicity", "judge.pii").
	CategoryPrefix = "judge."
)

// IsJudgeMeta is the canonical recursion-exclusion check for INTERNAL judge
// calls: true when the synthetic payload meta carries the judge marker, and
// such a payload MUST NOT re-enter the policy pipeline. It is satisfied only
// by the in-process meta label — never by the wire header, which inbound
// clients control and which the gateway rejects instead of honoring. nil
// meta is never a judge call.
func IsJudgeMeta(m *pipeline.RequestMeta) bool {
	if m == nil {
		return false
	}
	return m.Labels[MetaLabelJudge] == JudgeLabelValue
}

// ChatRequest is one judge-model invocation. Messages use the core Message
// type; the canonical shape is [system: rendered judge prompt, user: content
// under inspection]. Meta is REQUIRED and must carry the judge marker —
// JudgeClient implementations must refuse unmarked requests (the packaged
// adapter enforces this) so the recursion exclusion cannot be lost in
// transit.
type ChatRequest struct {
	// ModelRef is the raw policy value ("gpt-4o-mini",
	// "$(sovereign-classifier)"). Resolution to a concrete endpoint happens
	// inside the client via ModelResolver.
	ModelRef string
	// Messages is the chat to send to the judge model.
	Messages []pipeline.Message
	// Temperature: the step pins 0 for verdict determinism.
	Temperature float64
	// MaxTokens bounds the judge completion (the verdict schema is small).
	MaxTokens int
	// ResponseJSON asks the upstream for JSON mode when true (OpenAI
	// response_format); parsers still tolerate fenced/plain JSON.
	ResponseJSON bool
	// Meta is the synthetic request meta carrying the judge marker
	// (IsJudgeMeta) plus the org identity used for credential resolution.
	Meta *pipeline.RequestMeta
}

// ChatResponse is the judge model's answer: Content is the raw completion
// text (expected to be the JSON verdict), Model the resolved model name for
// observability.
type ChatResponse struct {
	Content string
	Model   string
}

// JudgeClient performs judge-model chat completions. Implementations must be
// safe for concurrent use (the engine may run judge steps in parallel
// groups), must honor ctx cancellation/deadlines, and must propagate the
// judge marker to the transport (MetaLabelJudge in meta, JudgeHeader on the
// wire).
type JudgeClient interface {
	JudgeChat(ctx context.Context, req ChatRequest) (ChatResponse, error)
}

// Deps bundles the collaborators the judge step needs. Client is required at
// compile time; a nil Prompts falls back to the embedded judge prompts; a
// nil Client is a policy LOAD error (never a silent skip at request time).
type Deps struct {
	Client  JudgeClient
	Prompts PromptSource
}

var (
	defaultsMu sync.RWMutex
	defaults   Deps
)

// SetDefaultDeps installs the process-wide judge dependencies used by
// Factory (the registration shape the gateway uses when its wiring code
// cannot reach FactoryWith). Call once at startup, before any policy load.
func SetDefaultDeps(d Deps) {
	defaultsMu.Lock()
	defer defaultsMu.Unlock()
	defaults = d
}

// DefaultDeps returns the currently installed process-wide dependencies.
func DefaultDeps() Deps {
	defaultsMu.RLock()
	defer defaultsMu.RUnlock()
	return defaults
}

// Register wires the judge step into a pipeline step registry under its
// "llm_judge" factory name. This is the canonical gateway integration point
// (OP-8).
func Register(r *pipeline.Registry, deps Deps) error {
	return r.Register(FactoryName, FactoryWith(deps))
}

// Factory builds judge steps from the process-wide default deps (see
// SetDefaultDeps). It satisfies pipeline.StepFactory directly.
func Factory(params map[string]any) (pipeline.Step, error) {
	return FactoryWith(DefaultDeps())(params)
}

// FactoryWith returns a pipeline.StepFactory bound to the given deps. The
// factory runs at policy compile time: every configuration error (missing
// client wiring, unknown prompt ref, bad threshold) surfaces as a policy
// LOAD error, never at request time.
func FactoryWith(deps Deps) pipeline.StepFactory {
	return func(params map[string]any) (pipeline.Step, error) {
		return newJudge(deps, params)
	}
}
