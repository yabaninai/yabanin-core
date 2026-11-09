// connects the declarative route_hint step to the gateway's real provider
// selection. The registry name is reserved by the pkg/pipeline contract (the
// core's route_hint kind resolves to it with the reserved "target" param);
// the implementation lives here because pkg/pipeline is import-only for the
//
// for hints that cannot influence the route):
//
//   - The step runs inside a pre_upstream policy and records its target (a
//     provider name, e.g. "anthropic") into the request-scoped Sink that the
//     gateway installs before policy evaluation. Shadow-mode policies never
//     record (a shadow observation must not change routing) and a request
//     without a Sink (other hooks, runtime off) leaves the step a no-op.
//   - The first recorded hint wins: policies compose in attachment-priority
//     order (org → key → model), so the highest-priority hint is applied and
//     later hints cannot silently override it. The run stays deterministic.
//   - After evaluation the gateway moves the collected hint onto the request
//     context; the fallback executor reorders the candidate chain so
//     hinted-provider candidates are attempted first (pkg/router
//     ExecuteWithProviderHint). The hint only reorders already-allowed
//     candidates: it never adds providers and every candidate still passes
//     the per-attempt policy gate, so region and access decisions are
//     untouched.
//     route fails explicitly with 400 route_hint_unsatisfiable instead of
//     being silently ignored — an unmatched hint on a chained pipeline
//     (router.HintRefusal before any dial) or a hint foreign to the serving
//     provider on a chainless native endpoint (gateway
//     enforceSingularRouteHint). Region and access refusals stay with the
//     per-attempt gate: a hinted candidate the identity may not use is a
//     terminal gate denial, never routed around.
//
// Each applied run appends an allow-ranked finding (category "route_hint") so
// the OP-9 decision record shows which hint a request carried. Evaluation is
// pure and goroutine-safe; the Sink is mutex-guarded (parallel groups are
// possible).
package routehint

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// FactoryName is the registry name (the core's route_hint kind resolves to
// it).
const FactoryName = "route_hint"

// FindingCategory is the finding category the step records; the decision
// record (OP-9) uses it to surface an applied hint.
const FindingCategory = "route_hint"

// Factory builds one route_hint step from the merged params. The reserved
// "target" key carries the hinted provider name (merged by the core, see
// pipeline.StepSpec resolveKind). An empty target is a factory error — policy
// LOAD failure, never a silent skip.
func Factory(params map[string]any) (pipeline.Step, error) {
	target, _ := params["target"].(string)
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("route_hint: target is required")
	}
	return &step{target: target}, nil
}

// step is one compiled route_hint step. Immutable; safe for concurrent Runs.
type step struct {
	target string
}

// Name returns the implementation name for diagnostics.
func (s *step) Name() string { return "gateway/route_hint" }

// Run records the hint into the request-scoped Sink. Enforce-mode policies
// only; without a Sink (hook other than pre_upstream, runtime off, or a
// direct engine use) the step is a no-op — it never mutates and never raises
// the verdict.
func (s *step) Run(ctx context.Context, p *pipeline.Pipeline, _ *pipeline.Payload, out *pipeline.Result) error {
	if p.Mode() != pipeline.ModeEnforce {
		return nil
	}
	sink := SinkFrom(ctx)
	if sink == nil {
		return nil
	}
	sink.Record(s.target)
	out.Findings = append(out.Findings, pipeline.Finding{
		Step:     p.StepID(),
		Category: FindingCategory,
		Severity: "info",
		Evidence: s.target,
		Action:   pipeline.ActionAllow,
	})
	return nil
}

// Sink is the per-request collector the evaluation path installs in the
// context and the step records into. First hint wins (see the package
// comment); the zero value is ready to use and nil-safe.
type Sink struct {
	mu   sync.Mutex
	hint string
}

// Record stores target unless a hint was already recorded.
func (s *Sink) Record(target string) {
	if s == nil || target == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hint == "" {
		s.hint = target
	}
}

// Hint returns the recorded hint ("" when none).
func (s *Sink) Hint() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hint
}

type sinkCtxKey struct{}
type hintCtxKey struct{}

// WithSink returns a context carrying s for the policy evaluation.
func WithSink(ctx context.Context, s *Sink) context.Context {
	return context.WithValue(ctx, sinkCtxKey{}, s)
}

// SinkFrom returns the Sink in ctx (nil when absent).
func SinkFrom(ctx context.Context) *Sink {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(sinkCtxKey{}).(*Sink)
	return s
}

// WithHint returns a context carrying an applied route hint ("" clears).
func WithHint(ctx context.Context, hint string) context.Context {
	return context.WithValue(ctx, hintCtxKey{}, hint)
}

// HintFrom returns the applied route hint in ctx ("" when absent).
func HintFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	hint, _ := ctx.Value(hintCtxKey{}).(string)
	return hint
}
