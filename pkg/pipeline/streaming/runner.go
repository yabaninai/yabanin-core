package streaming

import (
	"context"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Runner executes pre-selected compiled policies against one payload — the
// seam between the gateway middleware and the pipeline engine. Production
// wires it with EngineRunner; tests substitute fakes.
type Runner interface {
	// Run must not modify p (the engine clones it) and must honor ctx.
	Run(ctx context.Context, p *pipeline.Payload) *pipeline.Result
}

// RunnerFunc adapts a function to Runner.
type RunnerFunc func(ctx context.Context, p *pipeline.Payload) *pipeline.Result

// Run implements Runner.
func (f RunnerFunc) Run(ctx context.Context, p *pipeline.Payload) *pipeline.Result {
	return f(ctx, p)
}

// EngineRunner adapts a pipeline engine with pre-filtered, priority-ordered
// compiled policies (attach selection is the caller's job, plan §2.2 п.0)
// to Runner. The engine clones the payload per run, so the caller's payload
// is never modified. A nil engine fail-closes (deny) instead of panicking.
func EngineRunner(e *pipeline.Engine, policies []pipeline.Compiled) Runner {
	return RunnerFunc(func(ctx context.Context, p *pipeline.Payload) *pipeline.Result {
		if e == nil {
			return &pipeline.Result{
				Verdict: pipeline.ActionDeny,
				Trace: []pipeline.StepTrace{{
					Step:    "streaming",
					Outcome: pipeline.StepError,
					Error:   "nil engine",
				}},
			}
		}
		return e.Run(ctx, policies, p)
	})
}

// payloadText extracts the inspected text of a payload: all message contents
// joined with "\n"; when no message has content, Body; when both are absent,
// StreamChunk — the same convention as the builtin steps, so a released
// buffer always matches what detectors observed.
func payloadText(p *pipeline.Payload) string {
	if p == nil {
		return ""
	}
	var sb strings.Builder
	for _, m := range p.Messages {
		if m.Content == "" {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(m.Content)
	}
	if sb.Len() > 0 {
		return sb.String()
	}
	if len(p.Body) > 0 {
		return string(p.Body)
	}
	return p.StreamChunk
}
