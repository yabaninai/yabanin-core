package builtins

import (
	"context"
	"fmt"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// modelRewriteStep is builtin/model-rewrite: it replaces the request model
// (Payload.Meta.Model) — the data-boundary seam (RM-63..66): a PII finding
// can route the request to an in-region model instead of blocking it.
//
// TRACE NOTE (mandatory): the engine owns Result.Trace and steps must not
// write it, so the rewrite is recorded as a FLAG finding
// (Category "model_rewrite", Severity low, Evidence "<old> → <new>",
// content-free routing data). Decision-log (OP-9) and the admin UI surface
// it through the ordinary findings channel; a rewrite without its note is a
// contract violation, never a silent model swap.
//
// Kinds: request only, non-negotiable (a response's model identity is the
// upstream's, not ours). No-ops: nil Meta, model already == "to", a set
// "from" that does not match the current model.
type modelRewriteStep struct {
	pipeline.MutatorBase
	to   string
	from string // optional exact match requirement
}

// Name returns the step implementation name.
func (*modelRewriteStep) Name() string { return NameModelRewrite }

// Category of the mandatory rewrite note finding.
const modelRewriteCategory = "model_rewrite"

// Run rewrites Meta.Model and appends the note finding. ctx is honored
// before the rewrite.
func (m *modelRewriteStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || in.Kind != pipeline.KindRequest || in.Meta == nil {
		return nil
	}
	if m.from != "" && in.Meta.Model != m.from {
		return nil
	}
	if in.Meta.Model == m.to {
		return nil
	}
	old := in.Meta.Model
	in.Meta.Model = m.to
	out.Findings = append(out.Findings, finding(
		p.StepID(), modelRewriteCategory, sevLow, "",
		clipEvidence(old+" → "+m.to, maxEvidence), pipeline.ActionFlag,
	))
	return nil
}

// NewModelRewrite builds builtin/model-rewrite.
//
// Params: "to" (required target model), "from" (optional: rewrite only when
// the current model equals it). The "kinds" param is rejected — the step is
// request-only by contract.
func NewModelRewrite(params map[string]any) (pipeline.Step, error) {
	if _, ok := params["kinds"]; ok {
		return nil, fmt.Errorf("params.kinds: model-rewrite is request-only; the kinds param is not supported")
	}
	to, err := paramString(params, "to")
	if err != nil {
		return nil, err
	}
	from := ""
	if raw, ok := params["from"]; ok && raw != nil {
		if from, err = paramString(params, "from"); err != nil {
			return nil, err
		}
	}
	return &modelRewriteStep{to: to, from: from}, nil
}

// compile-time guard: model-rewrite is a Mutator.
var _ pipeline.Mutator = (*modelRewriteStep)(nil)
