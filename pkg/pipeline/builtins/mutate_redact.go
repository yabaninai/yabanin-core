package builtins

import (
	"context"
	"fmt"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// redactStep is builtin/redact: it replaces the sensitive spans of the run's
// findings (and/or its own configured patterns) with
// "[REDACTED:<category>:n]" tokens. n is the 1-based ordinal of the
// replacement within the payload, assigned in text order — the token is
// self-describing (what class of data was removed, which occurrence) without
// quoting any content.
//
// Spans: findings must carry Span "start:end" byte offsets into payloadText
// (the OP-1 detector convention); findings without a span are skipped
// (e.g. credential-keyed values). Own patterns additionally append a FLAG
// finding per match (span + category, evidence always EMPTY — the matched
// text is sensitive by definition and is never quoted).
//
// Kinds: request, response, tool_args, tool_result by default (stream kinds
// belong to OP-4); "kinds" overrides. Text beyond "max_input"
// (default 1 MiB, cap 64 MiB) fails the step fail-closed.
type redactStep struct {
	pipeline.MutatorBase
	cfg spanMutator
}

// Name returns the step implementation name.
func (*redactStep) Name() string { return NameRedact }

// Run applies the redaction plan to the payload in place. ctx is honored
// between findings, per match and per segment.
func (r *redactStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !r.cfg.kinds[in.Kind] {
		return nil
	}
	if len(payloadText(in)) > r.cfg.maxInput {
		return fmt.Errorf("input %d bytes exceeds max_input %d — refusing to scan (fail-closed; raise max_input or set on_error)", len(payloadText(in)), r.cfg.maxInput)
	}
	layout := layoutOf(in)
	edits, err := collectSpanEdits(ctx, r.cfg, layout, out.Findings)
	if err != nil {
		return err
	}
	if len(edits) == 0 {
		return nil
	}
	r.notePatternHits(out, p, layout, edits)
	texts, err := applySpanEdits(ctx, layout, edits, func(e plannedEdit, ord int) (string, error) {
		return "[REDACTED:" + tokenCategory(e.category) + ":" + fmt.Sprint(ord) + "]", nil
	})
	if err != nil {
		return err
	}
	writeBack(in, layout, texts)
	return nil
}

// notePatternHits appends one content-free flag finding per own-pattern hit.
// Span coordinates are translated back to the joined inspected text so the
// finding stays consistent with the detector span convention.
func (r *redactStep) notePatternHits(out *pipeline.Result, p *pipeline.Pipeline, l textLayout, edits []plannedEdit) {
	for _, e := range edits {
		if e.fromFinding {
			continue
		}
		seg := l.segs[e.seg]
		out.Findings = append(out.Findings, finding(
			p.StepID(), e.category, sevMedium,
			span(seg.start+e.start, seg.start+e.end),
			"", pipeline.ActionFlag,
		))
	}
}

// NewRedact builds builtin/redact.
//
// Params: "categories" (optional list of findings categories; exact names or
// a trailing ".*" wildcard; absent = every spanned finding), "patterns"
// (optional list of {category, pattern} maps scanned in addition to the
// findings), "max_input" (bytes, default 1 MiB, cap 64 MiB), plus the common
// kinds param. Default kinds: ALL payload kinds including
// stream policies must not silently skip a kinds-less redact step); an
// explicit "kinds" narrows as usual.
func NewRedact(params map[string]any) (pipeline.Step, error) {
	cfg, err := parseSpanMutator(params)
	if err != nil {
		return nil, err
	}
	return &redactStep{cfg: cfg}, nil
}

// compile-time guard: redact is a Mutator (linear order, never in groups).
var _ pipeline.Mutator = (*redactStep)(nil)
