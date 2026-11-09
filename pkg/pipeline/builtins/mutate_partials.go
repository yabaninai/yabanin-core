package builtins

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// PartialsSource is the minimal seam for builtin/partials-substitute: it
// resolves one named partial to its rendered body.
//
// PartialsSource through the step's "source" PARAM at wiring time (params
// are ordinary Go values at the programmatic Registry/factory boundary —
// YAML cannot carry one, so policies get the source only when the gateway
// wiring injects it).
//
//	type PartialsSource interface {
//	    Get(ctx context.Context, name string) (body string, found bool, err error)
//	}
//
// Implementations must be goroutine-safe (one step value serves concurrent
// runs) and must honor ctx. The name is the "{{partials.NAME}}" token's NAME
// part ([A-Za-z0-9_.-]+, no braces). found=false means the partial does not
// exist ("on_missing" decides); err aborts the step (on_error semantics).
//
// SUBSTITUTION SEMANTICS: single pass, left to right — a partial body is
// inserted verbatim and NEVER rescanned (no recursive expansion, a body may
// safely contain "{{partials.…}}" literal text). The substituted payload is
// the request sent upstream; the caller's payload is never touched (engine
// clone).
type PartialsSource interface {
	Get(ctx context.Context, name string) (body string, found bool, err error)
}

// NoopPartials is the built-in stub source: it resolves nothing
// (found=false for every name). With the default on_missing=skip the
// {{partials.name}} tokens pass through unchanged — a placeholder until
type NoopPartials struct{}

// Get resolves nothing.
func (NoopPartials) Get(context.Context, string) (string, bool, error) { return "", false, nil }

// compile-time guard: the stub satisfies the seam.
var _ PartialsSource = NoopPartials{}

// partialsRe matches "{{partials.name}}" tokens; the name group is the
// PartialsSource lookup key.
var partialsRe = regexp.MustCompile(`\{\{\s*partials\.([A-Za-z0-9_.-]+)\s*\}\}`)

// maxPartialBytes bounds one partial body (a source returning megabytes
// cannot blow the payload past the gateway limits silently).
const maxPartialBytes = 64 << 10

// partialsStep is builtin/partials-substitute.
type partialsStep struct {
	pipeline.MutatorBase
	kinds        map[pipeline.PayloadKind]bool
	src          PartialsSource
	onMissingErr bool
}

// Name returns the step implementation name.
func (*partialsStep) Name() string { return NamePartialsSubstitute }

// Run substitutes {{partials.name}} tokens per text segment (payloadText
// layout: messages, body fallback, chunk fallback). ctx is honored per
// segment and per lookup.
func (s *partialsStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !s.kinds[in.Kind] {
		return nil
	}
	layout := layoutOf(in)
	if len(layout.segs) == 0 {
		return nil
	}
	texts := make([]string, len(layout.segs))
	changed := false
	for i, seg := range layout.segs {
		if err := ctx.Err(); err != nil {
			return err
		}
		locs := partialsRe.FindAllStringSubmatchIndex(seg.text, -1)
		if len(locs) == 0 {
			texts[i] = seg.text
			continue
		}
		var sb strings.Builder
		pos := 0
		for _, loc := range locs {
			name := seg.text[loc[2]:loc[3]]
			body, found, err := s.src.Get(ctx, name)
			if err != nil {
				return fmt.Errorf("partial %q: %w", name, err)
			}
			if !found {
				if s.onMissingErr {
					return fmt.Errorf("partial %q: not found (on_missing=error)", name)
				}
				continue // skip: keep the token verbatim
			}
			if len(body) > maxPartialBytes {
				return fmt.Errorf("partial %q is %d bytes, exceeds the %d-byte limit", name, len(body), maxPartialBytes)
			}
			sb.WriteString(seg.text[pos:loc[0]])
			sb.WriteString(body)
			pos = loc[1]
		}
		if pos == 0 {
			texts[i] = seg.text
			continue
		}
		sb.WriteString(seg.text[pos:])
		texts[i] = sb.String()
		changed = true
	}
	if changed {
		writeBack(in, layout, texts)
	}
	return nil
}

// NewPartialsSubstitute builds builtin/partials-substitute.
//
// Params: "source" (optional PartialsSource value; default NoopPartials —
// nothing resolves, tokens pass through), "on_missing" ("skip" default |
// "error": an unresolved token fails the step, fail-closed), plus the common
// kinds param (default request).
func NewPartialsSubstitute(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params, pipeline.KindRequest)
	if err != nil {
		return nil, err
	}
	var src PartialsSource = NoopPartials{}
	if raw, ok := params["source"]; ok && raw != nil {
		s, ok := raw.(PartialsSource)
		if !ok {
			return nil, fmt.Errorf("params.source: %T does not implement builtins.PartialsSource", raw)
		}
		src = s
	}
	onMissingErr := false
	if raw, ok := params["on_missing"]; ok && raw != nil {
		v, err := anyToString(raw)
		if err != nil {
			return nil, fmt.Errorf("params.on_missing: %w", err)
		}
		switch v {
		case "skip":
		case "error":
			onMissingErr = true
		default:
			return nil, fmt.Errorf("params.on_missing: %q: want skip|error", v)
		}
	}
	return &partialsStep{kinds: kinds, src: src, onMissingErr: onMissingErr}, nil
}

// compile-time guard: partials-substitute is a Mutator.
var _ pipeline.Mutator = (*partialsStep)(nil)
