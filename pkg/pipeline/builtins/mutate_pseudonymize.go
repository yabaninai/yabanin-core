package builtins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// pseudonymizeStep is builtin/pseudonymize: reversible pseudonymization —
// every sensitive span is replaced with a stable "{{YPP_n}}" alias and the
// original→alias map lives ONLY within the Engine run (request_only, owner
// decision 2026-10-06). There is no global cache and nothing persists: the
// map is rebuilt deterministically from the payload + findings on every run
// and, when carry=session carries it, only through the run's own Meta —
// never through the step value (steps must not carry per-request state).
//
// NUMBERING: aliases are assigned by first occurrence in text order,
// continuing after the highest {{YPP_n}} already present in the text (so two
// pseudonymize steps of one run compose without shared state) and after the
// highest number of the session carrier (stable identity across turns).
// The same original text always maps to the same alias within a run.
//
// DIRECTION: substitutions flow OUTBOUND ONLY. The client sees aliases; the
// gateway never substitutes back into a response — that reversal is exactly
// what the request_only decision forbids (owner decision, plan §2.2 п.5).
//
// CARRY (OP-8 MultiTurn CONTRACT): "carry: none" (default) leaves nothing
// behind — the map dies with the run. "carry: session" writes the carrier
// (JSON alias→original) into payload.Meta.Labels[PseudonymCarrierLabel]:
// OP-8 persists it with the session and injects it into subsequent requests
// of the same session, and MUST strip the label before dispatching upstream
// or to the client — the carrier values are the original sensitive strings.
// See PseudonymCarrierLabel for the full contract.
type pseudonymizeStep struct {
	pipeline.MutatorBase
	cfg          spanMutator
	carrySession bool
}

// Name returns the step implementation name.
func (*pseudonymizeStep) Name() string { return NamePseudonymize }

// Run applies the alias plan to the payload in place. ctx is honored
// between findings, per match and per segment.
func (s *pseudonymizeStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !s.cfg.kinds[in.Kind] {
		return nil
	}
	if len(payloadText(in)) > s.cfg.maxInput {
		return fmt.Errorf("input %d bytes exceeds max_input %d — refusing to scan (fail-closed; raise max_input or set on_error)", len(payloadText(in)), s.cfg.maxInput)
	}
	aliasToOriginal, maxN, err := s.seedCarrier(in)
	if err != nil {
		return err
	}
	layout := layoutOf(in)
	// Numbering continues after the highest alias token already present in
	// the text (two pseudonymize steps of one run compose without shared
	// state) as well as after the highest carried number.
	if n := maxAliasInLayout(layout); n > maxN {
		maxN = n
	}
	edits, err := collectSpanEdits(ctx, s.cfg, layout, out.Findings)
	if err != nil {
		return err
	}
	if len(edits) == 0 {
		return nil
	}
	originalToAlias := make(map[string]string, len(aliasToOriginal)+len(edits))
	for alias, orig := range aliasToOriginal {
		originalToAlias[orig] = alias
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	texts, err := applySpanEdits(ctx, layout, edits, func(e plannedEdit, _ int) (string, error) {
		orig := layout.segs[e.seg].text[e.start:e.end]
		alias, ok := originalToAlias[orig]
		if !ok {
			if len(aliasToOriginal) >= maxPseudonyms {
				return "", fmt.Errorf("pseudonym map reached the %d-alias limit (fail-closed; narrow the patterns/categories or raise nothing — the limit is fixed)", maxPseudonyms)
			}
			maxN++
			alias = fmt.Sprintf("{{YPP_%d}}", maxN)
			originalToAlias[orig] = alias
			aliasToOriginal[alias] = orig
		}
		return alias, nil
	})
	if err != nil {
		return err
	}
	writeBack(in, layout, texts)
	return s.writeCarrier(in, aliasToOriginal)
}

// maxAliasInLayout returns the highest {{YPP_n}} number present in the
// layout's text (0 when none).
func maxAliasInLayout(l textLayout) int {
	maxN := 0
	for _, seg := range l.segs {
		for _, loc := range aliasTokenRe.FindAllStringIndex(seg.text, -1) {
			if g := aliasExactRe.FindStringSubmatch(seg.text[loc[0]:loc[1]]); g != nil {
				if n, err := strconv.Atoi(g[1]); err == nil && n > maxN {
					maxN = n
				}
			}
		}
	}
	return maxN
}

// seedCarrier reads the carry-session carrier from Meta.Labels (carry=none
// or an absent label seed an empty map; maxN=0 lets text numbering decide).
func (s *pseudonymizeStep) seedCarrier(in *pipeline.Payload) (map[string]string, int, error) {
	if !s.carrySession {
		return map[string]string{}, 0, nil
	}
	if in.Meta == nil {
		return nil, 0, fmt.Errorf("carry=session requires payload.Meta (request identity) — a payload without Meta cannot carry session state")
	}
	raw, ok := in.Meta.Labels[PseudonymCarrierLabel]
	if !ok || raw == "" {
		return map[string]string{}, 0, nil
	}
	m, maxN, err := decodePseudonymCarrier(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("pseudonym carrier label is corrupt: %w (fail-closed; the session carrier must be passed through unmodified)", err)
	}
	if len(m) > maxPseudonyms {
		return nil, 0, fmt.Errorf("pseudonym carrier carries %d aliases, above the %d-alias limit", len(m), maxPseudonyms)
	}
	return m, maxN, nil
}

// writeCarrier publishes the alias→original map into Meta.Labels when
// carry=session (see PseudonymCarrierLabel for the OP-8 obligations). With
// carry=none it is a no-op: nothing leaves the run.
func (s *pseudonymizeStep) writeCarrier(in *pipeline.Payload, aliasToOriginal map[string]string) error {
	if !s.carrySession {
		return nil
	}
	if in.Meta == nil {
		// writeBack created no Meta and seedCarrier already rejected nil Meta;
		// defensive only.
		return fmt.Errorf("carry=session requires payload.Meta")
	}
	encoded, err := encodePseudonymCarrier(aliasToOriginal)
	if err != nil {
		return err
	}
	if in.Meta.Labels == nil {
		in.Meta.Labels = make(map[string]string, 1)
	}
	in.Meta.Labels[PseudonymCarrierLabel] = encoded
	return nil
}

// NewPseudonymize builds builtin/pseudonymize.
//
// Params: "categories" and "patterns" (same semantics as builtin/redact —
// the alias spans come from findings and/or own patterns), "carry"
// ("none" default | "session"), "max_input" (bytes, default 1 MiB, cap
// 64 MiB), plus the common kinds param. Default kinds: ALL payload kinds
// kinds-less pseudonymize step must mutate the buffered prefix, not
// silently no-op); an explicit "kinds" narrows as usual.
func NewPseudonymize(params map[string]any) (pipeline.Step, error) {
	cfg, err := parseSpanMutator(params)
	if err != nil {
		return nil, err
	}
	carry, err := parseCarry(params)
	if err != nil {
		return nil, err
	}
	return &pseudonymizeStep{cfg: cfg, carrySession: carry}, nil
}

// parseCarry resolves the optional "carry" param: none (default) | session.
func parseCarry(params map[string]any) (bool, error) {
	raw, ok := params["carry"]
	if !ok || raw == nil {
		return false, nil
	}
	v, err := anyToString(raw)
	if err != nil {
		return false, fmt.Errorf("params.carry: %w", err)
	}
	switch v {
	case "none":
		return false, nil
	case "session":
		return true, nil
	default:
		return false, fmt.Errorf("params.carry: %q: want none|session", v)
	}
}

// compile-time guard: pseudonymize is a Mutator.
var _ pipeline.Mutator = (*pseudonymizeStep)(nil)
