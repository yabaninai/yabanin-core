package builtins

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// counterStep is the shared implementation of word/char/sentence-count: one
// finding when the measured count violates the [min,max] range. max = 0
// means "no upper bound"; both bounds 0 makes the step inert (a config bug
// worth a load error, so at least one bound is required).
type counterStep struct {
	pipeline.DetectorBase
	name     string
	category string
	kinds    map[pipeline.PayloadKind]bool
	act      pipeline.Action
	min      int
	max      int
	measure  func(text string) int
}

// Name returns the step implementation name.
func (c *counterStep) Name() string { return c.name }

// Run measures the payload text and reports one range-violation finding.
func (c *counterStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !c.kinds[in.Kind] {
		return nil
	}
	text := payloadText(in)
	n := c.measure(text)
	if n >= c.min && (c.max == 0 || n <= c.max) {
		return nil
	}
	out.Findings = append(out.Findings, finding(
		p.StepID(), c.category, sevMedium,
		"", fmt.Sprintf("count=%d min=%d max=%d (input %d bytes)", n, c.min, c.max, len(text)),
		c.act,
	))
	return nil
}

// NewWordCount builds builtin/word-count: Unicode-whitespace word count
// against the "min"/"max" range.
func NewWordCount(params map[string]any) (pipeline.Step, error) {
	return newCounter(params, "builtin/word-count", "word_count", func(text string) int {
		return len(strings.Fields(text))
	})
}

// NewCharCount builds builtin/char-count: character count in RUNES (not
// bytes) against the "min"/"max" range.
func NewCharCount(params map[string]any) (pipeline.Step, error) {
	return newCounter(params, "builtin/char-count", "char_count", utf8.RuneCountInString)
}

// NewSentenceCount builds builtin/sentence-count against the "min"/"max"
// range. The count is an offline heuristic: terminators (".", "!", "?", "…")
// terminate a sentence when followed by content; consecutive terminators
// collapse; a trailing unterminated sentence counts once. Decimal points
// ("3.14") may inflate the count — the heuristic trades precision for
// determinism and zero dependencies.
func NewSentenceCount(params map[string]any) (pipeline.Step, error) {
	return newCounter(params, "builtin/sentence-count", "sentence_count", countSentences)
}

// newCounter validates the shared counter params and builds the step.
func newCounter(params map[string]any, name, category string, measure func(string) int) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	min, err := paramInt(params, "min", 0)
	if err != nil {
		return nil, err
	}
	max, err := paramInt(params, "max", 0)
	if err != nil {
		return nil, err
	}
	if min < 0 || max < 0 {
		return nil, fmt.Errorf("params.min/params.max: negative bounds are not allowed (min=%d max=%d)", min, max)
	}
	if max > 0 && min > max {
		return nil, fmt.Errorf("params.min=%d exceeds params.max=%d", min, max)
	}
	if min == 0 && max == 0 {
		return nil, fmt.Errorf("params.min/params.max: at least one bound is required (a step with no bounds can never fire)")
	}
	return &counterStep{
		name: name, category: category, kinds: kinds, act: act,
		min: min, max: max, measure: measure,
	}, nil
}

// countSentences implements the sentence heuristic (see NewSentenceCount).
func countSentences(text string) int {
	n := 0
	prevTerm := false
	hasContent := false
	for _, r := range text {
		switch {
		case r == '.' || r == '!' || r == '?' || r == '…':
			if hasContent && !prevTerm {
				n++
			}
			prevTerm = true
		case unicode.IsSpace(r):
			// whitespace inside or between sentences: no state change beyond
			// leaving prevTerm as-is so "a.  b" stays one terminator.
		default:
			hasContent = true
			prevTerm = false
		}
	}
	if hasContent && !prevTerm {
		n++ // trailing sentence without terminator
	}
	return n
}

// compile-time guard: counters are read-only Detectors.
var _ pipeline.Detector = (*counterStep)(nil)

// containsMode vocabulary.
const (
	containsAny  = "any"
	containsAll  = "all"
	containsNone = "none"
)

// containsStep fires when the configured mode condition over the configured
// words holds in the inspected text:
//
//	any  — at least one word is present;
//	all  — every word is present;
//	none — any word is present (ban-list semantics).
//
// One finding per run listing the matched words (words are policy config,
// safe to quote); matching is substring-based, case-insensitively by default.
type containsStep struct {
	pipeline.DetectorBase
	kinds map[pipeline.PayloadKind]bool
	act   pipeline.Action
	words []string // lower-cased when fold
	mode  string
	fold  bool
}

// Name returns the step implementation name.
func (*containsStep) Name() string { return "builtin/contains" }

// Run evaluates the mode condition and reports one finding when it holds.
func (c *containsStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !c.kinds[in.Kind] {
		return nil
	}
	text := payloadText(in)
	if text == "" {
		return nil
	}
	if c.fold {
		text = strings.ToLower(text)
	}
	matched := make([]string, 0, len(c.words))
	for _, w := range c.words {
		if strings.Contains(text, w) {
			matched = append(matched, w)
		}
	}
	fired := false
	switch c.mode {
	case containsAny:
		fired = len(matched) > 0
	case containsAll:
		fired = len(matched) == len(c.words)
	case containsNone:
		fired = len(matched) > 0
	}
	if !fired {
		return nil
	}
	ev := "no match"
	if len(matched) > 0 {
		ev = "matched: " + clipEvidence(strings.Join(matched, ", "), maxEvidence)
	}
	out.Findings = append(out.Findings, finding(
		p.StepID(), "contains", sevMedium, "", ev, c.act,
	))
	return nil
}

// NewContains builds builtin/contains.
//
// Params: "words" (required, non-empty list), "mode" (any|all|none, default
// any), "case_insensitive" (default true), plus the common kinds/action.
func NewContains(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	words, err := paramStrings(params, "words")
	if err != nil {
		return nil, err
	}
	mode := containsAny
	if raw, ok := params["mode"]; ok && raw != nil {
		s, err := anyToString(raw)
		if err != nil {
			return nil, fmt.Errorf("params.mode: %w", err)
		}
		switch s {
		case containsAny, containsAll, containsNone:
			mode = s
		default:
			return nil, fmt.Errorf("params.mode: %q: want any|all|none", s)
		}
	}
	fold, err := paramBool(params, "case_insensitive", true)
	if err != nil {
		return nil, err
	}
	if fold {
		lowered := make([]string, len(words))
		for i, w := range words {
			lowered[i] = strings.ToLower(w)
		}
		words = lowered
	}
	return &containsStep{kinds: kinds, act: act, words: words, mode: mode, fold: fold}, nil
}

// compile-time guard: contains is a read-only Detector.
var _ pipeline.Detector = (*containsStep)(nil)
