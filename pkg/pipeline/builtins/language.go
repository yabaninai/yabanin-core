package builtins

import (
	"context"
	"fmt"
	"unicode"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// languageStep classifies the payload text by dominant script (offline
// heuristic — unicode range tables, never an LLM call):
//
//	ru    — Cyrillic is the dominant script and ≥30% of the letters;
//	en    — Latin is dominant and ≥30% of the letters (ties go to ru);
//	other — everything else (CJK, Arabic, mixed below threshold, …).
//
// With a non-empty "allowed" list ({ru,en,other}) the step reports one
// finding when the detected language is NOT allowed. An empty list makes the
// step inert and is a load error (a silently-inert policy step is a config
// bug).
type languageStep struct {
	pipeline.DetectorBase
	kinds   map[pipeline.PayloadKind]bool
	act     pipeline.Action
	allowed map[string]bool
}

// Name returns the step implementation name.
func (*languageStep) Name() string { return "builtin/language" }

// Run classifies the text and reports an allow-list violation.
func (s *languageStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !s.kinds[in.Kind] {
		return nil
	}
	text := payloadText(in)
	if text == "" {
		return nil
	}
	lang, cy, la := classifyScript(text)
	if s.allowed[lang] {
		return nil
	}
	out.Findings = append(out.Findings, finding(
		p.StepID(), "language", sevLow, "",
		fmt.Sprintf("detected=%s cyrillic=%d latin=%d", lang, cy, la), s.act,
	))
	return nil
}

// classifyScript counts Cyrillic and Latin letters and applies the
// dominance rule described on languageStep.
func classifyScript(text string) (lang string, cy, la int) {
	for _, r := range text {
		switch {
		case unicode.Is(unicode.Cyrillic, r):
			cy++
		case unicode.Is(unicode.Latin, r):
			la++
		}
	}
	total := cy + la
	if total == 0 {
		return "other", 0, 0
	}
	// percentOf letters, integer arithmetic (deterministic, no floats).
	switch {
	case cy >= la && cy*100 >= 30*total:
		return "ru", cy, la
	case la > cy && la*100 >= 30*total:
		return "en", cy, la
	default:
		return "other", cy, la
	}
}

// NewLanguage builds builtin/language.
//
// Params: "allowed" (required non-empty subset of ru|en|other), plus the
// common kinds/action.
func NewLanguage(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	items, err := paramStrings(params, "allowed")
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(items))
	for _, it := range items {
		switch it {
		case "ru", "en", "other":
			allowed[it] = true
		default:
			return nil, fmt.Errorf("params.allowed: %q: want ru|en|other", it)
		}
	}
	return &languageStep{kinds: kinds, act: act, allowed: allowed}, nil
}

// compile-time guard: language is a read-only Detector.
var _ pipeline.Detector = (*languageStep)(nil)
