package builtins

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Code-detection heuristics (offline, deterministic, best-effort): each
// language is scored by DISTINCT signal hits; crossing the threshold reports
// one finding per language. Signals are linear word-bounded regexes compiled
// once at package init (like guardhooks: compiled patterns, no global
// registry mutation).
//
// Precision is intentionally conservative (Python/TS signals are
// case-sensitive, SQL needs three distinct keywords) — the step is an
// observation (severity low, action default flag), not a hard gate.
const (
	codeThresholdSQL = 3
	codeThresholdPy  = 2
	codeThresholdTS  = 2
)

// code signal tables: one named regex per signal.
var (
	// SQL keywords are conventionally uppercase but accepted in any case;
	// multi-word keywords collapse to their head word via the \b group.
	sqlSignals = []signal{
		{"select", regexp.MustCompile(`(?i)\bselect\b`)},
		{"insert", regexp.MustCompile(`(?i)\binsert\b`)},
		{"update", regexp.MustCompile(`(?i)\bupdate\b`)},
		{"delete", regexp.MustCompile(`(?i)\bdelete\b`)},
		{"drop", regexp.MustCompile(`(?i)\bdrop\b`)},
		{"alter", regexp.MustCompile(`(?i)\balter\b`)},
		{"truncate", regexp.MustCompile(`(?i)\btruncate\b`)},
		{"create", regexp.MustCompile(`(?i)\bcreate\b`)},
		{"join", regexp.MustCompile(`(?i)\bjoin\b`)},
		{"where", regexp.MustCompile(`(?i)\bwhere\b`)},
		{"having", regexp.MustCompile(`(?i)\bhaving\b`)},
		{"union", regexp.MustCompile(`(?i)\bunion\b`)},
		{"group_by", regexp.MustCompile(`(?i)\bgroup\s+by\b`)},
		{"order_by", regexp.MustCompile(`(?i)\border\s+by\b`)},
	}

	pySignals = []signal{
		{"def", regexp.MustCompile(`\bdef \w`)},
		{"self", regexp.MustCompile(`\bself\.`)},
		{"elif", regexp.MustCompile(`\belif\b`)},
		{"__init__", regexp.MustCompile(`__init__`)},
		{"lambda", regexp.MustCompile(`\blambda\b`)},
		{"None", regexp.MustCompile(`\bNone\b`)},
		{"print", regexp.MustCompile(`\bprint\(`)},
		{"import", regexp.MustCompile(`\bimport \w`)},
		{"raise", regexp.MustCompile(`\braise \w`)},
		{"yield", regexp.MustCompile(`\byield\b`)},
	}

	tsSignals = []signal{
		{"const", regexp.MustCompile(`\bconst \w`)},
		{"let", regexp.MustCompile(`\blet \w`)},
		{"arrow", regexp.MustCompile(`=>`)},
		{"interface", regexp.MustCompile(`\binterface \w`)},
		{"export", regexp.MustCompile(`\bexport \w`)},
		{"function", regexp.MustCompile(`\bfunction \w`)},
		{"strict_eq", regexp.MustCompile(`=== ?`)},
		{"strict_neq", regexp.MustCompile(`!== ?`)},
		{"type_string", regexp.MustCompile(`: string\b`)},
		{"type_number", regexp.MustCompile(`: number\b`)},
	}
)

// signal is one named detection signal.
type signal struct {
	name string
	re   *regexp.Regexp
}

// codeStep reports detected programming languages in the payload text.
type codeStep struct {
	pipeline.DetectorBase
	kinds     map[pipeline.PayloadKind]bool
	act       pipeline.Action
	languages map[string]bool
}

// Name returns the step implementation name.
func (*codeStep) Name() string { return "builtin/code-detect" }

// Run scores each selected language and reports one finding per detection.
func (c *codeStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
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
	for _, lang := range []struct {
		name      string
		signals   []signal
		threshold int
	}{
		{"sql", sqlSignals, codeThresholdSQL},
		{"python", pySignals, codeThresholdPy},
		{"typescript", tsSignals, codeThresholdTS},
	} {
		if !c.languages[lang.name] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		hits := signalHits(text, lang.signals)
		if len(hits) >= lang.threshold {
			out.Findings = append(out.Findings, finding(
				p.StepID(), "code."+lang.name, sevLow, "",
				"signals: "+clipEvidence(strings.Join(hits, ", "), maxEvidence), c.act,
			))
		}
	}
	return nil
}

// signalHits returns the names of signals matching text (one entry per
// signal — distinct by construction).
func signalHits(text string, sigs []signal) []string {
	hits := make([]string, 0, len(sigs))
	for _, s := range sigs {
		if s.re.MatchString(text) {
			hits = append(hits, s.name)
		}
	}
	return hits
}

// NewCodeDetect builds builtin/code-detect.
//
// Params: "languages" (subset of sql|python|typescript, default all), plus
// the common kinds/action. Unknown language names are load errors.
func NewCodeDetect(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	languages := map[string]bool{"sql": true, "python": true, "typescript": true}
	if raw, ok := params["languages"]; ok && raw != nil {
		items, err := anyToStrings(raw)
		if err != nil {
			return nil, fmt.Errorf("params.languages: %w", err)
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("params.languages: at least one language is required")
		}
		languages = make(map[string]bool, len(items))
		for _, it := range items {
			switch it {
			case "sql", "python", "typescript":
				languages[it] = true
			default:
				return nil, fmt.Errorf("params.languages: %q: want sql|python|typescript", it)
			}
		}
	}
	return &codeStep{kinds: kinds, act: act, languages: languages}, nil
}

// compile-time guard: code-detect is a read-only Detector.
var _ pipeline.Detector = (*codeStep)(nil)
