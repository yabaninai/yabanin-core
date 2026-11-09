// Package policydecide implements the "decide" pipeline step (the verdict
// stage the sovereign-default pack uses) as gateway registration glue
// (OP-8). The registry name is reserved by the pkg/pipeline contract; the
// implementation lives here because pkg/pipeline is import-only for the
//
// The step's "expr" reserved param (merged by the core, see
// pipeline.StepSpec resolveKind) is a small decision DSL:
//
//	deny  if findings.any(f -> f.category matches 'secrets.*' and f.severity == 'high')
//	mask  if findings.any(f -> f.action == 'mask')
//	flag  otherwise
//
// Grammar (line-based, order-significant — the first matching rule wins):
//
//	rule     := action "if" cond | action "otherwise"
//	action   := deny | mask | flag | allow
//	cond     := "findings.any(f ->" pred ")"   (pred = comparison { "and" comparison })
//	comparison := "f." field op literal
//	field    := category | severity | action | step | span
//	op       := "==" | "matches"               (matches: '*' | trailing-star prefix | exact)
//	literal  := single-quoted string
//
// "otherwise" sets the fallback action when no rule matches (default allow).
// The step raises out.Verdict only — it never mutates and never appends
// findings. Unknown syntax is a factory error (policy LOAD failure, never a
// silent skip). Evaluation is pure and goroutine-safe.
package policydecide

import (
	"context"
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// FactoryName is the registry name (the core's decide kind resolves to it).
const FactoryName = "decide"

// Factory builds one decide step from the merged params. The reserved "expr"
// key carries the DSL source.
func Factory(params map[string]any) (pipeline.Step, error) {
	src, _ := params["expr"].(string)
	if strings.TrimSpace(src) == "" {
		return nil, fmt.Errorf("decide: expr source is required")
	}
	rules, fallback, err := parse(src)
	if err != nil {
		return nil, fmt.Errorf("decide: %w", err)
	}
	return &step{rules: rules, fallback: fallback}, nil
}

// step is one compiled decide step. Immutable; safe for concurrent Runs.
type step struct {
	rules    []rule
	fallback pipeline.Action
}

// Name returns the implementation name for diagnostics.
func (s *step) Name() string { return "gateway/decide" }

// Run applies the decision rules to the findings recorded so far and raises
// the verdict (decide steps may raise out.Verdict only).
func (s *step) Run(_ context.Context, p *pipeline.Pipeline, _ *pipeline.Payload, out *pipeline.Result) error {
	action := s.fallback
	for _, r := range s.rules {
		if r.matches(out.Findings) {
			action = r.action
			break
		}
	}
	if action == "" {
		return nil
	}
	out.Verdict = out.Verdict.Max(action)
	return nil
}

// rule is one compiled line of the DSL.
type rule struct {
	action pipeline.Action
	conds  []condition // empty = the otherwise fallback line
}

// matches reports whether every condition holds for the findings.
func (r rule) matches(findings []pipeline.Finding) bool {
	for _, c := range r.conds {
		if !c.any(findings) {
			return false
		}
	}
	return true
}

// condition is one findings.any(f -> ...) predicate.
type condition struct {
	field string
	op    string // "==" | "matches"
	value string
}

// any reports whether at least one finding satisfies the comparison.
func (c condition) any(findings []pipeline.Finding) bool {
	for _, f := range findings {
		if c.holds(f) {
			return true
		}
	}
	return false
}

func (c condition) holds(f pipeline.Finding) bool {
	var actual string
	switch c.field {
	case "category":
		actual = f.Category
	case "severity":
		actual = f.Severity
	case "action":
		actual = string(f.Action)
	case "step":
		actual = f.Step
	case "span":
		actual = f.Span
	default:
		return false
	}
	if c.op == "matches" {
		return matchPattern(c.value, actual)
	}
	return actual == c.value
}

// matchPattern mirrors the repo's pattern semantics ('*' alone, trailing-star
// prefix, exact).
func matchPattern(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return pattern == s
}

// parse compiles the DSL source. Unknown actions, malformed predicates and
// unknown fields are errors (policy LOAD failure).
func parse(src string) ([]rule, pipeline.Action, error) {
	var rules []rule
	fallback := pipeline.ActionAllow
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		actionTok, rest, found := strings.Cut(line, " ")
		if !found {
			return nil, "", fmt.Errorf("line %q: want \"<action> if <cond>\" or \"<action> otherwise\"", line)
		}
		action, err := parseAction(actionTok)
		if err != nil {
			return nil, "", fmt.Errorf("line %q: %w", line, err)
		}
		rest = strings.TrimSpace(rest)
		switch {
		case rest == "otherwise":
			fallback = action
			continue
		case strings.HasPrefix(rest, "if "):
			cond, err := parseCond(strings.TrimSpace(strings.TrimPrefix(rest, "if ")))
			if err != nil {
				return nil, "", fmt.Errorf("line %q: %w", line, err)
			}
			rules = append(rules, rule{action: action, conds: cond})
		default:
			return nil, "", fmt.Errorf("line %q: want \"if\" or \"otherwise\"", line)
		}
	}
	return rules, fallback, nil
}

func parseAction(tok string) (pipeline.Action, error) {
	a := pipeline.Action(tok)
	switch a {
	case pipeline.ActionDeny, pipeline.ActionMask, pipeline.ActionFlag, pipeline.ActionAllow:
		return a, nil
	default:
		return "", fmt.Errorf("unknown action %q (want deny|mask|flag|allow)", tok)
	}
}

// parseCond parses "findings.any(f -> PRED)" into its conjunction. PRED is
// comparisons joined by " and " (no or, no parentheses — the pack grammar).
func parseCond(src string) ([]condition, error) {
	const wrapper = "findings.any(f ->"
	if !strings.HasPrefix(src, wrapper) || !strings.HasSuffix(src, ")") {
		return nil, fmt.Errorf("cond %q: want findings.any(f -> <pred>)", src)
	}
	pred := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(src, wrapper), ")"))
	var conds []condition
	for _, part := range strings.Split(pred, " and ") {
		c, err := parseComparison(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		conds = append(conds, c)
	}
	return conds, nil
}

func parseComparison(src string) (condition, error) {
	fields := strings.Fields(src)
	if len(fields) != 3 || !strings.HasPrefix(fields[0], "f.") {
		return condition{}, fmt.Errorf("comparison %q: want \"f.<field> <op> '<literal>'\"", src)
	}
	field := strings.TrimPrefix(fields[0], "f.")
	switch field {
	case "category", "severity", "action", "step", "span":
	default:
		return condition{}, fmt.Errorf("comparison %q: unknown field %q", src, field)
	}
	op := fields[1]
	if op != "==" && op != "matches" {
		return condition{}, fmt.Errorf("comparison %q: unknown op %q (want == or matches)", src, op)
	}
	value, err := strconvUnquote(fields[2])
	if err != nil {
		return condition{}, fmt.Errorf("comparison %q: %w", src, err)
	}
	return condition{field: field, op: op, value: value}, nil
}

// strconvUnquote parses a single-quoted literal (no escapes in the grammar).
func strconvUnquote(tok string) (string, error) {
	if len(tok) >= 2 && strings.HasPrefix(tok, "'") && strings.HasSuffix(tok, "'") {
		return tok[1 : len(tok)-1], nil
	}
	return "", fmt.Errorf("literal %q must be single-quoted", tok)
}
