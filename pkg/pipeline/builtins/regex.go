package builtins

import (
	"context"
	"fmt"
	"regexp"
	"regexp/syntax"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// ReDoS protection (justification of the approach):
//
//  1. Go's regexp implements RE2. Matching is LINEAR in input length for
//     every pattern the parser accepts — there is no backtracking engine, so
//     the classic catastrophic-backtracking ReDoS ((a+)+ against "aaaa…b")
//     is structurally impossible at match time. No input can make a compiled
//     builtin/regex step go super-linear.
//
//  2. The remaining blowup is COMPILE-time expansion of bounded repeats:
//     (?:x{100}){100} parses fine but expands to 10_000 nodes while compiling.
//     A policy is admin-authored config, yet loading it must stay cheap and
//     predictable, so the factory audits the parsed syntax tree and rejects:
//     a. patterns longer than maxRegexPatternLen bytes;
//     b. NESTED QUANTIFIERS — any quantifier (*, +, ?, {n,m}) whose subtree
//     contains another quantifier. This is stricter than strictly
//     necessary for RE2 (unbounded nesting is linear to compile), but it
//     is the shape every expansion bomb needs, it keeps the audit simple
//     enough to reason about, and policy authors are org admins, not
//     regex specialists: linear unrolled forms (?:ab|cd)+ or [^"\\]+
//     remain writable without nesting.
//     c. repeat-expansion products above maxRegexExpansion on any path
//     through the tree. (Go additionally caps a single repeat at 1000
//     inside syntax.Parse — the product cap is the belt to that brace:
//     it keeps the invariant explicit if the upstream limit moves.)
//
//  3. Input-side bound: runs refuse payloads above "max_input" bytes
//     (default 1 MiB, hard cap 64 MiB) with a step ERROR — fail_closed by
//     default, so an oversized payload cannot silently bypass the check. A
//     policy may relax this via on_error or raise max_input within the cap.
//
// A pattern that fails the audit is a factory error, i.e. a policy LOAD
// error — a bad pattern can never reach request time.
const (
	maxRegexPatternLen = 512
	maxRegexExpansion  = 10000
	defRegexMaxInput   = 1 << 20 // 1 MiB
	maxRegexMaxInput   = 64 << 20
	maxRegexMatches    = 100
)

// regexStep fires on user-configured pattern matches (or, inverted, on their
// absence).
type regexStep struct {
	pipeline.DetectorBase
	kinds    map[pipeline.PayloadKind]bool
	act      pipeline.Action
	re       *regexp.Regexp
	invert   bool
	maxInput int
	pattern  string // for diagnostics only
}

// Name returns the step implementation name.
func (*regexStep) Name() string { return "builtin/regex" }

// Run scans the payload text. The RE2 scan is atomic (uninterruptible) but
// linear and input-bounded; ctx is honored between phases and per match.
func (r *regexStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !r.kinds[in.Kind] {
		return nil
	}
	text := payloadText(in)
	if len(text) > r.maxInput {
		return fmt.Errorf("input %d bytes exceeds max_input %d — refusing to scan (fail-closed; raise max_input or set on_error)", len(text), r.maxInput)
	}
	if text == "" {
		return nil
	}
	matches := r.re.FindAllStringIndex(text, maxRegexMatches)
	if r.invert {
		if len(matches) > 0 {
			return nil
		}
		out.Findings = append(out.Findings, finding(
			p.StepID(), "regex", sevMedium, "",
			"no match: "+clipEvidence(r.pattern, maxEvidence), r.act,
		))
		return nil
	}
	for _, m := range matches {
		if err := ctx.Err(); err != nil {
			return err
		}
		out.Findings = append(out.Findings, finding(
			p.StepID(), "regex", sevMedium,
			span(m[0], m[1]), clipEvidence(text[m[0]:m[1]], maxEvidence), r.act,
		))
	}
	return nil
}

// NewRegex builds builtin/regex.
//
// Params: "pattern" (required RE2 syntax), "invert" (default false: fire
// when the pattern does NOT match), "case_insensitive" (default false,
// implemented as a (?i) prefix), "max_input" (bytes, default 1 MiB, cap
// 64 MiB), plus the common kinds/action.
func NewRegex(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	pattern, err := paramString(params, "pattern")
	if err != nil {
		return nil, err
	}
	invert, err := paramBool(params, "invert", false)
	if err != nil {
		return nil, err
	}
	fold, err := paramBool(params, "case_insensitive", false)
	if err != nil {
		return nil, err
	}
	maxInput, err := paramInt(params, "max_input", defRegexMaxInput)
	if err != nil {
		return nil, err
	}
	if maxInput <= 0 || maxInput > maxRegexMaxInput {
		return nil, fmt.Errorf("params.max_input: %d: must be in (0, %d] bytes", maxInput, maxRegexMaxInput)
	}
	if len(pattern) > maxRegexPatternLen {
		return nil, fmt.Errorf("params.pattern: %d bytes exceeds the %d-byte limit", len(pattern), maxRegexPatternLen)
	}
	if fold {
		pattern = "(?i)" + pattern
	}
	re, err := compileAuditedRegex(pattern)
	if err != nil {
		return nil, fmt.Errorf("params.pattern: %w", err)
	}
	return &regexStep{kinds: kinds, act: act, re: re, invert: invert, maxInput: maxInput, pattern: pattern}, nil
}

// compileAuditedRegex parses pattern with the regexp/syntax tree parser,
// audits the tree (no nested quantifiers, bounded expansion product) and
// compiles it. Parsing twice (once for the audit, once to compile) is cheap
// relative to the safety of gating policy load.
func compileAuditedRegex(pattern string) (*regexp.Regexp, error) {
	tree, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}
	if err := auditQuantifiers(tree, 1); err != nil {
		return nil, err
	}
	return regexp.Compile(pattern)
}

// auditQuantifiers walks the syntax tree enforcing the no-nested-quantifier
// rule and bounding the bounded-repeat expansion product along each path.
// product is the expansion factor accumulated from enclosing repeats.
func auditQuantifiers(re *syntax.Regexp, product int) error {
	if product > maxRegexExpansion {
		return fmt.Errorf("repeat expansion product %d exceeds the limit %d", product, maxRegexExpansion)
	}
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		// re.Sub[0] is the quantified expression; if it contains any
		// quantifier itself, the pattern is rejected. (Non-greedy forms like
		// a+? are parser flags on this node, not nested quest nodes.)
		if err := hasQuantifier(re.Sub[0]); err != nil {
			return fmt.Errorf("nested quantifier: %w", err)
		}
		// Unbounded quantifiers compile to a single instruction (no
		// expansion); bounded OpRepeat expands to Max copies, multiplying
		// the product of enclosing bounded repeats.
		if re.Op == syntax.OpRepeat && re.Max > 0 {
			product *= re.Max
			if product > maxRegexExpansion {
				return fmt.Errorf("repeat expansion product %d exceeds the limit %d", product, maxRegexExpansion)
			}
		}
		// The child subtree is quantifier-free (checked above) — nothing
		// further to audit there.
		return nil
	default:
		for _, sub := range re.Sub {
			if err := auditQuantifiers(sub, product); err != nil {
				return err
			}
		}
		return nil
	}
}

// hasQuantifier reports whether the subtree rooted at re contains any
// quantifier node (the nested-quantifier rejection for quantifier children).
func hasQuantifier(re *syntax.Regexp) error {
	if re.Op == syntax.OpStar || re.Op == syntax.OpPlus || re.Op == syntax.OpQuest || re.Op == syntax.OpRepeat {
		return fmt.Errorf("quantifier directly or transitively inside another quantifier is rejected (rewrite without nesting)")
	}
	for _, sub := range re.Sub {
		if err := hasQuantifier(sub); err != nil {
			return err
		}
	}
	return nil
}

// compile-time guard: regex is a read-only Detector.
var _ pipeline.Detector = (*regexStep)(nil)
