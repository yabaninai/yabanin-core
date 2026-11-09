package builtins

import (
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

func TestRegex_Positive(t *testing.T) {
	params := map[string]any{"pattern": `[a-z]+@[a-z]+\.[a-z]{2,4}`, "action": "deny"}
	res := runOne(t, NameRegex, params, reqPayload("mail bob@example.com now"))
	assertRan(t, res)

	fs := findingsOf(res, "s1")
	if len(fs) != 1 {
		t.Fatalf("findings = %v, want 1", fs)
	}
	f := fs[0]
	if f.Category != "regex" || f.Severity != sevMedium || f.Action != pipeline.ActionDeny {
		t.Errorf("finding = %+v, want regex/medium/deny", f)
	}
	if f.Span != "5:20" {
		t.Errorf("span = %q, want 5:20 (bob@example.com)", f.Span)
	}
	if f.Evidence != "bob@example.com" {
		t.Errorf("evidence = %q, want the match", f.Evidence)
	}
	if res.Verdict != pipeline.ActionDeny {
		t.Errorf("verdict = %q, want deny", res.Verdict)
	}
}

func TestRegex_MatchesCapped(t *testing.T) {
	res := runOne(t, NameRegex, map[string]any{"pattern": "a"}, reqPayload(strings.Repeat("a", 500)))
	assertRan(t, res)
	if got := len(findingsOf(res, "s1")); got != maxRegexMatches {
		t.Errorf("findings = %d, want capped at %d", got, maxRegexMatches)
	}
}

func TestRegex_InvertAndCaseFold(t *testing.T) {
	res := runOne(t, NameRegex, map[string]any{"pattern": "approved", "invert": true}, reqPayload("status: pending"))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 1 {
		t.Errorf("invert on non-matching text: findings = %v, want 1", fs)
	}
	res = runOne(t, NameRegex, map[string]any{"pattern": "approved", "invert": true}, reqPayload("status: approved"))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("invert on matching text: findings = %v, want none", fs)
	}
	// case_insensitive=true folds via (?i) prefix.
	res = runOne(t, NameRegex, map[string]any{"pattern": "approved", "case_insensitive": true}, reqPayload("APPROVED"))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 1 {
		t.Errorf("case-insensitive: findings = %v, want 1", fs)
	}
}

func TestRegex_KindsAndEmpty(t *testing.T) {
	params := map[string]any{"pattern": "x", "kinds": []any{"response"}}
	res := runOne(t, NameRegex, params, reqPayload("xxx"))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("unselected kind findings = %v, want none", fs)
	}
	res = runOne(t, NameRegex, params, respPayload("xxx"))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 3 {
		t.Errorf("selected kind findings = %v, want 3", fs)
	}
	// Empty payload: nothing to scan — no finding even with invert.
	res = runOne(t, NameRegex, map[string]any{"pattern": "x", "invert": true}, &pipeline.Payload{Kind: pipeline.KindRequest})
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("empty payload findings = %v, want none", fs)
	}
}

// TestRegex_ReDoSAudit pins the factory-time rejection of the classic
// backtracking shapes and expansion bombs. RE2 matching is linear for any
// accepted pattern; the audit exists to bound COMPILE-time expansion and to
// keep the policy surface conservative (see regex.go for the rationale).
func TestRegex_ReDoSAudit(t *testing.T) {
	rejected := []string{
		`(a+)+`,           // classic nested quantifier
		`((a+)+b)+`,       // transitively nested
		`(?:x{100}){100}`, // nested counted repeats (expansion 10^4+ shape)
		`a{50000}`,        // single huge bounded repeat
		`a{2,4}{3,5}`,     // directly nested counted
		`x*+`,             // parsed as nested (star then plus)
		strings.Repeat("a", maxRegexPatternLen+1), // length cap
	}
	for _, p := range rejected {
		mustCompileErr(t, NameRegex, map[string]any{"pattern": p})
	}

	accepted := []string{
		`[a-z]+@[a-z]+\.[a-z]{2,4}`, // sequential (not nested) quantifiers
		`(?:a|aa)+`,                 // alternation of literals: no nested quantifier, RE2-linear
		`(?:ab|cd)+`,                // alternation of literals under a quantifier
		`[^"\\]+`,                   // the unrolled-loop idiom without nesting
		`a{1000}`,                   // Go's own per-repeat maximum
		`\b\d{13,19}\b`,             // PAN-shaped
	}
	for _, p := range accepted {
		// Acceptance = the step compiles and runs; matches themselves depend
		// on the payload.
		res := runOne(t, NameRegex, map[string]any{"pattern": p, "kinds": []any{"request"}}, reqPayload("nothing to see"))
		assertRan(t, res)
	}
}

func TestRegex_MaxInputFailClosed(t *testing.T) {
	big := strings.Repeat("a", 64)
	params := map[string]any{"pattern": "a", "max_input": 10}
	// Default on_error=fail_closed: the refusal is a step error and denies.
	res := runOne(t, NameRegex, params, reqPayload(big))
	if len(res.Trace) != 1 || res.Trace[0].Outcome != pipeline.StepError {
		t.Fatalf("trace = %+v, want one error outcome", res.Trace)
	}
	if res.Verdict != pipeline.ActionDeny {
		t.Errorf("verdict = %q, want deny (fail_closed)", res.Verdict)
	}
	// fail_open policy: the error is recorded and ignored.
	res = runOne(t, NameRegex, params, reqPayload(big), func(p *pipeline.Policy) {
		p.Steps[0].OnError = pipeline.OnErrorFailOpen
	})
	if res.Trace[0].Outcome != pipeline.StepError {
		t.Errorf("outcome = %q, want error (recorded)", res.Trace[0].Outcome)
	}
	if res.Verdict != pipeline.ActionAllow {
		t.Errorf("verdict = %q, want allow (fail_open)", res.Verdict)
	}
	// max_input validation at load time.
	mustCompileErr(t, NameRegex, map[string]any{"pattern": "a", "max_input": -1})
	mustCompileErr(t, NameRegex, map[string]any{"pattern": "a", "max_input": 1 << 30})
}

func TestRegex_GiantLinearInputFast(t *testing.T) {
	// ~750 KB input with a linear pattern: completes without any timeout
	// mechanism. If this regresses to super-linear behavior the test suite
	// wall-clock exposes it.
	res := runOne(t, NameRegex, map[string]any{"pattern": `ab{0,2}c`}, reqPayload(strings.Repeat("abcaaa", 125000)))
	assertRan(t, res)
	// The findings-per-run cap (maxRegexMatches) keeps the result bounded.
	if got := len(findingsOf(res, "s1")); got != maxRegexMatches {
		t.Errorf("findings = %d, want capped at %d", got, maxRegexMatches)
	}
}
