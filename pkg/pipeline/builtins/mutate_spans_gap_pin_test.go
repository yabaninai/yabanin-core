package builtins

// Permanent pins for redaction invariants that previously had no named
// test: hostile-category token parseability (tokenCategory) and the
// per-pattern, per-segment own-pattern match cap (maxSpanMatches). These
// tests PIN current behavior; a red run means a regression, not a license
// to change the mutation contract.

import (
	"context"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// GAP-R3: tokenCategory maps every rune outside [A-Za-z0-9._-] to "_", so a
// hostile detector category can never break the "[REDACTED:<cat>:<n>]" token
// shape that redactTokenRe (and every downstream consumer) re-parses.
func TestGapPinTokenCategorySanitization(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"pan", "pan"},
		{"innsnils.v2", "innsnils.v2"},
		{"api-key_1", "api-key_1"},
		{"my cat", "my_cat"},
		{"]:1] bad cat", "__1__bad_cat"},
		{"a[b]c", "a_b_c"},
		{"x:y\nz", "x_y_z"},
		{"🙂", "_"},
		{"", ""},
	} {
		if got := tokenCategory(tc.in); got != tc.want {
			t.Errorf("tokenCategory(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// GAP-R3 end-to-end (audit probe 6 in the appendix, adopted permanently): a
// finding whose category is a token-shape attack ("...]...:...") still yields
// a token redactTokenRe matches, and a re-run whose own pattern would match
// the digits inside the token leaves the token text untouched — the
// parseability and idempotency boundaries hold together.
func TestGapPinHostileCategoryTokenStaysParseable(t *testing.T) {
	st, err := NewRedact(nil)
	if err != nil {
		t.Fatal(err)
	}
	in := reqPayload("secret value here")
	out := &pipeline.Result{Findings: []pipeline.Finding{
		{Step: "d", Category: "]:1] bad cat", Span: "0:6", Action: pipeline.ActionMask},
	}}
	if err := st.Run(context.Background(), nil, in, out); err != nil {
		t.Fatal(err)
	}
	if got, want := in.Messages[0].Content, "[REDACTED:__1__bad_cat:1] value here"; got != want {
		t.Fatalf("hostile-category redaction = %q, want %q", got, want)
	}
	// The emitted token is parseable by the package's own token grammar.
	tok := redactTokenRe.FindString(in.Messages[0].Content)
	if tok == "" {
		t.Fatalf("no parseable [REDACTED:...] token in %q", in.Messages[0].Content)
	}
	if tok != "[REDACTED:__1__bad_cat:1]" {
		t.Fatalf("parsed token = %q, want the sanitized-category token", tok)
	}
	// A second run with a digit pattern aimed at the token's ordinal must be
	// a no-op: tokens are protected ranges.
	st2, err := NewRedact(map[string]any{
		"patterns": []any{map[string]any{"category": "n", "pattern": "[0-9]+"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(in.Messages[0].Content, tok)
	out2 := &pipeline.Result{Findings: []pipeline.Finding{
		{Step: "d", Category: "x", Span: itoa(i) + ":" + itoa(i+len(tok)), Action: pipeline.ActionMask},
	}}
	if err := st2.Run(context.Background(), nil, in, out2); err != nil {
		t.Fatal(err)
	}
	if in.Messages[0].Content != "[REDACTED:__1__bad_cat:1] value here" {
		t.Fatalf("re-run mutated the token text: %q", in.Messages[0].Content)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// GAP-R5: maxSpanMatches caps matches of ONE pattern per text segment at 100.
// Observable outcome: the step never errors on an over-cap segment; exactly
// the first 100 matches in text order are replaced (ordinals 1..100), the
// remainder stays literal. (Run through the engine like every own-pattern
// test: the engine supplies the *pipeline.Pipeline that notePatternHits
// reads the step id from — a hand-rolled Run with a nil pipeline is outside
// every production path and is not a supported call form.)
func TestGapPinOwnPatternMatchCap(t *testing.T) {
	params := map[string]any{
		"patterns": []any{map[string]any{"category": "d", "pattern": "[0-9]{3}"}},
	}
	res := runMutatorOne(t, NameRedact, params, reqPayload(strings.Repeat(" 111", 150)))
	assertRan(t, res)
	got := content(t, res)
	if n := strings.Count(got, "[REDACTED:"); n != maxSpanMatches {
		t.Fatalf("redacted matches = %d, want exactly %d", n, maxSpanMatches)
	}
	// The first match in text order got ordinal 1; the cap stops at 100.
	if !strings.HasPrefix(got, " [REDACTED:d:1]") {
		t.Errorf("first match not redacted in place: %q", got[:30])
	}
	if !strings.Contains(got, "[REDACTED:d:"+itoa(maxSpanMatches)+"]") {
		t.Errorf("missing ordinal %d token", maxSpanMatches)
	}
	if strings.Contains(got, "[REDACTED:d:"+itoa(maxSpanMatches+1)+"]") {
		t.Errorf("ordinal beyond the cap emitted")
	}
	// The 50 uncapped matches survive verbatim ("111" cannot appear inside a
	// token: ordinals never reach three digits).
	if n := strings.Count(got, "111"); n != 150-maxSpanMatches {
		t.Fatalf("literal leftovers = %d, want %d", n, 150-maxSpanMatches)
	}

	// The cap is PER SEGMENT: two messages over the cap redact 2×100 in one
	// run (and one cross-message span still fails closed — covered by the
	// layout tests). Ordinals keep counting across the whole payload.
	in2 := reqPayload(strings.Repeat(" 9", 120))
	in2.Messages = append(in2.Messages, pipeline.Message{Role: "user", Content: strings.Repeat(" 9", 120)})
	res2 := runMutatorOne(t, NameRedact, map[string]any{
		"patterns": []any{map[string]any{"category": "d", "pattern": "[0-9]"}},
	}, in2)
	assertRan(t, res2)
	if n := strings.Count(content(t, res2), "[REDACTED:"); n != 2*maxSpanMatches {
		t.Fatalf("two-segment redactions = %d, want %d (cap is per segment)", n, 2*maxSpanMatches)
	}
}
