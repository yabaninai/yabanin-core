package builtins

import (
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

func TestWordCount_Range(t *testing.T) {
	cases := []struct {
		name     string
		params   map[string]any
		text     string
		wantFire bool
	}{
		{"in range", map[string]any{"min": 1, "max": 3}, "one two three", false},
		{"below min", map[string]any{"min": 2}, "one", true},
		{"above max", map[string]any{"max": 1}, "one two", true},
		{"min only, pass", map[string]any{"min": 1}, "one", false},
		{"unicode fields", map[string]any{"min": 3}, "  привет\tмир\nмир  ", false},
	}
	for _, tc := range cases {
		res := runOne(t, NameWordCount, tc.params, reqPayload(tc.text))
		assertRan(t, res)
		fs := findingsOf(res, "s1")
		if tc.wantFire && len(fs) != 1 {
			t.Errorf("%s: findings = %v, want 1", tc.name, fs)
		}
		if !tc.wantFire && len(fs) != 0 {
			t.Errorf("%s: findings = %v, want none", tc.name, fs)
		}
		if tc.wantFire && len(fs) == 1 {
			if fs[0].Category != "word_count" || fs[0].Severity != sevMedium {
				t.Errorf("%s: finding = %+v, want word_count/medium", tc.name, fs[0])
			}
			if !strings.Contains(fs[0].Evidence, "count=") {
				t.Errorf("%s: evidence = %q, want count report", tc.name, fs[0].Evidence)
			}
		}
	}
}

func TestCharCount_Runes(t *testing.T) {
	// "привет" is 6 runes / 12 bytes: the count must be rune-based.
	res := runOne(t, NameCharCount, map[string]any{"min": 7}, reqPayload("привет"))
	assertRan(t, res)
	fs := findingsOf(res, "s1")
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence, "count=6") {
		t.Errorf("findings = %v, want one violation with count=6 (runes, not bytes)", fs)
	}
	res = runOne(t, NameCharCount, map[string]any{"min": 6}, reqPayload("привет"))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("findings = %v, want none (exactly at min)", fs)
	}
}

func TestSentenceCount_Heuristic(t *testing.T) {
	cases := []struct {
		text string
		want int
	}{
		{"", 0},
		{"Hello. World!", 2},
		{"wait...", 1},
		{"no terminator here", 1},
		{"One. Two. Three.", 3},
		{"3.14 alone", 2}, // decimal point is a heuristic false split — pinned
		{"Правда? Да! Итак…", 3},
	}
	for _, tc := range cases {
		if got := countSentences(tc.text); got != tc.want {
			t.Errorf("countSentences(%q) = %d, want %d", tc.text, got, tc.want)
		}
	}
	res := runOne(t, NameSentenceCount, map[string]any{"min": 2}, reqPayload("Only one."))
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 1 || fs[0].Category != "sentence_count" {
		t.Errorf("findings = %v, want one sentence_count violation", fs)
	}
}

func TestCounter_EmptyPayloadCounts(t *testing.T) {
	// Detectors skip empty payloads; counters measure the empty text as 0 and
	// fire against an explicit min — the documented asymmetry.
	in := &pipeline.Payload{Kind: pipeline.KindRequest, Meta: &pipeline.RequestMeta{Model: "m"}}
	res := runOne(t, NameWordCount, map[string]any{"min": 1}, in)
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 1 || !strings.Contains(fs[0].Evidence, "count=0") {
		t.Errorf("findings = %v, want count=0 violation", fs)
	}
}

func TestCounter_BoundsValidation(t *testing.T) {
	for _, params := range []map[string]any{
		{},                   // no bounds — inert step
		{"min": -1},          // negative
		{"min": 5, "max": 2}, // inverted
		{"min": "many"},      // non-integer
	} {
		mustCompileErr(t, NameWordCount, params)
	}
}

func TestContains_Modes(t *testing.T) {
	cases := []struct {
		name     string
		params   map[string]any
		text     string
		wantFire bool
	}{
		{"none fires", map[string]any{"words": []any{"password", "api key"}, "mode": "none"}, "my Password here", true},
		{"none clean", map[string]any{"words": []any{"password"}, "mode": "none"}, "all clean", false},
		{"any one suffices", map[string]any{"words": []any{"alpha", "beta"}, "mode": "any"}, "beta", true},
		{"any missing", map[string]any{"words": []any{"alpha", "beta"}, "mode": "any"}, "gamma", false},
		{"all needs both", map[string]any{"words": []any{"alpha", "beta"}, "mode": "all"}, "alpha", false},
		{"all fires", map[string]any{"words": []any{"alpha", "beta"}, "mode": "all"}, "alpha AND beta", true},
		{"case sensitive off", map[string]any{"words": []any{"password"}, "case_insensitive": false}, "PASSWORD", false},
	}
	for _, tc := range cases {
		res := runOne(t, NameContains, tc.params, reqPayload(tc.text))
		assertRan(t, res)
		fs := findingsOf(res, "s1")
		if tc.wantFire && len(fs) != 1 {
			t.Errorf("%s: findings = %v, want 1", tc.name, fs)
		}
		if !tc.wantFire && len(fs) != 0 {
			t.Errorf("%s: findings = %v, want none", tc.name, fs)
		}
		if tc.wantFire && len(fs) == 1 && fs[0].Category != "contains" {
			t.Errorf("%s: category = %q, want contains", tc.name, fs[0].Category)
		}
	}
}

func TestContains_Edges(t *testing.T) {
	// Empty payload: nothing to search — no finding.
	in := &pipeline.Payload{Kind: pipeline.KindRequest, Meta: &pipeline.RequestMeta{Model: "m"}}
	res := runOne(t, NameContains, map[string]any{"words": []any{"x"}, "mode": "any"}, in)
	assertRan(t, res)
	if fs := findingsOf(res, "s1"); len(fs) != 0 {
		t.Errorf("empty payload findings = %v, want none", fs)
	}
	// Config validation.
	mustCompileErr(t, NameContains, map[string]any{})
	mustCompileErr(t, NameContains, map[string]any{"words": []any{""}})
	mustCompileErr(t, NameContains, map[string]any{"words": []any{"x"}, "mode": "some"})
}
